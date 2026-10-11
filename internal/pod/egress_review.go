// Copyright 2026 Jerry David Chan, Konareef.ai
// SPDX-License-Identifier: Apache-2.0

// egress_review.go — the client copy of the server's egress review rules.
//
// reef-core reviews every published pod revision with a static egress
// scanner and records a closed set of finding codes. A listing server can
// then require a clean (or operator-approved) review before it lists the
// pod. This file holds the same rules on the client, so an author sees
// the server's answer before publishing. It contains:
//
//   - parseEgressRules and egressAllowed: how a [network] declaration is
//     read and how a host:port is matched against it. A port is a number,
//     a host is ASCII-lowercased with one trailing dot removed, and a "*."
//     rule matches one or more leading labels but never the apex.
//   - isIPLiteral: the inet_aton(3) reading of an address, so "127.1",
//     "2130706433" and "0x7f000001" all count as IP literals.
//   - EgressReviewPreview: the review's finding set for a pod directory.
//   - EgressWarnings: the declaration-level findings as `pod validate`
//     warnings.
//
// testdata/egress-vectors.json holds the shared cases. The Go tests run
// them against this file, and scripts/check_egress_vectors.exs runs them
// against the server's scanner, so a drift on either side fails a check.
//
// Everything here is advisory. The server's review is the record, and the
// runtime proxy is the enforcement. A clean preview means the pod's own
// files name no other host; a model can still build a hostname at run
// time that no static scan sees.
package pod

import (
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"unicode/utf8"
)

// EgressReviewScannerVersion and EgressReviewPolicyVersion name the
// server scanner and finding-policy versions these rules copy. They
// change only together with testdata/egress-vectors.json.
const (
	EgressReviewScannerVersion = "v1"
	EgressReviewPolicyVersion  = "v1"
)

// DefaultPlatformHost is the default platform LLM host of a reef-core
// node. A reference to it that the pod does not declare is reported as
// platform_host_referenced. A node operator can configure another host,
// so a preview against this default can miss one on such a node.
const DefaultPlatformHost = "api.anthropic.com:443"

// Review finding codes. They are the server's closed vocabulary, spelled
// exactly as the server stores them.
const (
	ReviewUndeclaredHost         = "undeclared_host"
	ReviewWildcardDeclared       = "wildcard_declared"
	ReviewDeclaredUnused         = "declared_unused"
	ReviewIPLiteralDeclared      = "ip_literal_declared"
	ReviewNonTLSPort             = "non_tls_port"
	ReviewPlatformHostReferenced = "platform_host_referenced"
)

// ReviewFlags reports whether a finding code makes the server's review
// "flagged" under policy v1. declared_unused and platform_host_referenced
// are advisory: they appear in the record but do not flag it.
func ReviewFlags(code string) bool {
	switch code {
	case ReviewUndeclaredHost, ReviewWildcardDeclared, ReviewIPLiteralDeclared, ReviewNonTLSPort:
		return true
	}
	return false
}

// Source classes: where a finding came from. A finding about the
// [network] table itself, and one from the inline [directive].task, both
// have the class "manifest".
const (
	SourceManifest   = "manifest"
	SourceDirective  = "directive"
	SourceSkill      = "skill"
	SourcePrompt     = "prompt"
	SourceMemoryFile = "memory_file"
	SourceMemoryHTTP = "memory_http"
)

// Warning codes `pod validate` emits for a declaration the server review
// flags. They never fail validation.
const (
	WarnEgressWildcardReview = "EGRESS_WILDCARD_REVIEW"
	WarnEgressIPLiteral      = "EGRESS_IP_LITERAL"
	WarnEgressNonTLSPort     = "EGRESS_NON_TLS_PORT"
)

// ReviewFinding is one finding of the egress review. Host is normalized,
// or "<invalid-host>" when the text named something that is not a host
// the server would store. It never carries a path, a query or a snippet.
type ReviewFinding struct {
	Code        string `json:"code"`
	Host        string `json:"host"`
	Port        int    `json:"port"`
	SourceClass string `json:"source_class"`
}

// String renders a finding as "code host:port (source_class)".
func (finding ReviewFinding) String() string {
	return fmt.Sprintf("%s %s:%d (%s)", finding.Code, finding.Host, finding.Port, finding.SourceClass)
}

// reviewRule is one parsed [network].egress or [[network.gateway]] entry.
// host is normalized and keeps IPv6 brackets; for a wildcard it has no
// leading "*.". declaredAs is the normalized entry as written, with the
// "*.", and is the host a declaration finding names.
type reviewRule struct {
	host       string
	port       int
	wildcard   bool
	declaredAs string
	path       string // the manifest path of the entry, for warnings
}

// EgressDeclared reports whether spec declares its egress: true for any
// [network] table, including a bare table, `egress = []` and a
// gateway-only table. This is the question a listing server's
// declaration gate asks. An absent table is undeclared.
func EgressDeclared(spec Spec) bool {
	return spec.Network != nil
}

// parseEgressRules reads [network].egress then [[network.gateway]] into
// match rules, in manifest order. An entry whose host is empty is
// skipped. Input: the parsed spec. Output: the rules, nil when the table
// is absent.
func parseEgressRules(spec Spec) []reviewRule {
	if spec.Network == nil {
		return nil
	}
	var rules []reviewRule
	for index, entry := range spec.Network.Egress {
		host, port := reviewSplitHostPort(strings.TrimSpace(entry))
		if host == "" {
			continue
		}
		host = normalizeHost(host)
		rule := reviewRule{host: host, port: port, declaredAs: host,
			path: fmt.Sprintf("network.egress[%d]", index)}
		if strings.HasPrefix(host, "*.") {
			rule.wildcard = true
			for strings.HasPrefix(rule.host, "*.") {
				rule.host = strings.TrimPrefix(rule.host, "*.")
			}
		}
		rules = append(rules, rule)
	}
	for index, entry := range spec.Network.Gateway {
		host, port := reviewSplitHostPort(strings.TrimSpace(entry.Host))
		if host == "" {
			continue
		}
		host = normalizeHost(host)
		rules = append(rules, reviewRule{host: host, port: port, declaredAs: host,
			path: fmt.Sprintf("network.gateway[%d].host", index)})
	}
	return rules
}

// egressAllowed reports whether host:port is covered by any rule. host is
// normalized first. A "*." rule matches one or more leading labels and
// never the apex: "*.example.com" covers "api.example.com" but not
// "example.com" or "badexample.com".
func egressAllowed(rules []reviewRule, host string, port int) bool {
	host = normalizeHost(host)
	for _, rule := range rules {
		if rule.port != port {
			continue
		}
		if rule.wildcard {
			if strings.HasSuffix(host, "."+rule.host) {
				return true
			}
			continue
		}
		if host == rule.host {
			return true
		}
	}
	return false
}

// normalizeHost removes one trailing dot and lowercases ASCII letters
// only. The server does the same; a Unicode lowercase here would make the
// two sides store different hosts for the same text.
func normalizeHost(host string) string {
	host = strings.TrimSuffix(host, ".")
	var builder strings.Builder
	builder.Grow(len(host))
	for index := 0; index < len(host); index++ {
		char := host[index]
		if char >= 'A' && char <= 'Z' {
			char += 'a' - 'A'
		}
		builder.WriteByte(char)
	}
	return builder.String()
}

// reviewSplitHostPort splits a declared "host", "host:port", "[v6]" or
// "[v6]:port" entry. The port must be a whole decimal number in 1..65535;
// anything else is not a port, and the whole entry is then the host with
// port 443. A bracketed IPv6 host keeps its brackets.
func reviewSplitHostPort(entry string) (string, int) {
	if strings.HasPrefix(entry, "[") {
		end := strings.Index(entry, "]")
		if end < 0 {
			return entry, 443
		}
		host := entry[:end+1]
		if rest := entry[end+1:]; strings.HasPrefix(rest, ":") {
			if port, ok := parsePort(rest[1:]); ok {
				return host, port
			}
		}
		return host, 443
	}
	index := strings.LastIndex(entry, ":")
	if index < 0 {
		return entry, 443
	}
	if port, ok := parsePort(entry[index+1:]); ok {
		return entry[:index], port
	}
	return entry, 443
}

// parsePort reads a port the way the server's Integer.parse does: an
// optional sign, then decimal digits and nothing else, in 1..65535.
func parsePort(text string) (int, bool) {
	value, ok := parseSignedDecimal(text)
	if !ok || value < 1 || value > 65535 {
		return 0, false
	}
	return int(value), true
}

// parseSignedDecimal accepts an optional "+" or "-" followed by one or
// more ASCII digits. It reports false for anything else, including a
// value too large for int64.
func parseSignedDecimal(text string) (int64, bool) {
	digits := strings.TrimPrefix(strings.TrimPrefix(text, "+"), "-")
	if len(text)-len(digits) > 1 || digits == "" {
		return 0, false
	}
	for index := 0; index < len(digits); index++ {
		if digits[index] < '0' || digits[index] > '9' {
			return 0, false
		}
	}
	value, err := strconv.ParseInt(text, 10, 64)
	if err != nil {
		return 0, false
	}
	return value, true
}

// isIPLiteral reports whether host is an IP address in any form the
// server's CONNECT proxy treats as one: every IPv4 and IPv6 form
// net/netip reads, plus the legacy inet_aton(3) forms — one to four
// parts, each decimal, octal (leading 0) or hex (leading 0x), where the
// last part fills the remaining bytes. A host in [brackets] is read
// without them.
func isIPLiteral(host string) bool {
	if strings.HasPrefix(host, "[") {
		if inner, ok := strings.CutSuffix(host[1:], "]"); ok && !strings.Contains(inner, "]") {
			host = inner
		}
	}
	if _, err := netip.ParseAddr(host); err == nil {
		return true
	}
	return inetAtonValid(host)
}

// inetAtonValid reports whether host parses as an inet_aton(3) IPv4
// address. Each part before the last names one byte; the last part names
// every remaining byte, so it may be as large as the space left.
func inetAtonValid(host string) bool {
	parts := strings.Split(host, ".")
	if len(parts) < 1 || len(parts) > 4 {
		return false
	}
	numbers := make([]uint64, len(parts))
	for index, part := range parts {
		number, ok := inetAtonPart(part)
		if !ok {
			return false
		}
		numbers[index] = number
	}
	for _, leading := range numbers[:len(numbers)-1] {
		if leading > 0xFF {
			return false
		}
	}
	remainingBits := uint(4-(len(numbers)-1)) * 8
	return numbers[len(numbers)-1] < uint64(1)<<remainingBits
}

// inetAtonPart parses one inet_aton part: "0x" or "0X" means hex, a
// leading "0" means octal, "0" alone is zero, and anything else is
// decimal. The whole part must be consumed. Like the server's parser, one
// optional sign is accepted after the base prefix.
func inetAtonPart(part string) (uint64, bool) {
	switch {
	case part == "":
		return 0, false
	case strings.HasPrefix(part, "0x"), strings.HasPrefix(part, "0X"):
		return parseUnsignedInBase(part[2:], 16)
	case part == "0":
		return 0, true
	case strings.HasPrefix(part, "0"):
		return parseUnsignedInBase(part[1:], 8)
	default:
		return parseUnsignedInBase(part, 10)
	}
}

// parseUnsignedInBase parses digits in base with one optional sign, the
// way the server's Integer.parse does. A "-" is accepted only when the
// value is zero ("-0" is 0 there); any other negative value is refused,
// since no address part may be negative.
func parseUnsignedInBase(digits string, base int) (uint64, bool) {
	negative := false
	if digits != "" && (digits[0] == '+' || digits[0] == '-') {
		negative = digits[0] == '-'
		digits = digits[1:]
	}
	if digits == "" || digits[0] == '+' || digits[0] == '-' {
		return 0, false
	}
	value, err := strconv.ParseUint(digits, base, 64)
	if err != nil || (negative && value != 0) {
		return 0, false
	}
	return value, true
}

// maxURLMatchBytes caps one extracted URL before trimming, as the server
// does, so a very long run of URL characters is not read in full.
const maxURLMatchBytes = 2048

// reviewURLPattern reads the scheme and authority of an extracted URL.
// The authority ends at the first "/", "?", "#" or whitespace.
var reviewURLPattern = regexp.MustCompile(`^(?i:(https?))://([^/?#\t\n\v\f\r ]*)`)

// reviewReference is one URL found in scanned text, reduced to what a
// finding needs.
type reviewReference struct {
	sourceClass string
	host        string
	port        int
	scheme      string
}

// parseReviewURL reads the scheme, host and port of an extracted URL the
// way the server does. It deliberately does not use net/url: a template
// host such as "{{HOST}}" must survive as its literal text, which
// url.Parse refuses. Userinfo is dropped. Output: false when the text has
// no usable authority.
func parseReviewURL(raw string) (host string, port int, scheme string, ok bool) {
	match := reviewURLPattern.FindStringSubmatch(raw)
	if match == nil || match[2] == "" {
		return "", 0, "", false
	}
	scheme = strings.ToLower(match[1])
	authority := match[2]
	if at := strings.LastIndex(authority, "@"); at >= 0 {
		authority = authority[at+1:]
	}
	host, explicitPort, ok := splitReviewAuthority(authority)
	if !ok {
		return "", 0, "", false
	}
	if explicitPort == 0 {
		explicitPort = 443
		if scheme == "http" {
			explicitPort = 80
		}
	}
	return normalizeHost(host), explicitPort, scheme, true
}

// splitReviewAuthority splits a URL authority into host and port. Port 0
// means "no explicit port". A bracketed host must be followed by nothing
// or by ":<port>" with a valid port. An unbracketed authority whose text
// after the last ":" is not a valid port is all host.
func splitReviewAuthority(authority string) (string, int, bool) {
	if strings.HasPrefix(authority, "[") {
		end := strings.Index(authority, "]")
		if end < 0 {
			return "", 0, false
		}
		host, rest := authority[:end+1], authority[end+1:]
		switch {
		case rest == "":
			return host, 0, true
		case strings.HasPrefix(rest, ":"):
			if port, ok := parsePort(rest[1:]); ok {
				return host, port, true
			}
		}
		return "", 0, false
	}
	if authority == "" {
		return "", 0, false
	}
	index := strings.LastIndex(authority, ":")
	if index < 0 {
		return authority, 0, true
	}
	if port, ok := parsePort(authority[index+1:]); ok {
		return authority[:index], port, true
	}
	return authority, 0, true
}

// maxFindingHostBytes and findingHostPattern bound what a finding stores
// as its host. Anything else is replaced with invalidFindingHost.
const (
	maxFindingHostBytes = 253
	invalidFindingHost  = "<invalid-host>"
)

var findingHostPattern = regexp.MustCompile(`^[a-z0-9.\-:\[\]{}$_*]*$`)

// newFinding builds a finding and sanitizes its host exactly as the
// server does before it stores one.
func newFinding(code, host string, port int, sourceClass string) ReviewFinding {
	if len(host) > maxFindingHostBytes || !utf8.ValidString(host) || !findingHostPattern.MatchString(host) {
		host = invalidFindingHost
	}
	return ReviewFinding{Code: code, Host: host, Port: port, SourceClass: sourceClass}
}

// reviewUnit is one piece of scanned text with its source class, or one
// URL the manifest declares outright (a kind = "http" memory entry).
type reviewUnit struct {
	sourceClass string
	text        string
	isURL       bool
}

// EgressReviewPreview computes the server review's finding set for the pod
// at dir. It reads the same sources as SafetyCheckStrict and fails the
// same way: a declared context source that cannot be read is an error,
// never a clean result. platformHost is the "host" or "host:port" of the
// node's platform LLM rule; pass DefaultPlatformHost when it is unknown.
//
// The result is advisory. The server applies size and time limits this
// preview does not, and may run a newer scanner.
func EgressReviewPreview(dir string, spec Spec, platformHost string) ([]ReviewFinding, error) {
	units, err := reviewUnits(dir, spec)
	if err != nil {
		return nil, err
	}
	return reviewFindings(spec, units, platformHost), nil
}

// reviewUnits collects the text and URLs the review scans, each tagged
// with its source class. Files come from contextFiles, which enforces
// containment; an uninspectable source is returned as an error.
func reviewUnits(dir string, spec Spec) ([]reviewUnit, error) {
	var units []reviewUnit
	if spec.Directive != nil && spec.Directive.Task != "" {
		units = append(units, reviewUnit{sourceClass: SourceManifest, text: spec.Directive.Task})
	}
	if spec.Context != nil {
		for _, memory := range spec.Context.Memory {
			if strings.EqualFold(memory.Kind, "http") && memory.URL != "" {
				units = append(units, reviewUnit{sourceClass: SourceMemoryHTTP, text: memory.URL, isURL: true})
			}
		}
	}
	sources, uninspectable, err := contextFiles(dir, spec)
	if err != nil {
		return nil, err
	}
	if len(uninspectable) > 0 {
		return nil, &uninspectableSourcesError{sources: uninspectable}
	}
	for _, source := range sources {
		content, err := os.ReadFile(filepath.Join(dir, filepath.FromSlash(source.rel)))
		if err != nil {
			return nil, fmt.Errorf("read context file %s: %w", source.rel, err)
		}
		units = append(units, reviewUnit{sourceClass: source.class, text: string(content)})
	}
	return units, nil
}

// reviewFindings is the rule set itself: declaration findings for each
// rule, one decision per referenced URL, and declared_unused for each
// exact rule no reference names. Duplicate findings are dropped.
func reviewFindings(spec Spec, units []reviewUnit, platformHost string) []ReviewFinding {
	rules := parseEgressRules(spec)
	platformHostName, platformPort := reviewSplitHostPort(strings.TrimSpace(platformHost))
	platformHostName = normalizeHost(platformHostName)

	var findings []ReviewFinding
	for _, rule := range rules {
		findings = append(findings, declarationFindings(rule)...)
	}

	var references []reviewReference
	for _, unit := range units {
		urls := []string{unit.text}
		if !unit.isURL {
			urls = extractReviewURLs(unit.text)
		}
		for _, raw := range urls {
			host, port, scheme, ok := parseReviewURL(raw)
			if ok {
				references = append(references,
					reviewReference{sourceClass: unit.sourceClass, host: host, port: port, scheme: scheme})
			}
		}
	}

	used := make(map[string]bool)
	for _, reference := range references {
		used[reference.host+"\x00"+strconv.Itoa(reference.port)] = true
		declared := egressAllowed(rules, reference.host, reference.port)
		plaintext := reference.scheme == "http"
		switch {
		case !declared && reference.host == platformHostName && reference.port == platformPort:
			findings = append(findings, newFinding(ReviewPlatformHostReferenced,
				reference.host, reference.port, reference.sourceClass))
		case !declared:
			findings = append(findings, newFinding(ReviewUndeclaredHost,
				reference.host, reference.port, reference.sourceClass))
			if plaintext {
				findings = append(findings, newFinding(ReviewNonTLSPort,
					reference.host, reference.port, reference.sourceClass))
			}
		case plaintext:
			findings = append(findings, newFinding(ReviewNonTLSPort,
				reference.host, reference.port, reference.sourceClass))
		}
	}

	for _, rule := range rules {
		if !rule.wildcard && !used[rule.host+"\x00"+strconv.Itoa(rule.port)] {
			findings = append(findings, newFinding(ReviewDeclaredUnused, rule.declaredAs, rule.port, SourceManifest))
		}
	}

	return uniqueFindings(findings)
}

// declarationFindings are the findings one rule causes by itself, with no
// scanned text: a wildcard, an IP literal, and a port other than 443
// (the CONNECT proxy carries TLS only).
func declarationFindings(rule reviewRule) []ReviewFinding {
	var findings []ReviewFinding
	if rule.wildcard {
		findings = append(findings, newFinding(ReviewWildcardDeclared, rule.declaredAs, rule.port, SourceManifest))
	}
	if isIPLiteral(rule.host) {
		findings = append(findings, newFinding(ReviewIPLiteralDeclared, rule.declaredAs, rule.port, SourceManifest))
	}
	if rule.port != 443 {
		findings = append(findings, newFinding(ReviewNonTLSPort, rule.declaredAs, rule.port, SourceManifest))
	}
	return findings
}

// extractReviewURLs extracts URLs with the same pattern SafetyCheck uses,
// capping each match before trimming trailing punctuation.
func extractReviewURLs(text string) []string {
	matches := urlPattern.FindAllString(text, -1)
	out := make([]string, 0, len(matches))
	for _, match := range matches {
		if len(match) > maxURLMatchBytes {
			match = match[:maxURLMatchBytes]
		}
		if trimmed := strings.TrimRight(match, trailingPunctuation); trimmed != "" {
			out = append(out, trimmed)
		}
	}
	return out
}

// uniqueFindings drops repeated findings, keeping the first of each.
func uniqueFindings(findings []ReviewFinding) []ReviewFinding {
	seen := make(map[ReviewFinding]bool, len(findings))
	out := findings[:0]
	for _, finding := range findings {
		if !seen[finding] {
			seen[finding] = true
			out = append(out, finding)
		}
	}
	return out
}

// EgressWarnings returns one `pod validate` warning for each
// declaration-level finding the server review flags: a wildcard entry,
// an IP-literal entry, and an entry on a port other than 443. Each
// warning names the manifest entry that caused it. They are advice: the
// manifest stays valid, and a pod that carries them still runs.
//
// A wildcard whose base is a public suffix, or a proper ancestor of a
// PSL rule, gets no wildcard warning:
// egressBreadthRules reports it as the egress_wildcard_public_suffix
// issue instead, because reef-core refuses it outright.
func EgressWarnings(spec Spec) []Warning {
	var warnings []Warning
	for _, rule := range parseEgressRules(spec) {
		for _, finding := range declarationFindings(rule) {
			if finding.Code == ReviewWildcardDeclared && wildcardBaseRefused(rule.host) {
				continue
			}
			warnings = append(warnings, egressWarning(rule, finding.Code))
		}
	}
	return warnings
}

// egressWarning renders one declaration finding as a Warning.
func egressWarning(rule reviewRule, code string) Warning {
	authority := rule.declaredAs + ":" + strconv.Itoa(rule.port)
	switch code {
	case ReviewWildcardDeclared:
		return Warning{Path: rule.path, Code: WarnEgressWildcardReview, Message: fmt.Sprintf(
			"%s is a wildcard: a server egress review flags it, so a listing server that requires review lists this revision only after an operator approves it", authority)}
	case ReviewIPLiteralDeclared:
		return Warning{Path: rule.path, Code: WarnEgressIPLiteral, Message: fmt.Sprintf(
			"%s is an IP address: a reef-core node that runs its CONNECT proxy refuses IP-literal hosts, so the pod cannot reach it through a tunnel, and a server egress review flags it", authority)}
	default:
		return Warning{Path: rule.path, Code: WarnEgressNonTLSPort, Message: fmt.Sprintf(
			"%s is not on port 443: a server egress review flags every entry on another port, and a reef-core node that runs its CONNECT proxy refuses any traffic on it that is not TLS", authority)}
	}
}
