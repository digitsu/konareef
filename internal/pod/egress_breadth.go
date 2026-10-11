// Copyright 2026 Jerry David Chan, Konareef.ai
// SPDX-License-Identifier: Apache-2.0

// egress_breadth.go — the client copy of reef-core's egress breadth rules
// (EGRESS-BREADTH, reef-core#87).
//
// A pod that no listing review sees (an inline run, a git-ref run, or a
// private run of a closed pod) gets two limits on its [network].egress
// declaration from reef-core:
//
//   - B1: a wildcard whose base is a public suffix ("*.com", "*.co.uk",
//     "*.github.io"), or a proper ancestor of any PSL rule
//     ("*.amazonaws.com", "*.kawasaki.jp"), is refused at spawn in every
//     mode and at publish, with the code egress_wildcard_public_suffix.
//     `pod validate` reports it as an Issue, so validation fails. Owner
//     decisions D2 and D2a: the Public Suffix List is vendored at a
//     pinned commit, and both its ICANN and PRIVATE sections count. Owner
//     ruling 2026-10-09: the ancestor case is refused too, because such a
//     wildcard covers public suffixes and so every owner under them.
//   - B2: a run that no egress review covers may declare at most
//     EgressRuleLimitUnreviewed distinct rules, else the spawn is refused
//     with egress_rule_limit_exceeded. Only the server knows whether a
//     run is reviewed, so `pod validate` reports a count above the limit
//     as a Warning. Owner decisions D1 (16) and D1b (a wildcard counts as
//     one rule).
//
// The list is psl/public_suffix_list.dat, embedded byte for byte. reef-core
// vendors the same file. The "breadth" section of
// testdata/egress-vectors.json holds the shared cases and pins the same
// SHA-256, so a drift on either side fails a test.
//
// The base of a wildcard is refused when either test is true:
//
//   - It is a public suffix under the PSL algorithm: the prevailing rule
//     for it has as many labels as the base itself. An exception rule
//     ("!www.ck") wins, then an exact rule ("co.uk"), then a wildcard rule
//     ("*.ck") one label up, and the default rule "*" makes every
//     single-label base a public suffix, listed or not.
//   - It is in the ancestor set: a proper ancestor of an exact rule
//     ("amazonaws.com" for "s3.amazonaws.com"), the base of a wildcard
//     rule or one of its ancestors ("sch.uk" for "*.sch.uk",
//     "kawasaki.jp" for "*.kawasaki.jp"), or a proper ancestor of an
//     exception rule ("kawasaki.jp" for "!city.kawasaki.jp"). The set is
//     built once from the list, so the test is one map lookup.
//
// Malformed entries: these rules run only after the schema pass, whose
// egress pattern (spec_v0_1.schema.json) accepts one optional "*.", ASCII
// labels and a ":" port of 1 to 5 digits. So an entry such as
// "host:+443", "*.*.com" or "" never reaches them through `pod validate`.
// For a direct caller of EgressRuleCount or EgressWildcardPublicSuffix,
// the client is the same as reef-core or stricter: reef-core skips an
// entry its Policy.authority/1 rejects (not counted, not refused), while
// this file counts every entry with a non-empty host. The shared vectors
// therefore hold only well-formed entries.
package pod

import (
	_ "embed"
	"fmt"
	"strconv"
	"strings"
	"sync"
)

// PSLCommit is the upstream publicsuffix/list commit of the embedded
// list. It is also the PSL version string the vectors and reef-core's
// refusal bodies carry.
const PSLCommit = "3929462652695bad04f0a27afb600974014a3c8b"

// PSLSHA256 is the SHA-256 of psl/public_suffix_list.dat, in lowercase
// hex. A test recomputes it from the embedded bytes.
const PSLSHA256 = "2919eb9803c91a3f73a507cc6fedc934de005543c22c4016f72e3343de5dd6e7"

// EgressRuleLimitUnreviewed is the most distinct [network].egress rules
// a reef-core node admits for a run that no egress review covers (owner
// decision D1). A wildcard counts as one rule (D1b). [[network.gateway]]
// entries do not count: each has its own per-run call cap.
const EgressRuleLimitUnreviewed = 16

// CodeEgressWildcardPublicSuffix is the Issue code for a wildcard whose
// base is a public suffix. It mirrors reef-core's refusal code, so it
// uses reef-core's bytes (see the Issue doc comment).
const CodeEgressWildcardPublicSuffix = "egress_wildcard_public_suffix"

// WarnEgressRuleLimitExceeded is the Warning code for a declaration with
// more than EgressRuleLimitUnreviewed distinct rules. It mirrors
// reef-core's refusal code.
const WarnEgressRuleLimitExceeded = "egress_rule_limit_exceeded"

//go:embed psl/public_suffix_list.dat
var embeddedPSL []byte

// publicSuffixList is the parsed list. Every key is in ASCII form: an
// internationalized label is stored as "xn--" plus its Punycode.
type publicSuffixList struct {
	exact     map[string]bool // "co.uk" for the rule "co.uk"
	wildcard  map[string]bool // "ck" for the rule "*.ck"
	exception map[string]bool // "www.ck" for the rule "!www.ck"
	// ancestor holds every domain that lies strictly above some rule:
	// the proper ancestors of each exact and exception rule, and each
	// wildcard rule's base with its proper ancestors.
	ancestor map[string]bool
}

// loadPSL parses the embedded list once, on first use.
var loadPSL = sync.OnceValue(func() *publicSuffixList { return parsePSL(embeddedPSL) })

// parsePSL reads a list in the publicsuffix.org format. Input: the file
// bytes. Output: the rule sets. A rule is the text of a line up to its
// first whitespace; blank lines and "//" comments are skipped. Rules from
// every section are kept (D2a: ICANN and PRIVATE). A rule whose label
// cannot be converted to ASCII is skipped; the pinned list has none.
func parsePSL(data []byte) *publicSuffixList {
	list := &publicSuffixList{
		exact:     map[string]bool{},
		wildcard:  map[string]bool{},
		exception: map[string]bool{},
		ancestor:  map[string]bool{},
	}
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 0 || strings.HasPrefix(fields[0], "//") {
			continue
		}
		rule := fields[0]
		target := list.exact
		switch {
		case strings.HasPrefix(rule, "!"):
			target, rule = list.exception, rule[1:]
		case strings.HasPrefix(rule, "*."):
			target, rule = list.wildcard, rule[2:]
		}
		ascii, ok := pslRuleToASCII(rule)
		if !ok {
			continue
		}
		target[ascii] = true
	}
	for domain := range list.exact {
		addProperAncestors(list.ancestor, domain)
	}
	for domain := range list.exception {
		addProperAncestors(list.ancestor, domain)
	}
	for base := range list.wildcard {
		list.ancestor[base] = true
		addProperAncestors(list.ancestor, base)
	}
	return list
}

// addProperAncestors adds every proper ancestor of domain to set: for
// "a.b.c" it adds "b.c" and "c". Input: the set and an ASCII domain.
func addProperAncestors(set map[string]bool, domain string) {
	for dot := strings.IndexByte(domain, '.'); dot >= 0; dot = strings.IndexByte(domain, '.') {
		domain = domain[dot+1:]
		set[domain] = true
	}
}

// pslRuleToASCII converts each label of a rule to its ASCII form and
// lowercases it. Input: a rule without its "!" or "*." prefix. Output:
// the ASCII rule, and false when a label is empty or cannot be encoded.
func pslRuleToASCII(rule string) (string, bool) {
	labels := strings.Split(rule, ".")
	for index, label := range labels {
		if label == "" {
			return "", false
		}
		ascii, err := toASCIILabel(label)
		if err != nil {
			return "", false
		}
		labels[index] = normalizeHost(ascii)
	}
	return strings.Join(labels, "."), true
}

// isPublicSuffix reports whether domain is itself a public suffix under
// the PSL algorithm. Input: an ASCII domain, already normalized (ASCII
// lowercase, no trailing dot). Output: true for "com", "co.uk",
// "github.io", "foo.ck" and any unlisted single label; false for
// "example.com", "www.ck" and the empty string.
func isPublicSuffix(domain string) bool {
	if domain == "" {
		return false
	}
	list := loadPSL()
	if list.exception[domain] {
		return false
	}
	if list.exact[domain] {
		return true
	}
	dot := strings.IndexByte(domain, '.')
	if dot < 0 {
		return true // the default rule "*"
	}
	return list.wildcard[domain[dot+1:]]
}

// wildcardBaseRefused reports whether a "*." entry with this base is
// refused: the base is a public suffix, or a proper ancestor of any PSL
// rule. Input: the base, normalized, without the "*.". Output: true for
// "com", "co.uk", "amazonaws.com", "sch.uk" and "kawasaki.jp"; false for
// "example.com", "www.ck" and "city.kawasaki.jp".
func wildcardBaseRefused(base string) bool {
	return isPublicSuffix(base) || loadPSL().ancestor[base]
}

// EgressWildcardPublicSuffix reports whether one [network].egress entry
// is a wildcard that reef-core refuses with egress_wildcard_public_suffix:
// its base is a public suffix or a proper ancestor of a PSL rule (see
// wildcardBaseRefused). Input: the entry as
// authored ("*.co.uk:443", "*.Example.com."). The entry is read the way
// parseEgressRules reads it: an optional port, then the host normalized.
// Output: true only for a "*." entry whose base is refused; an exact
// entry such as "com:443" is never refused here.
func EgressWildcardPublicSuffix(entry string) bool {
	host, _ := reviewSplitHostPort(strings.TrimSpace(entry))
	host = normalizeHost(host)
	if !strings.HasPrefix(host, "*.") {
		return false
	}
	for strings.HasPrefix(host, "*.") {
		host = strings.TrimPrefix(host, "*.")
	}
	return wildcardBaseRefused(host)
}

// EgressRuleCount returns the number of distinct authorities in a
// [network].egress list, the number reef-core compares with
// EgressRuleLimitUnreviewed. Input: the entries as authored. Two entries
// are one rule when their normalized host and numeric port are equal, so
// "A.example.com.", "a.example.com" and "a.example.com:0443" count once.
// A wildcard counts as one rule, distinct from its apex. An entry with
// an empty host is skipped. Output: the count.
func EgressRuleCount(entries []string) int {
	seen := make(map[string]bool, len(entries))
	for _, entry := range entries {
		host, port := reviewSplitHostPort(strings.TrimSpace(entry))
		if host == "" {
			continue
		}
		seen[normalizeHost(host)+"\x00"+strconv.Itoa(port)] = true
	}
	return len(seen)
}

// egressBreadthRules applies B1 and B2 to a parsed spec. Input: the spec.
// Output: one Issue per public-suffix wildcard entry, on that entry's
// path, and one Warning on "network.egress" when the distinct rule count
// is above EgressRuleLimitUnreviewed. Both are empty when the spec has
// no [network] table.
func egressBreadthRules(spec Spec) ([]Issue, []Warning) {
	if spec.Network == nil {
		return nil, nil
	}
	var issues []Issue
	for index, entry := range spec.Network.Egress {
		if !EgressWildcardPublicSuffix(entry) {
			continue
		}
		issues = append(issues, Issue{
			Path: fmt.Sprintf("network.egress[%d]", index),
			Code: CodeEgressWildcardPublicSuffix,
			Message: fmt.Sprintf("%q is a wildcard on a public suffix, or on a domain above one "+
				"(Public Suffix List %s): it covers every unrelated owner under that suffix, so reef-core refuses it at spawn "+
				"and at publish; declare the exact hosts, or a wildcard under a domain the pod's "+
				"service owns", entry, PSLCommit[:12]),
		})
	}
	var warnings []Warning
	if count := EgressRuleCount(spec.Network.Egress); count > EgressRuleLimitUnreviewed {
		warnings = append(warnings, Warning{
			Path: "network.egress",
			Code: WarnEgressRuleLimitExceeded,
			Message: fmt.Sprintf("declares %d distinct egress rules: a reef-core node refuses a run "+
				"with more than %d unless an egress review covers it (a listed pod whose review is "+
				"clean or approved, or a published pod whose review is clean), so an inline, git-ref "+
				"or unreviewed run of this pod is refused with egress_rule_limit_exceeded",
				count, EgressRuleLimitUnreviewed),
		})
	}
	return issues, warnings
}
