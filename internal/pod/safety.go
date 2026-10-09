// Copyright 2026 Jerry David Chan, Konareef.ai
// SPDX-License-Identifier: Apache-2.0

// safety.go — the static egress safety check.
//
// Scans every file that enters the model's context — the [directive]
// template, the markdown named by [[context.skills]], the files named by
// [[context.prompts]], and the files named by [[context.memory]] entries
// whose kind is "file" — for absolute http and https URLs, and reports
// any whose host and port are not declared in [network].egress. It also
// checks the url of every [[context.memory]] entry whose kind is "http",
// which is an egress the manifest declares outright.
//
// # Scope, and why it is drawn here
//
// Only files an agent reads as part of its prompt are scanned. A README
// is written for a human and never enters the context, so a
// documentation link in one is not a pod reaching for a host. Scanning
// it would make every scaffolded pod fail on its own boilerplate, and a
// check that cries wolf is a check authors learn to skip.
//
// # The limit, which matters more than the feature
//
// This check reads text. A pod driven by a model can build a hostname at
// runtime from model output, from an input, or from a tool result, and
// no scan of the pod's files will ever see it. The check catches the
// careless and the honest. It is not a proof of anything.
//
// The enforceable guarantee is a runtime one: a proxy that refuses a
// connection to an undeclared host. Never report a passing safety check
// as evidence that a pod only reaches the hosts it declared. It means
// the pod's own files name no other host, and nothing more.
//
// # Two entry points, for two audiences
//
// SafetyCheck is the advisory one. `konareef pod safety` runs it against
// a pod an author is still assembling, so a declared source that is not
// written yet is skipped.
//
// SafetyCheckStrict is the one the listing gate runs. It reports the
// same findings and additionally refuses any declared context source it
// could not read, because a clean result there is what lets a stranger
// commission the pod. The distinction matters because "scanned, found
// nothing" and "never scanned" are indistinguishable in a finding list,
// and only one of them is a safety claim.
package pod

import (
	"errors"
	"fmt"
	"io/fs"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
)

// SafetyFinding is one URL in one context file whose host and port are
// not covered by [network].egress. File is relative to the pod
// directory, so findings are stable across machines.
type SafetyFinding struct {
	File   string // pod-relative path, or "pod.toml" for a manifest URL
	URL    string // the URL exactly as it appeared
	Host   string // the host parsed out of URL
	Port   string // the effective port: explicit, or the scheme default
	Reason string // why it was reported
}

// String renders a finding as one diagnostic line.
func (f SafetyFinding) String() string {
	return fmt.Sprintf("%s: %s (%s:%s) — %s", f.File, f.URL, f.Host, f.Port, f.Reason)
}

// urlBodyChar matches one character of a URL after the scheme. It stops
// at whitespace and at the delimiters markdown and shell wrap URLs in, so
// `[docs](https://example.com)` yields the URL without the trailing
// paren. Those exclusions are load-bearing: widening them to catch more
// host spellings would make every markdown link swallow its closing
// bracket, so the spellings below are added as explicit alternatives
// instead of by loosening this class.
//
// Whitespace is spelled out as tab, newline, vertical tab, form feed,
// carriage return and space rather than written \s: RE2's \s leaves out
// the vertical tab, and the server's PCRE \s includes it, so \s here let
// one URL run on past a vertical tab and swallow the next URL whole.
const urlBodyChar = "[^\\t\\n\\v\\f\\r <>\"'`()\\[\\]{},;]"

// urlTemplateToken matches a balanced template placeholder — `{{VAR}}` or
// `${VAR}` — as a single unit. A pod's prompt text routinely writes a
// destination it fills in at runtime, and the braces must be part of the
// match or the extractor truncates the URL to `https://$` and reports a
// host no author can recognize. Matching only the balanced pair, rather
// than allowing a bare brace anywhere, keeps a prose `}` working as a
// closing delimiter.
const urlTemplateToken = `(?:\{\{[^{}\t\n\v\f\r ]*\}\}|\$\{[^{}\t\n\v\f\r ]*\})`

// urlIPv6Authority matches a bracketed IPv6 literal host with an optional
// port. An address such as `[::1]` is a valid absolute URL authority, and
// its brackets and colons are exactly the characters urlBodyChar refuses,
// so without this branch `https://[::1]/x` matched nothing at all and the
// destination went unreported.
const urlIPv6Authority = `\[[0-9A-Fa-f:.]*\](?::[0-9]+)?`

// urlPattern matches absolute http and https URLs.
//
// The scheme is matched case-insensitively because a URL scheme IS
// case-insensitive: `HTTPS://evil.example.com/x` names the same host a
// browser or an agent would reach, and a case-sensitive extractor let
// that spelling through the listing gate untouched. Only the scheme is
// folded — the rest is matched verbatim so a finding's URL field
// reproduces the text an author has to go and find in the file.
//
// The first character after `://` may be an IPv6 authority, a template
// token, or an ordinary URL character; every character after that may be
// a template token or an ordinary URL character.
var urlPattern = regexp.MustCompile(
	`(?i:https?)://` +
		`(?:` + urlIPv6Authority + `|` + urlTemplateToken + `|` + urlBodyChar + `)` +
		`(?:` + urlTemplateToken + `|` + urlBodyChar + `)*`)

// trailingPunctuation is stripped from a matched URL. A sentence ending
// in a URL puts the period inside the match; a period is legal in a path
// but almost never ends one in prose.
const trailingPunctuation = ".,:;!?"

// SafetyCheck scans a pod directory for undeclared egress, leniently.
//
// dir is the pod directory; spec is its parsed manifest. It returns one
// finding per undeclared URL, ordered by file then by order of
// appearance, and an error only when the pod directory cannot be read.
// A pod that declares no [network] table has an empty allowlist, so
// every URL found is reported — that is the intended behavior, not a
// missing default.
//
// A declared source that is not on disk yet is skipped, not reported.
// This is the entry point behind `konareef pod safety`, which an author
// runs against a pod they are still building, and failing it on a prompt
// they have not written yet would teach them to stop running it. Use
// SafetyCheckStrict wherever a clean result is taken as permission to
// expose the pod.
func SafetyCheck(dir string, spec Spec) ([]SafetyFinding, error) {
	findings, _, err := safetyScan(dir, spec)
	return findings, err
}

// SafetyCheckStrict scans a pod directory for undeclared egress and
// fails closed on any declared context source it could not inspect.
//
// It returns what SafetyCheck returns, except that a declared
// [directive].template, [[context.memory]] kind = "file" path,
// [[context.prompts]].path, or local [[context.skills]].source that is
// missing — or that resolves to something no text can be read from — is
// an error rather than a skipped entry.
//
// The difference from SafetyCheck is a difference of audience, not of
// rigor. The lenient check advises an author mid-build. This one stands
// where the pod is exposed to strangers, and there "the source was never
// read" and "the source named no undeclared host" have to be different
// answers: reporting the first as the second lets a manifest whose
// model-context surface was never examined pass the listing gate.
func SafetyCheckStrict(dir string, spec Spec) ([]SafetyFinding, error) {
	findings, uninspectable, err := safetyScan(dir, spec)
	if err != nil {
		return nil, err
	}
	if len(uninspectable) > 0 {
		return findings, &uninspectableSourcesError{sources: uninspectable}
	}
	return findings, nil
}

// safetyScan is the whole check, reporting both the undeclared egress it
// found and the declared sources it could not look inside. The two
// exported entry points differ only in what they do with the second
// result, which keeps the scan itself single-sourced: a class of context
// file added here is covered by the advisory command and the listing
// gate at once.
func safetyScan(dir string, spec Spec) ([]SafetyFinding, []uninspectableSource, error) {
	allowed := parseEgressRules(spec)

	var findings []SafetyFinding

	// The manifest's own declared fetches come first: a [[context.memory]]
	// entry with kind = "http" names a URL the runtime will fetch, which
	// is egress whether or not any skill mentions it.
	if spec.Context != nil {
		for _, memory := range spec.Context.Memory {
			if !strings.EqualFold(memory.Kind, "http") || memory.URL == "" {
				continue
			}
			if finding, ok := checkURL("pod.toml", memory.URL, allowed); ok {
				findings = append(findings,
					withReason(finding, "[[context.memory]] kind=\"http\" fetches an undeclared host"))
			}
		}
	}

	// An inline [directive].task is prompt text that never touches the
	// filesystem, so it has to be scanned from the manifest itself.
	if spec.Directive != nil && spec.Directive.Task != "" {
		for _, raw := range extractURLs(spec.Directive.Task) {
			if finding, ok := checkURL("pod.toml", raw, allowed); ok {
				findings = append(findings,
					withReason(finding, "[directive].task names an undeclared host"))
			}
		}
	}

	sources, uninspectable, err := contextFiles(dir, spec)
	if err != nil {
		return nil, nil, err
	}
	// Every path contextFiles returns has passed both containment checks —
	// the lexical one in safeRel and the symlink-resolved one in
	// podRoot.verify — so the read below cannot leave the pod directory.
	// That invariant lives in contextFiles, not here; do not add a path to
	// this loop from anywhere else without verifying it the same way.
	for _, file := range uniqueContextPaths(sources) {
		content, err := os.ReadFile(filepath.Join(dir, file))
		if err != nil {
			return nil, nil, fmt.Errorf("read context file %s: %w", file, err)
		}
		for _, raw := range extractURLs(string(content)) {
			if finding, ok := checkURL(file, raw, allowed); ok {
				findings = append(findings,
					withReason(finding, "host is not listed in [network].egress"))
			}
		}
	}

	return findings, uninspectable, nil
}

// uninspectableSource is a declared context source whose text the check
// never read: it is not on disk, or it resolves to something no prompt
// can be read from. field names the manifest key so an author knows
// which table to fix, and path quotes the source exactly as the manifest
// spells it rather than as the filesystem resolved it.
type uninspectableSource struct {
	field  string // the manifest key, e.g. `[directive].template`
	path   string // the source exactly as the manifest wrote it
	reason string // why nothing could be scanned
}

// Reasons an uninspectableSource carries. A missing source and a source
// that is the wrong kind of thing are separated because they send the
// author to different fixes: one is a file to add, the other is a path
// to correct.
//
// A source that is not written in canonical form ("./" and a clean
// relative path, with no "//", "." or ".." segment and no trailing "/")
// is recorded as well, although the scan still reads it: the server's
// review looks a source up by its exact name in the published body, so
// it cannot resolve such a source and records an error, and the listing
// pre-check must not pass what the server will refuse. A skill directory
// that holds no file at all is recorded for the same reason.
const (
	reasonMissing      = "does not exist"
	reasonNotAFile     = "is a directory, not a file"
	reasonNotCanonical = "is not a clean \"./\" path, so the server review cannot resolve it"
	reasonEmptyDir     = "is a directory with no file in it"
)

// String renders one uninspectable source as a diagnostic line.
func (source uninspectableSource) String() string {
	return fmt.Sprintf("%s %q: %s", source.field, source.path, source.reason)
}

// uninspectableSourcesError is what SafetyCheckStrict returns when a
// declared context source was never read. It names every such source
// rather than the first, because an author fixing a half-built pod would
// otherwise have to run the gate once per missing file.
type uninspectableSourcesError struct {
	sources []uninspectableSource
}

// Error states the failure in the terms the gate turns on: not that a
// file is missing, which publish and `pod validate` already say better,
// but that its egress was never checked and so cannot be vouched for.
func (e *uninspectableSourcesError) Error() string {
	parts := make([]string, 0, len(e.sources))
	for _, source := range e.sources {
		parts = append(parts, source.String())
	}
	return "declared context source was not inspected, so its egress is unchecked: " +
		strings.Join(parts, "; ")
}

// withReason sets a finding's reason unless checkURL already gave it a
// more specific one. An unparseable URL must not be reported as "host is
// not listed", which would send an author looking for the wrong fix.
func withReason(finding SafetyFinding, reason string) SafetyFinding {
	if finding.Reason == "" {
		finding.Reason = reason
	}
	return finding
}

// checkURL parses raw and reports it when its host:port is not allowed.
// A URL that does not parse, or that carries no host, is reported too:
// refusing to interpret it is safer than silently passing it. A host
// built from a template variable lands here, which is correct — a host
// this check cannot resolve is exactly one a reviewer should see.
//
// url.Parse returns a NIL *URL alongside its error for input such as
// "https://${TARGET}/x". The err check below must stay first: the
// short-circuit in the condition is what stops a nil dereference.
//
// The host is matched the way the server's review matches it: one
// trailing dot removed, ASCII lowercased, an IPv6 address kept in
// brackets, and the port compared as a number. "https://api.example.com./"
// therefore matches a declaration of "api.example.com", which the server
// accepts too; reporting it here was a false positive.
func checkURL(file, raw string, allowed []reviewRule) (SafetyFinding, bool) {
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Hostname() == "" {
		return SafetyFinding{
			File:   file,
			URL:    raw,
			Reason: "URL does not parse to a host",
		}, true
	}

	host := normalizeHost(parsed.Hostname())
	// The rules keep an IPv6 address in brackets, as the manifest writes
	// it; url.Hostname removes them. They are put back for the match only,
	// so the finding still shows the address the way it did before.
	matchHost := host
	if strings.HasPrefix(parsed.Host, "[") {
		matchHost = "[" + host + "]"
	}
	port := parsed.Port()
	if port == "" {
		port = defaultPort(parsed.Scheme)
	}

	if number, err := strconv.Atoi(port); err == nil && egressAllowed(allowed, matchHost, number) {
		return SafetyFinding{}, false
	}
	return SafetyFinding{File: file, URL: raw, Host: host, Port: port}, true
}

// defaultPort returns the port a scheme implies when the URL omits one.
func defaultPort(scheme string) string {
	if strings.EqualFold(scheme, "http") {
		return "80"
	}
	return "443"
}

// egressRule is one parsed [network].egress entry, as the gateway overlap
// rules in gateway.go read it. The undeclared-URL scan uses reviewRule
// (egress_review.go), which matches the way the server's review does.
type egressRule struct {
	host     string // lowercased; without the leading "*." when wildcard
	port     string
	wildcard bool
}

// splitHostPort separates an egress entry into host and port, defaulting
// the port to 443. It does not use net.SplitHostPort: that errors on an
// entry with no port at all, which is the common case here.
//
// An IPv6 literal is written bracketed, the way it appears in a URL
// authority: "[::1]" or "[::1]:8080". Both the brackets and the address's
// own colons have to be handled here, because the trailing-colon rule
// below reads "[::1]" as host "[::" and port "1]", and even when it does
// not, the brackets it leaves on the host can never equal the host
// url.Hostname() returns — which strips them. An egress entry for an
// IPv6 host therefore matched nothing and the pod was reported as
// undeclared however it declared the address.
func splitHostPort(entry string) (host, port string) {
	if strings.HasPrefix(entry, "[") {
		if end := strings.Index(entry, "]"); end >= 0 {
			host = entry[1:end]
			rest := entry[end+1:]
			if candidate := strings.TrimPrefix(rest, ":"); rest != candidate &&
				candidate != "" && isAllDigits(candidate) {
				return host, candidate
			}
			return host, "443"
		}
	}
	if index := strings.LastIndex(entry, ":"); index >= 0 {
		candidate := entry[index+1:]
		if candidate != "" && isAllDigits(candidate) {
			return entry[:index], candidate
		}
	}
	return entry, "443"
}

// hostAllowed reports whether host:port matches any rule.
//
// A "*." wildcard matches one or more leading labels and deliberately
// does NOT match the bare suffix: "*.example.com" covers
// "api.example.com" but not "example.com". A pod that needs both
// declares both, which keeps the broader claim visible to a reviewer.
func hostAllowed(host, port string, allowed []egressRule) bool {
	for _, rule := range allowed {
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

// extractURLs pulls every absolute http/https URL out of text, in order
// of appearance, including URLs inside code fences. A URL in an example
// command is exactly the kind an agent copies and runs, so excluding
// fenced blocks would miss the cases that matter most.
func extractURLs(text string) []string {
	matches := urlPattern.FindAllString(text, -1)
	out := make([]string, 0, len(matches))
	for _, match := range matches {
		trimmed := strings.TrimRight(match, trailingPunctuation)
		if trimmed != "" {
			out = append(out, trimmed)
		}
	}
	return out
}

// podRoot is a pod directory together with its symlink-resolved form.
//
// Both spellings are needed at once. Manifest errors and findings quote
// paths relative to dir, which is what the author wrote and can go and
// fix; containment can only be decided against resolved, which is what
// the kernel will actually open. Resolving the root is not an optional
// nicety even for a pod that contains no symlink of its own: on macOS a
// temp-directory pod lives under /var, which is itself a symlink to
// /private/var, so a resolved candidate compared against an unresolved
// root would read as an escape for every such pod.
type podRoot struct {
	dir      string // the pod directory as the caller named it
	resolved string // dir with every symlink component resolved
}

// newPodRoot resolves a pod directory's symlinks once, for reuse across
// every candidate path in one check.
func newPodRoot(dir string) (podRoot, error) {
	resolved, err := filepath.EvalSymlinks(dir)
	if err != nil {
		return podRoot{}, fmt.Errorf("resolve pod directory %q: %w", dir, err)
	}
	return podRoot{dir: dir, resolved: resolved}, nil
}

// resolvedPath is a context path that has passed containment: rel is the
// pod-relative path to quote back to the author, real is the same file
// with every symlink resolved, and info is the stat of what real names.
// A nil info means the path does not exist and the caller must skip it.
type resolvedPath struct {
	rel  string
	real string
	info os.FileInfo
}

// verify resolves a pod-relative path's symlinks and requires the result
// to stay inside the pod directory.
//
// This is the syscall half of the containment contract, and it exists
// because the lexical half is not enough on its own. safeRel decides
// containment by Clean/Join/Rel on the text of a path, but os.Stat and
// os.ReadFile follow symlinks, so a lexically impeccable source such as
// "./prompts/system.md" can be a link to any file on the host. Without
// this step the check reads that outside file, finds only declared hosts
// in it, and reports the pod clean — which inverts the fail-closed
// contract the rest of this file states, and lets the listing gate
// validate content that is not in the submitted pod tree at all.
//
// A path that does not exist, a dangling symlink included, is not an
// escape: it comes back as a nil info with a nil error. Containment is
// all this function judges. Whether a missing source is tolerable is a
// question about audience rather than about paths — see contextFiles,
// which records it, and SafetyCheck versus SafetyCheckStrict, which
// answer it differently. Only an existing path that resolves outside the
// root is an error here.
func (root podRoot) verify(rel string) (resolvedPath, error) {
	candidate := filepath.Join(root.dir, filepath.FromSlash(rel))

	real, err := filepath.EvalSymlinks(candidate)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return resolvedPath{rel: rel}, nil
		}
		return resolvedPath{}, fmt.Errorf("resolve: %w", err)
	}

	inside, err := filepath.Rel(root.resolved, real)
	if err != nil {
		return resolvedPath{}, fmt.Errorf("resolve: %w", err)
	}
	if inside == ".." || strings.HasPrefix(inside, ".."+string(filepath.Separator)) {
		return resolvedPath{}, fmt.Errorf("escapes the pod directory: it is a symlink to %s", real)
	}

	info, err := os.Stat(real)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return resolvedPath{rel: rel}, nil
		}
		return resolvedPath{}, fmt.Errorf("stat: %w", err)
	}
	return resolvedPath{rel: rel, real: real, info: info}, nil
}

// resolveSource applies both containment checks to a manifest-declared
// source, in the order that gives the clearest diagnostic: safeRel first,
// so a written-out "./../../etc" is named as the traversal it is, then
// verify, which catches the same escape spelled as a symlink.
func (root podRoot) resolveSource(source string) (resolvedPath, error) {
	rel, err := safeRel(root.dir, source)
	if err != nil {
		return resolvedPath{}, err
	}
	return root.verify(rel)
}

// contextFiles lists the pod-relative files that enter the model's
// context: the [directive] template, each [[context.memory]] kind =
// "file" path, markdown under each [[context.skills]] source, and each
// [[context.prompts]] path. Results are deduplicated and ordered, and
// every one of them is guaranteed to resolve inside the pod directory,
// which is what makes the caller's os.ReadFile safe.
//
// The second result is every declared source that produced no file to
// scan. It is reported rather than dropped so the caller can decide what
// an uninspected source means: advice, or a refusal. Dropping it was the
// bug — SafetyCheck returned "no findings" for a manifest whose prompts
// it had never opened, and the listing gate reads no findings as
// permission to expose the pod.
//
// A source that escapes the pod directory is an error, not a skipped
// entry. The schema requires a "./" prefix but does not stop
// "./../../etc", and a check that silently ignores a traversal attempt
// hides the most interesting manifest it will ever see. A symlink that
// points out of the pod is the same escape written in a way the text of
// the manifest cannot show, and is refused on the same terms.
func contextFiles(dir string, spec Spec) ([]contextSource, []uninspectableSource, error) {
	root, err := newPodRoot(dir)
	if err != nil {
		return nil, nil, err
	}

	seen := make(map[contextSource]bool)
	var files []contextSource
	// add records one file under one source class. The same file under two
	// classes is kept twice, because the server's review reports a finding
	// once per class that put the text in front of the model.
	add := func(class string) func(rel string) {
		return func(rel string) {
			source := contextSource{rel: rel, class: class}
			if !seen[source] {
				seen[source] = true
				files = append(files, source)
			}
		}
	}

	var uninspectable []uninspectableSource
	// record notes a declared source that yielded nothing to scan. It
	// takes the reason as an argument because the two cases send an
	// author to different fixes, and a single "unusable" would tell them
	// neither.
	record := func(field, path, reason string) {
		uninspectable = append(uninspectable,
			uninspectableSource{field: field, path: path, reason: reason})
	}
	// addFile is the shared rule for the three source classes whose
	// declared path names one whole file — the directive template,
	// file-backed memory, and a prompt. Each is put in front of the model
	// verbatim whatever its extension, so the only question is whether
	// there is a file there at all.
	addFile := func(field, declared, class string, file resolvedPath) {
		switch {
		case file.info == nil:
			record(field, declared, reasonMissing)
		case file.info.IsDir():
			record(field, declared, reasonNotAFile)
		default:
			add(class)(file.rel)
		}
	}

	// The directive template is THE prompt — the one file guaranteed to
	// reach the model on every run. It is listed first because a pod may
	// carry a directive and no [context] table at all, which is how the
	// first version of this check scanned nothing and passed.
	// checkCanonical records a declared source that the server's review
	// cannot resolve by exact name. It does not stop the scan.
	checkCanonical := func(field, declared string) {
		if !canonicalSource(declared) {
			record(field, declared, reasonNotCanonical)
		}
	}

	if spec.Directive != nil && spec.Directive.Template != "" {
		checkCanonical("[directive].template", spec.Directive.Template)
		template, err := root.resolveSource(spec.Directive.Template)
		if err != nil {
			return nil, nil, fmt.Errorf("[directive].template %q: %w", spec.Directive.Template, err)
		}
		addFile("[directive].template", spec.Directive.Template, SourceDirective, template)
	}

	if spec.Context == nil {
		return files, uninspectable, nil
	}

	// A [[context.memory]] entry with kind = "file" preloads that file's
	// text into the model's context, so it is a context file in exactly
	// the sense this check means. It is declared as memory rather than as
	// a prompt, which is how the first version of this check walked past
	// it: the manifest loop above reads memory entries but only follows
	// the ones with kind = "http", and this loop did not read them at all.
	for _, memory := range spec.Context.Memory {
		if !strings.EqualFold(memory.Kind, "file") || memory.Path == "" {
			continue
		}
		checkCanonical("[[context.memory]] path", memory.Path)
		file, err := root.resolveSource(memory.Path)
		if err != nil {
			return nil, nil, fmt.Errorf("[[context.memory]] path %q: %w", memory.Path, err)
		}
		addFile("[[context.memory]] path", memory.Path, SourceMemoryFile, file)
	}

	for _, skill := range spec.Context.Skills {
		checkCanonical("[[context.skills]] source", skill.Source)
		source, err := root.resolveSource(skill.Source)
		if err != nil {
			return nil, nil, fmt.Errorf("[[context.skills]] source %q: %w", skill.Source, err)
		}
		if source.info == nil {
			// A missing skill reads as a packaging problem, and schema
			// validation and the publish tarball step do report it with
			// better context than this check could — which is why the
			// advisory command still lets it pass. It is recorded rather
			// than dropped because at the listing gate the same fact means
			// something else: a skill the model would have been given was
			// never scanned, and neither of those better reports runs
			// between here and exposure.
			record("[[context.skills]] source", skill.Source, reasonMissing)
			continue
		}
		if !source.info.IsDir() {
			if isMarkdown(source.rel) {
				add(SourceSkill)(source.rel)
			}
			continue
		}
		// The walk starts at the resolved directory, not the declared one.
		// A skill source that is a symlink to a directory inside the pod
		// is legitimate, and filepath.WalkDir does not descend through a
		// symlink, so walking the declared path would silently scan
		// nothing at all and call the pod clean.
		fileCount, err := walkMarkdown(root, source.real, add(SourceSkill), record)
		if err != nil {
			return nil, nil, err
		}
		if fileCount == 0 {
			record("[[context.skills]] source", skill.Source, reasonEmptyDir)
		}
	}

	for _, prompt := range spec.Context.Prompts {
		checkCanonical("[[context.prompts]].path", prompt.Path)
		file, err := root.resolveSource(prompt.Path)
		if err != nil {
			return nil, nil, fmt.Errorf("[[context.prompts]] path %q: %w", prompt.Path, err)
		}
		addFile("[[context.prompts]].path", prompt.Path, SourcePrompt, file)
	}

	return files, uninspectable, nil
}

// contextSource is one file that enters the model's context, with the
// review source class of the manifest entry that put it there.
type contextSource struct {
	rel   string // pod-relative path, verified inside the pod directory
	class string // SourceDirective, SourceSkill, SourcePrompt or SourceMemoryFile
}

// uniqueContextPaths returns each distinct path in sources once, in
// first-seen order. The undeclared-URL scan reads each file once however
// many entries name it.
func uniqueContextPaths(sources []contextSource) []string {
	seen := make(map[string]bool, len(sources))
	var paths []string
	for _, source := range sources {
		if !seen[source.rel] {
			seen[source.rel] = true
			paths = append(paths, source.rel)
		}
	}
	return paths
}

// walkMarkdown adds every markdown file under base, which must be an
// already-resolved directory inside root.
//
// Each entry is verified in its own right rather than trusted because the
// directory it sits in was verified. filepath.WalkDir does not follow a
// symlink, but it does report one as an entry, so an otherwise honest
// skill directory can hold a link named SKILL.md that points anywhere on
// the host — and SafetyCheck reads every path this function adds. The
// per-entry check is what stops that read.
//
// record is called for a markdown entry the walk reached but could not
// read — a link inside the skill directory that points at nothing. The
// walk itself continues, for the same reason the missing-skill case does:
// what to do about it is the caller's decision, not this function's.
//
// The count it returns is every entry under base that is not a
// directory, markdown or not. The caller uses it to tell an empty skill
// directory, which the server's review cannot resolve, from one that
// simply holds no markdown.
func walkMarkdown(root podRoot, base string, add func(string), record func(field, path, reason string)) (int, error) {
	fileCount := 0
	err := filepath.WalkDir(base, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() {
			return nil
		}
		fileCount++
		if !isMarkdown(path) {
			return nil
		}
		// Relative to the resolved root, because base is resolved: this is
		// the pod-relative name of the file the walk actually reached.
		rel, relErr := filepath.Rel(root.resolved, path)
		if relErr != nil {
			return relErr
		}
		rel = filepath.ToSlash(rel)

		entryPath, err := root.verify(rel)
		if err != nil {
			return fmt.Errorf("[[context.skills]] file %q: %w", rel, err)
		}
		// A dangling link is skipped for the same reason a missing skill
		// is, and recorded for the same reason too: under the listing gate
		// a markdown file the model would have been handed, that nothing
		// read, is not a pass. A link to a directory is not a file to
		// scan and the walk reaches its contents on its own.
		if entryPath.info == nil {
			record("[[context.skills]] file", rel, reasonMissing)
			return nil
		}
		if entryPath.info.IsDir() {
			return nil
		}
		add(rel)
		return nil
	})
	return fileCount, err
}

// canonicalSource reports whether a declared source is written the way
// the server's review can look it up: "./" followed by a clean relative
// path, with no empty, "." or ".." segment and no trailing "/".
func canonicalSource(declared string) bool {
	rest, ok := strings.CutPrefix(declared, "./")
	return ok && rest != "" && path.Clean(rest) == rest && !strings.HasPrefix(rest, "../") && rest != ".."
}

func isMarkdown(path string) bool {
	return strings.EqualFold(filepath.Ext(path), ".md")
}

// safeRel resolves a manifest-declared source to a pod-relative path and
// refuses anything that escapes the pod directory or is absolute.
//
// The judgement here is purely lexical — Clean, Join, Rel — so it sees
// only what the manifest says, never what the filesystem holds. It is
// therefore half of the containment contract, not all of it: a path it
// passes must still go through podRoot.verify before anything stats or
// reads it, or a symlink walks straight out of the pod.
func safeRel(dir, source string) (string, error) {
	if source == "" {
		return "", fmt.Errorf("empty source")
	}
	if filepath.IsAbs(source) {
		return "", fmt.Errorf("absolute path")
	}
	cleaned := filepath.Clean(filepath.FromSlash(source))
	joined := filepath.Join(dir, cleaned)

	rel, err := filepath.Rel(dir, joined)
	if err != nil {
		return "", fmt.Errorf("resolve: %w", err)
	}
	if rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("escapes the pod directory")
	}
	return filepath.ToSlash(rel), nil
}
