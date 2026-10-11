// Copyright 2026 Jerry David Chan, Konareef.ai
// SPDX-License-Identifier: Apache-2.0

// credentials.go — the credential scan over a pod bundle.
//
// A pod bundle is every file a publish ships: the files the canonical
// manifest binds in `[_files]` (canon.BodyFiles), plus pod.toml and
// pod.lock, which the open-pod tarball carries and the hash walk leaves
// out. This scan reads all of them. That is a wider scope than safety.go,
// which reads only the files that enter a model's context: a URL in a
// README is harmless, but a key in a README is published with the pod. For
// a closed pod the key is sealed, and a buyer's run still has it. For an
// open pod anyone can read it.
//
// # What it matches, and what it does not
//
// Known-prefix and structure patterns only (credentialClasses). There is
// no entropy rule: a check that flags every hash and every id teaches
// authors to skip it. The price is that a key with no known shape is not
// found. Never report a clean scan as proof that a bundle holds no secret.
// It means the bundle holds no string of the shapes below.
//
// # The finding never carries the value
//
// A finding is a file, a line and a class name. The matched text is
// dropped inside the scan, so no caller can print it by accident. The
// refusal names the correct path: `konareef pod secret set`.
//
// # The allow file
//
// A test fixture may hold a credential-shaped string that is not a
// credential. The author allows one matched string at a time in
// credential-allow.toml at the pod root (CredentialAllowFile). An entry
// names the file, the class, the line and the digest of the string, so a
// second string on the same line is still refused. The file is part of
// the bundle, so it is bound into pod_hash and shipped with the pod. For
// an open pod a listing review can read it. For a closed pod it is inside
// the sealed body, and a listing review sees only its hash in [_files]
// until reef-core#88 reports allowed findings. It is not in pod.toml because the
// pod.toml schema is a byte-for-byte copy of reef-core's and has no place
// for it; see the SECRET-SCAN merge request.
//
// # Shared vectors
//
// testdata/credential-patterns/vectors.json is the contract with the
// reef-core scanner (SECRET-SCAN-R). Its format is documented in the file
// and in docs/reference/pod-credential-scan.md. A change to a pattern here
// needs a change to that file and a matching change on the server side.
package pod

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/BurntSushi/toml"
	"github.com/digitsu/konareef/internal/canon"
)

// CodeBundleCredentialFound is the stable code of a publish refusal caused
// by a credential-shaped string in the bundle.
const CodeBundleCredentialFound = "BUNDLE_CREDENTIAL_FOUND"

// CodeBundleCredentialScanFailed is the stable code of a publish refusal
// caused by a scan that could not finish: a bundle that cannot be
// enumerated or read (a symlink, an unreadable file) or a malformed allow
// file. It is not CodeBundleCredentialFound, because no credential was
// found; the command still stops, because "not scanned" is not "clean".
const CodeBundleCredentialScanFailed = "BUNDLE_CREDENTIAL_SCAN_FAILED"

// CredentialAllowFile is the pod-root file that allows individual
// findings. Its name has no leading dot on purpose: a hidden file is not
// in the bundle, and an allow file a reviewer cannot see is a bypass.
const CredentialAllowFile = "credential-allow.toml"

// credentialClass is one named pattern.
type credentialClass struct {
	name    string
	pattern *regexp.Regexp
}

// credentialClasses is the pattern list, in the order findings on one line
// are reported. Every expression is valid in both RE2 (Go) and PCRE (the
// reef-core scanner) and uses only `\b`, ASCII classes, literals and
// counted repeats. The two engines agree only when PCRE compiles the
// expressions with no UTF and no UCP flag (in Elixir: no `u` modifier) and
// matches over raw bytes, because then `\b` uses the ASCII word set
// [A-Za-z0-9_] in both; docs/reference/pod-credential-scan.md states the
// full rule.
//
// `\b` before a prefix keeps a prefix inside a longer word from matching:
// "risk-" is not the start of an `sk-` key. A trailing `\b` is used only
// where the shape has a fixed length. The patterns run over scanLine, not
// over the raw line, so that an escape such as `\n` just before a key does
// not hide it.
var credentialClasses = []credentialClass{
	{"anthropic_api_key", regexp.MustCompile(`\bsk-ant-[A-Za-z0-9_-]{20,}`)},
	{"openai_api_key", regexp.MustCompile(`\bsk-proj-[A-Za-z0-9_-]{20,}|\bsk-[A-Za-z0-9]{32,}`)},
	{"aws_access_key_id", regexp.MustCompile(`\b(?:AKIA|ASIA)[0-9A-Z]{16}\b`)},
	{"github_token", regexp.MustCompile(`\bgh[pousr]_[A-Za-z0-9]{36,}|\bgithub_pat_[A-Za-z0-9_]{22,}`)},
	{"gitlab_token", regexp.MustCompile(`\bglpat-[A-Za-z0-9_-]{20,}`)},
	{"slack_token", regexp.MustCompile(`\bxox[abpr]-[A-Za-z0-9-]{10,}`)},
	{"private_key_block", regexp.MustCompile(`-----BEGIN [A-Z ]*PRIVATE KEY-----`)},
	{"jwt", regexp.MustCompile(`\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}`)},
}

// CredentialClassNames returns the pattern class names in report order.
func CredentialClassNames() []string {
	names := make([]string, 0, len(credentialClasses))
	for _, class := range credentialClasses {
		names = append(names, class.name)
	}
	return names
}

// TextCredentialFinding is one line and class with credential-shaped
// strings in one text: the 1-based line, the class, and the digest
// (credentialMatchDigest) of each distinct matched string, in the order of
// the first match. It holds no part of the value.
type TextCredentialFinding struct {
	Line    int
	Class   string
	Matches []string
}

// escapedControlPattern matches the two-character text escapes `\n`, `\r`
// and `\t`: a backslash and then n, r or t.
var escapedControlPattern = regexp.MustCompile(`\\[nrt]`)

// scanLine returns the text the patterns run over for one line: the line
// with each escapedControlPattern match replaced by two spaces.
//
// Input: one line. Output: a string of the same length. In a JSON, YAML or
// TOML string, `"use:\nsk-ant-…"` holds the letter n just before the
// prefix; n is a word character, so `\b` fails and the key is hidden
// (review M3 on konareef!149). After the rewrite the prefix follows a
// space. The rewrite keeps every byte offset, and no pattern class holds a
// backslash, so no match that the raw line has is lost.
func scanLine(line string) string {
	return escapedControlPattern.ReplaceAllLiteralString(line, "  ")
}

// credentialMatchDigest identifies one matched string without holding it.
//
// Input: the matched text. Output: the first 16 lowercase hex characters
// of SHA-256 over its bytes. An allow entry names a finding by this
// digest, so one entry covers one string and not every match on its line
// (review M1 on konareef!149). 64 bits of a hash of a real key do not give
// the key back, so a refusal may print the digest.
func credentialMatchDigest(match string) string {
	sum := sha256.Sum256([]byte(match))
	return hex.EncodeToString(sum[:])[:16]
}

// ScanCredentialText finds credential-shaped strings in text.
//
// Input: the file content. Output: one finding per line and class, ordered
// by line and then by class order, each with the digests of its distinct
// matched strings. Lines are split at "\n", so a "\r" at the end of a CRLF
// line does not change the numbering. Each line is rewritten by scanLine
// before the patterns run, and a match is the text of a non-overlapping,
// leftmost match in the rewritten line.
func ScanCredentialText(text string) []TextCredentialFinding {
	var findings []TextCredentialFinding
	for index, rawLine := range strings.Split(text, "\n") {
		line := scanLine(rawLine)
		for _, class := range credentialClasses {
			matches := class.pattern.FindAllString(line, -1)
			if len(matches) == 0 {
				continue
			}
			finding := TextCredentialFinding{Line: index + 1, Class: class.name}
			seen := map[string]bool{}
			for _, match := range matches {
				digest := credentialMatchDigest(match)
				if !seen[digest] {
					seen[digest] = true
					finding.Matches = append(finding.Matches, digest)
				}
			}
			findings = append(findings, finding)
		}
	}
	return findings
}

// CredentialFinding is one distinct credential-shaped string on one line
// of one bundle file. File is pod-relative with forward slashes. SHA256 is
// the credentialMatchDigest of the string. Reason is set only on an
// allowed finding and is the author's stated reason.
type CredentialFinding struct {
	File   string
	Line   int
	Class  string
	SHA256 string
	Reason string
}

// String renders a finding as "file:line: class". It never holds the value.
func (finding CredentialFinding) String() string {
	return fmt.Sprintf("%s:%d: %s", finding.File, finding.Line, finding.Class)
}

// CredentialScan is the result of scanning a bundle. Refused findings stop
// a publish. Allowed findings matched an entry in the allow file; they are
// kept so a listing diagnostic can show them.
type CredentialScan struct {
	Refused []CredentialFinding
	Allowed []CredentialFinding
}

// credentialAllowEntry is one [[allow]] table of the allow file.
type credentialAllowEntry struct {
	File   string `toml:"file"`
	Class  string `toml:"class"`
	Line   int    `toml:"line"`
	SHA256 string `toml:"sha256"`
	Reason string `toml:"reason"`
}

// credentialAllowDocument is the whole allow file.
type credentialAllowDocument struct {
	Allow []credentialAllowEntry `toml:"allow"`
}

// ScanBundleCredentials scans every file in the pod bundle at dir.
//
// Input: the pod directory. Output: the refused and the allowed findings,
// ordered by file and then by line. An error means the bundle could not
// be enumerated or read, or the allow file is malformed. A malformed allow
// file is an error and never an empty allow list, so a typo cannot widen
// or silently drop an allowance.
func ScanBundleCredentials(dir string) (CredentialScan, error) {
	allow, err := readCredentialAllowFile(dir)
	if err != nil {
		return CredentialScan{}, err
	}

	bundle, err := bundleFiles(dir)
	if err != nil {
		return CredentialScan{}, err
	}

	var scan CredentialScan
	for _, rel := range bundle {
		content, err := os.ReadFile(filepath.Join(dir, filepath.FromSlash(rel)))
		if err != nil {
			return CredentialScan{}, fmt.Errorf("read bundle file %s: %w", rel, err)
		}
		for _, found := range ScanCredentialText(string(content)) {
			for _, digest := range found.Matches {
				finding := CredentialFinding{File: rel, Line: found.Line, Class: found.Class, SHA256: digest}
				if entry, ok := allow[allowKey{rel, found.Class, found.Line, digest}]; ok {
					finding.Reason = entry.Reason
					scan.Allowed = append(scan.Allowed, finding)
					continue
				}
				scan.Refused = append(scan.Refused, finding)
			}
		}
	}
	return scan, nil
}

// bundleFiles lists the pod-relative files a publish ships, sorted:
// canon.BodyFiles plus pod.toml and pod.lock when they exist.
func bundleFiles(dir string) ([]string, error) {
	body, err := canon.BodyFiles(dir)
	if err != nil {
		return nil, fmt.Errorf("enumerate bundle files: %w", err)
	}
	files := append([]string{}, body...)
	for _, name := range []string{"pod.toml", "pod.lock"} {
		info, err := os.Lstat(filepath.Join(dir, name))
		if err == nil && info.Mode().IsRegular() {
			files = append(files, name)
		}
	}
	sort.Strings(files)
	return files, nil
}

// allowKey identifies one allowed finding: one matched string, by its
// digest, of one class on one line of one file.
type allowKey struct {
	file   string
	class  string
	line   int
	sha256 string
}

// allowDigestPattern is the form of an allow entry's sha256 field.
var allowDigestPattern = regexp.MustCompile(`^[0-9a-f]{16}$`)

// readCredentialAllowFile parses and checks the allow file. A missing file
// is an empty allow list. Every rule below is a refusal: an unknown key,
// an unknown class, a path that leaves the pod, a line under 1, a sha256
// that is not 16 lowercase hex characters, or an empty reason.
func readCredentialAllowFile(dir string) (map[allowKey]credentialAllowEntry, error) {
	raw, err := os.ReadFile(filepath.Join(dir, CredentialAllowFile))
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", CredentialAllowFile, err)
	}

	var document credentialAllowDocument
	meta, err := toml.Decode(string(raw), &document)
	if err != nil {
		return nil, fmt.Errorf("parse %s: %w", CredentialAllowFile, err)
	}
	if undecoded := meta.Undecoded(); len(undecoded) > 0 {
		return nil, fmt.Errorf("%s: unknown key %s", CredentialAllowFile, undecoded[0])
	}

	known := map[string]bool{}
	for _, name := range CredentialClassNames() {
		known[name] = true
	}
	allow := make(map[allowKey]credentialAllowEntry, len(document.Allow))
	for index, entry := range document.Allow {
		where := fmt.Sprintf("%s: [[allow]] entry %d", CredentialAllowFile, index+1)
		file := strings.TrimPrefix(entry.File, "./")
		if file == "" || path.Clean(file) != file || file == ".." || strings.HasPrefix(file, "../") || path.IsAbs(file) {
			return nil, fmt.Errorf("%s: file %q must be a clean path inside the pod", where, entry.File)
		}
		if !known[entry.Class] {
			return nil, fmt.Errorf("%s: class %q is not one of %s", where, entry.Class,
				strings.Join(CredentialClassNames(), ", "))
		}
		if entry.Line < 1 {
			return nil, fmt.Errorf("%s: line must be 1 or more", where)
		}
		if !allowDigestPattern.MatchString(entry.SHA256) {
			return nil, fmt.Errorf("%s: sha256 must be the 16 lowercase hex characters that the refusal names", where)
		}
		if strings.TrimSpace(entry.Reason) == "" {
			return nil, fmt.Errorf("%s: reason must say why the string is not a credential", where)
		}
		allow[allowKey{file, entry.Class, entry.Line, entry.SHA256}] = entry
	}
	return allow, nil
}

// RefusalMessage renders the publish refusal for the refused findings.
//
// Input: the command that refuses ("publish" or "listing"). Output: text
// that starts with the stable code, names each file, line, class and
// digest, never prints a value, and gives the correct path and the allow
// rule.
func (scan CredentialScan) RefusalMessage(command string) string {
	var out strings.Builder
	fmt.Fprintf(&out, "%s: %s: %d credential-shaped string(s) in the pod bundle. The values are not shown.\n",
		command, CodeBundleCredentialFound, len(scan.Refused))
	for _, finding := range scan.Refused {
		fmt.Fprintf(&out, "  %s (sha256 = %q)\n", finding, finding.SHA256)
	}
	out.WriteString(credentialRemedy)
	return out.String()
}

// credentialRemedy tells the author what to do instead. It uses no value.
const credentialRemedy = `
A key in a pod bundle is published with the pod. Do not put it in a file. Store it as a
sealed secret and let the pod name it:

  konareef pod secret set <NAME>

Then list <NAME> in [dependencies].secrets and, for a paid host, add a [[network.gateway]]
entry so the gateway attaches it. The pod never receives the value.

If a finding is a test fixture and not a credential, allow that one finding in
` + CredentialAllowFile + ` at the pod root. A listing review can read it:

  [[allow]]
  file = "path/of/the/file"
  class = "the class named above"
  line = 1
  sha256 = "the sha256 named above"
  reason = "why this string is not a credential"
`

// AllowedNotice renders the allowed findings for a diagnostic line block,
// or "" when none. Each line carries the author's reason.
func (scan CredentialScan) AllowedNotice() string {
	if len(scan.Allowed) == 0 {
		return ""
	}
	var out strings.Builder
	fmt.Fprintf(&out, "%d credential-shaped string(s) allowed by %s:\n", len(scan.Allowed), CredentialAllowFile)
	for _, finding := range scan.Allowed {
		fmt.Fprintf(&out, "  %s — %s\n", finding, finding.Reason)
	}
	return out.String()
}
