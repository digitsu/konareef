// Copyright 2026 Jerry David Chan, Konareef.ai
// SPDX-License-Identifier: Apache-2.0

// egress_breadth_test.go — konareef's half of the shared egress breadth
// vectors (EGRESS-BREADTH, reef-core#87), plus the PSL pin, the Punycode
// encoder and the `pod validate` wiring of the breadth rules.
//
// The "breadth" section of testdata/egress-vectors.json is checked here
// against egress_breadth.go and in reef-core against EgressBreadth. Both
// sides embed the same Public Suffix List file, pinned by SHA-256.
package pod

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// breadthVectors is the "breadth" section of the shared vector file.
// Field names follow the JSON.
type breadthVectors struct {
	PSL struct {
		Upstream string   `json:"upstream"`
		File     string   `json:"file"`
		Commit   string   `json:"commit"`
		Version  string   `json:"version"`
		SHA256   string   `json:"sha256"`
		Sections []string `json:"sections"`
	} `json:"psl"`
	RuleLimitUnreviewed  int `json:"rule_limit_unreviewed"`
	PublicSuffixWildcard []struct {
		Entry                string `json:"entry"`
		PublicSuffixWildcard bool   `json:"public_suffix_wildcard"`
	} `json:"public_suffix_wildcard"`
	RuleCount []struct {
		Name     string   `json:"name"`
		Egress   []string `json:"egress"`
		Count    int      `json:"count"`
		Limit    int      `json:"limit"`
		Exceeded bool     `json:"exceeded"`
	} `json:"rule_count"`
}

// loadBreadthVectors reads the "breadth" section of the shared vector
// file, failing the test on any error or when the section is absent.
// Output: the decoded section.
func loadBreadthVectors(t *testing.T) breadthVectors {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", "egress-vectors.json"))
	if err != nil {
		t.Fatalf("read vectors: %v", err)
	}
	var file struct {
		Breadth *breadthVectors `json:"breadth"`
	}
	if err := json.Unmarshal(raw, &file); err != nil {
		t.Fatalf("decode vectors: %v", err)
	}
	if file.Breadth == nil {
		t.Fatal("vector file has no breadth section")
	}
	return *file.Breadth
}

// TestPSLPin checks that the embedded list, the file on disk, the
// package constants and the vectors all name the same PSL: one commit
// and one SHA-256. reef-core pins the same SHA-256, so a list replaced
// on one side only fails here or there.
func TestPSLPin(t *testing.T) {
	sum := sha256.Sum256(embeddedPSL)
	if got := hex.EncodeToString(sum[:]); got != PSLSHA256 {
		t.Fatalf("embedded PSL sha256 = %s, PSLSHA256 = %s", got, PSLSHA256)
	}
	onDisk, err := os.ReadFile(filepath.Join("psl", "public_suffix_list.dat"))
	if err != nil {
		t.Fatalf("read psl file: %v", err)
	}
	if string(onDisk) != string(embeddedPSL) {
		t.Fatal("psl/public_suffix_list.dat differs from the embedded bytes")
	}
	vectors := loadBreadthVectors(t)
	if vectors.PSL.SHA256 != PSLSHA256 {
		t.Errorf("vectors psl.sha256 = %s, PSLSHA256 = %s", vectors.PSL.SHA256, PSLSHA256)
	}
	if vectors.PSL.Commit != PSLCommit {
		t.Errorf("vectors psl.commit = %s, PSLCommit = %s", vectors.PSL.Commit, PSLCommit)
	}
	if want := "publicsuffix/list@" + PSLCommit; vectors.PSL.Version != want {
		t.Errorf("vectors psl.version = %q, want %q (reef-core's psl_version string)", vectors.PSL.Version, want)
	}
	if vectors.PSL.File != "public_suffix_list.dat" {
		t.Errorf("vectors psl.file = %q", vectors.PSL.File)
	}
	if strings.Join(vectors.PSL.Sections, ",") != "ICANN,PRIVATE" {
		t.Errorf("vectors psl.sections = %v, want [ICANN PRIVATE] (owner decision D2a)", vectors.PSL.Sections)
	}
	if vectors.RuleLimitUnreviewed != EgressRuleLimitUnreviewed {
		t.Errorf("vectors rule_limit_unreviewed = %d, EgressRuleLimitUnreviewed = %d",
			vectors.RuleLimitUnreviewed, EgressRuleLimitUnreviewed)
	}
}

// TestPSLSections checks that both sections of the list are present in
// the embedded file and that rules from each one are loaded.
func TestPSLSections(t *testing.T) {
	for _, marker := range []string{
		"===BEGIN ICANN DOMAINS===", "===END ICANN DOMAINS===",
		"===BEGIN PRIVATE DOMAINS===", "===END PRIVATE DOMAINS===",
	} {
		if !strings.Contains(string(embeddedPSL), marker) {
			t.Errorf("embedded PSL has no %q marker", marker)
		}
	}
	list := loadPSL()
	for _, rule := range []string{"co.uk", "github.io", "xn--55qx5d.cn"} {
		if !list.exact[rule] {
			t.Errorf("exact rule %q not loaded", rule)
		}
	}
	if !list.wildcard["ck"] || !list.exception["www.ck"] {
		t.Error("wildcard rule *.ck or exception rule !www.ck not loaded")
	}
	if len(list.exact) < 5000 {
		t.Errorf("only %d exact rules loaded", len(list.exact))
	}
}

// TestEgressBreadthVectorsPublicSuffix runs every public_suffix_wildcard
// vector through EgressWildcardPublicSuffix.
func TestEgressBreadthVectorsPublicSuffix(t *testing.T) {
	vectors := loadBreadthVectors(t)
	if len(vectors.PublicSuffixWildcard) == 0 {
		t.Fatal("no public_suffix_wildcard vectors")
	}
	for _, vector := range vectors.PublicSuffixWildcard {
		if got := EgressWildcardPublicSuffix(vector.Entry); got != vector.PublicSuffixWildcard {
			t.Errorf("EgressWildcardPublicSuffix(%q) = %v, want %v", vector.Entry, got, vector.PublicSuffixWildcard)
		}
	}
}

// TestEgressBreadthVectorsRuleCount runs every rule_count vector through
// EgressRuleCount and the limit comparison reef-core makes.
func TestEgressBreadthVectorsRuleCount(t *testing.T) {
	vectors := loadBreadthVectors(t)
	if len(vectors.RuleCount) == 0 {
		t.Fatal("no rule_count vectors")
	}
	for _, vector := range vectors.RuleCount {
		got := EgressRuleCount(vector.Egress)
		if got != vector.Count {
			t.Errorf("%s: EgressRuleCount = %d, want %d", vector.Name, got, vector.Count)
		}
		if exceeded := got > vector.Limit; exceeded != vector.Exceeded {
			t.Errorf("%s: exceeded = %v, want %v", vector.Name, exceeded, vector.Exceeded)
		}
	}
}

// TestPunycodeEncode checks the encoder against known IDNA labels and
// the RFC 3492 section 7.1 sample (B), Chinese (simplified).
func TestPunycodeEncode(t *testing.T) {
	cases := map[string]string{
		"bücher":    "xn--bcher-kva",
		"münchen":   "xn--mnchen-3ya",
		"公司":        "xn--55qx5d",
		"рф":        "xn--p1ai",
		"中国":        "xn--fiqs8s",
		"他们为什么不说中文": "xn--ihqwcrb4cv8a8dqg056pqjye",
		"example":   "example",
	}
	for label, want := range cases {
		got, err := toASCIILabel(label)
		if err != nil {
			t.Errorf("toASCIILabel(%q): %v", label, err)
			continue
		}
		if got != want {
			t.Errorf("toASCIILabel(%q) = %q, want %q", label, got, want)
		}
	}
}

// breadthIssueAndWarningCodes validates a manifest whose egress list is
// egress (TOML array body) and returns the issue codes and warning codes
// by path. Output: two maps of "path: CODE" to true.
func breadthIssueAndWarningCodes(t *testing.T, egress string) (map[string]bool, map[string]bool) {
	t.Helper()
	manifest := strings.Replace(minimalValidPodTOMLForEgress, "EGRESS", egress, 1)
	issues, warnings, err := ValidateWithWarnings([]byte(manifest))
	if err != nil {
		t.Fatalf("ValidateWithWarnings: %v", err)
	}
	issueCodes := map[string]bool{}
	for _, issue := range issues {
		issueCodes[issue.Path+": "+issue.Code] = true
		if issue.Message == "" {
			t.Errorf("issue %v has no message", issue)
		}
	}
	warningCodes := map[string]bool{}
	for _, warning := range warnings {
		warningCodes[warning.Path+": "+warning.Code] = true
	}
	return issueCodes, warningCodes
}

// TestValidatePublicSuffixWildcardIsAnIssue checks owner decision D2 at
// `pod validate`: a public-suffix wildcard fails validation with the
// server's code on that entry, in place of the advisory wildcard warning.
// A wildcard under a registrable domain stays a warning only.
func TestValidatePublicSuffixWildcardIsAnIssue(t *testing.T) {
	issues, warnings := breadthIssueAndWarningCodes(t, `"*.com:443", "*.co.uk:443", "*.example.com:443", "*.github.io"`)
	for _, path := range []string{"network.egress[0]", "network.egress[1]", "network.egress[3]"} {
		if !issues[path+": "+CodeEgressWildcardPublicSuffix] {
			t.Errorf("no %s issue on %s; issues = %v", CodeEgressWildcardPublicSuffix, path, issues)
		}
		if warnings[path+": "+WarnEgressWildcardReview] {
			t.Errorf("%s still has the %s warning", path, WarnEgressWildcardReview)
		}
	}
	if len(issues) != 3 {
		t.Errorf("issues = %v, want exactly 3", issues)
	}
	if !warnings["network.egress[2]: "+WarnEgressWildcardReview] {
		t.Errorf("*.example.com lost its %s warning; warnings = %v", WarnEgressWildcardReview, warnings)
	}
}

// TestValidateExactPublicSuffixHostIsNotRefused checks that an exact
// entry naming a public suffix (one host) is not a breadth issue.
func TestValidateExactPublicSuffixHostIsNotRefused(t *testing.T) {
	issues, _ := breadthIssueAndWarningCodes(t, `"co.uk:443"`)
	if len(issues) != 0 {
		t.Errorf("issues = %v, want none", issues)
	}
}

// TestValidateRuleLimitIsAWarning checks owner decision D1 at `pod
// validate`: more than 16 distinct rules is a warning with the server's
// code, never an issue, and 16 is not above the limit.
func TestValidateRuleLimitIsAWarning(t *testing.T) {
	quoted := func(count int) string {
		entries := make([]string, 0, count)
		for index := 1; index <= count; index++ {
			entries = append(entries, fmt.Sprintf("%q", fmt.Sprintf("h%02d.example.com", index)))
		}
		return strings.Join(entries, ", ")
	}
	issues, warnings := breadthIssueAndWarningCodes(t, quoted(17))
	if len(issues) != 0 {
		t.Errorf("issues = %v, want none: the rule limit is advisory on the client", issues)
	}
	if !warnings["network.egress: "+WarnEgressRuleLimitExceeded] {
		t.Errorf("no %s warning for 17 rules; warnings = %v", WarnEgressRuleLimitExceeded, warnings)
	}
	_, warnings = breadthIssueAndWarningCodes(t, quoted(16))
	if warnings["network.egress: "+WarnEgressRuleLimitExceeded] {
		t.Error("16 rules warned; the limit is inclusive")
	}
}

// TestEgressBreadthIgnoresGateway checks that [[network.gateway]] entries
// do not count toward the rule limit: each has its own call cap.
func TestEgressBreadthIgnoresGateway(t *testing.T) {
	spec := Spec{Network: &Network{Egress: []string{"a.example.com"}}}
	for index := 0; index < 20; index++ {
		spec.Network.Gateway = append(spec.Network.Gateway, Gateway{Host: fmt.Sprintf("g%02d.example.com", index)})
	}
	issues, warnings := egressBreadthRules(spec)
	if len(issues) != 0 || len(warnings) != 0 {
		t.Errorf("issues = %v, warnings = %v, want none", issues, warnings)
	}
	if issues, warnings := egressBreadthRules(Spec{}); issues != nil || warnings != nil {
		t.Errorf("absent [network]: issues = %v, warnings = %v", issues, warnings)
	}
}

// TestPSLAncestorSet checks the ancestor set from the owner ruling of
// 2026-10-09: proper ancestors of exact and exception rules, and each
// wildcard rule's base with its ancestors, are in it; a rule that has
// nothing beneath it is not.
func TestPSLAncestorSet(t *testing.T) {
	list := loadPSL()
	for _, domain := range []string{"amazonaws.com", "uk", "sch.uk", "kawasaki.jp", "kobe.jp", "jp"} {
		if !list.ancestor[domain] {
			t.Errorf("%q is not in the ancestor set", domain)
		}
	}
	for _, domain := range []string{"example.com", "city.kobe.jp", "www.ck", "co.uk.example"} {
		if list.ancestor[domain] {
			t.Errorf("%q is in the ancestor set", domain)
		}
	}
	set := map[string]bool{}
	addProperAncestors(set, "a.b.c")
	if len(set) != 2 || !set["b.c"] || !set["c"] {
		t.Errorf("addProperAncestors(a.b.c) = %v", set)
	}
}
