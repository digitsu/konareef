// Copyright 2026 Jerry David Chan, Konareef.ai
// SPDX-License-Identifier: Apache-2.0

// egress_review_test.go — konareef's half of the shared egress vectors.
//
// testdata/egress-vectors.json is checked here against the konareef
// rules and by scripts/check_egress_vectors.exs against the reef-core
// rules. Both passing is the evidence that `pod validate`, `pod safety`
// and the listing pre-check agree with the server's review.

package pod

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// egressVectors is the decoded vector file. Field names follow the JSON.
type egressVectors struct {
	Format         string `json:"format"`
	ScannerVersion string `json:"scanner_version"`
	PolicyVersion  string `json:"policy_version"`
	PlatformHost   string `json:"platform_host"`
	HostMatching   []struct {
		Declared string `json:"declared"`
		Host     string `json:"host"`
		Port     int    `json:"port"`
		Allowed  bool   `json:"allowed"`
	} `json:"host_matching"`
	IPLiteral []struct {
		Host string `json:"host"`
		IP   bool   `json:"ip"`
	} `json:"ip_literal"`
	DeclarationPresence []struct {
		Name     string `json:"name"`
		Manifest string `json:"manifest"`
		Declared bool   `json:"declared"`
		Rules    []struct {
			Host     string `json:"host"`
			Port     int    `json:"port"`
			Wildcard bool   `json:"wildcard"`
		} `json:"rules"`
	} `json:"declaration_presence"`
	Findings []struct {
		Name     string            `json:"name"`
		Manifest string            `json:"manifest"`
		Files    map[string]string `json:"files"`
		Findings []ReviewFinding   `json:"findings"`
		// SafetyCheckStricter marks a vector where the listing pre-check
		// refuses and the server review has no host finding. The reverse
		// (the pre-check passing what the review reports) is never allowed.
		SafetyCheckStricter bool `json:"safety_check_stricter"`
	} `json:"findings"`
	Uninspectable []struct {
		Name     string            `json:"name"`
		Manifest string            `json:"manifest"`
		Files    map[string]string `json:"files"`
		Dirs     []string          `json:"dirs"`
	} `json:"uninspectable"`
}

// loadEgressVectors reads and decodes the shared vector file, failing the
// test on any error. Output: the decoded vectors.
func loadEgressVectors(t *testing.T) egressVectors {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", "egress-vectors.json"))
	if err != nil {
		t.Fatalf("read vectors: %v", err)
	}
	var vectors egressVectors
	if err := json.Unmarshal(raw, &vectors); err != nil {
		t.Fatalf("decode vectors: %v", err)
	}
	if vectors.Format != "konareef-egress-vectors/v1" {
		t.Fatalf("vector format = %q", vectors.Format)
	}
	return vectors
}

// TestEgressVectorsVersions pins the reef-core scanner and policy
// versions the vectors were checked against to the constants this
// package reports, so a server bump shows up as a konareef test change.
func TestEgressVectorsVersions(t *testing.T) {
	vectors := loadEgressVectors(t)
	if vectors.ScannerVersion != EgressReviewScannerVersion {
		t.Errorf("scanner_version = %q, package says %q", vectors.ScannerVersion, EgressReviewScannerVersion)
	}
	if vectors.PolicyVersion != EgressReviewPolicyVersion {
		t.Errorf("policy_version = %q, package says %q", vectors.PolicyVersion, EgressReviewPolicyVersion)
	}
	if vectors.PlatformHost != DefaultPlatformHost {
		t.Errorf("platform_host = %q, package default is %q", vectors.PlatformHost, DefaultPlatformHost)
	}
}

// TestEgressVectorsHostMatching checks the declaration matcher, and then
// checks that SafetyCheck — the check behind `pod safety` and the listing
// pre-check — reaches the same answer for a URL naming that host:port.
func TestEgressVectorsHostMatching(t *testing.T) {
	vectors := loadEgressVectors(t)
	for _, vector := range vectors.HostMatching {
		name := fmt.Sprintf("%s vs %s:%d", vector.Declared, vector.Host, vector.Port)
		t.Run(name, func(t *testing.T) {
			spec := Spec{Network: &Network{Egress: []string{vector.Declared}}}
			rules := parseEgressRules(spec)
			if got := egressAllowed(rules, vector.Host, vector.Port); got != vector.Allowed {
				t.Fatalf("egressAllowed = %v, want %v", got, vector.Allowed)
			}

			spec.Directive = &Directive{Task: fmt.Sprintf("https://%s:%d/x", vector.Host, vector.Port)}
			findings, err := SafetyCheck(t.TempDir(), spec)
			if err != nil {
				t.Fatalf("SafetyCheck: %v", err)
			}
			if clean := len(findings) == 0; clean != vector.Allowed {
				t.Fatalf("SafetyCheck clean = %v, want %v (findings %v)", clean, vector.Allowed, findings)
			}
		})
	}
}

// TestEgressVectorsIPLiteral checks the inet_aton-compatible address
// classifier behind the ip_literal_declared finding.
func TestEgressVectorsIPLiteral(t *testing.T) {
	vectors := loadEgressVectors(t)
	for _, vector := range vectors.IPLiteral {
		if got := isIPLiteral(vector.Host); got != vector.IP {
			t.Errorf("isIPLiteral(%q) = %v, want %v", vector.Host, got, vector.IP)
		}
	}
}

// TestEgressVectorsDeclarationPresence checks that an absent table, a
// bare table, an empty egress list and a gateway-only table decode as the
// server reads them: absent is undeclared, every present form is
// declared, and the parsed rules match.
func TestEgressVectorsDeclarationPresence(t *testing.T) {
	vectors := loadEgressVectors(t)
	for _, vector := range vectors.DeclarationPresence {
		t.Run(vector.Name, func(t *testing.T) {
			spec, err := Parse([]byte(vector.Manifest))
			if err != nil {
				t.Fatalf("Parse: %v", err)
			}
			if got := EgressDeclared(spec); got != vector.Declared {
				t.Fatalf("EgressDeclared = %v, want %v", got, vector.Declared)
			}
			rules := parseEgressRules(spec)
			if len(rules) != len(vector.Rules) {
				t.Fatalf("rules = %+v, want %+v", rules, vector.Rules)
			}
			for index, want := range vector.Rules {
				got := rules[index]
				if got.host != want.Host || got.port != want.Port || got.wildcard != want.Wildcard {
					t.Errorf("rule %d = %+v, want %+v", index, got, want)
				}
			}
		})
	}
}

// TestEgressVectorsFindings runs the review preview over each vector's
// manifest and body files, and checks the finding set equals the one the
// server produces. It then checks that SafetyCheck refuses every vector
// whose review names an undeclared or platform host, and refuses no other
// vector unless the vector is marked safety_check_stricter. The listing
// pre-check is therefore never looser than the server review.
func TestEgressVectorsFindings(t *testing.T) {
	vectors := loadEgressVectors(t)
	for _, vector := range vectors.Findings {
		t.Run(vector.Name, func(t *testing.T) {
			spec, err := Parse([]byte(vector.Manifest))
			if err != nil {
				t.Fatalf("Parse: %v", err)
			}
			dir := writeVectorBody(t, vector.Files, nil)

			got, err := EgressReviewPreview(dir, spec, vectors.PlatformHost)
			if err != nil {
				t.Fatalf("EgressReviewPreview: %v", err)
			}
			if want := sortedFindings(vector.Findings); !equalFindings(sortedFindings(got), want) {
				t.Fatalf("findings\n got %v\nwant %v", sortedFindings(got), want)
			}

			hostFinding := false
			for _, finding := range got {
				if finding.Code == ReviewUndeclaredHost || finding.Code == ReviewPlatformHostReferenced {
					hostFinding = true
				}
			}
			safety, err := SafetyCheckStrict(dir, spec)
			if err != nil {
				t.Fatalf("SafetyCheckStrict: %v", err)
			}
			switch {
			case hostFinding && len(safety) == 0:
				t.Fatalf("SafetyCheckStrict passed a pod whose review has host findings %v", got)
			case vector.SafetyCheckStricter && (hostFinding || len(safety) == 0):
				t.Fatalf("vector is marked safety_check_stricter, but SafetyCheckStrict = %v and review = %v", safety, got)
			case !vector.SafetyCheckStricter && !hostFinding && len(safety) > 0:
				t.Fatalf("SafetyCheckStrict findings %v disagree with review host findings %v", safety, got)
			}
		})
	}
}

// TestEgressVectorsUninspectable checks the cases where the server's
// review cannot resolve a declared source and records an error: the
// preview and the listing pre-check must refuse them too, rather than
// pass a pod the server then reports as egress_review_error.
func TestEgressVectorsUninspectable(t *testing.T) {
	vectors := loadEgressVectors(t)
	if len(vectors.Uninspectable) == 0 {
		t.Fatal("no uninspectable vectors")
	}
	for _, vector := range vectors.Uninspectable {
		t.Run(vector.Name, func(t *testing.T) {
			spec, err := Parse([]byte(vector.Manifest))
			if err != nil {
				t.Fatalf("Parse: %v", err)
			}
			dir := writeVectorBody(t, vector.Files, vector.Dirs)
			if findings, err := EgressReviewPreview(dir, spec, vectors.PlatformHost); err == nil {
				t.Errorf("EgressReviewPreview = %v, want an error", findings)
			}
			if findings, err := SafetyCheckStrict(dir, spec); err == nil {
				t.Errorf("SafetyCheckStrict = %v, want an error", findings)
			}
		})
	}
}

// writeVectorBody writes a vector's body files, and any empty
// directories it names, into a fresh pod directory. Output: the dir.
func writeVectorBody(t *testing.T, files map[string]string, dirs []string) string {
	t.Helper()
	dir := t.TempDir()
	for _, rel := range dirs {
		if err := os.MkdirAll(filepath.Join(dir, filepath.FromSlash(rel)), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	for rel, content := range files {
		path := filepath.Join(dir, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

// sortedFindings returns a copy of findings in a fixed order so two sets
// can be compared element by element.
func sortedFindings(findings []ReviewFinding) []ReviewFinding {
	out := append([]ReviewFinding(nil), findings...)
	sort.Slice(out, func(i, j int) bool { return out[i].String() < out[j].String() })
	return out
}

// equalFindings reports whether two sorted finding lists are equal.
func equalFindings(a, b []ReviewFinding) bool {
	if len(a) != len(b) {
		return false
	}
	for index := range a {
		if a[index] != b[index] {
			return false
		}
	}
	return true
}

// TestEgressWarnings checks the advisory `pod validate` warnings: one per
// declaration-level finding the server review flags, each on the entry
// that caused it, and none for a plain declaration.
func TestEgressWarnings(t *testing.T) {
	spec := Spec{Network: &Network{
		Egress: []string{"api.example.com", "*.cdn.example.com", "127.0.0.1", "svc.example.com:22"},
		Gateway: []Gateway{
			{Host: "pay.example.com"},
			{Host: "pay.example.com:8443"},
		},
	}}
	got := EgressWarnings(spec)
	want := []string{
		"network.egress[1]: EGRESS_WILDCARD_REVIEW",
		"network.egress[2]: EGRESS_IP_LITERAL",
		"network.egress[3]: EGRESS_NON_TLS_PORT",
		"network.gateway[1].host: EGRESS_NON_TLS_PORT",
	}
	if len(got) != len(want) {
		t.Fatalf("warnings = %v, want %d", got, len(want))
	}
	for index, warning := range got {
		if prefix := warning.Path + ": " + warning.Code; prefix != want[index] {
			t.Errorf("warning %d = %q, want %q", index, prefix, want[index])
		}
		if warning.Message == "" {
			t.Errorf("warning %d has no message", index)
		}
	}

	if warnings := EgressWarnings(Spec{}); len(warnings) != 0 {
		t.Errorf("absent [network] produced warnings %v", warnings)
	}
}

// minimalValidPodTOMLForEgress is a schema-valid manifest whose one
// egress entry is the placeholder EGRESS.
const minimalValidPodTOMLForEgress = `
pod_spec_version = "0.1"

[pod]
name    = "minimal"
version = "0.1.0"

[runtime]
kind = "lobster"

[network]
egress = [EGRESS]

[directive]
task = "Say hello and exit."
`

// TestEgressWarningsInValidate checks that `pod validate` surfaces the
// egress warnings and that they never become issues.
func TestEgressWarningsInValidate(t *testing.T) {
	manifest := strings.Replace(minimalValidPodTOMLForEgress, "EGRESS", `"10.0.0.1:8080"`, 1)
	issues, warnings, err := ValidateWithWarnings([]byte(manifest))
	if err != nil {
		t.Fatalf("ValidateWithWarnings: %v", err)
	}
	if len(issues) != 0 {
		t.Fatalf("issues = %v, want none", issues)
	}
	codes := map[string]bool{}
	for _, warning := range warnings {
		codes[warning.Code] = true
	}
	if !codes[WarnEgressIPLiteral] || !codes[WarnEgressNonTLSPort] {
		t.Fatalf("warnings = %v, want %s and %s", warnings, WarnEgressIPLiteral, WarnEgressNonTLSPort)
	}
}

// TestEgressReviewPreviewUninspectable checks that the preview is strict:
// a declared source it cannot read is an error, never a clean result.
func TestEgressReviewPreviewUninspectable(t *testing.T) {
	spec := Spec{Directive: &Directive{Template: "./missing.md"}}
	if _, err := EgressReviewPreview(t.TempDir(), spec, DefaultPlatformHost); err == nil {
		t.Fatal("EgressReviewPreview with a missing template returned no error")
	}
}
