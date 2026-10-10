// Copyright 2026 Jerry David Chan, Konareef.ai
// SPDX-License-Identifier: Apache-2.0

// Tests for the pod.toml validator. Uses inline TOML strings rather than
// fixture files to keep the test suite self-contained — same convention the
// smoke package uses for its CannedBundle.
package pod

import (
	"strings"
	"testing"
)

// TestValidate_Valid covers documents that should validate cleanly.
func TestValidate_Valid(t *testing.T) {
	cases := []struct {
		name string
		toml string
	}{
		{
			name: "minimal valid pod with inline directive",
			toml: `
pod_spec_version = "0.1"

[pod]
name    = "minimal"
version = "0.1.0"

[runtime]
kind = "lobster"

[directive]
task = "Say hello and exit."
`,
		},
		{
			name: "hello-world example shape",
			toml: `
pod_spec_version = "0.1"

[pod]
name        = "hello-world"
version     = "0.1.0"
authors     = ["jerry@konareef.ai"]
license     = "MIT"
description = "Smallest pod that exercises the v0.1 spec end-to-end."
tags        = ["example", "smoke-test"]

[runtime]
kind    = "lobster"
version = "^0.1"

[model]
provider   = "anthropic"
name       = "claude-sonnet-4-5"
max_tokens = 1024

[inputs]
name = { type = "string", required = true, description = "Person to greet." }

[directive]
template       = "./prompts/greeting.md"
max_iterations = 1

[output]
[[output.failure]]
kind  = "timeout_seconds"
value = 60

[[output.failure]]
kind = "budget_exhausted"

[budget]
max_sats = 200
`,
		},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			issues, err := Validate([]byte(testCase.toml))
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if len(issues) != 0 {
				t.Fatalf("expected valid, got %d issue(s):\n%s", len(issues), formatIssues(issues))
			}
		})
	}
}

// TestValidate_Invalid covers documents that should fail validation. Each
// case asserts that at least one issue mentions a substring tied to the
// expected violation, so the test is robust against minor wording changes
// in the underlying validator's messages.
func TestValidate_Invalid(t *testing.T) {
	cases := []struct {
		name         string
		toml         string
		wantInIssues string
	}{
		{
			name: "missing top-level pod_spec_version",
			toml: `
[pod]
name    = "x"
version = "0.1.0"

[runtime]
kind = "lobster"

[directive]
task = "x"
`,
			wantInIssues: "pod_spec_version",
		},
		{
			name: "missing required [runtime] table",
			toml: `
pod_spec_version = "0.1"

[pod]
name    = "x"
version = "0.1.0"

[directive]
task = "x"
`,
			wantInIssues: "runtime",
		},
		{
			name: "directive without task or template",
			toml: `
pod_spec_version = "0.1"

[pod]
name    = "x"
version = "0.1.0"

[runtime]
kind = "lobster"

[directive]
max_iterations = 5
`,
			wantInIssues: "directive",
		},
		{
			name: "wrong pod_spec_version constant",
			toml: `
pod_spec_version = "9.9"

[pod]
name    = "x"
version = "0.1.0"

[runtime]
kind = "lobster"

[directive]
task = "x"
`,
			wantInIssues: "0.1",
		},
		{
			name: "pod.name violates identifier pattern",
			toml: `
pod_spec_version = "0.1"

[pod]
name    = "Has Capitals"
version = "0.1.0"

[runtime]
kind = "lobster"

[directive]
task = "x"
`,
			wantInIssues: "name",
		},
		{
			name: "pod.version not semver",
			toml: `
pod_spec_version = "0.1"

[pod]
name    = "ok"
version = "not-a-version"

[runtime]
kind = "lobster"

[directive]
task = "x"
`,
			wantInIssues: "version",
		},
		{
			name: "model.temperature out of range",
			toml: `
pod_spec_version = "0.1"

[pod]
name    = "ok"
version = "0.1.0"

[runtime]
kind = "lobster"

[model]
provider    = "anthropic"
name        = "claude-sonnet-4-5"
temperature = 9.9

[directive]
task = "x"
`,
			wantInIssues: "temperature",
		},
		{
			name: "wallet strategy = reuse without reuse field",
			toml: `
pod_spec_version = "0.1"

[pod]
name    = "ok"
version = "0.1.0"

[runtime]
kind = "lobster"

[directive]
task = "x"

[wallet]
strategy = "reuse"
`,
			wantInIssues: "reuse",
		},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			issues, err := Validate([]byte(testCase.toml))
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if len(issues) == 0 {
				t.Fatalf("expected invalid, got zero issues")
			}
			combined := formatIssues(issues)
			if !strings.Contains(combined, testCase.wantInIssues) {
				t.Errorf("expected substring %q in issues, got:\n%s",
					testCase.wantInIssues, combined)
			}
		})
	}
}

// TestValidate_TOMLParseError verifies that a syntactically invalid TOML
// input is reported as a parse error, not as a schema-validation issue.
func TestValidate_TOMLParseError(t *testing.T) {
	_, err := Validate([]byte("this == is == not = toml"))
	if err == nil {
		t.Fatal("expected toml parse error, got nil")
	}
	if !strings.Contains(err.Error(), "toml parse") {
		t.Errorf("expected 'toml parse' in error, got: %v", err)
	}
}

// formatIssues joins issues into a multi-line string for use in test
// failure messages.
func formatIssues(issues []Issue) string {
	var builder strings.Builder
	for _, issue := range issues {
		builder.WriteString("  - ")
		builder.WriteString(issue.String())
		builder.WriteByte('\n')
	}
	return builder.String()
}

// egressManifest wraps one [network].egress array in the smallest
// manifest that validates, so a case fails on the egress entry and on
// nothing else.
func egressManifest(entries string) string {
	return `
pod_spec_version = "0.1"

[pod]
name    = "egress-shape"
version = "0.1.0"

[runtime]
kind = "lobster"

[directive]
task = "Say hello and exit."

[network]
egress = [` + entries + `]
`
}

// TestValidate_EgressAcceptsBracketedIPv6 closes the gap between the two
// halves of the egress contract. SafetyCheck reads "[::1]:8443" as a
// declaration of host ::1 on port 8443, but the schema's host pattern
// knew only DNS labels, so `konareef pod validate` rejected the one
// spelling the checker required. An author with an IPv6 endpoint had no
// way to satisfy both, which made the allowlist unusable for that
// endpoint rather than merely awkward.
func TestValidate_EgressAcceptsBracketedIPv6(t *testing.T) {
	accepted := []string{
		`"[::1]"`,
		`"[::1]:8443"`,
		`"[2001:db8::1]:8443"`,
		`"[2001:db8:0:0:0:0:0:1]"`,
		`"[::ffff:192.0.2.1]:443"`,
		// The DNS spellings the pattern already took must keep working:
		// the IPv6 branch is an addition, not a replacement.
		`"api.example.com"`,
		`"api.example.com:8080"`,
		`"*.example.com"`,
	}
	for _, entry := range accepted {
		t.Run(entry, func(t *testing.T) {
			issues, err := Validate([]byte(egressManifest(entry)))
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if len(issues) != 0 {
				t.Fatalf("egress = [%s] must validate, got:\n%s", entry, formatIssues(issues))
			}
		})
	}
}

// The IPv6 branch must not become a hole. A pattern loosened far enough
// to admit brackets and colons can admit anything, and an egress entry
// the schema waves through but splitHostPort cannot read is an
// allowlist entry that silently matches no host at all.
func TestValidate_EgressStillRejectsMalformedHosts(t *testing.T) {
	rejected := []string{
		`"[::1"`,           // unclosed bracket
		`"::1"`,            // unbracketed, so the last colon reads as a port
		`"[]"`,             // brackets with no address
		`"[not:an:addr!]"`, // characters no address contains
		`"[::1]:notaport"`,
		`"[::1]extra"`,
		`"http://api.example.com"`,
		`"api.example.com/path"`,
		`"api example.com"`,
	}
	for _, entry := range rejected {
		t.Run(entry, func(t *testing.T) {
			issues, err := Validate([]byte(egressManifest(entry)))
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if len(issues) == 0 {
				t.Fatalf("egress = [%s] is malformed and must be rejected", entry)
			}
		})
	}
}

// TestValidate_EgressIPv6AgreesWithTheSafetyChecker walks the consistency
// in both directions at once: every spelling the schema accepts is read
// by splitHostPort as the host and port the author meant, and that host
// is the one url.Hostname() yields for the same address in a URL. A
// declaration that validates but resolves to a different host would be an
// allowlist entry that never matches, which reads to an author as the
// checker ignoring their declaration.
func TestValidate_EgressIPv6AgreesWithTheSafetyChecker(t *testing.T) {
	cases := []struct {
		entry string
		host  string
		port  string
	}{
		{"[::1]", "::1", "443"},
		{"[::1]:8443", "::1", "8443"},
		{"[2001:db8::1]:8443", "2001:db8::1", "8443"},
		{"[::ffff:192.0.2.1]:443", "::ffff:192.0.2.1", "443"},
	}
	for _, testCase := range cases {
		t.Run(testCase.entry, func(t *testing.T) {
			issues, err := Validate([]byte(egressManifest(`"` + testCase.entry + `"`)))
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if len(issues) != 0 {
				t.Fatalf("schema rejected %q:\n%s", testCase.entry, formatIssues(issues))
			}

			host, port := splitHostPort(testCase.entry)
			if host != testCase.host || port != testCase.port {
				t.Fatalf("splitHostPort(%q) = (%q, %q), want (%q, %q)",
					testCase.entry, host, port, testCase.host, testCase.port)
			}

			spec := Spec{Network: &Network{Egress: []string{testCase.entry}}}
			dir := writePod(t, map[string]string{
				"skills/local.md": "Fetch https://[" + testCase.host + "]:" + testCase.port + "/x now.",
			})
			spec.Context = &Context{Skills: []ContextSkill{{Source: "./skills/local.md"}}}

			findings, err := SafetyCheckStrict(dir, spec)
			if err != nil {
				t.Fatalf("SafetyCheckStrict: %v", err)
			}
			if len(findings) != 0 {
				t.Fatalf("a schema-valid IPv6 declaration must satisfy the checker; got %v", findings)
			}
		})
	}
}

// gatewayPodTOML is a valid pod with one paid host. Tests below vary one
// field at a time from it.
const gatewayPodTOML = `
pod_spec_version = "0.1"

[pod]
name    = "voice"
version = "0.1.0"

[runtime]
kind = "lobster"

[dependencies]
secrets = ["ELEVENLABS_API_KEY"]

[network]
egress = ["cdn.example.com"]

[[network.gateway]]
host = "api.elevenlabs.io"
secret = "ELEVENLABS_API_KEY"
auth = "header:xi-api-key"
max_calls = 3

[directive]
task = "Speak."
`

// TestValidate_GatewayTable covers the schema shape of [[network.gateway]].
// Cross-field rules (secret declared, no wildcard) live in gateway_test.go.
func TestValidate_GatewayTable(t *testing.T) {
	issues, err := Validate([]byte(gatewayPodTOML))
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if len(issues) != 0 {
		t.Fatalf("valid gateway pod produced issues: %v", issues)
	}

	invalid := []struct {
		name    string
		replace string
		with    string
		want    string
	}{
		{"missing max_calls", "max_calls = 3\n", "", "max_calls"},
		{"zero max_calls", "max_calls = 3", "max_calls = 0", "max_calls"},
		{"bad auth form", `auth = "header:xi-api-key"`, `auth = "cookie:sid"`, "auth"},
		{"lowercase secret", `secret = "ELEVENLABS_API_KEY"`, `secret = "elevenlabs"`, "secret"},
		{"unknown key", "max_calls = 3", "max_calls = 3\nmax_bytes = 9", "max_bytes"},
	}
	for _, tc := range invalid {
		t.Run(tc.name, func(t *testing.T) {
			doc := strings.Replace(gatewayPodTOML, tc.replace, tc.with, 1)
			issues, err := Validate([]byte(doc))
			if err != nil {
				t.Fatalf("Validate: %v", err)
			}
			if len(issues) == 0 {
				t.Fatalf("expected an issue mentioning %q, got none", tc.want)
			}
			found := false
			for _, issue := range issues {
				if strings.Contains(issue.String(), tc.want) {
					found = true
				}
			}
			if !found {
				t.Fatalf("no issue mentions %q: %v", tc.want, issues)
			}
		})
	}
}

// TestValidate_GatewayMCPShape covers the schema shape of a brokered MCP
// grant. Namespace rules live in gateway_test.go.
func TestValidate_GatewayMCPShape(t *testing.T) {
	cases := []struct {
		name  string
		with  string
		valid bool
	}{
		{"mcp with name and tools", "max_calls = 3\nprotocol = \"mcp\"\nmcp_name = \"jira\"\nmcp_tools = [\"get_issue\"]", true},
		{"mcp with path", "max_calls = 3\nprotocol = \"mcp\"\nmcp_path = \"/v1/mcp\"\nmcp_name = \"jira\"\nmcp_tools = [\"get_issue\"]", true},
		{"explicit http", "max_calls = 3\nprotocol = \"http\"", true},
		{"mcp without tools", "max_calls = 3\nprotocol = \"mcp\"\nmcp_name = \"jira\"", false},
		{"mcp without name", "max_calls = 3\nprotocol = \"mcp\"\nmcp_tools = [\"get_issue\"]", false},
		{"mcp with empty tools", "max_calls = 3\nprotocol = \"mcp\"\nmcp_name = \"jira\"\nmcp_tools = []", false},
		{"http with mcp_name", "max_calls = 3\nmcp_name = \"jira\"", false},
		{"unknown protocol", "max_calls = 3\nprotocol = \"grpc\"", false},
		{"uppercase name", "max_calls = 3\nprotocol = \"mcp\"\nmcp_name = \"Jira\"\nmcp_tools = [\"get_issue\"]", false},
		{"dotted name", "max_calls = 3\nprotocol = \"mcp\"\nmcp_name = \"ji.ra\"\nmcp_tools = [\"get_issue\"]", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			issues, err := validateSchema(gatewayDoc("max_calls = 3", tc.with))
			if err != nil {
				t.Fatalf("validateSchema: %v", err)
			}
			if tc.valid && len(issues) != 0 {
				t.Fatalf("issues = %+v, want none", issues)
			}
			if !tc.valid && len(issues) == 0 {
				t.Fatalf("schema accepted an invalid grant")
			}
		})
	}
}

// TestValidateWarnsOnUncommittedToolAuthority covers the authoring-time warning
// for [directive].tools_allowed entries that name tools absent from [[context.tools]].
// Spec R-V2.14: a v2 publish rejects this case, so warn at authoring time so the
// author sees it from their own `pod validate` run rather than from a buyer's
// commission failing later.
func TestValidateWarnsOnUncommittedToolAuthority(t *testing.T) {
	body := []byte("pod_spec_version = \"0.1\"\n[pod]\nname = \"p\"\nversion=\"0.1.0\"\n[runtime]\nkind=\"lobster\"\n[model]\nprovider=\"o\"\nname=\"m\"\n" +
		"[[context.tools]]\nsource = \"bash\"\n[directive]\ntask=\"test\"\ntools_allowed = [\"curl\", \"bash\"]\n")
	issues, warnings, err := ValidateWithWarnings(body)
	if err != nil {
		t.Fatal(err)
	}
	if len(issues) != 0 {
		t.Fatalf("this must warn, not fail: %v", issues)
	}
	var found bool
	for _, w := range warnings {
		if w.Code == "tools-allowed-uncommitted" && strings.Contains(w.Message, "curl") {
			found = true
		}
		if strings.Contains(w.Message, "bash") {
			t.Fatalf("bash IS declared in [[context.tools]]; it must not warn: %v", w)
		}
	}
	if !found {
		t.Fatalf("no warning for curl: %v", warnings)
	}
}

// D5 (tool-policy semantics ADR): a name in both tools_allowed and
// tools_denied is an Issue — validation FAILS — not a Warning, unlike
// every other tool-policy finding in this file. This is deliberate: a
// manifest cannot mean "deny wins" and "narrow the runtime set" for the
// same name at once.
func TestValidateFailsOnToolsDeniedOverlapAllowed(t *testing.T) {
	body := []byte("pod_spec_version = \"0.1\"\n[pod]\nname = \"p\"\nversion=\"0.1.0\"\n[runtime]\nkind=\"lobster\"\n[model]\nprovider=\"o\"\nname=\"m\"\n" +
		"[[context.tools]]\nsource = \"bash\"\n[directive]\ntask=\"test\"\ntools_allowed = [\"bash\"]\ntools_denied = [\"bash\"]\n")
	issues, _, err := ValidateWithWarnings(body)
	if err != nil {
		t.Fatal(err)
	}
	var found bool
	for _, iss := range issues {
		if iss.Code == "tools-denied-overlap-allowed" && strings.Contains(iss.Message, "bash") {
			found = true
		}
	}
	if !found {
		t.Fatalf("want a tools-denied-overlap-allowed issue, got %+v", issues)
	}
}

// D5, Option B: a tools_denied name with no [[context.tools]] referent only
// warns — there is no runtime name inventory to check it against, so it
// may simply be a label (the code-reviewer example's shape).
func TestValidateWarnsOnToolsDeniedUnknownReferent(t *testing.T) {
	body := []byte("pod_spec_version = \"0.1\"\n[pod]\nname = \"p\"\nversion=\"0.1.0\"\n[runtime]\nkind=\"lobster\"\n[model]\nprovider=\"o\"\nname=\"m\"\n" +
		"[[context.tools]]\nsource = \"bash\"\n[directive]\ntask=\"test\"\ntools_denied = [\"secrets_read\"]\n")
	issues, warnings, err := ValidateWithWarnings(body)
	if err != nil {
		t.Fatal(err)
	}
	if len(issues) != 0 {
		t.Fatalf("an unknown deny referent must warn, not fail: %v", issues)
	}
	var found bool
	for _, w := range warnings {
		if w.Code == "tools-denied-unknown" && strings.Contains(w.Message, "secrets_read") {
			found = true
		}
	}
	if !found {
		t.Fatalf("want a tools-denied-unknown warning, got %+v", warnings)
	}
}

// D4: an explicit tools_allowed = [] beside a non-empty [[context.tools]]
// contradicts itself — "this pod uses no tools" and "this pod commits
// tools" cannot both be true — and warns distinctly from the omitted case.
func TestValidateWarnsOnEmptyToolsAllowedContradiction(t *testing.T) {
	body := []byte("pod_spec_version = \"0.1\"\n[pod]\nname = \"p\"\nversion=\"0.1.0\"\n[runtime]\nkind=\"lobster\"\n[model]\nprovider=\"o\"\nname=\"m\"\n" +
		"[[context.tools]]\nsource = \"bash\"\n[directive]\ntask=\"test\"\ntools_allowed = []\n")
	issues, warnings, err := ValidateWithWarnings(body)
	if err != nil {
		t.Fatal(err)
	}
	if len(issues) != 0 {
		t.Fatalf("this must warn, not fail: %v", issues)
	}
	var found bool
	for _, w := range warnings {
		if w.Code == "tools-allowed-empty-contradicts-declared" {
			found = true
		}
	}
	if !found {
		t.Fatalf("want a tools-allowed-empty-contradicts-declared warning, got %+v", warnings)
	}
}

// An OMITTED tools_allowed beside a non-empty [[context.tools]] is not a
// contradiction — presence (decision D4) is what tells the two apart.
func TestValidateDoesNotWarnOnOmittedToolsAllowed(t *testing.T) {
	body := []byte("pod_spec_version = \"0.1\"\n[pod]\nname = \"p\"\nversion=\"0.1.0\"\n[runtime]\nkind=\"lobster\"\n[model]\nprovider=\"o\"\nname=\"m\"\n" +
		"[[context.tools]]\nsource = \"bash\"\n[directive]\ntask=\"test\"\n")
	_, warnings, err := ValidateWithWarnings(body)
	if err != nil {
		t.Fatal(err)
	}
	for _, w := range warnings {
		if w.Code == "tools-allowed-empty-contradicts-declared" {
			t.Fatalf("an omitted tools_allowed must not be treated as an explicit empty one: %+v", w)
		}
	}
}

// D5: a non-NFC name in either directive list warns, and names WHICH field
// and WHICH name in the message.
func TestValidateWarnsOnNonNFCToolNames(t *testing.T) {
	nfd := "café"
	body := []byte("pod_spec_version = \"0.1\"\n[pod]\nname = \"p\"\nversion=\"0.1.0\"\n[runtime]\nkind=\"lobster\"\n[model]\nprovider=\"o\"\nname=\"m\"\n" +
		"[[context.tools]]\nsource = \"bash\"\n[directive]\ntask=\"test\"\ntools_allowed = [\"" + nfd + "\"]\n")
	_, warnings, err := ValidateWithWarnings(body)
	if err != nil {
		t.Fatal(err)
	}
	var found bool
	for _, w := range warnings {
		if w.Code == "tools-non-nfc" && strings.Contains(w.Message, nfd) {
			found = true
		}
	}
	if !found {
		t.Fatalf("want a tools-non-nfc warning naming %q, got %+v", nfd, warnings)
	}
}

// TestValidate_RelativePathRefusesDotDot pins the relative_path pattern
// vendored from reef-core (reef-core#58). A leading "./" alone let
// "./../x" through, so a pod could name a file outside its own
// directory. Any ".." segment is now refused; names that only contain
// dots stay valid. reef-core runs the same cases in
// test/pod/spec/parser_test.exs, so the CLI and the node agree.
func TestValidate_RelativePathRefusesDotDot(t *testing.T) {
	manifest := func(template string) []byte {
		return []byte(`
pod_spec_version = "0.1"

[pod]
name    = "x"
version = "0.1.0"

[runtime]
kind = "lobster"

[directive]
template = "` + template + `"
`)
	}

	for _, path := range []string{"./..", "./../x", "./a/../../x", "./a/..", "./a/../b"} {
		issues, err := Validate(manifest(path))
		if err != nil {
			t.Fatalf("%s: unexpected error: %v", path, err)
		}
		if len(issues) == 0 {
			t.Errorf("%s: expected a schema issue, got none", path)
		}
	}

	for _, path := range []string{"./..x", "./x..", "./.hidden", "./a/...", "./a/..b/c", "./a/.b"} {
		issues, err := Validate(manifest(path))
		if err != nil {
			t.Fatalf("%s: unexpected error: %v", path, err)
		}
		if len(issues) != 0 {
			t.Errorf("%s: expected no issues, got %v", path, issues)
		}
	}
}
