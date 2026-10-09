// Copyright 2026 Jerry David Chan, Konareef.ai
// SPDX-License-Identifier: Apache-2.0

// Tests for the [[network.gateway]] cross-field rules: the ones a JSON
// schema cannot express because they read two tables at once.
package pod

import (
	"strings"
	"testing"
)

// gatewayDoc rewrites one line of gatewayPodTOML.
func gatewayDoc(replace, with string) []byte {
	return []byte(strings.Replace(gatewayPodTOML, replace, with, 1))
}

func issueCodes(issues []Issue) []string {
	codes := make([]string, 0, len(issues))
	for _, issue := range issues {
		codes = append(codes, issue.Code)
	}
	return codes
}

func TestValidateWithWarnings_ValidGatewayWarnsSecretLeavesEnv(t *testing.T) {
	issues, warnings, err := ValidateWithWarnings([]byte(gatewayPodTOML))
	if err != nil {
		t.Fatalf("ValidateWithWarnings: %v", err)
	}
	if len(issues) != 0 {
		t.Fatalf("issues = %v, want none", issues)
	}
	if len(warnings) != 1 || warnings[0].Code != WarnGatewaySecretLeavesEnv {
		t.Fatalf("warnings = %+v, want one %s", warnings, WarnGatewaySecretLeavesEnv)
	}
	if !strings.Contains(warnings[0].Message, "ELEVENLABS_API_KEY") ||
		!strings.Contains(warnings[0].Message, "REEF_GATEWAY_URL") {
		t.Fatalf("warning message = %q", warnings[0].Message)
	}
	if warnings[0].Path != "network.gateway[0].secret" {
		t.Fatalf("warning path = %q", warnings[0].Path)
	}
}

func TestValidateWithWarnings_GatewayCodes(t *testing.T) {
	cases := []struct {
		name    string
		replace string
		with    string
		code    string
		path    string
	}{
		{"secret not declared", `secrets = ["ELEVENLABS_API_KEY"]`, `secrets = ["OTHER"]`,
			CodeGatewaySecretUndeclared, "network.gateway[0].secret"},
		{"wildcard host", `host = "api.elevenlabs.io"`, `host = "*.elevenlabs.io"`,
			CodeGatewayHostWildcard, "network.gateway[0].host"},
		{"max_units without adapter", "max_calls = 3", "max_calls = 3\nmax_units = 5000",
			CodeGatewayNoAdapter, "network.gateway[0].max_units"},
		{"daily_max_units without adapter", "max_calls = 3", "max_calls = 3\ndaily_max_units = 9",
			CodeGatewayNoAdapter, "network.gateway[0].daily_max_units"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			issues, _, err := ValidateWithWarnings(gatewayDoc(tc.replace, tc.with))
			if err != nil {
				t.Fatalf("ValidateWithWarnings: %v", err)
			}
			if len(issues) != 1 || issues[0].Code != tc.code || issues[0].Path != tc.path {
				t.Fatalf("issues = %+v, want one %s at %s", issues, tc.code, tc.path)
			}
			if !strings.Contains(issues[0].String(), tc.code) {
				t.Fatalf("Issue.String() = %q does not carry the code", issues[0].String())
			}
		})
	}
}

func TestValidateWithWarnings_DuplicateHost(t *testing.T) {
	doc := gatewayDoc("max_calls = 3\n", "max_calls = 3\n\n[[network.gateway]]\nhost = \"api.elevenlabs.io:443\"\nsecret = \"ELEVENLABS_API_KEY\"\nauth = \"bearer\"\nmax_calls = 1\n")
	issues, _, err := ValidateWithWarnings(doc)
	if err != nil {
		t.Fatalf("ValidateWithWarnings: %v", err)
	}
	if len(issues) != 1 || issues[0].Code != CodeGatewayHostDuplicate || issues[0].Path != "network.gateway[1].host" {
		t.Fatalf("issues = %+v", issues)
	}
}

// twoGatewayDoc returns gatewayPodTOML with a second [[network.gateway]]
// entry. It sets the first entry's host to firstHost and the second's to
// secondHost. When secondMCP is true the second entry is a brokered MCP
// grant; otherwise it is a plain http entry.
func twoGatewayDoc(firstHost, secondHost string, secondMCP bool) []byte {
	doc := strings.Replace(gatewayPodTOML, `host = "api.elevenlabs.io"`, `host = "`+firstHost+`"`, 1)
	second := "\n[[network.gateway]]\nhost = \"" + secondHost + "\"\nsecret = \"ELEVENLABS_API_KEY\"\nauth = \"bearer\"\nmax_calls = 1\n"
	if secondMCP {
		second = mcpGrant(secondHost, "jira")
	}
	return []byte(strings.Replace(doc, "max_calls = 3\n", "max_calls = 3\n"+second, 1))
}

// Duplicate gateway authorities are keyed on the canonical port, so every
// spelling of one numeric port is the same authority. The wantKey column
// is the "host:port" key that reef-core's gateway_duplicate_hosts/1 builds
// for the SECOND host. It was captured from the real
// Pod.Spec.SpawnerAdapter.gateway_entries/1 at reef-core origin/main
// (String.to_integer/1 on the port, 443 when absent). konareef strips the
// brackets from an IPv6 literal and reef-core keeps them, so the IPv6 rows
// compare the bracket-free form. The duplicate/distinct result is the
// same on both sides.
func TestValidateWithWarnings_DuplicateHostCanonicalPort(t *testing.T) {
	cases := []struct {
		name          string
		first, second string
		secondMCP     bool
		wantDuplicate bool
		wantKey       string
	}{
		{"implicit vs explicit 443", "api.example.com", "api.example.com:443", false, true, "api.example.com:443"},
		{"implicit vs 0443", "api.example.com", "api.example.com:0443", false, true, "api.example.com:443"},
		{"implicit vs 00443", "api.example.com", "api.example.com:00443", false, true, "api.example.com:443"},
		{"443 vs 0443", "api.example.com:443", "api.example.com:0443", false, true, "api.example.com:443"},
		{"0443 vs 00443", "api.example.com:0443", "api.example.com:00443", false, true, "api.example.com:443"},
		{"8443 vs 08443", "api.example.com:8443", "api.example.com:08443", false, true, "api.example.com:8443"},
		{"0 vs 00000", "api.example.com:0", "api.example.com:00000", false, true, "api.example.com:0"},
		{"host case folds", "api.example.com", "API.Example.COM:0443", false, true, "api.example.com:443"},
		{"ipv6 implicit vs 0443", "[::1]", "[::1]:0443", false, true, "::1:443"},
		{"http then mcp on 0443 is a cross-protocol duplicate", "api.example.com", "api.example.com:0443", true, true, "api.example.com:443"},
		{"443 vs 8443 are distinct", "api.example.com", "api.example.com:8443", false, false, ""},
		{"0443 vs 8443 are distinct", "api.example.com:0443", "api.example.com:8443", false, false, ""},
		{"ipv6 443 vs 8443 are distinct", "[::1]", "[::1]:8443", false, false, ""},
		{"different hosts on one port are distinct", "api.example.com:0443", "other.example.com:443", false, false, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			issues, _, err := ValidateWithWarnings(twoGatewayDoc(tc.first, tc.second, tc.secondMCP))
			if err != nil {
				t.Fatalf("ValidateWithWarnings: %v", err)
			}
			var duplicates []Issue
			for _, issue := range issues {
				if issue.Code == "" {
					t.Fatalf("schema issue %+v: this vector must be schema-valid", issue)
				}
				if issue.Code == CodeGatewayHostDuplicate {
					duplicates = append(duplicates, issue)
				}
			}
			if !tc.wantDuplicate {
				if len(duplicates) != 0 {
					t.Fatalf("issues = %+v, want no %s", issues, CodeGatewayHostDuplicate)
				}
				return
			}
			if len(duplicates) != 1 || duplicates[0].Path != "network.gateway[1].host" {
				t.Fatalf("issues = %+v, want one %s at network.gateway[1].host", issues, CodeGatewayHostDuplicate)
			}
			if !strings.Contains(duplicates[0].Message, "gateway host "+tc.wantKey+" ") {
				t.Fatalf("message = %q, want canonical authority %s", duplicates[0].Message, tc.wantKey)
			}
			if !strings.Contains(duplicates[0].Message, tc.second) {
				t.Fatalf("message = %q, want the authored host %q", duplicates[0].Message, tc.second)
			}
		})
	}
}

// An already-canonical duplicate keeps its diagnostic byte for byte, so a
// UI or log that matched the old message still matches it.
func TestValidateWithWarnings_DuplicateHostCanonicalMessageUnchanged(t *testing.T) {
	issues, _, err := ValidateWithWarnings(twoGatewayDoc("api.example.com", "api.example.com:443", false))
	if err != nil {
		t.Fatalf("ValidateWithWarnings: %v", err)
	}
	want := "network.gateway[1].host: GATEWAY_HOST_DUPLICATE: gateway host api.example.com:443 is declared more than once"
	if len(issues) != 1 || issues[0].String() != want {
		t.Fatalf("issues = %+v, want exactly %q", issues, want)
	}
}

// A malformed port never reaches the duplicate rule: the schema's
// `(:[0-9]{1,5})?$` suffix refuses it first, so it cannot be normalized
// into a valid authority that collides with, or hides, a real one.
func TestValidateWithWarnings_DuplicateHostMalformedPortIsSchemaRefused(t *testing.T) {
	for _, bad := range []string{
		"api.example.com:000443", // six digits: over the schema bound
		"api.example.com:123456",
		"api.example.com:",
		"api.example.com:+443",
		"api.example.com:-443",
		"api.example.com:4_43",
		"api.example.com:0x1bb",
		"api.example.com: 443",
	} {
		t.Run(bad, func(t *testing.T) {
			issues, _, err := ValidateWithWarnings(twoGatewayDoc("api.example.com", bad, false))
			if err != nil {
				t.Fatalf("ValidateWithWarnings: %v", err)
			}
			if len(issues) == 0 || issues[0].Code != "" {
				t.Fatalf("issues = %+v, want a schema issue with an empty code", issues)
			}
			for _, issue := range issues {
				if issue.Code == CodeGatewayHostDuplicate {
					t.Fatalf("malformed port %q reached the duplicate rule: %+v", bad, issue)
				}
			}
		})
	}
}

// Validate keeps its signature and now carries the cross-field codes too,
// so `pod publish` and `pod listing publish` refuse a bad gateway table.
func TestValidate_CarriesGatewayCodes(t *testing.T) {
	issues, err := Validate(gatewayDoc(`host = "api.elevenlabs.io"`, `host = "*.elevenlabs.io"`))
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if got := issueCodes(issues); len(got) != 1 || got[0] != CodeGatewayHostWildcard {
		t.Fatalf("codes = %v", got)
	}
}

// A schema failure short-circuits the cross-field pass: the Spec is not
// trustworthy until the schema accepts the document.
func TestValidateWithWarnings_SchemaFailureSkipsGatewayRules(t *testing.T) {
	issues, warnings, err := ValidateWithWarnings(gatewayDoc("max_calls = 3", "max_calls = 0"))
	if err != nil {
		t.Fatalf("ValidateWithWarnings: %v", err)
	}
	if len(issues) == 0 || issues[0].Code != "" {
		t.Fatalf("issues = %+v, want a schema issue with an empty code", issues)
	}
	if len(warnings) != 0 {
		t.Fatalf("warnings = %+v, want none", warnings)
	}
}

func TestIssueString_WithCode(t *testing.T) {
	issue := Issue{Path: "a.b", Code: "X_Y", Message: "bad"}
	if got := issue.String(); got != "a.b: X_Y: bad" {
		t.Fatalf("String() = %q", got)
	}
	plain := Issue{Path: "a.b", Message: "bad"}
	if got := plain.String(); got != "a.b: bad" {
		t.Fatalf("String() = %q", got)
	}
}

// mcpGrant returns a [[network.gateway]] block for a brokered MCP grant.
func mcpGrant(host, name string) string {
	return "\n[[network.gateway]]\nhost = \"" + host + "\"\nsecret = \"ELEVENLABS_API_KEY\"\nauth = \"bearer\"\nmax_calls = 1\nprotocol = \"mcp\"\nmcp_name = \"" + name + "\"\nmcp_tools = [\"get_issue\"]\n"
}

func TestValidateWithWarnings_MCPGrantWarnsBrokerPending(t *testing.T) {
	issues, warnings, err := ValidateWithWarnings(gatewayDoc("max_calls = 3\n", "max_calls = 3\n"+mcpGrant("jira.example.com", "jira")))
	if err != nil {
		t.Fatalf("ValidateWithWarnings: %v", err)
	}
	if len(issues) != 0 {
		t.Fatalf("issues = %v, want none", issues)
	}
	codes := make([]string, 0, len(warnings))
	for _, warning := range warnings {
		codes = append(codes, warning.Code)
	}
	// Entry 0 (http) warns once. Entry 1 (mcp) warns that its secret
	// leaves the env, then that the broker is pending.
	want := []string{WarnGatewaySecretLeavesEnv, WarnGatewaySecretLeavesEnv, WarnGatewayMCPBrokerPending}
	if strings.Join(codes, ",") != strings.Join(want, ",") {
		t.Fatalf("warning codes = %v, want %v", codes, want)
	}
	if warnings[2].Path != "network.gateway[1].protocol" {
		t.Fatalf("warning path = %q", warnings[2].Path)
	}
	if strings.Contains(warnings[1].Message, "REEF_GATEWAY_URL") {
		t.Fatalf("mcp secret warning points the pod at the HTTP gateway: %q", warnings[1].Message)
	}
}

func TestValidateWithWarnings_MCPNameReserved(t *testing.T) {
	for _, name := range []string{"openbrain", "proofs", "budget", "plan"} {
		t.Run(name, func(t *testing.T) {
			issues, _, err := ValidateWithWarnings(gatewayDoc("max_calls = 3\n", "max_calls = 3\n"+mcpGrant("jira.example.com", name)))
			if err != nil {
				t.Fatalf("ValidateWithWarnings: %v", err)
			}
			if len(issues) != 1 || issues[0].Code != CodeGatewayMCPNameReserved || issues[0].Path != "network.gateway[1].mcp_name" {
				t.Fatalf("issues = %+v, want one %s", issues, CodeGatewayMCPNameReserved)
			}
		})
	}
}

func TestValidateWithWarnings_MCPNameDuplicate(t *testing.T) {
	doc := gatewayDoc("max_calls = 3\n", "max_calls = 3\n"+mcpGrant("a.example.com", "jira")+mcpGrant("b.example.com", "jira"))
	issues, _, err := ValidateWithWarnings(doc)
	if err != nil {
		t.Fatalf("ValidateWithWarnings: %v", err)
	}
	if len(issues) != 1 || issues[0].Code != CodeGatewayMCPNameDuplicate || issues[0].Path != "network.gateway[2].mcp_name" {
		t.Fatalf("issues = %+v, want one %s at network.gateway[2].mcp_name", issues, CodeGatewayMCPNameDuplicate)
	}
}

// mcpEgressDoc builds a pod with one mcp grant (host = grantHost) and a
// chosen [network].egress list, for the host-also-egress cross-field rule.
// egress is a TOML array literal, e.g. `["mcp.example.com"]`.
func mcpEgressDoc(egress, grantHost string) []byte {
	doc := strings.Replace(gatewayPodTOML, `egress = ["cdn.example.com"]`, "egress = "+egress, 1)
	return []byte(strings.Replace(doc, "max_calls = 3\n", "max_calls = 3\n"+mcpGrant(grantHost, "jira"), 1))
}

// mirrors the reef-core spawner_adapter_test.exs cases for
// mcp_hosts_also_in_egress/1: a grant host also reachable through
// [network].egress is refused under all three egress spellings (bare host,
// explicit default port, and a covering wildcard), an unrelated egress host
// is allowed, and the match is on the full {host, port} authority rather
// than the host alone, so a grant and an egress entry that name the same
// host on different ports are not a double declaration.
func TestValidateWithWarnings_MCPHostAlsoEgress(t *testing.T) {
	cases := []struct {
		name      string
		egress    string
		grantHost string
		wantIssue bool
	}{
		{"the bare host", `["mcp.example.com"]`, "mcp.example.com", true},
		{"the host with an explicit port", `["mcp.example.com:443"]`, "mcp.example.com", true},
		{"a wildcard covering the host", `["*.example.com"]`, "mcp.example.com", true},
		{"an unrelated egress host is allowed", `["api.unrelated.com", "*.other.example"]`, "mcp.example.com", false},
		{"same host, same explicit port, is refused", `["mcp.example.com:8443"]`, "mcp.example.com:8443", true},
		{"same host, different port, is allowed", `["mcp.example.com:8443"]`, "mcp.example.com", false},
		{"a leading-zero port canonicalizes to the same authority", `["mcp.example.com:0443"]`, "mcp.example.com", true},
		{"a leading-zero port on the GRANT side canonicalizes to the same authority", `["mcp.example.com:443"]`, "mcp.example.com:0443", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			issues, _, err := ValidateWithWarnings(mcpEgressDoc(tc.egress, tc.grantHost))
			if err != nil {
				t.Fatalf("ValidateWithWarnings: %v", err)
			}
			codes := issueCodes(issues)
			hasIssue := false
			for _, code := range codes {
				if code == CodeGatewayMCPHostAlsoEgress {
					hasIssue = true
				}
			}
			if hasIssue != tc.wantIssue {
				t.Fatalf("issues = %+v, want CodeGatewayMCPHostAlsoEgress present=%v", issues, tc.wantIssue)
			}
		})
	}
}

// Only a brokered grant claims exclusivity, so an http gateway entry and an
// [network].egress entry for one host are never refused: the pod may
// legitimately author both. But (MCP-00 D8(a)) reef-core's runtime never
// lets the pod reach a [[network.gateway]] authority through a direct
// CONNECT, http or mcp, so the egress entry can never actually be used for
// that host — `pod validate` warns about it instead of staying silent.
// gatewayPodTOML's own entry 0 is http (protocol defaults to "http"), so
// pointing egress at its host must not raise CodeGatewayMCPHostAlsoEgress,
// but must raise WarnGatewayHTTPHostAlsoEgress.
func TestValidateWithWarnings_MCPHostAlsoEgress_HTTPGatewayExempt(t *testing.T) {
	doc := gatewayDoc(`egress = ["cdn.example.com"]`, `egress = ["api.elevenlabs.io"]`)
	issues, warnings, err := ValidateWithWarnings(doc)
	if err != nil {
		t.Fatalf("ValidateWithWarnings: %v", err)
	}
	if len(issues) != 0 {
		t.Fatalf("issues = %+v, want none (an http gateway host may also be directly reachable)", issues)
	}
	var codes []string
	for _, warning := range warnings {
		codes = append(codes, warning.Code)
	}
	want := []string{WarnGatewaySecretLeavesEnv, WarnGatewayHTTPHostAlsoEgress}
	if strings.Join(codes, ",") != strings.Join(want, ",") {
		t.Fatalf("warning codes = %v, want %v", codes, want)
	}
	if warnings[1].Path != "network.gateway[0].host" {
		t.Fatalf("warning path = %q", warnings[1].Path)
	}
}

// httpEgressDoc builds a pod with one plain http gateway entry (host =
// gatewayHost) and a chosen [network].egress list, for the
// WarnGatewayHTTPHostAlsoEgress cross-field rule. egress is a TOML array
// literal, e.g. `["api.example.com"]`.
func httpEgressDoc(egress, gatewayHost string) []byte {
	doc := strings.Replace(gatewayPodTOML, `egress = ["cdn.example.com"]`, "egress = "+egress, 1)
	return []byte(strings.Replace(doc, `host = "api.elevenlabs.io"`, `host = "`+gatewayHost+`"`, 1))
}

// TestValidateWithWarnings_HTTPHostAlsoEgress mirrors
// TestValidateWithWarnings_MCPHostAlsoEgress's cases for the http entry's
// warning instead of the mcp entry's refusal: same match rule
// (hostAllowed on the canonical {host, port} authority), different
// severity.
func TestValidateWithWarnings_HTTPHostAlsoEgress(t *testing.T) {
	cases := []struct {
		name        string
		egress      string
		gatewayHost string
		wantWarning bool
	}{
		{"the bare host", `["api.example.com"]`, "api.example.com", true},
		{"the host with an explicit port", `["api.example.com:443"]`, "api.example.com", true},
		{"a wildcard covering the host", `["*.example.com"]`, "api.example.com", true},
		{"an unrelated egress host is allowed", `["api.unrelated.com", "*.other.example"]`, "api.example.com", false},
		{"same host, same explicit port, warns", `["api.example.com:8443"]`, "api.example.com:8443", true},
		{"same host, different port, is allowed", `["api.example.com:8443"]`, "api.example.com", false},
		{"a leading-zero port canonicalizes to the same authority", `["api.example.com:0443"]`, "api.example.com", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			issues, warnings, err := ValidateWithWarnings(httpEgressDoc(tc.egress, tc.gatewayHost))
			if err != nil {
				t.Fatalf("ValidateWithWarnings: %v", err)
			}
			if len(issues) != 0 {
				t.Fatalf("issues = %+v, want none: an http entry is never refused for this", issues)
			}
			hasWarning := false
			for _, warning := range warnings {
				if warning.Code == WarnGatewayHTTPHostAlsoEgress {
					hasWarning = true
				}
			}
			if hasWarning != tc.wantWarning {
				t.Fatalf("warnings = %+v, want WarnGatewayHTTPHostAlsoEgress present=%v", warnings, tc.wantWarning)
			}
		})
	}
}
