// Copyright 2026 Jerry David Chan, Konareef.ai
// SPDX-License-Identifier: Apache-2.0

// Tests for the brokered-MCP runtime and tool-name rules in mcp_broker.go.
//
// The vector tests read testdata/mcp_broker_vectors.json. reef-core's side of
// the same file is checked by scripts/check_mcp_broker_vectors.exs, so a
// vector that passes both is a case where `pod validate` and the reef-core
// spawn path agree.
package pod

import (
	"encoding/json"
	"os"
	"reflect"
	"strings"
	"testing"
)

// mcpBrokerVectors is the decoded form of testdata/mcp_broker_vectors.json.
type mcpBrokerVectors struct {
	OpencodeServerKey string   `json:"opencode_server_key"`
	BuiltinToolNames  []string `json:"builtin_tool_names"`
	OpencodeToolName  []struct {
		Name     string `json:"name"`
		Tool     string `json:"tool"`
		Rendered string `json:"rendered"`
	} `json:"opencode_tool_name"`
	NameCollisions []struct {
		Name   string `json:"name"`
		Grants []struct {
			MCPName string   `json:"mcp_name"`
			Tools   []string `json:"tools"`
		} `json:"grants"`
		Collisions []string `json:"collisions"`
	} `json:"name_collisions"`
	RuntimeKinds []struct {
		Kind            string `json:"kind"`
		BrokerSupported bool   `json:"broker_supported"`
	} `json:"runtime_kinds"`
}

// loadMCPBrokerVectors reads and decodes the shared vector file. It fails
// the test on any read or decode error.
func loadMCPBrokerVectors(t *testing.T) mcpBrokerVectors {
	t.Helper()
	data, err := os.ReadFile("testdata/mcp_broker_vectors.json")
	if err != nil {
		t.Fatalf("read vectors: %v", err)
	}
	var vectors mcpBrokerVectors
	if err := json.Unmarshal(data, &vectors); err != nil {
		t.Fatalf("decode vectors: %v", err)
	}
	return vectors
}

func TestMCPBrokerVectors_ServerKeyAndBuiltins(t *testing.T) {
	vectors := loadMCPBrokerVectors(t)
	if mcpOpencodeServerKey != vectors.OpencodeServerKey {
		t.Fatalf("server key = %q, vectors say %q", mcpOpencodeServerKey, vectors.OpencodeServerKey)
	}
	if !reflect.DeepEqual(mcpBuiltinToolNames, vectors.BuiltinToolNames) {
		t.Fatalf("built-in tools = %q, vectors say %q", mcpBuiltinToolNames, vectors.BuiltinToolNames)
	}
}

func TestMCPBrokerVectors_OpencodeToolName(t *testing.T) {
	for _, vector := range loadMCPBrokerVectors(t).OpencodeToolName {
		t.Run(vector.Name, func(t *testing.T) {
			if got := opencodeToolName(vector.Tool); got != vector.Rendered {
				t.Fatalf("opencodeToolName(%q) = %q, want %q", vector.Tool, got, vector.Rendered)
			}
		})
	}
}

func TestMCPBrokerVectors_NameCollisions(t *testing.T) {
	vectors := loadMCPBrokerVectors(t)
	for _, vector := range vectors.NameCollisions {
		t.Run(vector.Name, func(t *testing.T) {
			grants := make([]mcpGrantTools, 0, len(vector.Grants))
			for _, grant := range vector.Grants {
				grants = append(grants, mcpGrantTools{MCPName: grant.MCPName, Tools: grant.Tools})
			}
			got := mcpToolNameCollisions(grants, vectors.BuiltinToolNames)
			if len(got) == 0 && len(vector.Collisions) == 0 {
				return
			}
			if !reflect.DeepEqual(got, vector.Collisions) {
				t.Fatalf("collisions = %q, want %q", got, vector.Collisions)
			}
		})
	}
}

func TestMCPBrokerVectors_RuntimeKinds(t *testing.T) {
	vectors := loadMCPBrokerVectors(t)
	listed := map[string]bool{}
	for _, vector := range vectors.RuntimeKinds {
		listed[vector.Kind] = true
		if got := mcpBrokerRuntimeKinds[vector.Kind]; got != vector.BrokerSupported {
			t.Errorf("runtime %q supported = %v, vectors say %v", vector.Kind, got, vector.BrokerSupported)
		}
	}
	// Every kind the Go side supports must have a vector, so the reef-core
	// check sees it too.
	for kind := range mcpBrokerRuntimeKinds {
		if !listed[kind] {
			t.Errorf("runtime %q is supported here but has no vector", kind)
		}
	}
}

// mcpToolsGrant returns a [[network.gateway]] block for a brokered MCP grant
// with the given namespace and tool list. tools is a TOML array literal.
func mcpToolsGrant(host, name, tools string) string {
	return "\n[[network.gateway]]\nhost = \"" + host + "\"\nsecret = \"ELEVENLABS_API_KEY\"\nauth = \"bearer\"\nmax_calls = 1\nprotocol = \"mcp\"\nmcp_name = \"" + name + "\"\nmcp_tools = " + tools + "\n"
}

// mcpBrokerDoc builds gatewayPodTOML with the given runtime kind and extra
// gateway blocks appended after the HTTP entry.
func mcpBrokerDoc(kind string, grants ...string) []byte {
	doc := strings.Replace(gatewayPodTOML, `kind = "lobster"`, `kind = "`+kind+`"`, 1)
	return []byte(strings.Replace(doc, "max_calls = 3\n", "max_calls = 3\n"+strings.Join(grants, ""), 1))
}

// TestValidateWithWarnings_MCPToolNameCollision covers the refusal: two
// names that differ only in "." vs "_" render to one runtime name, and a
// grant that renders to a built-in name is refused even though its
// namespace is not reserved.
func TestValidateWithWarnings_MCPToolNameCollision(t *testing.T) {
	cases := []struct {
		name   string
		grants []string
		paths  []string
	}{
		{"grant against grant", []string{
			mcpToolsGrant("a.example.com", "a_b", `["c"]`),
			mcpToolsGrant("b.example.com", "a", `["b_c"]`),
		}, []string{"network.gateway[1].mcp_tools[0]", "network.gateway[2].mcp_tools[0]"}},
		{"dot against underscore in one grant", []string{
			mcpToolsGrant("a.example.com", "jira", `["get.issue", "get_issue"]`),
		}, []string{"network.gateway[1].mcp_tools[0]", "network.gateway[1].mcp_tools[1]"}},
		{"grant against built-in", []string{
			mcpToolsGrant("a.example.com", "plan_get", `["state", "other"]`),
		}, []string{"network.gateway[1].mcp_tools[0]"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			issues, _, err := ValidateWithWarnings(mcpBrokerDoc("lobster", tc.grants...))
			if err != nil {
				t.Fatalf("ValidateWithWarnings: %v", err)
			}
			var paths []string
			for _, issue := range issues {
				if issue.Code != CodeGatewayMCPToolNameCollision {
					t.Fatalf("unexpected issue %+v", issue)
				}
				paths = append(paths, issue.Path)
			}
			if !reflect.DeepEqual(paths, tc.paths) {
				t.Fatalf("collision paths = %q, want %q (issues %+v)", paths, tc.paths, issues)
			}
			if !strings.Contains(issues[0].Message, "open_brain_") {
				t.Fatalf("message does not name the runtime name: %q", issues[0].Message)
			}
		})
	}
}

// TestValidateWithWarnings_MCPBuiltinCollisionNamesTheBuiltin checks that
// the message tells the author which built-in tool they hit.
func TestValidateWithWarnings_MCPBuiltinCollisionNamesTheBuiltin(t *testing.T) {
	issues, _, err := ValidateWithWarnings(mcpBrokerDoc("orca", mcpToolsGrant("a.example.com", "openbrain_get", `["recall_trace"]`)))
	if err != nil {
		t.Fatalf("ValidateWithWarnings: %v", err)
	}
	if len(issues) != 1 || !strings.Contains(issues[0].Message, "built-in tool openbrain.get_recall_trace") {
		t.Fatalf("issues = %+v", issues)
	}
}

// TestValidateWithWarnings_MCPSimilarNamesAccepted is the control: names
// that look alike but render differently are legal on both supported
// runtimes.
func TestValidateWithWarnings_MCPSimilarNamesAccepted(t *testing.T) {
	for _, kind := range []string{"orca", "lobster"} {
		t.Run(kind, func(t *testing.T) {
			doc := mcpBrokerDoc(kind,
				mcpToolsGrant("a.example.com", "jira", `["get-issue", "get_issue", "Get_Issue"]`),
				mcpToolsGrant("b.example.com", "plan_get", `["state2"]`),
			)
			issues, warnings, err := ValidateWithWarnings(doc)
			if err != nil {
				t.Fatalf("ValidateWithWarnings: %v", err)
			}
			if len(issues) != 0 {
				t.Fatalf("issues = %+v, want none", issues)
			}
			if !strings.Contains(strings.Join(issueCodesOfWarnings(warnings), ","), WarnGatewayMCPBrokerPending) {
				t.Fatalf("warnings = %+v, want the broker-pending warning", warnings)
			}
		})
	}
}

// TestValidateWithWarnings_MCPRuntimeUnsupported covers the runtime rule:
// a brokered grant on any runtime other than orca or lobster is refused,
// including a runtime whose friendly name sounds right.
func TestValidateWithWarnings_MCPRuntimeUnsupported(t *testing.T) {
	for _, kind := range []string{"pi-agent", "kimi-cli", "custody-null", "openclaw", "opencode", "omo"} {
		t.Run(kind, func(t *testing.T) {
			issues, _, err := ValidateWithWarnings(mcpBrokerDoc(kind, mcpToolsGrant("a.example.com", "jira", `["get_issue"]`)))
			if err != nil {
				t.Fatalf("ValidateWithWarnings: %v", err)
			}
			if len(issues) != 1 || issues[0].Code != CodeGatewayMCPRuntimeUnsupported || issues[0].Path != "runtime.kind" {
				t.Fatalf("issues = %+v, want one %s at runtime.kind", issues, CodeGatewayMCPRuntimeUnsupported)
			}
			if !strings.Contains(issues[0].Message, kind) {
				t.Fatalf("message does not name the runtime: %q", issues[0].Message)
			}
		})
	}
}

// TestValidateWithWarnings_HTTPGatewayIgnoresRuntime: the runtime rule is
// about brokered MCP only. A pod with HTTP gateway entries and no mcp grant
// keeps validating on any runtime kind.
func TestValidateWithWarnings_HTTPGatewayIgnoresRuntime(t *testing.T) {
	issues, _, err := ValidateWithWarnings(mcpBrokerDoc("pi-agent"))
	if err != nil {
		t.Fatalf("ValidateWithWarnings: %v", err)
	}
	if len(issues) != 0 {
		t.Fatalf("issues = %+v, want none", issues)
	}
}

// issueCodesOfWarnings returns the Code of each warning, in order.
func issueCodesOfWarnings(warnings []Warning) []string {
	codes := make([]string, 0, len(warnings))
	for _, warning := range warnings {
		codes = append(codes, warning.Code)
	}
	return codes
}
