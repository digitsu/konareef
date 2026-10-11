// Copyright 2026 Jerry David Chan, Konareef.ai
// SPDX-License-Identifier: Apache-2.0

// CLI test for GATEWAY_MCP_HOST_ALSO_EGRESS: `konareef pod validate` names
// the grant entry and every matching egress entry, the wildcard included.
package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// conflictPodTOML is the manifest of reef-core's wildcard controller test
// on MR !108: an http gateway entry at index 0, the mcp grant at index 1,
// and an egress list where index 1 (a wildcard) and index 2 (the literal
// host) both cover the grant.
const conflictPodTOML = `pod_spec_version = "0.1"

[pod]
name    = "mcp-conflict"
version = "0.1.0"

[runtime]
kind = "lobster"

[dependencies]
secrets = ["API_KEY", "JIRA_TOKEN"]

[network]
egress = ["api.unrelated.com", "*.example.com", "mcp.example.com"]

[[network.gateway]]
host      = "api.elevenlabs.io"
secret    = "API_KEY"
auth      = "bearer"
max_calls = 1

[[network.gateway]]
host      = "mcp.example.com"
secret    = "JIRA_TOKEN"
auth      = "bearer"
max_calls = 1
protocol  = "mcp"
mcp_name  = "jira"
mcp_tools = ["get_issue"]

[directive]
task = "Read one issue."
`

func TestPodValidate_MCPHostAlsoEgressNamesEachEgressEntry(t *testing.T) {
	path := filepath.Join(t.TempDir(), "pod.toml")
	if err := os.WriteFile(path, []byte(conflictPodTOML), 0o644); err != nil {
		t.Fatal(err)
	}
	out, err := exec.Command(buildCLI(t), "pod", "validate", path).CombinedOutput()
	if err == nil {
		t.Fatalf("pod validate accepted a grant host that egress also declares:\n%s", out)
	}
	text := string(out)
	for _, want := range []string{
		"2 validation issue(s)",
		`network.gateway[1].host: GATEWAY_MCP_HOST_ALSO_EGRESS: mcp grant host "mcp.example.com" (mcp.example.com:443) is also reachable through network.egress[1] "*.example.com"`,
		`network.gateway[1].host: GATEWAY_MCP_HOST_ALSO_EGRESS: mcp grant host "mcp.example.com" (mcp.example.com:443) is also reachable through network.egress[2] "mcp.example.com"`,
	} {
		if !strings.Contains(text, want) {
			t.Errorf("output does not contain %q:\n%s", want, text)
		}
	}
}
