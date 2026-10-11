// Copyright 2026 Jerry David Chan, Konareef.ai
// SPDX-License-Identifier: Apache-2.0

// mcp_broker_publish_test.go — the brokered-MCP runtime and tool-name rules
// (internal/pod/mcp_broker.go) through Prepare, the entry point both
// `pod publish` (konareef-toml/v1) and `pod publish --zk` share. A --zk
// publish of a pod with a grant emits konareef-toml/v3
// (v3_publish_test.go).
package publish

import (
	"fmt"
	"strings"
	"testing"
)

// mcpBrokerPublishTOML is validMemoryFreePodTOML with one brokered MCP
// grant. kind is the [runtime].kind and tools a TOML array literal.
func mcpBrokerPublishTOML(kind, tools string) string {
	body := strings.Replace(validMemoryFreePodTOML, `kind = "lobster"`, `kind = "`+kind+`"`, 1)
	return strings.Replace(body, "[directive]", `[dependencies]
secrets = ["JIRA_TOKEN"]

[[network.gateway]]
host = "mcp.example.com"
secret = "JIRA_TOKEN"
auth = "bearer"
max_calls = 5
protocol = "mcp"
mcp_name = "jira"
mcp_tools = `+tools+`

[directive]`, 1)
}

// TestPrepareAppliesMCPBrokerRulesToBothManifestVersions: a v1 publish and
// a --zk (v2) publish both run pod validation first, so both refuse a
// brokered grant on an unsupported runtime or with colliding tool names,
// and both accept the valid control.
func TestPrepareAppliesMCPBrokerRulesToBothManifestVersions(t *testing.T) {
	cases := []struct {
		name   string
		body   string
		refuse bool
	}{
		{"valid grant", mcpBrokerPublishTOML("lobster", `["get_issue", "get-issue"]`), false},
		{"colliding names", mcpBrokerPublishTOML("lobster", `["get.issue", "get_issue"]`), true},
		{"unsupported runtime", mcpBrokerPublishTOML("kimi-cli", `["get_issue"]`), true},
	}
	for _, tc := range cases {
		for _, zk := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/zk=%v", tc.name, zk), func(t *testing.T) {
				_, err := Prepare(writePodFixture(t, tc.body), testIdentity(t), PrepareOptions{ZK: zk})
				switch {
				case tc.refuse && (err == nil || !strings.Contains(err.Error(), "validation issue")):
					t.Fatalf("err = %v, want a validation refusal", err)
				case !tc.refuse && err != nil:
					t.Fatalf("err = %v, want success", err)
				}
			})
		}
	}
}
