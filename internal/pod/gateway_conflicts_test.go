// Copyright 2026 Jerry David Chan, Konareef.ai
// SPDX-License-Identifier: Apache-2.0

// Tests for the (brokered MCP grant, [network].egress entry) pairs behind
// GATEWAY_MCP_HOST_ALSO_EGRESS. The cases come from the fixture vendored
// from reef-core (testdata/mcp_egress_conflicts/cases.json), so the local
// validator and the reef-core spawn refusal are held to the same expected
// pairs, not to two sets of hand-picked cases.
package pod

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"
)

// conflictFixture is the shape of testdata/mcp_egress_conflicts/cases.json.
type conflictFixture struct {
	Version int `json:"version"`
	Cases   []struct {
		Name    string   `json:"name"`
		Egress  []string `json:"egress"`
		Gateway []struct {
			Host     string `json:"host"`
			Protocol string `json:"protocol"`
		} `json:"gateway"`
		Expected struct {
			Hosts     []string            `json:"hosts"`
			Conflicts []MCPEgressConflict `json:"conflicts"`
		} `json:"expected"`
	} `json:"cases"`
}

// loadConflictFixture reads and decodes the vendored fixture. It fails the
// test on a read or decode error, or when the file holds no cases.
func loadConflictFixture(t *testing.T) conflictFixture {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", "mcp_egress_conflicts", "cases.json"))
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	var fixture conflictFixture
	if err := json.Unmarshal(data, &fixture); err != nil {
		t.Fatalf("decode fixture: %v", err)
	}
	if fixture.Version != 1 || len(fixture.Cases) == 0 {
		t.Fatalf("fixture version %d with %d cases; this test reads version 1", fixture.Version, len(fixture.Cases))
	}
	return fixture
}

// TestMCPEgressConflicts_SharedFixture checks, for every shared case, that
// the local validator finds exactly the pairs reef-core reports in its 422
// body, that the legacy host list derived from them matches, and that
// gatewayRules emits one GATEWAY_MCP_HOST_ALSO_EGRESS issue per pair that
// names both the grant entry and the matching egress entry.
func TestMCPEgressConflicts_SharedFixture(t *testing.T) {
	for _, tc := range loadConflictFixture(t).Cases {
		t.Run(tc.Name, func(t *testing.T) {
			spec := Spec{
				Dependencies: &Dependencies{Secrets: []string{"KEY"}},
				Network:      &Network{Egress: tc.Egress},
			}
			for index, entry := range tc.Gateway {
				spec.Network.Gateway = append(spec.Network.Gateway, Gateway{
					Host: entry.Host, Protocol: entry.Protocol, Secret: "KEY",
					Auth: "bearer", MaxCalls: 1, MCPName: fmt.Sprintf("grant%d", index),
				})
			}

			got := mcpEgressConflicts(spec)
			want := tc.Expected.Conflicts
			if len(want) == 0 {
				want = nil
			}
			if !reflect.DeepEqual(got, want) {
				t.Fatalf("conflicts:\n got  %+v\n want %+v", got, want)
			}

			hostSet := map[string]bool{}
			for _, conflict := range got {
				hostSet[conflict.Grant] = true
			}
			hosts := make([]string, 0, len(hostSet))
			for host := range hostSet {
				hosts = append(hosts, host)
			}
			sort.Strings(hosts)
			if !reflect.DeepEqual(hosts, append([]string{}, tc.Expected.Hosts...)) {
				t.Fatalf("hosts = %v, want %v", hosts, tc.Expected.Hosts)
			}

			issues, _ := gatewayRules(spec)
			var conflictIssues []Issue
			for _, issue := range issues {
				if issue.Code == CodeGatewayMCPHostAlsoEgress {
					conflictIssues = append(conflictIssues, issue)
				}
			}
			if len(conflictIssues) != len(got) {
				t.Fatalf("issues = %+v, want %d %s issues", issues, len(got), CodeGatewayMCPHostAlsoEgress)
			}
			for index, conflict := range got {
				issue := conflictIssues[index]
				if wantPath := fmt.Sprintf("network.gateway[%d].host", conflict.GrantIndex); issue.Path != wantPath {
					t.Errorf("issue %d path = %q, want %q", index, issue.Path, wantPath)
				}
				for _, part := range []string{
					fmt.Sprintf("network.egress[%d]", conflict.EgressIndex),
					fmt.Sprintf("%q", conflict.Egress),
					fmt.Sprintf("%q", conflict.Grant),
					conflict.Authority,
				} {
					if !strings.Contains(issue.Message, part) {
						t.Errorf("issue %d message %q does not contain %s", index, issue.Message, part)
					}
				}
			}
		})
	}
}

// TestMCPEgressConflicts_EscapesAuthoredStrings checks that an authored
// string reaches the issue message quoted, so a control character in a
// manifest reaches the terminal that prints `pod validate` output only as
// an escape sequence such as \t. The schema refuses such hosts, but
// gatewayRules is also called on specs that never went through it.
func TestMCPEgressConflicts_EscapesAuthoredStrings(t *testing.T) {
	// TrimSpace removes the tabs before matching, so both egress entries
	// match the grant, but the authored strings still carry them.
	spec := Spec{Network: &Network{
		Egress:  []string{"*.example.com", "mcp.example.com\t"},
		Gateway: []Gateway{{Host: "\tmcp.example.com", Protocol: "mcp", MCPName: "jira"}},
	}}
	issues, _ := gatewayRules(spec)
	found := 0
	for _, issue := range issues {
		if issue.Code != CodeGatewayMCPHostAlsoEgress {
			continue
		}
		found++
		if strings.Contains(issue.Message, "\t") {
			t.Fatalf("message carries a raw control character: %q", issue.Message)
		}
	}
	if found != 2 {
		t.Fatalf("issues = %+v, want 2 %s issues", issues, CodeGatewayMCPHostAlsoEgress)
	}
}
