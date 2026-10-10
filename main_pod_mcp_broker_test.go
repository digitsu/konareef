// Copyright 2026 Jerry David Chan, Konareef.ai
// SPDX-License-Identifier: Apache-2.0

// main_pod_mcp_broker_test.go — the brokered-MCP runtime and tool-name
// rules (internal/pod/mcp_broker.go) through the real `konareef pod
// validate` binary: exit status, stream, and stable code.
package main

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// mcpBrokerPodTOML returns a pod.toml with one brokered MCP grant. kind is
// the [runtime].kind; mcpName and tools (a TOML array literal) fill the
// grant.
func mcpBrokerPodTOML(kind, mcpName, tools string) string {
	return `pod_spec_version = "0.1"

[pod]
name    = "broker"
version = "0.1.0"

[runtime]
kind = "` + kind + `"

[dependencies]
secrets = ["JIRA_TOKEN"]

[[network.gateway]]
host = "mcp.example.com"
secret = "JIRA_TOKEN"
auth = "bearer"
max_calls = 5
protocol = "mcp"
mcp_name = "` + mcpName + `"
mcp_tools = ` + tools + `

[directive]
task = "Read the issue."
`
}

// runPodValidateCLI writes body to a pod.toml and runs `konareef pod
// validate` on it. It returns the exit code, stdout, and stderr.
func runPodValidateCLI(t *testing.T, bin, body string) (int, string, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "pod.toml")
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(bin, "pod", "validate", path)
	var stdout, stderr strings.Builder
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	err := cmd.Run()
	var exitErr *exec.ExitError
	switch {
	case err == nil:
		return 0, stdout.String(), stderr.String()
	case errors.As(err, &exitErr):
		return exitErr.ExitCode(), stdout.String(), stderr.String()
	default:
		t.Fatalf("run konareef: %v", err)
		return 0, "", ""
	}
}

func TestPodValidateCLI_MCPBrokerRules(t *testing.T) {
	bin := buildCLI(t)
	cases := []struct {
		name     string
		body     string
		exitCode int
		code     string
		issues   string
	}{
		{"supported runtime, distinct names", mcpBrokerPodTOML("lobster", "jira", `["get-issue", "get_issue"]`), 0, "", ""},
		{"orca is supported", mcpBrokerPodTOML("orca", "jira", `["get_issue"]`), 0, "", ""},
		{"dot and underscore collide", mcpBrokerPodTOML("lobster", "jira", `["get.issue", "get_issue"]`), 1, "GATEWAY_MCP_TOOL_NAME_COLLISION", "2 validation issue(s)"},
		{"built-in collision", mcpBrokerPodTOML("orca", "plan_get", `["state"]`), 1, "GATEWAY_MCP_TOOL_NAME_COLLISION", "1 validation issue(s)"},
		{"unsupported runtime", mcpBrokerPodTOML("pi-agent", "jira", `["get_issue"]`), 1, "GATEWAY_MCP_RUNTIME_UNSUPPORTED", "1 validation issue(s)"},
		{"openclaw is not supported", mcpBrokerPodTOML("openclaw", "jira", `["get_issue"]`), 1, "GATEWAY_MCP_RUNTIME_UNSUPPORTED", "1 validation issue(s)"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			exitCode, stdout, stderr := runPodValidateCLI(t, bin, tc.body)
			if exitCode != tc.exitCode {
				t.Fatalf("exit %d, want %d\nstdout: %s\nstderr: %s", exitCode, tc.exitCode, stdout, stderr)
			}
			if tc.code == "" {
				if !strings.Contains(stdout, ": valid") {
					t.Fatalf("stdout = %q, want the valid line", stdout)
				}
				// A valid grant still tells the author that a node must
				// enable the broker before it runs this pod.
				if !strings.Contains(stderr, "GATEWAY_MCP_BROKER_PENDING") {
					t.Fatalf("stderr = %q, want the broker-pending warning", stderr)
				}
				return
			}
			if !strings.Contains(stderr, tc.issues) || !strings.Contains(stderr, tc.code) {
				t.Fatalf("stderr = %q, want %s with %s", stderr, tc.issues, tc.code)
			}
		})
	}
}

// TestPodValidateCLI_ReservedSecret checks that `konareef pod validate`
// warns about a reserved [dependencies].secrets name with the
// secret_reserved code but still passes, because a self-host reef-core can
// supply the name; and that the same pod with a plain name gets no warning.
func TestPodValidateCLI_ReservedSecret(t *testing.T) {
	bin := buildCLI(t)
	pod := func(secret string) string {
		return `pod_spec_version = "0.1"

[pod]
name    = "voice"
version = "0.1.0"

[runtime]
kind = "lobster"

[dependencies]
secrets = ["` + secret + `"]

[directive]
task = "Speak."
`
	}
	exitCode, stdout, stderr := runPodValidateCLI(t, bin, pod("OPENCODE_DISABLE_MODELS_FETCH"))
	if exitCode != 0 || !strings.Contains(stdout, ": valid") ||
		!strings.Contains(stderr, "dependencies.secrets[0]: secret_reserved") {
		t.Fatalf("reserved: exit %d\nstdout: %s\nstderr: %s", exitCode, stdout, stderr)
	}
	exitCode, stdout, stderr = runPodValidateCLI(t, bin, pod("ELEVENLABS_API_KEY"))
	if exitCode != 0 || strings.Contains(stderr, "secret_reserved") {
		t.Fatalf("control: exit %d\nstdout: %s\nstderr: %s", exitCode, stdout, stderr)
	}
}
