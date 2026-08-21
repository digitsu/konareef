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
