// Copyright 2026 Jerry David Chan, Konareef.ai
// SPDX-License-Identifier: Apache-2.0

// Tests for the optional [runtime].execution_class field. Coverage targets:
//   - A declared "local-mount" value parses into the typed field and validates
//   - An unknown value is rejected by the schema enum
//   - Omitting the field keeps the manifest valid (additive/optional) and
//     leaves the typed field empty, which callers treat as "cloud"

package pod

import "testing"

// A manifest declaring runtime.execution_class = "local-mount" must parse
// into the typed field and pass schema validation.
func TestExecutionClassParsesAndValidates(t *testing.T) {
	const src = `
pod_spec_version = "0.1"
[pod]
name = "mounty"
version = "0.1.0"
[runtime]
kind = "lobster"
execution_class = "local-mount"
[directive]
task = "Mount the drive."
`
	spec, issues, err := ParseAndValidate([]byte(src))
	if err != nil {
		t.Fatalf("ParseAndValidate error: %v", err)
	}
	if len(issues) != 0 {
		t.Fatalf("unexpected schema issues: %v", issues)
	}
	if spec.Runtime.ExecutionClass != "local-mount" {
		t.Errorf("ExecutionClass = %q, want \"local-mount\"", spec.Runtime.ExecutionClass)
	}
}

// An unknown execution_class value must be rejected by the schema.
func TestExecutionClassRejectsUnknownValue(t *testing.T) {
	const src = `
pod_spec_version = "0.1"
[pod]
name = "mounty"
version = "0.1.0"
[runtime]
kind = "lobster"
execution_class = "gpu-cluster"
[directive]
task = "Mount the drive."
`
	_, issues, err := ParseAndValidate([]byte(src))
	if err != nil {
		t.Fatalf("ParseAndValidate error: %v", err)
	}
	if len(issues) == 0 {
		t.Error("expected a schema issue for unknown execution_class, got none")
	}
}

// A manifest omitting execution_class stays valid (additive/optional) and
// leaves the field empty (callers treat empty as "cloud").
func TestExecutionClassOptional(t *testing.T) {
	const src = `
pod_spec_version = "0.1"
[pod]
name = "cloudy"
version = "0.1.0"
[runtime]
kind = "lobster"
[directive]
task = "Stay in the cloud."
`
	spec, issues, err := ParseAndValidate([]byte(src))
	if err != nil {
		t.Fatalf("ParseAndValidate error: %v", err)
	}
	if len(issues) != 0 {
		t.Fatalf("unexpected schema issues: %v", issues)
	}
	if spec.Runtime.ExecutionClass != "" {
		t.Errorf("ExecutionClass = %q, want empty", spec.Runtime.ExecutionClass)
	}
}
