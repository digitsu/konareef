// Copyright 2026 Jerry David Chan, Konareef.ai
// SPDX-License-Identifier: Apache-2.0

// Tests for the optional [pod].visibility field. Coverage targets:
//   - A declared "closed" value parses into the typed field and validates
//   - An explicit "open" value is equally accepted
//   - An unknown value is rejected by the schema enum
//   - Omitting the field keeps the manifest valid (additive/optional) and
//     leaves the typed field empty, which callers treat as "open"

package pod

import "testing"

// A manifest declaring pod.visibility = "closed" must parse into the typed
// field and pass schema validation.
func TestVisibilityClosedParsesAndValidates(t *testing.T) {
	const src = `
pod_spec_version = "0.1"
[pod]
name = "secretive"
version = "0.1.0"
visibility = "closed"
[runtime]
kind = "lobster"
[directive]
task = "Keep the body private."
`
	spec, issues, err := ParseAndValidate([]byte(src))
	if err != nil {
		t.Fatalf("ParseAndValidate error: %v", err)
	}
	if len(issues) != 0 {
		t.Fatalf("closed visibility must validate, got issues: %v", issues)
	}
	if spec.Pod.Visibility != "closed" {
		t.Errorf("Visibility = %q, want \"closed\"", spec.Pod.Visibility)
	}
}

// An explicitly declared "open" value must also validate and round-trip.
func TestVisibilityOpenParsesAndValidates(t *testing.T) {
	const src = `
pod_spec_version = "0.1"
[pod]
name = "sharing"
version = "0.1.0"
visibility = "open"
[runtime]
kind = "lobster"
[directive]
task = "Publish the body in the clear."
`
	spec, issues, err := ParseAndValidate([]byte(src))
	if err != nil {
		t.Fatalf("ParseAndValidate error: %v", err)
	}
	if len(issues) != 0 {
		t.Fatalf("open visibility must validate, got issues: %v", issues)
	}
	if spec.Pod.Visibility != "open" {
		t.Errorf("Visibility = %q, want \"open\"", spec.Pod.Visibility)
	}
}

// visibility must be constrained to the open|closed enum.
func TestVisibilityRejectsUnknownValue(t *testing.T) {
	const src = `
pod_spec_version = "0.1"
[pod]
name = "sneaky"
version = "0.1.0"
visibility = "secret"
[runtime]
kind = "lobster"
[directive]
task = "Try an undeclared visibility."
`
	_, issues, err := ParseAndValidate([]byte(src))
	if err != nil {
		t.Fatalf("ParseAndValidate error: %v", err)
	}
	if len(issues) == 0 {
		t.Fatal("visibility must be constrained to open|closed, got no schema issue")
	}
	// Assert the enum is what rejected it. Before visibility was a
	// declared property the root's additionalProperties:false rejected
	// any value, so a bare "some issue exists" assertion would pass even
	// if the enum were dropped from the schema.
	found := false
	for _, issue := range issues {
		if issue.Path == "pod.visibility" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected an issue at pod.visibility from the enum, got: %v", issues)
	}
}

// A manifest omitting visibility stays valid (additive/optional) and leaves
// the field empty; callers treat empty as "open".
func TestVisibilityOptional(t *testing.T) {
	const src = `
pod_spec_version = "0.1"
[pod]
name = "ordinary"
version = "0.1.0"
[runtime]
kind = "lobster"
[directive]
task = "Behave exactly as before."
`
	spec, issues, err := ParseAndValidate([]byte(src))
	if err != nil {
		t.Fatalf("ParseAndValidate error: %v", err)
	}
	if len(issues) != 0 {
		t.Fatalf("unexpected schema issues: %v", issues)
	}
	if spec.Pod.Visibility != "" {
		t.Errorf("Visibility = %q, want empty", spec.Pod.Visibility)
	}
}
