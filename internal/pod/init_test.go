// Copyright 2026 Jerry David Chan, Konareef.ai
// SPDX-License-Identifier: Apache-2.0

// Tests for the pod scaffolder. Every successful Init must produce a tree
// where pod.toml validates against the embedded v0.1 schema; the round-trip
// is asserted explicitly so generator-template bugs surface as test
// failures rather than as broken scaffolds shipped to users.
package pod

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestInit_Success_DefaultsAndValidation(t *testing.T) {
	tempBase := t.TempDir()
	outputDir := filepath.Join(tempBase, "my-pod")

	written, err := Init(InitOptions{
		Name: "my-pod",
		Dir:  outputDir,
	})
	if err != nil {
		t.Fatalf("Init returned error: %v", err)
	}

	wantFiles := []string{
		filepath.Join(outputDir, "pod.toml"),
		filepath.Join(outputDir, "prompts", "system.md"),
		filepath.Join(outputDir, "README.md"),
	}
	if len(written) != len(wantFiles) {
		t.Fatalf("expected %d files written, got %d: %v", len(wantFiles), len(written), written)
	}
	for index, expectedPath := range wantFiles {
		if written[index] != expectedPath {
			t.Errorf("written[%d] = %q, want %q", index, written[index], expectedPath)
		}
		if _, err := os.Stat(expectedPath); err != nil {
			t.Errorf("expected file %s to exist: %v", expectedPath, err)
		}
	}

	podTOMLBytes, err := os.ReadFile(filepath.Join(outputDir, "pod.toml"))
	if err != nil {
		t.Fatalf("read generated pod.toml: %v", err)
	}
	issues, err := Validate(podTOMLBytes)
	if err != nil {
		t.Fatalf("validate generated pod.toml: %v", err)
	}
	if len(issues) > 0 {
		t.Fatalf("generated pod.toml failed schema validation:\n%s", formatIssues(issues))
	}

	contents := string(podTOMLBytes)
	for _, expectedSubstring := range []string{
		`name        = "my-pod"`,
		`kind    = "lobster"`,
		`provider = "anthropic"`,
		`name     = "claude-sonnet-4-5"`,
	} {
		if !strings.Contains(contents, expectedSubstring) {
			t.Errorf("pod.toml missing expected substring %q", expectedSubstring)
		}
	}
}

func TestInit_Success_CustomRuntimeAndModel(t *testing.T) {
	outputDir := filepath.Join(t.TempDir(), "research-bot")

	_, err := Init(InitOptions{
		Name:    "research-bot",
		Dir:     outputDir,
		Runtime: "orca",
		Model:   "moonshot/kimi-k2-instruct",
	})
	if err != nil {
		t.Fatalf("Init returned error: %v", err)
	}

	podTOMLBytes, err := os.ReadFile(filepath.Join(outputDir, "pod.toml"))
	if err != nil {
		t.Fatalf("read generated pod.toml: %v", err)
	}
	contents := string(podTOMLBytes)
	for _, expectedSubstring := range []string{
		`kind    = "orca"`,
		`provider = "moonshot"`,
		`name     = "kimi-k2-instruct"`,
	} {
		if !strings.Contains(contents, expectedSubstring) {
			t.Errorf("pod.toml missing expected substring %q", expectedSubstring)
		}
	}

	issues, err := Validate(podTOMLBytes)
	if err != nil {
		t.Fatalf("validate generated pod.toml: %v", err)
	}
	if len(issues) > 0 {
		t.Fatalf("generated pod.toml failed schema validation:\n%s", formatIssues(issues))
	}
}

func TestInit_ModelStringFallbacks(t *testing.T) {
	cases := []struct {
		name         string
		input        string
		wantProvider string
		wantModel    string
	}{
		{"empty falls back to default", "", "anthropic", "claude-sonnet-4-5"},
		{"only model name", "kimi-k2-instruct", "anthropic", "kimi-k2-instruct"},
		{"full provider/name", "moonshot/kimi-k2-instruct", "moonshot", "kimi-k2-instruct"},
		{"empty provider falls back", "/kimi-k2", "anthropic", "claude-sonnet-4-5"},
		{"empty name falls back", "moonshot/", "anthropic", "claude-sonnet-4-5"},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			provider, modelName := splitModelString(testCase.input)
			if provider != testCase.wantProvider {
				t.Errorf("provider = %q, want %q", provider, testCase.wantProvider)
			}
			if modelName != testCase.wantModel {
				t.Errorf("model = %q, want %q", modelName, testCase.wantModel)
			}
		})
	}
}

func TestInit_RejectsExistingDirectory(t *testing.T) {
	outputDir := filepath.Join(t.TempDir(), "already-exists")
	if err := os.MkdirAll(outputDir, 0o755); err != nil {
		t.Fatalf("setup mkdir: %v", err)
	}

	_, err := Init(InitOptions{Name: "already-exists", Dir: outputDir})
	if err == nil {
		t.Fatal("expected error when directory already exists, got nil")
	}
	if !strings.Contains(err.Error(), "already exists") {
		t.Errorf("expected 'already exists' in error, got: %v", err)
	}
}

func TestInit_RejectsInvalidNames(t *testing.T) {
	cases := []struct {
		name        string
		podName     string
		wantInError string
	}{
		{"empty name", "", "name is required"},
		{"capital letters", "MyPod", "must match"},
		{"starts with digit", "9pod", "must match"},
		{"starts with hyphen", "-pod", "must match"},
		{"contains slash", "my/pod", "must match"},
		{"contains space", "my pod", "must match"},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			outputDir := filepath.Join(t.TempDir(), "out")
			_, err := Init(InitOptions{Name: testCase.podName, Dir: outputDir})
			if err == nil {
				t.Fatal("expected error, got nil")
			}
			if !strings.Contains(err.Error(), testCase.wantInError) {
				t.Errorf("expected substring %q in error, got: %v", testCase.wantInError, err)
			}
			// The output directory must NOT have been created when the
			// name validation failed up front.
			if _, statErr := os.Stat(outputDir); statErr == nil {
				t.Errorf("output dir was created despite name validation failure")
			}
		})
	}
}

func TestInit_RejectsLongNames(t *testing.T) {
	longName := strings.Repeat("a", 65)
	_, err := Init(InitOptions{Name: longName, Dir: filepath.Join(t.TempDir(), "out")})
	if err == nil {
		t.Fatal("expected error for >64-char name, got nil")
	}
	if !strings.Contains(err.Error(), "64 characters") {
		t.Errorf("expected '64 characters' in error, got: %v", err)
	}
}
