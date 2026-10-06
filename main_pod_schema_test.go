// Copyright 2026 Jerry David Chan, Konareef.ai
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// buildCLI compiles the binary once for this test file and returns its path.
func buildCLI(t *testing.T) string {
	t.Helper()
	bin := filepath.Join(t.TempDir(), "konareef")
	cmd := exec.Command("go", "build", "-o", bin, ".")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("build konareef: %v\n%s", err, out)
	}
	return bin
}

func TestPodSchema_PrintsParseableSchemaAndExitsZero(t *testing.T) {
	out, err := exec.Command(buildCLI(t), "pod", "schema").Output()
	if err != nil {
		t.Fatalf("konareef pod schema failed: %v", err)
	}
	var doc map[string]any
	if err := json.Unmarshal(out, &doc); err != nil {
		t.Fatalf("stdout is not valid JSON: %v", err)
	}
	if doc["$id"] != "https://konareef.ai/schemas/pod-toml/v0.1.json" {
		t.Fatalf("$id = %v, want the v0.1 schema id", doc["$id"])
	}
}

func TestPodSchema_MatchesTheFileTheValidatorUses(t *testing.T) {
	out, err := exec.Command(buildCLI(t), "pod", "schema").Output()
	if err != nil {
		t.Fatalf("konareef pod schema failed: %v", err)
	}
	want, err := os.ReadFile(filepath.Join("internal", "pod", "spec_v0_1.schema.json"))
	if err != nil {
		t.Fatalf("read canonical schema: %v", err)
	}
	var gotDoc, wantDoc any
	if err := json.Unmarshal(out, &gotDoc); err != nil {
		t.Fatalf("stdout is not valid JSON: %v", err)
	}
	if err := json.Unmarshal(want, &wantDoc); err != nil {
		t.Fatalf("canonical schema is not valid JSON: %v", err)
	}
	gotNorm, _ := json.Marshal(gotDoc)
	wantNorm, _ := json.Marshal(wantDoc)
	if string(gotNorm) != string(wantNorm) {
		t.Fatal("konareef pod schema does not match internal/pod/spec_v0_1.schema.json")
	}
}

func TestPodSchema_RejectsExtraArguments(t *testing.T) {
	err := exec.Command(buildCLI(t), "pod", "schema", "unexpected").Run()
	if err == nil {
		t.Fatal("konareef pod schema accepted an extra argument; it takes none")
	}
	exitErr, ok := err.(*exec.ExitError)
	if !ok {
		t.Fatalf("konareef pod schema unexpected: got %T (%v), want *exec.ExitError", err, err)
	}
	if got := exitErr.ExitCode(); got != 2 {
		t.Fatalf("konareef pod schema unexpected: exit code = %d, want 2 (usage error)", got)
	}
}
