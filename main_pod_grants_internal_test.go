// Copyright 2026 Jerry David Chan, Konareef.ai
// SPDX-License-Identifier: Apache-2.0

// main_pod_grants_internal_test.go — in-package tests for the sealed
// grants CLI helpers (MCP-C01).
package main

import (
	"os"
	"path/filepath"
	"testing"
)

// TestSealedGrantsInspectLine checks the only statement the CLI makes
// about a closed pod's grants from its head.
func TestSealedGrantsInspectLine(t *testing.T) {
	sealed, _ := os.ReadFile(filepath.Join("internal/pod/testdata/sealed_grants/v1", "heads/closed-sealed.toml"))
	legacy, _ := os.ReadFile(filepath.Join("internal/pod/testdata/sealed_grants/v1", "heads/closed-no-marker.toml"))
	if got := sealedGrantsInspectLine(sealed); got != "  sealed grants: present" {
		t.Fatalf("marker head line %q", got)
	}
	if got := sealedGrantsInspectLine(legacy); got != "" {
		t.Fatalf("legacy head line %q", got)
	}
}
