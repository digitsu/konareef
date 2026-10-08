// Copyright 2026 Jerry David Chan, Konareef.ai
// SPDX-License-Identifier: Apache-2.0

// magic_near_miss_golden_test.go — KR-MAGIC: CheckManifestCommitment over
// the real MCP-Z04 manifests (the vendored subset in
// internal/canon/testdata/mcp_z04). Before KR-MAGIC the fixture recorded
// "ok" for six of the 15 near-miss variants; every one must now be refused
// with MAGIC_NEAR_MISS, and the genuine v3 manifest must still pass.
package commission

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// TestCheckManifestCommitment_Z04Fixture replays the vendored fixture.
func TestCheckManifestCommitment_Z04Fixture(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "canon", "testdata", "mcp_z04", "near_miss_vectors.json"))
	if err != nil {
		t.Fatalf("read vendored MCP-Z04 vectors: %v", err)
	}
	var doc struct {
		Variants []struct {
			ID         string `json:"id"`
			Manifest   string `json:"manifest"`
			PS1Verdict string `json:"ps1_verdict"`
		} `json:"variants"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("decode: %v", err)
	}
	sawGenuine := false
	for _, v := range doc.Variants {
		m, err := base64.StdEncoding.DecodeString(v.Manifest)
		if err != nil {
			t.Fatalf("%s: base64: %v", v.ID, err)
		}
		err = CheckManifestCommitment(m)
		switch {
		case v.PS1Verdict == "commit_trailer_malformed":
			if !isMagicNearMiss(err) {
				t.Errorf("%s: CheckManifestCommitment = %v, want MAGIC_NEAR_MISS", v.ID, err)
			}
		case v.ID == "genuine-v3":
			sawGenuine = true
			if err != nil {
				t.Errorf("control %s: CheckManifestCommitment = %v, want nil", v.ID, err)
			}
		}
	}
	if !sawGenuine {
		t.Error("fixture has no genuine-v3 control")
	}
}
