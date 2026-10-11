// Copyright 2026 Jerry David Chan, Konareef.ai
// SPDX-License-Identifier: Apache-2.0

// magicline_golden_test.go — KR-MAGIC parity with paygate-zk PS-1 on the
// MCP-Z04 fixture. testdata/mcp_z04/near_miss_vectors.json is a vendored
// subset of paygate-zk's mcp_z04_broker_v3.json (its source block names
// the commit and the sha256 of the original). Each variant carries the PS-1
// verdict on its magic line; CheckMagicLine must agree on every one, so the
// two implementations cannot drift apart without this test failing.

package canon

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// z04NearMissVector is one manifest variant of the vendored fixture.
type z04NearMissVector struct {
	ID         string `json:"id"`
	Manifest   string `json:"manifest"`    // base64 manifest bytes
	PS1Verdict string `json:"ps1_verdict"` // commit_trailer_malformed | magic_ok
}

// loadZ04NearMissVectors reads the vendored fixture.
//
// Input: t. Output: the variants; the test fails if the file is missing
// or malformed.
func loadZ04NearMissVectors(t *testing.T) []z04NearMissVector {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", "mcp_z04", "near_miss_vectors.json"))
	if err != nil {
		t.Fatalf("read vendored MCP-Z04 vectors: %v", err)
	}
	var doc struct {
		Schema   string              `json:"schema"`
		Variants []z04NearMissVector `json:"variants"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("decode vendored MCP-Z04 vectors: %v", err)
	}
	if doc.Schema != "konareef/kr-magic-near-miss-vectors/v1" {
		t.Fatalf("unexpected schema %q", doc.Schema)
	}
	return doc.Variants
}

// TestCheckMagicLine_MatchesPS1OnZ04Fixture pins parity: MAGIC_NEAR_MISS
// exactly where PS-1 answers commit_trailer_malformed, and nil where PS-1
// accepts the magic line. It also requires all 15 near-miss variants.
func TestCheckMagicLine_MatchesPS1OnZ04Fixture(t *testing.T) {
	vectors := loadZ04NearMissVectors(t)
	refused := 0
	for _, v := range vectors {
		manifest, err := base64.StdEncoding.DecodeString(v.Manifest)
		if err != nil {
			t.Fatalf("%s: base64: %v", v.ID, err)
		}
		got := CheckMagicLine(manifest)
		switch v.PS1Verdict {
		case "commit_trailer_malformed":
			refused++
			var ce *Error
			if !errors.As(got, &ce) || ce.Code != ErrMagicNearMiss {
				t.Errorf("%s: CheckMagicLine = %v, want %s (PS-1 refuses it)", v.ID, got, ErrMagicNearMiss)
			}
		case "magic_ok":
			if got != nil {
				t.Errorf("%s: CheckMagicLine = %v, want nil (PS-1 accepts the magic line)", v.ID, got)
			}
		default:
			t.Fatalf("%s: unknown ps1_verdict %q", v.ID, v.PS1Verdict)
		}
	}
	if refused != 15 {
		t.Errorf("fixture has %d near-miss variants, want the 15 MCP-Z04 variants", refused)
	}
}
