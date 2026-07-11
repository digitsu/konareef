// Copyright 2026 Jerry David Chan, Konareef.ai
// SPDX-License-Identifier: Apache-2.0

package verify

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/digitsu/konareef/internal/poseidon"
)

// TestRegenerateParityTRoot rewrites the Poseidon t_root carried in the
// Type-C parity fixture's Spartan public-input vector (offset 64..96) to
// match poseidon.TRoot of its (unchanged) T_log_records. It is the
// reproducible regeneration step for the t_root SHA-256 -> Poseidon
// migration: a real post-Lever-1 prover commits a Poseidon t_root, so the
// fixture's carried value must be the Poseidon root of its records.
//
// Guarded behind REGEN_PARITY=1 so it never mutates testdata during a
// normal `go test`. The replacement is in-place on the raw CBOR bytes (only
// the 32 t_root bytes change), so no other field is re-encoded or perturbed.
//
//	REGEN_PARITY=1 go test ./internal/verify/ -run TestRegenerateParityTRoot
func TestRegenerateParityTRoot(t *testing.T) {
	if os.Getenv("REGEN_PARITY") == "" {
		t.Skip("set REGEN_PARITY=1 to regenerate the parity fixture t_root")
	}
	path := filepath.Join("testdata", "parity-v2-typec.cbor")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	b, err := decodeBundleV2(raw)
	if err != nil {
		t.Fatalf("decode fixture: %v", err)
	}
	if b.WitnessDisclosure == nil {
		t.Fatal("fixture has no witness disclosure (not Type-C?)")
	}
	pib := b.SpartanCompressResult.FirstStepPublicInputs
	if len(pib) < 96 {
		t.Fatalf("public-input vector too short: %d", len(pib))
	}
	oldRoot := append([]byte(nil), pib[64:96]...)

	newRoot, err := poseidon.Default().TRoot(b.WitnessDisclosure.TLogRecords)
	if err != nil {
		t.Fatalf("compute Poseidon t_root: %v", err)
	}

	idx := bytes.Index(raw, oldRoot)
	if idx < 0 {
		t.Fatal("old t_root bytes not found in raw CBOR")
	}
	if bytes.Index(raw[idx+1:], oldRoot) >= 0 {
		t.Fatal("old t_root bytes not unique in raw CBOR; in-place patch unsafe")
	}
	patched := append([]byte(nil), raw...)
	copy(patched[idx:idx+32], newRoot[:])
	if err := os.WriteFile(path, patched, 0o644); err != nil {
		t.Fatalf("write patched fixture: %v", err)
	}
	t.Logf("patched t_root %x -> %x at raw offset %d", oldRoot, newRoot, idx)
}
