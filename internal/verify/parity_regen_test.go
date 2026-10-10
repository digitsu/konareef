// Copyright 2026 Jerry David Chan, Konareef.ai
// SPDX-License-Identifier: Apache-2.0

package verify

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/digitsu/konareef/internal/poseidon"
	"github.com/fxamacker/cbor/v2"
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
// It patches both Type-C fixtures: v1 and v1.1 (VHASH-FU,
// script-verify/paygate-zk#13). A fixture that already carries the Poseidon
// root is written back unchanged.
//
//	REGEN_PARITY=1 go test ./internal/verify/ -run TestRegenerateParityTRoot
func TestRegenerateParityTRoot(t *testing.T) {
	if os.Getenv("REGEN_PARITY") == "" {
		t.Skip("set REGEN_PARITY=1 to regenerate the parity fixture t_root")
	}
	for _, name := range []string{"parity-v2-typec.cbor", "parity-v2-typec-v1_1.cbor"} {
		t.Run(name, func(t *testing.T) {
			regenerateParityTRoot(t, filepath.Join("testdata", name))
		})
	}
}

// regenerateParityTRoot rewrites, in place, the t_root of one Type-C parity
// fixture to the Poseidon root of its T_log_records.
//
// Input: the test handle and the fixture path. Output: none; the file is
// rewritten, and the test fails if the patch is not safe.
func regenerateParityTRoot(t *testing.T, path string) {
	t.Helper()
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

// parityCustodyData is the custody blob that TestRegenerateParityCustodyLink
// writes into the Type-C parity fixture's custody link. It is a well-formed
// legacy v3 record (no TOOL_LOG_ROOT and no MCP_BROKER line), so
// ParseCustodyBlob accepts it and the bundle shows no broker claim. The
// hashes and names are synthetic; TOOLS_USED names the fixture's two tool
// calls.
const parityCustodyData = "CUSTODY_PROOF: v3\n" +
	"CUSTOMER_KEY: [REDACTED]\n" +
	"TASK_HASH: sha256:1111111111111111111111111111111111111111111111111111111111111111\n" +
	"RESULT_HASH: sha256:2222222222222222222222222222222222222222222222222222222222222222\n" +
	"STRUCTURED_BUNDLE_HASH: sha256:0000000000000000000000000000000000000000000000000000000000000000\n" +
	"OPENBRAIN_SNAPSHOT_ROOT: sha256:0000000000000000000000000000000000000000000000000000000000000000\n" +
	"OPENBRAIN_CAPTURE_ROOT: sha256:0000000000000000000000000000000000000000000000000000000000000000\n" +
	"OPENBRAIN_ACCESS_LOG_HASH: sha256:0000000000000000000000000000000000000000000000000000000000000000\n" +
	"OPENBRAIN_ACCESSED_COUNT: 0\n" +
	"ITERATIONS: 1\n" +
	"DURATION_SECS: 1\n" +
	"TOOLS_USED: read, write\n" +
	"TOTAL_SATS: 0\n" +
	"AGENT_KEY: fixture-type-c-v1"

// TestRegenerateParityCustodyLink makes the Type-C parity fixture's single
// custody link honest: it replaces the link data with parityCustodyData
// and the stored hash with SHA-256(data || timestamp), the rule reef-core
// uses for a genesis link (ReefCore.Proofs.Hash.compute/3 with a nil
// prev_hash).
//
// reef-core's BundleV2Fixture writes data `{}` and sets the hash to
// SHA-256("fixture-type-c-v1"), which is not the chain hash of that data.
// That was harmless while the v2 verifier did not recompute link hashes.
// checkTypeCLinkHashes now does (MCP-K04 residual R2). Once the hash
// recomputes, assessCustodyV2 also applies the custody rules to the data,
// and `{}` fails them (custody_version_missing). So both fields change.
//
// Guarded behind REGEN_PARITY=1 so it never mutates testdata during a
// normal `go test`. As in TestRegenerateParityTRoot, the change is made in
// place on the raw CBOR bytes. The data byte string gets a longer header
// and body, and the 32 hash bytes are overwritten. No map or array count
// changes, so no other field is re-encoded or perturbed.
//
//	REGEN_PARITY=1 go test ./internal/verify/ -run TestRegenerateParityCustodyLink
func TestRegenerateParityCustodyLink(t *testing.T) {
	if os.Getenv("REGEN_PARITY") == "" {
		t.Skip("set REGEN_PARITY=1 to regenerate the parity fixture custody link")
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
	if len(b.Chain) != 1 || b.Chain[0].ProofType != "custody" || len(b.Chain[0].PrevHash) != 0 {
		t.Fatal("fixture chain is not a single genesis custody link; this step does not apply")
	}
	link := b.Chain[0]
	newHash := ComputeChainHash("", parityCustodyData, link.Timestamp)
	if string(link.Data) == parityCustodyData && bytes.Equal(link.Hash, newHash[:]) {
		t.Log("custody link already honest; nothing to do")
		return
	}

	// Overwrite the hash first: the data splice below shifts later offsets.
	patched := append([]byte(nil), raw...)
	idx := bytes.Index(patched, link.Hash)
	if idx < 0 || bytes.Index(patched[idx+1:], link.Hash) >= 0 {
		t.Fatal("old link hash bytes not found exactly once in raw CBOR; in-place patch unsafe")
	}
	copy(patched[idx:idx+32], newHash[:])

	enc, err := cbor.CoreDetEncOptions().EncMode()
	if err != nil {
		t.Fatalf("enc mode: %v", err)
	}
	key, err := enc.Marshal("data")
	if err != nil {
		t.Fatalf("encode key: %v", err)
	}
	oldVal, err := enc.Marshal(link.Data)
	if err != nil {
		t.Fatalf("encode old data: %v", err)
	}
	newVal, err := enc.Marshal([]byte(parityCustodyData))
	if err != nil {
		t.Fatalf("encode new data: %v", err)
	}
	oldEntry := append(append([]byte(nil), key...), oldVal...)
	newEntry := append(append([]byte(nil), key...), newVal...)
	if bytes.Count(patched, oldEntry) != 1 {
		t.Fatal("old data entry not found exactly once in raw CBOR; in-place patch unsafe")
	}
	patched = bytes.Replace(patched, oldEntry, newEntry, 1)

	check, err := decodeBundleV2(patched)
	if err != nil {
		t.Fatalf("patched fixture does not decode: %v", err)
	}
	if string(check.Chain[0].Data) != parityCustodyData || !bytes.Equal(check.Chain[0].Hash, newHash[:]) {
		t.Fatal("patched fixture does not carry the new custody link")
	}
	if err := os.WriteFile(path, patched, 0o644); err != nil {
		t.Fatalf("write patched fixture: %v", err)
	}
	t.Logf("patched custody link hash %x -> %x and data (%d -> %d bytes)",
		link.Hash, newHash, len(link.Data), len(parityCustodyData))
}
