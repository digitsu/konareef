// Copyright 2026 Jerry David Chan, Konareef.ai
// SPDX-License-Identifier: Apache-2.0

// feeder_witness_writer_test.go — unit test for the `konareef feeder`
// --step-disclosure entrypoint helper (C1 Phase-C, spec §3), exercised
// without spawning the CLI as a subprocess.
package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/digitsu/konareef/internal/feeder"
)

const feederFixtureManifestCanon = `pod_spec_version = "0.1"

[pod]
name = "voice-forge"
version = "0.1.3"

[runtime]
kind = "lobster"

[model]
provider = "anthropic"
name = "claude-sonnet-4-5"

[budget]
max_sats = 5000
`

// writeFeederInstallFixture writes a fixture install cache directory
// (<home>/.konareef/installed/<handle>/<pod>/<version>/) matching what
// `konareef install` produces: manifest.canon, signature.bin, meta.json.
func writeFeederInstallFixture(t *testing.T, home, handle, podName, version string) {
	t.Helper()
	dir := filepath.Join(home, ".konareef", "installed", handle, podName, version)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("mkdir fixture install dir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "manifest.canon"), []byte(feederFixtureManifestCanon), 0o644); err != nil {
		t.Fatalf("write manifest.canon: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "signature.bin"), make([]byte, 72), 0o644); err != nil {
		t.Fatalf("write signature.bin: %v", err)
	}
	// A genuinely on-curve compressed secp256k1 pubkey — WriteWitness →
	// AssemblePodRecord now parses pk_pub, so an all-zero / bad-prefix blob
	// would be rejected at the seam.
	const validPubKeyHex = "0214ead9ee11d32623a312b230bb691c9437a469184fc2b121de4b1043350f4f8b"
	// pod_hash is SHA-256(manifest.canon); LoadManifestParams checks it.
	podHash := sha256.Sum256([]byte(feederFixtureManifestCanon))
	meta := `{"pod_hash":"` + hex.EncodeToString(podHash[:]) + `","publisher_pubkey_hex":"` + validPubKeyHex + `"}`
	if err := os.WriteFile(filepath.Join(dir, "meta.json"), []byte(meta), 0o644); err != nil {
		t.Fatalf("write meta.json: %v", err)
	}
}

func TestRunFeederWitnessWriter(t *testing.T) {
	home := t.TempDir()
	writeFeederInstallFixture(t, home, "acme", "voice-forge", "0.1.3")

	workspace := t.TempDir()
	sd := feeder.StepDisclosure{
		Index:   0,
		P:       []byte("prompt-commitment"),
		R:       []byte("response-commitment"),
		C:       1234,
		Model:   "claude-sonnet-4-5",
		ModelID: "anthropic/claude-sonnet-4-5",
	}
	sdBytes, err := json.Marshal(sd)
	if err != nil {
		t.Fatalf("marshal step-disclosure fixture: %v", err)
	}
	stepDisclosurePath := filepath.Join(workspace, "step-disclosure.json")
	if err := os.WriteFile(stepDisclosurePath, sdBytes, 0o644); err != nil {
		t.Fatalf("write step-disclosure fixture: %v", err)
	}
	witnessPath := filepath.Join(workspace, "witness.json")

	if err := runFeederWitnessWriter(home, "acme/voice-forge@0.1.3", stepDisclosurePath, witnessPath, leafTableSource{}); err != nil {
		t.Fatalf("runFeederWitnessWriter: %v", err)
	}

	raw, err := os.ReadFile(witnessPath)
	if err != nil {
		t.Fatalf("read witness.json: %v", err)
	}
	var w feeder.Witness
	if err := json.Unmarshal(raw, &w); err != nil {
		t.Fatalf("unmarshal witness.json: %v", err)
	}
	if string(w.P) != "prompt-commitment" || string(w.R) != "response-commitment" {
		t.Fatalf("P/R not carried from step-disclosure: %+v", w)
	}
	// w.Model is the step-disclosure's qualified model_id (reef-core#50),
	// not the bare model. Models is the MANIFEST's declared set, so it
	// carries the committed "<provider>/<name>" identifier (spec §4.1,
	// R-V2.5) — the same form internal/publish.DeriveCommitParams folds into
	// fields_root. The feeder requires the first to be a member of the
	// second (IB-03, konareef#21).
	if w.Model != "anthropic/claude-sonnet-4-5" {
		t.Fatalf("Model = %q, want anthropic/claude-sonnet-4-5", w.Model)
	}
	if len(w.Models) != 1 || w.Models[0] != "anthropic/claude-sonnet-4-5" {
		t.Fatalf("Models = %v, want [anthropic/claude-sonnet-4-5] from manifest", w.Models)
	}
	if w.CMax != 5000 {
		t.Fatalf("CMax = %d, want 5000 from manifest budget", w.CMax)
	}
	if w.ToolLog == nil || len(w.ToolLog) != 0 {
		t.Fatalf("ToolLog = %v, want empty non-nil slice (Step 1)", w.ToolLog)
	}

	// Round-trip through AssemblePodRecord, the same check feeder.Run
	// performs, to confirm the produced witness.json is well-formed.
	pr, err := feeder.AssemblePodRecord(w)
	if err != nil {
		t.Fatalf("round-trip AssemblePodRecord: %v", err)
	}
	if pr.Model != "anthropic/claude-sonnet-4-5" || pr.CMax != 5000 {
		t.Fatalf("PodRecord Model/CMax not preserved: %+v", pr)
	}
}

func TestRunFeederWitnessWriterRequiresVersion(t *testing.T) {
	home := t.TempDir()
	workspace := t.TempDir()
	witnessPath := filepath.Join(workspace, "witness.json")

	err := runFeederWitnessWriter(home, "acme/voice-forge", filepath.Join(workspace, "step-disclosure.json"), witnessPath, leafTableSource{})
	if err == nil {
		t.Fatal("expected error for --pod spec missing @version, got nil")
	}
	if _, statErr := os.Stat(witnessPath); statErr == nil {
		t.Fatal("witness.json should not have been written")
	}
}
