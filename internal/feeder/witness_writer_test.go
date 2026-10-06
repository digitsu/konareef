package feeder

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func validManifestParams() ManifestParams {
	return ManifestParams{
		Manifest:    []byte("#!konareef-toml/v1\n..."), // v1: commits no fields_root, so no trailer to check
		Models:      []string{"anthropic/claude-sonnet-4-5"},
		Tools:       []string{},
		CMax:        5000,
		SigManifest: validSigLane(),
		PkPub:       validPubKeyBytes(),
	}
}

func writeSeamFixture(t *testing.T, dir string, sd StepDisclosure) string {
	t.Helper()
	raw, err := json.Marshal(sd)
	if err != nil {
		t.Fatalf("marshal fixture: %v", err)
	}
	path := filepath.Join(dir, "step-disclosure.json")
	if err := os.WriteFile(path, raw, 0o644); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
	return path
}

func TestWriteWitness(t *testing.T) {
	dir := t.TempDir()
	sd := StepDisclosure{
		Index:   0,
		P:       []byte("prompt-commitment"),
		R:       []byte("response-commitment"),
		C:       1234,
		Model:   "claude-sonnet-4-5",
		ModelID: "anthropic/claude-sonnet-4-5",
	}
	seamPath := writeSeamFixture(t, dir, sd)
	outPath := filepath.Join(dir, "witness.json")
	mp := validManifestParams()

	if err := WriteWitness(seamPath, mp, outPath); err != nil {
		t.Fatalf("WriteWitness: %v", err)
	}

	raw, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatalf("read output: %v", err)
	}
	var w Witness
	if err := json.Unmarshal(raw, &w); err != nil {
		t.Fatalf("unmarshal witness.json: %v", err)
	}
	if w.ToolLog == nil {
		t.Fatal("ToolLog is nil, want empty non-nil slice")
	}
	if len(w.ToolLog) != 0 {
		t.Fatalf("ToolLog len = %d, want 0", len(w.ToolLog))
	}
	if string(w.P) != "prompt-commitment" {
		t.Fatalf("P = %q, want %q", w.P, "prompt-commitment")
	}
	if string(w.R) != "response-commitment" {
		t.Fatalf("R = %q, want %q", w.R, "response-commitment")
	}
	// The witness model is the seam's qualified model_id, never the bare
	// name (IB-03, konareef#21).
	if w.Model != "anthropic/claude-sonnet-4-5" {
		t.Fatalf("Model = %q, want %q", w.Model, "anthropic/claude-sonnet-4-5")
	}
	if w.CMax != 5000 {
		t.Fatalf("CMax = %d, want 5000", w.CMax)
	}

	pr, err := AssemblePodRecord(w)
	if err != nil {
		t.Fatalf("round-trip AssemblePodRecord: %v", err)
	}
	if string(pr.P) != "prompt-commitment" || string(pr.R) != "response-commitment" {
		t.Fatalf("PodRecord P/R not preserved: %+v", pr)
	}
	if pr.Model != "anthropic/claude-sonnet-4-5" || pr.CMax != 5000 {
		t.Fatalf("PodRecord Model/CMax not preserved: %+v", pr)
	}
}

func TestWriteWitnessRejectsBadPkPub(t *testing.T) {
	dir := t.TempDir()
	sd := StepDisclosure{Index: 0, P: []byte("p"), R: []byte("r"), C: 1, Model: "claude-sonnet-4-5", ModelID: "anthropic/claude-sonnet-4-5"}
	seamPath := writeSeamFixture(t, dir, sd)
	outPath := filepath.Join(dir, "witness.json")

	mp := validManifestParams()
	mp.PkPub = make([]byte, 32) // wrong length: must be 33

	err := WriteWitness(seamPath, mp, outPath)
	if err == nil {
		t.Fatal("expected error on wrong-length PkPub, got nil")
	}
	if _, statErr := os.Stat(outPath); statErr == nil {
		t.Fatal("witness.json should not have been written on validation failure")
	}
}
