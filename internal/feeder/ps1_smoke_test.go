package feeder_test

// ps1_smoke_test.go — C1 Phase-C live PS-1 smoke.
//
// Gated: runs ONLY when KONAREEF_PS1_SMOKE_URL is set (e.g.
// http://127.0.0.1:8787). It drives the real Step-1 feeder chain against a
// LIVE PS-1 prover, over the REAL installed voice-forge manifest (no
// fixtures, no placeholder signature): install cache -> WitnessWriter
// (empty tool-log) -> feeder.Run -> live PS-1 /v1/prove/spartan-compress ->
// stub reef-core ingest. It asserts a genuine Spartan proof comes back.
//
// This validates the feeder<->PS-1 wire contract end to end without needing
// reef-core. Run:
//
//	KONAREEF_PS1_SMOKE_URL=http://127.0.0.1:8787 \
//	  go test -run TestPS1SmokeVoiceForge -v -count=1 ./internal/feeder/...

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/digitsu/konareef/internal/feeder"
	"github.com/digitsu/konareef/internal/install"
	"github.com/digitsu/konareef/internal/poseidon"
)

func TestPS1SmokeVoiceForge(t *testing.T) {
	ps1URL := os.Getenv("KONAREEF_PS1_SMOKE_URL")
	if ps1URL == "" {
		t.Skip("KONAREEF_PS1_SMOKE_URL not set; skipping live PS-1 smoke")
	}

	home, err := os.UserHomeDir()
	if err != nil {
		t.Fatalf("home: %v", err)
	}

	// Real installed voice-forge manifest (bob/voice-forge@0.1.4 — declares the
	// `bash` tool the circuit requires; sig padded to the 74-byte lane by the loader).
	mp, err := install.LoadManifestParams(home, "bob", "voice-forge", "0.1.4")
	if err != nil {
		t.Fatalf("LoadManifestParams(bob/voice-forge@0.1.4): %v", err)
	}
	t.Logf("manifest: %d bytes, sig %d bytes, pk %d bytes, models=%v, tools=%v, cmax=%d",
		len(mp.Manifest), len(mp.SigManifest), len(mp.PkPub), mp.Models, mp.Tools, mp.CMax)

	if len(mp.Tools) == 0 {
		t.Fatalf("voice-forge@0.1.4 must declare >=1 tool; got none (re-publish with [[context.tools]])")
	}
	if len(mp.SigManifest) != 74 {
		t.Fatalf("expected LoadManifestParams to return a 74-byte sig lane, got %d", len(mp.SigManifest))
	}

	// Fixture step disclosure — arbitrary P/R bytes, bare model matching Models[0],
	// cost within budget, empty tool log (Step 1).
	ws := t.TempDir()
	sd := feeder.StepDisclosure{
		Index: 0,
		P:     []byte("ps1-smoke-prompt-commitment"),
		R:     []byte("ps1-smoke-result-commitment"),
		C:     100,
		Model: "claude-sonnet-4-5",
	}
	sdBytes, err := json.Marshal(sd)
	if err != nil {
		t.Fatalf("marshal step disclosure: %v", err)
	}
	seamPath := filepath.Join(ws, "step-disclosure.json")
	if err := os.WriteFile(seamPath, sdBytes, 0o644); err != nil {
		t.Fatalf("write seam: %v", err)
	}

	witnessPath := filepath.Join(ws, "witness.json")
	if err := feeder.WriteWitness(seamPath, mp, witnessPath); err != nil {
		t.Fatalf("WriteWitness: %v", err)
	}

	// Stub reef-core ingest — captures the POSTed body, returns 201.
	var captured []byte
	ingest := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		captured, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusCreated)
	}))
	defer ingest.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	start := time.Now()
	if err := feeder.Run(ctx, feeder.Opts{
		WitnessPath: witnessPath,
		PaygateURL:  ps1URL,
		IngestURL:   ingest.URL,
		IngestToken: "smoke-token",
		CircuitID:   "konareef-pod-step-v1",
	}); err != nil {
		t.Fatalf("feeder.Run against live PS-1 %s: %v", ps1URL, err)
	}
	t.Logf("live prove+ingest round-trip: %s", time.Since(start))

	// The stub ingest must have received a body carrying a real proof.
	var body struct {
		SpartanCompressResult struct {
			CircuitID    string `json:"circuit_id"`
			SpartanSnark []byte `json:"spartan_snark"`
		} `json:"spartan_compress_result"`
		WitnessDisclosure struct {
			TLogRecords []json.RawMessage `json:"T_log_records"`
		} `json:"witness_disclosure"`
		ZKStamp struct {
			DisclosurePolicy string `json:"disclosure_policy"`
			ModelID          string `json:"model_id"`
		} `json:"zk_stamp"`
	}
	if err := json.Unmarshal(captured, &body); err != nil {
		t.Fatalf("parse captured ingest body: %v\nbody=%s", err, captured)
	}
	if len(body.SpartanCompressResult.SpartanSnark) == 0 {
		t.Fatalf("live PS-1 returned an empty spartan_snark; body=%s", captured)
	}
	if len(body.WitnessDisclosure.TLogRecords) != 0 {
		t.Fatalf("expected empty T_log_records (Step 1), got %d", len(body.WitnessDisclosure.TLogRecords))
	}
	if body.ZKStamp.DisclosurePolicy != "C" {
		t.Fatalf("disclosure_policy = %q, want C", body.ZKStamp.DisclosurePolicy)
	}
	if body.ZKStamp.ModelID != "claude-sonnet-4-5" {
		t.Fatalf("model_id = %q, want claude-sonnet-4-5", body.ZKStamp.ModelID)
	}
	t.Logf("PASS: live PS-1 produced a %d-byte spartan_snark over the real voice-forge manifest (empty tool-log)",
		len(body.SpartanCompressResult.SpartanSnark))
}

// TestPS1SmokeVoiceForgeWithTools is the Step-2 byte-exactness gate: it drives
// a NON-EMPTY tool_log through the feeder to the live PS-1, then asserts that
// konareef's Poseidon t_root over the served (canonical 113-B) T_log_records
// EQUALS the t_root PS-1 committed as a public input (FirstStepPublicInputs
// offset 64). A mismatch means internal/tlog.RecordBytes is not byte-identical
// to paygate-zk's encode_record — exactly the failure this test exists to catch.
func TestPS1SmokeVoiceForgeWithTools(t *testing.T) {
	ps1URL := os.Getenv("KONAREEF_PS1_SMOKE_URL")
	if ps1URL == "" {
		t.Skip("KONAREEF_PS1_SMOKE_URL not set; skipping live PS-1 smoke")
	}

	home, err := os.UserHomeDir()
	if err != nil {
		t.Fatalf("home: %v", err)
	}
	mp, err := install.LoadManifestParams(home, "bob", "voice-forge", "0.1.4")
	if err != nil {
		t.Fatalf("LoadManifestParams(bob/voice-forge@0.1.4): %v", err)
	}

	h := func(s string) []byte { d := sha256.Sum256([]byte(s)); return d[:] }
	toolLog := []feeder.SeamToolRecord{
		{ToolID: "bash", ArgsHash: h("mkdir -p output"), ResultHash: h(""), TsUs: 1748736000000000},
		{ToolID: "bash", ArgsHash: h("curl -sS https://api.elevenlabs.io/..."), ResultHash: h("speech.mp3 written"), TsUs: 1748736001000000},
	}

	ws := t.TempDir()
	sd := feeder.StepDisclosure{
		Index:   0,
		P:       []byte("ps1-smoke-tools-prompt"),
		R:       []byte("ps1-smoke-tools-result"),
		C:       100, // Σ sats (0) ≤ c ≤ c_max (5000)
		Model:   "claude-sonnet-4-5",
		ToolLog: toolLog,
	}
	sdBytes, err := json.Marshal(sd)
	if err != nil {
		t.Fatalf("marshal step disclosure: %v", err)
	}
	seamPath := filepath.Join(ws, "step-disclosure.json")
	if err := os.WriteFile(seamPath, sdBytes, 0o644); err != nil {
		t.Fatalf("write seam: %v", err)
	}

	witnessPath := filepath.Join(ws, "witness.json")
	if err := feeder.WriteWitness(seamPath, mp, witnessPath); err != nil {
		t.Fatalf("WriteWitness: %v", err)
	}

	var captured []byte
	ingest := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		captured, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusCreated)
	}))
	defer ingest.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	start := time.Now()
	if err := feeder.Run(ctx, feeder.Opts{
		WitnessPath: witnessPath,
		PaygateURL:  ps1URL,
		IngestURL:   ingest.URL,
		IngestToken: "smoke-token",
		CircuitID:   "konareef-pod-step-v1",
	}); err != nil {
		t.Fatalf("feeder.Run (tool_log) against live PS-1 %s: %v", ps1URL, err)
	}
	t.Logf("live tool-log prove+ingest round-trip: %s", time.Since(start))

	var body struct {
		SpartanCompressResult struct {
			FirstStepPublicInputs []byte `json:"first_step_public_inputs"`
		} `json:"spartan_compress_result"`
		WitnessDisclosure struct {
			TLogRecords [][]byte `json:"T_log_records"`
		} `json:"witness_disclosure"`
	}
	if err := json.Unmarshal(captured, &body); err != nil {
		t.Fatalf("parse captured ingest body: %v\nbody=%s", err, captured)
	}

	records := body.WitnessDisclosure.TLogRecords
	if len(records) != len(toolLog) {
		t.Fatalf("served T_log_records = %d, want %d", len(records), len(toolLog))
	}
	for i, rec := range records {
		if len(rec) != 113 {
			t.Fatalf("T_log_records[%d] len = %d, want 113 (canonical record)", i, len(rec))
		}
		if rec[0] != 0x20 {
			t.Fatalf("T_log_records[%d][0] = %#x, want 0x20 (digest-shape prefix)", i, rec[0])
		}
	}

	// The verifier's t_root gate: poseidon.TRoot(served records) == the proof's
	// t_root public input (FirstStepPublicInputs offset 64, 32 bytes).
	konareefTRoot, err := poseidon.Default().TRoot(records)
	if err != nil {
		t.Fatalf("poseidon.TRoot(served records): %v", err)
	}
	pi := body.SpartanCompressResult.FirstStepPublicInputs
	if len(pi) < 96 {
		t.Fatalf("FirstStepPublicInputs len = %d, need >= 96", len(pi))
	}
	ps1TRoot := pi[64:96]
	if !bytes.Equal(konareefTRoot[:], ps1TRoot) {
		t.Fatalf("T_ROOT MISMATCH — internal/tlog.RecordBytes != paygate-zk encode_record\n konareef: %x\n PS-1:     %x", konareefTRoot[:], ps1TRoot)
	}
	t.Logf("PASS: konareef t_root == PS-1 t_root (%x) over %d canonical 113-B tool records — encode_record byte-exact",
		konareefTRoot[:], len(records))
}
