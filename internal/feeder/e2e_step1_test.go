// Package feeder_test — C1 Phase-C Step-1 end-to-end plumbing test.
//
// This is an external (black-box) test package rather than `package feeder`
// because it exercises internal/install.LoadManifestParams, the real
// install-cache loader, and internal/install imports internal/feeder (for
// feeder.ManifestParams). A `package feeder` test file importing
// internal/install would create an import cycle; `package feeder_test` can
// safely import both sides.
//
// The chain under test:
//
//	step-disclosure.json (fixture) + installed-pod manifest (fixture cache)
//	  -> install.LoadManifestParams -> feeder.WriteWitness -> witness.json
//	  -> feeder.Run -> mock PS-1 -> stub reef-core ingest
//
// No live PS-1 or reef-core is involved; both are httptest stubs modeled on
// the existing patterns in spartan_test.go (okSpartanResponse) and
// ingest_test.go (capture-body-and-201).
package feeder_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/digitsu/konareef/internal/feeder"
	"github.com/digitsu/konareef/internal/install"
)

// e2eStep1ManifestCanon is a voice-forge-shaped pod.toml: a valid manifest
// with a model, a budget, and no declared tools (Step 1 has an empty tool
// log by construction, so an empty tools list matches the scenario).
const e2eStep1ManifestCanon = `pod_spec_version = "0.1"

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

// writeE2EInstallFixture writes a fixture install cache directory
// (<home>/.konareef/installed/<handle>/<pod>/<version>/) with the three
// files install.LoadManifestParams reads: manifest.canon, signature.bin,
// meta.json. Modeled on internal/install's own writeInstallFixture helper
// (manifest_params_test.go), reimplemented here since that helper is
// unexported and this is a different package.
func writeE2EInstallFixture(t *testing.T, home, handle, podName, version string) {
	t.Helper()
	dir := filepath.Join(home, ".konareef", "installed", handle, podName, version)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("mkdir fixture dir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "manifest.canon"), []byte(e2eStep1ManifestCanon), 0o644); err != nil {
		t.Fatalf("write manifest.canon: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "signature.bin"), make([]byte, 72), 0o644); err != nil {
		t.Fatalf("write signature.bin: %v", err)
	}
	// A genuinely on-curve compressed secp256k1 pubkey — the feeder's
	// AssemblePodRecord now parses pk_pub (secp256k1.ParsePubKey), so an
	// all-zero / bad-prefix 33-byte blob would be rejected at the seam.
	const validPubKeyHex = "0214ead9ee11d32623a312b230bb691c9437a469184fc2b121de4b1043350f4f8b"
	// pod_hash is SHA-256(manifest.canon); LoadManifestParams checks it.
	podHash := sha256.Sum256([]byte(e2eStep1ManifestCanon))
	meta := `{"pod_hash":"` + hex.EncodeToString(podHash[:]) + `","publisher_pubkey_hex":"` + validPubKeyHex + `"}`
	if err := os.WriteFile(filepath.Join(dir, "meta.json"), []byte(meta), 0o644); err != nil {
		t.Fatalf("write meta.json: %v", err)
	}
}

// e2eOKSpartanResponse writes a well-formed SpartanCompressResult, modeled
// on spartan_test.go's okSpartanResponse (unexported, hence reimplemented
// here for this external test package).
func e2eOKSpartanResponse(w http.ResponseWriter) {
	b64 := base64.StdEncoding.EncodeToString
	_ = json.NewEncoder(w).Encode(map[string]string{
		"spartan_snark": b64([]byte("snark")), "first_step_public_inputs": b64(make([]byte, 298)),
		"last_step_public_inputs": b64(make([]byte, 298)), "vkey_hash": b64(make([]byte, 32)),
		"genesis_fields_root": b64(make([]byte, 32)),
		"z0":                  b64(make([]byte, 736)), "vkey": b64(make([]byte, 32)),
		"circuit_id": "konareef-pod-step-v1",
	})
}

// TestStep1EndToEndNoLivePS1 exercises the full C1 Phase-C Step-1 plumbing
// with no live PS-1: fixture step-disclosure.json + fixture installed-pod
// manifest (loaded via the real install.LoadManifestParams) feed
// feeder.WriteWitness to produce witness.json, which feeder.Run then carries
// through a mock PS-1 and a stub reef-core ingest. It asserts the exact
// shape of the empty-tool-log ingest body (spec §6 Step 1: ToolLog is always
// empty).
func TestStep1EndToEndNoLivePS1(t *testing.T) {
	// --- Arrange: fixture install cache, loaded via the real loader. ---
	home := t.TempDir()
	writeE2EInstallFixture(t, home, "acme", "voice-forge", "0.1.3")

	mp, err := install.LoadManifestParams(home, "acme", "voice-forge", "0.1.3")
	if err != nil {
		t.Fatalf("install.LoadManifestParams: %v", err)
	}

	// --- Arrange: fixture step-disclosure.json in a separate workspace dir. ---
	workspace := t.TempDir()
	fixtureP := []byte("integration-test-prompt-commitment")
	fixtureR := []byte("integration-test-response-commitment")
	sd := feeder.StepDisclosure{
		Index:   0,
		P:       fixtureP,
		R:       fixtureR,
		C:       5000,
		Model:   "claude-sonnet-4-5",
		ModelID: "anthropic/claude-sonnet-4-5",
	}
	sdRaw, err := json.Marshal(sd)
	if err != nil {
		t.Fatalf("marshal step-disclosure fixture: %v", err)
	}
	seamPath := filepath.Join(workspace, "step-disclosure.json")
	if err := os.WriteFile(seamPath, sdRaw, 0o644); err != nil {
		t.Fatalf("write step-disclosure.json: %v", err)
	}

	// --- Act: WriteWitness combines the seam file with the installed manifest. ---
	witnessPath := filepath.Join(workspace, "witness.json")
	if err := feeder.WriteWitness(seamPath, mp, witnessPath); err != nil {
		t.Fatalf("WriteWitness: %v", err)
	}

	// --- Arrange: mock PS-1 and stub reef-core ingest. ---
	mockPS1 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/prove/spartan-compress" {
			t.Errorf("unexpected PS-1 path %s", r.URL.Path)
		}
		e2eOKSpartanResponse(w)
	}))
	defer mockPS1.Close()

	var gotAuth string
	var gotBody map[string]any
	stubIngest := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		raw, _ := io.ReadAll(r.Body)
		if err := json.Unmarshal(raw, &gotBody); err != nil {
			t.Errorf("stub ingest: unmarshal posted body: %v", err)
		}
		w.WriteHeader(http.StatusCreated)
	}))
	defer stubIngest.Close()

	// --- Act: run the feeder pipeline against the mocks. ---
	err = feeder.Run(context.Background(), feeder.Opts{
		WitnessPath: witnessPath,
		PaygateURL:  mockPS1.URL,
		IngestURL:   stubIngest.URL,
		IngestToken: "test-token-x",
		CircuitID:   "konareef-pod-step-v1",
	})
	if err != nil {
		t.Fatalf("feeder.Run: %v", err)
	}

	// --- Assert: the ingest body's empty-tool-log Step-1 shape. ---
	if gotAuth != "Bearer test-token-x" {
		t.Fatalf("Authorization header = %q, want %q", gotAuth, "Bearer test-token-x")
	}

	wd, ok := gotBody["witness_disclosure"].(map[string]any)
	if !ok {
		t.Fatal("witness_disclosure missing or not an object")
	}
	zk, ok := gotBody["zk_stamp"].(map[string]any)
	if !ok {
		t.Fatal("zk_stamp missing or not an object")
	}
	toolCalls, ok := gotBody["tool_calls"].([]any)
	if !ok {
		t.Fatal("tool_calls missing or not an array")
	}

	tlogRecords, ok := wd["T_log_records"].([]any)
	if !ok {
		t.Fatal("witness_disclosure.T_log_records missing or not an array")
	}
	if len(tlogRecords) != 0 {
		t.Fatalf("witness_disclosure.T_log_records len = %d, want 0 (empty tool log)", len(tlogRecords))
	}
	if len(toolCalls) != 0 {
		t.Fatalf("tool_calls len = %d, want 0 (empty tool log)", len(toolCalls))
	}

	toolLogRootB64, ok := zk["tool_log_root"].(string)
	if !ok {
		t.Fatal("zk_stamp.tool_log_root missing or not a base64 string")
	}
	toolLogRoot, err := base64.StdEncoding.DecodeString(toolLogRootB64)
	if err != nil {
		t.Fatalf("zk_stamp.tool_log_root not valid base64: %v", err)
	}
	if !bytes.Equal(toolLogRoot, make([]byte, 32)) {
		t.Fatalf("zk_stamp.tool_log_root = %x, want 32 zero bytes", toolLogRoot)
	}

	if got := zk["disclosure_policy"]; got != "C" {
		t.Fatalf("zk_stamp.disclosure_policy = %v, want %q", got, "C")
	}
	// zk_stamp.model_id carries the qualified ID end to end; the bare name
	// never replaces it (IB-03, konareef#21).
	if got := zk["model_id"]; got != "anthropic/claude-sonnet-4-5" {
		t.Fatalf("zk_stamp.model_id = %v, want %q", got, "anthropic/claude-sonnet-4-5")
	}

	decodeField := func(m map[string]any, key string) []byte {
		t.Helper()
		s, ok := m[key].(string)
		if !ok {
			t.Fatalf("%s missing or not a base64 string", key)
		}
		b, err := base64.StdEncoding.DecodeString(s)
		if err != nil {
			t.Fatalf("%s not valid base64: %v", key, err)
		}
		return b
	}
	if got := decodeField(wd, "P"); !bytes.Equal(got, fixtureP) {
		t.Fatalf("witness_disclosure.P = %q, want %q", got, fixtureP)
	}
	if got := decodeField(wd, "R"); !bytes.Equal(got, fixtureR) {
		t.Fatalf("witness_disclosure.R = %q, want %q", got, fixtureR)
	}
}

// TestStep2EndToEndWithToolLog is the non-gated counterpart to the env-gated
// live smoke: a seam step-disclosure.json carrying a 2-record tool_log flows
// through WriteWitness -> feeder.Run -> mock PS-1 -> stub ingest, and the
// ingest body must carry two canonical 113-B T_log_records (each 0x20-prefixed,
// in call order) plus tool_calls with the sats field. This exercises the
// populated tool-log emission path (ingest.go's tlog.RecordBytes loop +
// witness_writer.go's seam→witness mapping) that the empty-log tests skip.
func TestStep2EndToEndWithToolLog(t *testing.T) {
	home := t.TempDir()
	writeE2EInstallFixture(t, home, "acme", "voice-forge", "0.1.3")
	mp, err := install.LoadManifestParams(home, "acme", "voice-forge", "0.1.3")
	if err != nil {
		t.Fatalf("install.LoadManifestParams: %v", err)
	}

	h := func(s string) []byte { d := sha256.Sum256([]byte(s)); return d[:] }
	workspace := t.TempDir()
	sd := feeder.StepDisclosure{
		Index: 0, P: []byte("p"), R: []byte("r"), C: 5000, Model: "claude-sonnet-4-5", ModelID: "anthropic/claude-sonnet-4-5",
		ToolLog: []feeder.SeamToolRecord{
			{ToolID: "bash", ArgsHash: h("mkdir -p output"), ResultHash: h(""), TsUs: 1748736000000000},
			{ToolID: "bash", ArgsHash: h("curl ..."), ResultHash: h("ok"), TsUs: 1748736001000000},
		},
	}
	sdRaw, err := json.Marshal(sd)
	if err != nil {
		t.Fatalf("marshal step-disclosure: %v", err)
	}
	seamPath := filepath.Join(workspace, "step-disclosure.json")
	if err := os.WriteFile(seamPath, sdRaw, 0o644); err != nil {
		t.Fatalf("write step-disclosure.json: %v", err)
	}
	witnessPath := filepath.Join(workspace, "witness.json")
	if err := feeder.WriteWitness(seamPath, mp, witnessPath); err != nil {
		t.Fatalf("WriteWitness: %v", err)
	}

	mockPS1 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		e2eOKSpartanResponse(w)
	}))
	defer mockPS1.Close()
	var gotBody map[string]any
	stubIngest := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		if err := json.Unmarshal(raw, &gotBody); err != nil {
			t.Errorf("stub ingest unmarshal: %v", err)
		}
		w.WriteHeader(http.StatusCreated)
	}))
	defer stubIngest.Close()

	if err := feeder.Run(context.Background(), feeder.Opts{
		WitnessPath: witnessPath, PaygateURL: mockPS1.URL, IngestURL: stubIngest.URL,
		IngestToken: "t", CircuitID: "konareef-pod-step-v1",
	}); err != nil {
		t.Fatalf("feeder.Run: %v", err)
	}

	wd, ok := gotBody["witness_disclosure"].(map[string]any)
	if !ok {
		t.Fatal("witness_disclosure missing")
	}
	tlogRecords, ok := wd["T_log_records"].([]any)
	if !ok || len(tlogRecords) != 2 {
		t.Fatalf("T_log_records = %v, want 2 records", wd["T_log_records"])
	}
	for i, rec := range tlogRecords {
		b, err := base64.StdEncoding.DecodeString(rec.(string))
		if err != nil {
			t.Fatalf("T_log_records[%d] not base64: %v", i, err)
		}
		if len(b) != 113 {
			t.Fatalf("T_log_records[%d] len = %d, want 113 (canonical record)", i, len(b))
		}
		if b[0] != 0x20 {
			t.Fatalf("T_log_records[%d][0] = %#x, want 0x20 (digest-shape prefix)", i, b[0])
		}
	}

	toolCalls, ok := gotBody["tool_calls"].([]any)
	if !ok || len(toolCalls) != 2 {
		t.Fatalf("tool_calls = %v, want 2", gotBody["tool_calls"])
	}
	tc0, ok := toolCalls[0].(map[string]any)
	if !ok {
		t.Fatal("tool_calls[0] not an object")
	}
	if tc0["tool"] != "bash" {
		t.Fatalf("tool_calls[0].tool = %v, want bash", tc0["tool"])
	}
	if _, ok := tc0["sats"]; !ok {
		t.Fatal("tool_calls[0] missing sats field")
	}
	if idx, _ := tc0["call_index"].(float64); idx != 0 {
		t.Fatalf("tool_calls[0].call_index = %v, want 0 (call order preserved)", tc0["call_index"])
	}
}

// TestStep2EndToEndPricedToolLog is the MCP-Z02 end-to-end check: a
// broker-priced-v1 seam with a nonzero broker price and a zero-priced
// local call goes through WriteWitness and feeder.Run. The price stays
// nonzero at every hop: the PS-1 request tool_log, the ingest tool_calls
// and the last 8 bytes of each T_log record. The PS-1 request has no
// tool_log_format (MCP-Z00 D2 option A); the ingest body has one.
func TestStep2EndToEndPricedToolLog(t *testing.T) {
	home := t.TempDir()
	writeE2EInstallFixture(t, home, "acme", "voice-forge", "0.1.3")
	mp, err := install.LoadManifestParams(home, "acme", "voice-forge", "0.1.3")
	if err != nil {
		t.Fatalf("install.LoadManifestParams: %v", err)
	}

	h := func(s string) []byte { d := sha256.Sum256([]byte(s)); return d[:] }
	priced := feeder.ToolLogFormatPriced
	workspace := t.TempDir()
	sd := feeder.StepDisclosure{
		Index: 0, P: []byte("p"), R: []byte("r"), C: 5000, Model: "claude-sonnet-4-5", ModelID: "anthropic/claude-sonnet-4-5",
		ToolLogFormat: &priced,
		ToolLog: []feeder.SeamToolRecord{
			{ToolID: "jira.get_issue", ArgsHash: h("KR-1"), ResultHash: h("ok"), TsUs: 1758672000000000, Sats: json.RawMessage("250")},
			{ToolID: "bash", ArgsHash: h("ls"), ResultHash: h(""), TsUs: 1758672001000000, Sats: json.RawMessage("0")},
		},
	}
	wantSats := []uint64{250, 0}
	sdRaw, err := json.Marshal(sd)
	if err != nil {
		t.Fatalf("marshal step-disclosure: %v", err)
	}
	seamPath := filepath.Join(workspace, "step-disclosure.json")
	if err := os.WriteFile(seamPath, sdRaw, 0o644); err != nil {
		t.Fatalf("write step-disclosure.json: %v", err)
	}
	witnessPath := filepath.Join(workspace, "witness.json")
	if err := feeder.WriteWitness(seamPath, mp, witnessPath); err != nil {
		t.Fatalf("WriteWitness: %v", err)
	}

	var ps1Body map[string]any
	mockPS1 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		if err := json.Unmarshal(raw, &ps1Body); err != nil {
			t.Errorf("mock PS-1 unmarshal: %v", err)
		}
		e2eOKSpartanResponse(w)
	}))
	defer mockPS1.Close()
	var gotBody map[string]any
	stubIngest := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		if err := json.Unmarshal(raw, &gotBody); err != nil {
			t.Errorf("stub ingest unmarshal: %v", err)
		}
		w.WriteHeader(http.StatusCreated)
	}))
	defer stubIngest.Close()

	if err := feeder.Run(context.Background(), feeder.Opts{
		WitnessPath: witnessPath, PaygateURL: mockPS1.URL, IngestURL: stubIngest.URL,
		IngestToken: "t", CircuitID: "konareef-pod-step-v1",
	}); err != nil {
		t.Fatalf("feeder.Run: %v", err)
	}

	// PS-1 request: sats per record, no format label anywhere in the body.
	podRecord, _ := ps1Body["pod_record"].(map[string]any)
	if _, ok := ps1Body["tool_log_format"]; ok {
		t.Fatal("PS-1 request carries tool_log_format; the PS-1 wire has no such field")
	}
	if _, ok := podRecord["tool_log_format"]; ok {
		t.Fatal("PS-1 pod_record carries tool_log_format; the PS-1 wire has no such field")
	}
	ps1Log, ok := podRecord["tool_log"].([]any)
	if !ok || len(ps1Log) != len(wantSats) {
		t.Fatalf("PS-1 pod_record.tool_log = %v, want %d records", podRecord["tool_log"], len(wantSats))
	}
	for i, want := range wantSats {
		if got, _ := ps1Log[i].(map[string]any)["sats"].(float64); uint64(got) != want {
			t.Fatalf("PS-1 tool_log[%d].sats = %v, want %d", i, got, want)
		}
	}

	// Ingest body: format label, sats in tool_calls and in the record bytes.
	if gotBody["tool_log_format"] != feeder.ToolLogFormatPriced {
		t.Fatalf("ingest tool_log_format = %v, want %s", gotBody["tool_log_format"], feeder.ToolLogFormatPriced)
	}
	toolCalls, _ := gotBody["tool_calls"].([]any)
	records, _ := gotBody["witness_disclosure"].(map[string]any)["T_log_records"].([]any)
	if len(toolCalls) != len(wantSats) || len(records) != len(wantSats) {
		t.Fatalf("tool_calls=%d T_log_records=%d, want %d each", len(toolCalls), len(records), len(wantSats))
	}
	for i, want := range wantSats {
		if got, _ := toolCalls[i].(map[string]any)["sats"].(float64); uint64(got) != want {
			t.Fatalf("tool_calls[%d].sats = %v, want %d", i, got, want)
		}
		b, err := base64.StdEncoding.DecodeString(records[i].(string))
		if err != nil || len(b) != 113 {
			t.Fatalf("T_log_records[%d]: len=%d err=%v", i, len(b), err)
		}
		if got := binary.BigEndian.Uint64(b[105:]); got != want {
			t.Fatalf("T_log_records[%d] sats bytes = %d, want %d", i, got, want)
		}
	}
}

// TestWriteWitnessRejectsShortToolHash asserts the seam guard fails closed on a
// tool_log record whose args_hash is not 32 bytes — without it, ingest.go would
// silently zero-pad the []byte into a [32]byte, producing a wrong 113-B record.
func TestWriteWitnessRejectsShortToolHash(t *testing.T) {
	home := t.TempDir()
	writeE2EInstallFixture(t, home, "acme", "voice-forge", "0.1.3")
	mp, err := install.LoadManifestParams(home, "acme", "voice-forge", "0.1.3")
	if err != nil {
		t.Fatalf("LoadManifestParams: %v", err)
	}
	ws := t.TempDir()
	sd := feeder.StepDisclosure{
		Model: "claude-sonnet-4-5", ModelID: "anthropic/claude-sonnet-4-5", C: 1,
		ToolLog: []feeder.SeamToolRecord{
			{ToolID: "bash", ArgsHash: make([]byte, 20), ResultHash: make([]byte, 32), TsUs: 1},
		},
	}
	raw, _ := json.Marshal(sd)
	seam := filepath.Join(ws, "step-disclosure.json")
	if err := os.WriteFile(seam, raw, 0o644); err != nil {
		t.Fatalf("write seam: %v", err)
	}
	if err := feeder.WriteWitness(seam, mp, filepath.Join(ws, "witness.json")); err == nil {
		t.Fatal("expected WriteWitness to reject a 20-byte args_hash, got nil")
	}
}
