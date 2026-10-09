package feeder

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestPostArtifact(t *testing.T) {
	var gotAuth string
	var gotBody map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		raw, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(raw, &gotBody)
		w.WriteHeader(http.StatusCreated)
	}))
	defer srv.Close()

	scr := &SpartanCompressResult{VkeyHash: make([]byte, 32), CircuitID: "konareef-pod-step-v1"}
	wit := Witness{P: []byte("p"), R: []byte("r"), Model: "claude",
		ToolLog: []ToolCallRecord{{Tool: "search", InHash: make([]byte, 32), OutHash: make([]byte, 32), Ts: 1}}}

	if err := PostArtifact(context.Background(), srv.URL, "tok", scr, wit); err != nil {
		t.Fatalf("post: %v", err)
	}
	if gotAuth != "Bearer tok" {
		t.Fatalf("auth header = %q", gotAuth)
	}
	if _, ok := gotBody["spartan_compress_result"]; !ok {
		t.Fatal("missing spartan_compress_result")
	}
	if _, ok := gotBody["zk_stamp"]; !ok {
		t.Fatal("missing zk_stamp")
	}
}

// TestPostArtifact_ForwardsZ0VkeyGenesisRoot is the C1 cross-repo contract
// (Hermes joint review of !48/!25): the feeder MUST forward z0, the raw vkey,
// and genesis_fields_root byte-for-byte into the ingest body, preserving
// vkey_hash == SHA-256(vkey), so reef-core ingest can persist the complete
// konareef-bundle/v2 artifact.
//
// z0 is 736 bytes (Z_ARITY = 23 lanes × 32, per paygate-zk circuit.rs:130;
// Hermes's acceptance text said 704, the stale pre-CL-6 figure). The feeder
// forwards whatever PS-1 emits byte-for-byte and does not derive these.
func TestPostArtifact_ForwardsZ0VkeyGenesisRoot(t *testing.T) {
	z0 := make([]byte, 736)
	for i := range z0 {
		z0[i] = byte(i % 251)
	}
	vkey := make([]byte, 32)
	for i := range vkey {
		vkey[i] = byte(i + 1)
	}
	vkeyHash := sha256.Sum256(vkey)
	genesisRoot := make([]byte, 32)
	for i := range genesisRoot {
		genesisRoot[i] = byte(0xA0 + i)
	}

	var gotBody map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(raw, &gotBody)
		w.WriteHeader(http.StatusCreated)
	}))
	defer srv.Close()

	scr := &SpartanCompressResult{
		SpartanSnark:          []byte("snark"),
		FirstStepPublicInputs: make([]byte, 298),
		LastStepPublicInputs:  make([]byte, 298),
		VkeyHash:              vkeyHash[:],
		GenesisFieldsRoot:     genesisRoot,
		Z0:                    z0,
		Vkey:                  vkey,
		CircuitID:             "konareef-pod-step-v1",
	}
	wit := Witness{P: []byte("p"), R: []byte("r"), Model: "claude"}
	if err := PostArtifact(context.Background(), srv.URL, "tok", scr, wit); err != nil {
		t.Fatalf("post: %v", err)
	}

	m, ok := gotBody["spartan_compress_result"].(map[string]any)
	if !ok {
		t.Fatal("spartan_compress_result missing or not an object")
	}
	// Go marshals []byte as base64 strings; decode each and compare byte-exact.
	dec := func(key string) []byte {
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
	if got := dec("z0"); !bytes.Equal(got, z0) {
		t.Fatalf("z0 not forwarded byte-for-byte: len got=%d want=%d", len(got), len(z0))
	}
	if got := dec("vkey"); len(got) != 32 || !bytes.Equal(got, vkey) {
		t.Fatalf("vkey not forwarded byte-for-byte (want 32 B, got %d)", len(got))
	}
	if got := dec("genesis_fields_root"); !bytes.Equal(got, genesisRoot) {
		t.Fatal("genesis_fields_root not forwarded byte-for-byte")
	}
	if got := dec("vkey_hash"); !bytes.Equal(got, vkeyHash[:]) {
		t.Fatal("vkey_hash not forwarded")
	}
	// The forwarded artifact preserves vkey_hash == SHA-256(vkey).
	recomputed := sha256.Sum256(dec("vkey"))
	if !bytes.Equal(recomputed[:], dec("vkey_hash")) {
		t.Fatal("vkey_hash != SHA-256(vkey) in the forwarded body")
	}
}
