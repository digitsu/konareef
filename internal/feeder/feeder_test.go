// Package feeder integration test — end-to-end stub for the feeder pipeline.
package feeder

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

// TestRunEndToEndStub exercises the full feeder pipeline (witness.json →
// AssemblePodRecord → SpartanCompress → PostArtifact) against in-process
// HTTP stubs for PS-1 and reef-core ingest.
func TestRunEndToEndStub(t *testing.T) {
	b64 := base64.StdEncoding.EncodeToString
	ps1 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]string{
			"spartan_snark": b64([]byte("snark")), "first_step_public_inputs": b64(make([]byte, 298)),
			"last_step_public_inputs": b64(make([]byte, 298)), "vkey_hash": b64(make([]byte, 32)),
			"genesis_fields_root": b64(make([]byte, 32)),
			"z0":                  b64(make([]byte, 736)), "vkey": b64(make([]byte, 32)),
			"circuit_id": "konareef-pod-step-v1",
		})
	}))
	defer ps1.Close()

	var ingested bool
	ingest := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ingested = true
		w.WriteHeader(http.StatusCreated)
	}))
	defer ingest.Close()

	wit := Witness{Manifest: []byte("m"), P: []byte("p"), R: []byte("r"), Model: "claude",
		SigManifest: validSigLane(), PkPub: validPubKeyBytes()}
	dir := t.TempDir()
	path := filepath.Join(dir, "witness.json")
	raw, _ := json.Marshal(wit)
	_ = os.WriteFile(path, raw, 0o600)

	err := Run(context.Background(), Opts{
		WitnessPath: path, PaygateURL: ps1.URL, IngestURL: ingest.URL,
		IngestToken: "tok", CircuitID: "konareef-pod-step-v1",
	})
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if !ingested {
		t.Fatal("artifact was not ingested")
	}
}
