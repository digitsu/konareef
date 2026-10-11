// Package feeder is the konareef Pod-Trust-Domain sidecar: it reads the
// relayed step data, assembles the PS-1 PodRecord, calls the prover, and
// POSTs the artifact to reef-core. It is the witness-of-record; reef-core
// never assembles a PodRecord.
package feeder

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// shrinkSpartanBackoff replaces the package backoff timings with tiny values
// for the duration of a test so the 503-retry suite stays fast, restoring
// them via t.Cleanup. Production defaults are 1s/15s.
func shrinkSpartanBackoff(t *testing.T) {
	t.Helper()
	origBase, origMax := spartanBackoffBase, spartanBackoffMaxWait
	spartanBackoffBase = 1 * time.Millisecond
	spartanBackoffMaxWait = 5 * time.Millisecond
	t.Cleanup(func() {
		spartanBackoffBase = origBase
		spartanBackoffMaxWait = origMax
	})
}

// okSpartanResponse writes a minimal well-formed SpartanCompressResult.
func okSpartanResponse(w http.ResponseWriter) {
	b64 := base64.StdEncoding.EncodeToString
	_ = json.NewEncoder(w).Encode(map[string]string{
		"spartan_snark": b64([]byte("snark")), "first_step_public_inputs": b64(make([]byte, 298)),
		"last_step_public_inputs": b64(make([]byte, 298)), "vkey_hash": b64(make([]byte, 32)),
		"genesis_fields_root": b64(make([]byte, 32)),
		"z0":                  b64(make([]byte, 736)), "vkey": b64(make([]byte, 32)),
		"circuit_id": "konareef-pod-step-v1",
	})
}

func TestSpartanCompress(t *testing.T) {
	b64 := base64.StdEncoding.EncodeToString
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/prove/spartan-compress" {
			t.Errorf("unexpected path %s", r.URL.Path)
		}
		_ = json.NewEncoder(w).Encode(map[string]string{
			"spartan_snark":            b64([]byte("snark")),
			"first_step_public_inputs": b64(make([]byte, 298)),
			"last_step_public_inputs":  b64(make([]byte, 298)),
			"vkey_hash":                b64(make([]byte, 32)),
			"genesis_fields_root":      b64(make([]byte, 32)),
			"z0":                       b64(make([]byte, 736)),
			"vkey":                     b64(make([]byte, 32)),
			"circuit_id":               "konareef-pod-step-v1",
		})
	}))
	defer srv.Close()

	res, err := SpartanCompress(context.Background(), srv.URL, "konareef-pod-step-v1", PodRecord{PkPub: make([]byte, 33), SigManifest: make([]byte, 74)})
	if err != nil {
		t.Fatalf("compress: %v", err)
	}
	if res.CircuitID != "konareef-pod-step-v1" || len(res.VkeyHash) != 32 {
		t.Fatalf("bad result: %+v", res)
	}
}

// TestSpartanCompressRetriesOn503 asserts that a 503 ERR_BUSY (PS-1
// single-flight) is retried and the call eventually succeeds once PS-1
// returns 200 (spec §6/§1).
func TestSpartanCompressRetriesOn503(t *testing.T) {
	shrinkSpartanBackoff(t)
	var calls int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Return 503 on the first 3 calls, then 200.
		if atomic.AddInt32(&calls, 1) <= 3 {
			w.WriteHeader(http.StatusServiceUnavailable)
			_, _ = w.Write([]byte(`{"error":"ERR_BUSY"}`))
			return
		}
		okSpartanResponse(w)
	}))
	defer srv.Close()

	res, err := SpartanCompress(context.Background(), srv.URL, "konareef-pod-step-v1",
		PodRecord{PkPub: make([]byte, 33), SigManifest: make([]byte, 74)})
	if err != nil {
		t.Fatalf("expected eventual success, got: %v", err)
	}
	if res.CircuitID != "konareef-pod-step-v1" {
		t.Fatalf("bad result: %+v", res)
	}
	if got := atomic.LoadInt32(&calls); got != 4 {
		t.Fatalf("expected 4 calls (3x503 + 1x200), got %d", got)
	}
}

// TestSpartanCompressGivesUpAfterMaxAttempts asserts that a PS-1 that stays
// busy (always 503) makes the call give up after spartanMaxAttempts and
// return the busy error.
func TestSpartanCompressGivesUpAfterMaxAttempts(t *testing.T) {
	shrinkSpartanBackoff(t)
	var calls int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&calls, 1)
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = w.Write([]byte(`{"error":"ERR_BUSY"}`))
	}))
	defer srv.Close()

	_, err := SpartanCompress(context.Background(), srv.URL, "konareef-pod-step-v1",
		PodRecord{PkPub: make([]byte, 33), SigManifest: make([]byte, 74)})
	if err == nil {
		t.Fatal("expected give-up error after max attempts, got nil")
	}
	if !strings.Contains(err.Error(), "busy") {
		t.Fatalf("expected busy error, got: %v", err)
	}
	if got := atomic.LoadInt32(&calls); got != spartanMaxAttempts {
		t.Fatalf("expected %d attempts, got %d", spartanMaxAttempts, got)
	}
}

// TestSpartanCompressTerminalOnNon503 asserts a non-503 error (e.g. 400) is
// terminal — no retry — and surfaces immediately.
func TestSpartanCompressTerminalOnNon503(t *testing.T) {
	shrinkSpartanBackoff(t)
	var calls int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&calls, 1)
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"error":"ERR_BAD_REQUEST"}`))
	}))
	defer srv.Close()

	_, err := SpartanCompress(context.Background(), srv.URL, "konareef-pod-step-v1",
		PodRecord{PkPub: make([]byte, 33), SigManifest: make([]byte, 74)})
	if err == nil {
		t.Fatal("expected terminal error on 400, got nil")
	}
	if got := atomic.LoadInt32(&calls); got != 1 {
		t.Fatalf("expected exactly 1 call (no retry on non-503), got %d", got)
	}
}

// TestSpartanCompressRejectsMalformedBody asserts the floor-field validation:
// a 200 response missing a required field (here spartan_snark) fails at the
// producer instead of forwarding JSON null into the seam.
func TestSpartanCompressRejectsMalformedBody(t *testing.T) {
	b64 := base64.StdEncoding.EncodeToString
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Omit spartan_snark entirely.
		_ = json.NewEncoder(w).Encode(map[string]string{
			"first_step_public_inputs": b64(make([]byte, 298)),
			"last_step_public_inputs":  b64(make([]byte, 298)), "vkey_hash": b64(make([]byte, 32)),
			"circuit_id": "konareef-pod-step-v1",
		})
	}))
	defer srv.Close()

	_, err := SpartanCompress(context.Background(), srv.URL, "konareef-pod-step-v1",
		PodRecord{PkPub: make([]byte, 33), SigManifest: make([]byte, 74)})
	if err == nil {
		t.Fatal("expected error on missing spartan_snark, got nil")
	}
	if !strings.Contains(err.Error(), "spartan_snark") {
		t.Fatalf("expected spartan_snark validation error, got: %v", err)
	}
}

// spartanServerAnswering returns a PS-1 stub whose response carries circuitID.
func spartanServerAnswering(t *testing.T, circuitID string) *httptest.Server {
	t.Helper()
	b64 := base64.StdEncoding.EncodeToString
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]string{
			"spartan_snark": b64([]byte("snark")), "first_step_public_inputs": b64(make([]byte, 298)),
			"last_step_public_inputs": b64(make([]byte, 298)), "vkey_hash": b64(make([]byte, 32)),
			"z0": b64(make([]byte, 736)), "vkey": b64(make([]byte, 32)), "circuit_id": circuitID,
		})
	}))
}

// TestSpartanCompress_V1_1AndEchoCheck covers the VHASH migration
// (paygate-zk#12): a v1.1 request answered as v1.1 succeeds, and a response
// for a different circuit than requested is refused (not retried).
func TestSpartanCompress_V1_1AndEchoCheck(t *testing.T) {
	pr := PodRecord{PkPub: make([]byte, 33), SigManifest: make([]byte, 74)}
	ok := spartanServerAnswering(t, "konareef-pod-step-v1.1")
	defer ok.Close()
	res, err := SpartanCompress(context.Background(), ok.URL, "konareef-pod-step-v1.1", pr)
	if err != nil || res.CircuitID != "konareef-pod-step-v1.1" {
		t.Fatalf("v1.1: res=%+v err=%v", res, err)
	}
	wrong := spartanServerAnswering(t, "konareef-pod-step-v1")
	defer wrong.Close()
	if _, err := SpartanCompress(context.Background(), wrong.URL, "konareef-pod-step-v1.1", pr); err == nil ||
		!strings.Contains(err.Error(), "requested") {
		t.Fatalf("mismatched circuit_id must be refused, got %v", err)
	}
}

// TestRun_RefusesUnsupportedCircuitID checks that Run refuses a circuit id
// this build does not accept before any I/O.
func TestRun_RefusesUnsupportedCircuitID(t *testing.T) {
	err := Run(context.Background(), Opts{
		WitnessPath: "/nonexistent", PaygateURL: "http://x", IngestURL: "http://y",
		IngestToken: "t", CircuitID: "konareef-pod-step-v2",
	})
	if err == nil || !strings.Contains(err.Error(), "unsupported circuit_id") {
		t.Fatalf("want unsupported circuit_id, got %v", err)
	}
}
