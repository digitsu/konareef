package publish

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// samplePreparedPod returns a minimal-but-shaped PreparedPod used by
// the Submit tests. Fields carry stable bytes so the test server can
// assert exact wire-format expectations.
func samplePreparedPod() *PreparedPod {
	return &PreparedPod{
		Handle:         "alice",
		PodName:        "research-bot",
		PodVersion:     "1.0.0",
		PodHash:        [32]byte{0xe7, 0xf2, 0xa3, 0xb4},
		CanonicalBytes: []byte("canonical bytes"),
		Signature:      []byte("der-encoded-signature-bytes-here"),
		// 33-byte compressed pubkey (02 prefix + 32 bytes), all hex.
		PublicKeyHex: "020123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
	}
}

func TestSubmitPostsExpectedWireFormat(t *testing.T) {
	prep := samplePreparedPod()

	var captured map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/pods" {
			t.Errorf("URL.Path = %q, want /api/pods", r.URL.Path)
		}
		if r.Method != http.MethodPost {
			t.Errorf("Method = %q, want POST", r.Method)
		}
		if ct := r.Header.Get("Content-Type"); ct != "application/json" {
			t.Errorf("Content-Type = %q, want application/json", ct)
		}

		body, _ := io.ReadAll(r.Body)
		if err := json.Unmarshal(body, &captured); err != nil {
			t.Fatalf("request body is not JSON: %v", err)
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"install_url":"https://example.com/install/alice/research-bot","registered_at":"2026-05-23T10:00:00Z"}`))
	}))
	defer server.Close()

	resp, err := Submit(server.URL, prep, SubmitOpts{})
	if err != nil {
		t.Fatalf("Submit: %v", err)
	}
	if resp.InstallURL != "https://example.com/install/alice/research-bot" {
		t.Errorf("InstallURL = %q", resp.InstallURL)
	}

	// Wire-format assertions against captured body.
	if captured["handle"] != "alice" {
		t.Errorf("handle = %v", captured["handle"])
	}
	if captured["pod_name"] != "research-bot" {
		t.Errorf("pod_name = %v", captured["pod_name"])
	}
	if captured["pod_version"] != "1.0.0" {
		t.Errorf("pod_version = %v", captured["pod_version"])
	}
	if wantHex := hex.EncodeToString(prep.PodHash[:]); captured["pod_hash"] != wantHex {
		t.Errorf("pod_hash = %v, want %q", captured["pod_hash"], wantHex)
	}
	if wantB64 := base64.StdEncoding.EncodeToString(prep.CanonicalBytes); captured["manifest_canonical"] != wantB64 {
		t.Errorf("manifest_canonical mismatch")
	}
	if wantB64 := base64.StdEncoding.EncodeToString(prep.Signature); captured["signature"] != wantB64 {
		t.Errorf("signature mismatch")
	}
	pubBytes, _ := hex.DecodeString(prep.PublicKeyHex)
	if wantB64 := base64.StdEncoding.EncodeToString(pubBytes); captured["publisher_pubkey"] != wantB64 {
		t.Errorf("publisher_pubkey mismatch")
	}
}

func TestSubmitFailsOnServerError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"error":"signature_invalid"}`))
	}))
	defer server.Close()

	if _, err := Submit(server.URL, samplePreparedPod(), SubmitOpts{}); err == nil {
		t.Errorf("Submit accepted a 400 response")
	}
}

func TestSubmitFailsOnNetworkError(t *testing.T) {
	// Use a closed httptest server URL so the connection is refused.
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	url := server.URL
	server.Close()
	if _, err := Submit(url, samplePreparedPod(), SubmitOpts{}); err == nil {
		t.Errorf("Submit succeeded against a closed server")
	}
}

// TestSubmitOmitsPublicBundleByDefault asserts the default wire body
// does NOT include a `public_bundle` key (WI-P0-012). The reef-core
// controller defaults to false on absence, so omitting the field is
// the safe and idiomatic encoding for opted-out publishers and
// keeps the wire body byte-identical to the pre-WI-P0-012 format.
func TestSubmitOmitsPublicBundleByDefault(t *testing.T) {
	var captured map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(body, &captured)
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"install_url":"x","registered_at":"2026-05-25T00:00:00Z"}`))
	}))
	defer server.Close()

	if _, err := Submit(server.URL, samplePreparedPod(), SubmitOpts{}); err != nil {
		t.Fatalf("Submit: %v", err)
	}
	if _, present := captured["public_bundle"]; present {
		t.Errorf("public_bundle key should be absent in the default wire body, got %v", captured["public_bundle"])
	}
}

// TestSubmitSendsPublicBundleTrue asserts that opting in serializes
// the literal JSON boolean `true` on the wire. reef-core's
// parse_public_bundle only honors a literal `true`, so anything else
// (a string "true", 1, etc.) would silently mean opt-out.
func TestSubmitSendsPublicBundleTrue(t *testing.T) {
	var captured map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(body, &captured)
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"install_url":"x","registered_at":"2026-05-25T00:00:00Z"}`))
	}))
	defer server.Close()

	if _, err := Submit(server.URL, samplePreparedPod(), SubmitOpts{PublicBundle: true}); err != nil {
		t.Fatalf("Submit: %v", err)
	}
	if got, ok := captured["public_bundle"].(bool); !ok || got != true {
		t.Errorf("public_bundle = %v (%T), want true (bool)", captured["public_bundle"], captured["public_bundle"])
	}
}

func TestSubmitFailsOnMalformedResponse(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`not json`))
	}))
	defer server.Close()
	if _, err := Submit(server.URL, samplePreparedPod(), SubmitOpts{}); err == nil {
		t.Errorf("Submit accepted a non-JSON 201 response")
	}
}

// captureRequestBody spins up an httptest.Server that records the
// posted body and returns 201 with a stub response, then invokes the
// caller's submit function against it.
func captureRequestBody(t *testing.T, do func(serverURL string) error) []byte {
	t.Helper()
	var captured []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		captured = body
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"install_url":"https://example.test/p","registered_at":"2026-06-10T00:00:00Z"}`))
	}))
	defer srv.Close()
	if err := do(srv.URL); err != nil {
		t.Fatalf("submit: %v", err)
	}
	return captured
}

// TestSubmitWireBodyLegacyByteIdentical asserts SubmitOpts{} produces
// a wire body that omits all P1.3 fields (byte-identical to pre-P1.3
// shape).
func TestSubmitWireBodyLegacyByteIdentical(t *testing.T) {
	captured := captureRequestBody(t, func(serverURL string) error {
		prep := samplePreparedPod()
		_, err := Submit(serverURL, prep, SubmitOpts{})
		return err
	})
	for _, key := range []string{"\"circuit_id\"", "\"zk_enabled\"", "\"disclosure_policy\"", "\"lineage_id\""} {
		if strings.Contains(string(captured), key) {
			t.Errorf("legacy wire body must omit %s; got %s", key, captured)
		}
	}
}

// TestSubmitWireBodyZKShape asserts the --zk opts populate the three
// new wire fields with the expected JSON shape.
func TestSubmitWireBodyZKShape(t *testing.T) {
	captured := captureRequestBody(t, func(serverURL string) error {
		prep := samplePreparedPod()
		_, err := Submit(serverURL, prep, SubmitOpts{
			CircuitID:        "konareef-pod-step-v1",
			ZkEnabled:        true,
			DisclosurePolicy: "C",
		})
		return err
	})
	want := []string{
		"\"circuit_id\":\"konareef-pod-step-v1\"",
		"\"zk_enabled\":true",
		"\"disclosure_policy\":\"C\"",
	}
	for _, w := range want {
		if !strings.Contains(string(captured), w) {
			t.Errorf("zk wire body missing %s; got %s", w, captured)
		}
	}
}

// TestSubmitWireBodyTypeDLineageID asserts a Type-D publish with a
// sealed witness threads the lineage_id (32-char hex) into the wire
// body but NEVER carries salt (PRD 4 § B.2).
func TestSubmitWireBodyTypeDLineageID(t *testing.T) {
	captured := captureRequestBody(t, func(serverURL string) error {
		prep := samplePreparedPod()
		w := &Witness{
			LineageID: [16]byte{0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab,
				0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab},
			Salt: [32]byte{0xcd}, // anything non-zero
		}
		_, err := Submit(serverURL, prep, SubmitOpts{
			CircuitID:        "konareef-pod-step-v1",
			ZkEnabled:        true,
			DisclosurePolicy: "D",
			Witness:          w,
		})
		return err
	})
	if !strings.Contains(string(captured), "\"lineage_id\":\"abababababababababababababababab\"") {
		t.Errorf("Type-D wire body must carry lineage_id hex; got %s", captured)
	}
	// PRD 4 § B.2 — salt MUST NOT be serialised.
	if strings.Contains(string(captured), "\"salt\"") {
		t.Errorf("wire body MUST NOT contain salt (PRD 4 § B.2); got %s", captured)
	}
}
