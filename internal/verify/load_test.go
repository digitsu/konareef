package verify

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

func sampleBundleJSON(t *testing.T) []byte {
	t.Helper()
	body, err := json.Marshal(map[string]any{
		"version": BundleVersion,
		"chain":   []any{},
	})
	if err != nil {
		t.Fatalf("marshal sample: %v", err)
	}
	return body
}

func TestLoadFromFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bundle.json")
	if err := os.WriteFile(path, sampleBundleJSON(t), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	b, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if b.Version != BundleVersion {
		t.Errorf("Version = %q, want %q", b.Version, BundleVersion)
	}
}

func TestLoadFromHTTPURL(t *testing.T) {
	body := sampleBundleJSON(t)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(body)
	}))
	defer server.Close()

	b, err := Load(server.URL + "/api/public/proofs/abc/bundle")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if b.Version != BundleVersion {
		t.Errorf("Version = %q, want %q", b.Version, BundleVersion)
	}
}

func TestLoadFileNotFound(t *testing.T) {
	if _, err := Load(filepath.Join(t.TempDir(), "nope.json")); err == nil {
		t.Errorf("Load accepted a missing file")
	}
}

func TestLoadHTTPNonOK(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`{"error":"not_found"}`))
	}))
	defer server.Close()
	if _, err := Load(server.URL); err == nil {
		t.Errorf("Load accepted a 404 response")
	}
}

func TestLoadMalformedJSON(t *testing.T) {
	path := filepath.Join(t.TempDir(), "bad.json")
	if err := os.WriteFile(path, []byte("not json"), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	if _, err := Load(path); err == nil {
		t.Errorf("Load accepted malformed JSON")
	}
}

func TestLoadRejectsUnsupportedVersion(t *testing.T) {
	body, _ := json.Marshal(map[string]any{
		"version": "konareef-bundle/v999",
		"chain":   []any{},
	})
	path := filepath.Join(t.TempDir(), "future.json")
	if err := os.WriteFile(path, body, 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	if _, err := Load(path); err == nil {
		t.Errorf("Load accepted an unsupported bundle version")
	}
}
