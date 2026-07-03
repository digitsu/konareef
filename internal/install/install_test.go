package install

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/digitsu/konareef/internal/identity"
)

// fixture returns a real signed FetchedPod for tests: a fresh
// secp256k1 keypair, a small canonical-shaped manifest, and an
// actual signature over those bytes. Tests then tamper individual
// fields to exercise the rejection paths.
func fixture(t *testing.T) *FetchedPod {
	t.Helper()
	id, err := identity.Generate("alice")
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	canonBytes := []byte("#!konareef-toml/v1\n[pod]\nname = \"research-bot\"\nversion = \"1.0.0\"\n[_files]\n")
	sig, err := id.Sign(canonBytes)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	return &FetchedPod{
		Handle:             "alice",
		PodName:            "research-bot",
		PodVersion:         "1.0.0",
		PodHash:            sha256.Sum256(canonBytes),
		ManifestCanonical:  canonBytes,
		Signature:          sig,
		PublisherPubkeyHex: id.PublicKeyHex,
	}
}

// serveFixture wraps f in a httptest server that returns it as
// fetch wire JSON for any request path.
func serveFixture(t *testing.T, f *FetchedPod) *httptest.Server {
	t.Helper()
	pubBytes, err := hex.DecodeString(f.PublisherPubkeyHex)
	if err != nil {
		t.Fatalf("decode pubkey hex: %v", err)
	}
	body, _ := json.Marshal(map[string]string{
		"handle":             f.Handle,
		"pod_name":           f.PodName,
		"pod_version":        f.PodVersion,
		"pod_hash":           hex.EncodeToString(f.PodHash[:]),
		"manifest_canonical": base64.StdEncoding.EncodeToString(f.ManifestCanonical),
		"signature":          base64.StdEncoding.EncodeToString(f.Signature),
		"publisher_pubkey":   base64.StdEncoding.EncodeToString(pubBytes),
	})
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(body)
	}))
}

func TestFetchHappyPath(t *testing.T) {
	f := fixture(t)
	server := serveFixture(t, f)
	defer server.Close()

	got, err := Fetch(server.URL, "alice", "research-bot", "")
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if got.Handle != f.Handle {
		t.Errorf("Handle = %q", got.Handle)
	}
	if got.PodVersion != f.PodVersion {
		t.Errorf("PodVersion = %q", got.PodVersion)
	}
	if got.PodHash != f.PodHash {
		t.Errorf("PodHash mismatch")
	}
	if string(got.ManifestCanonical) != string(f.ManifestCanonical) {
		t.Errorf("ManifestCanonical mismatch")
	}
	if got.PublisherPubkeyHex != f.PublisherPubkeyHex {
		t.Errorf("PublisherPubkeyHex mismatch")
	}
}

func TestFetchTargetsExpectedURL(t *testing.T) {
	var hitPath string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hitPath = r.URL.Path
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"handle":"a","pod_name":"b","pod_version":"1.0.0","pod_hash":"` +
			hex.EncodeToString(make([]byte, 32)) + `","manifest_canonical":"","signature":"","publisher_pubkey":""}`))
	}))
	defer server.Close()

	_, _ = Fetch(server.URL, "alice", "research-bot", "")
	if hitPath != "/api/pods/alice/research-bot/latest" {
		t.Errorf("path = %q, want /api/pods/alice/research-bot/latest", hitPath)
	}
	_, _ = Fetch(server.URL, "alice", "research-bot", "1.0.0")
	if hitPath != "/api/pods/alice/research-bot/1.0.0" {
		t.Errorf("path = %q, want /api/pods/alice/research-bot/1.0.0", hitPath)
	}
}

func TestFetchSurfaces404(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`{"error":"not_found"}`))
	}))
	defer server.Close()
	if _, err := Fetch(server.URL, "alice", "ghost", ""); err == nil {
		t.Errorf("Fetch accepted a 404 response")
	}
}

func TestFetchSurfaces404AsManifestNotFound(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`{"error":"not_found"}`))
	}))
	defer server.Close()

	_, err := Fetch(server.URL, "alice", "ghost", "")
	if err == nil {
		t.Fatalf("Fetch accepted a 404 response")
	}
	if !errors.Is(err, ErrManifestNotFound) {
		t.Errorf("Fetch error is not ErrManifestNotFound: %v", err)
	}
}

func TestVerifyAcceptsValidPod(t *testing.T) {
	f := fixture(t)
	if err := Verify(f); err != nil {
		t.Errorf("Verify rejected a valid pod: %v", err)
	}
}

func TestVerifyRejectsHashMismatch(t *testing.T) {
	f := fixture(t)
	f.PodHash[0] ^= 0xff
	if err := Verify(f); err == nil {
		t.Errorf("Verify accepted a pod with a mutated pod_hash")
	}
}

func TestVerifyRejectsTamperedManifest(t *testing.T) {
	f := fixture(t)
	tampered := append([]byte{}, f.ManifestCanonical...)
	tampered[len(tampered)-2] ^= 0xff
	f.ManifestCanonical = tampered
	if err := Verify(f); err == nil {
		t.Errorf("Verify accepted a pod with a tampered manifest")
	}
}

func TestVerifyRejectsTamperedSignature(t *testing.T) {
	f := fixture(t)
	f.Signature[len(f.Signature)-1] ^= 0xff
	if err := Verify(f); err == nil {
		t.Errorf("Verify accepted a tampered signature")
	}
}

func TestVerifyRejectsWrongPubkey(t *testing.T) {
	f := fixture(t)
	other, _ := identity.Generate("eve")
	f.PublisherPubkeyHex = other.PublicKeyHex
	if err := Verify(f); err == nil {
		t.Errorf("Verify accepted a pod under a swapped pubkey")
	}
}

func TestCacheWritesExpectedLayout(t *testing.T) {
	f := fixture(t)
	home := t.TempDir()
	dir, err := Cache(home, f)
	if err != nil {
		t.Fatalf("Cache: %v", err)
	}
	want := filepath.Join(home, ".konareef", "installed", "alice", "research-bot", "1.0.0")
	if dir != want {
		t.Errorf("cache dir = %q, want %q", dir, want)
	}
	for _, name := range []string{"manifest.canon", "signature.bin", "meta.json"} {
		if _, err := os.Stat(filepath.Join(dir, name)); err != nil {
			t.Errorf("%s not written: %v", name, err)
		}
	}
	// manifest.canon round-trips byte-exact
	got, err := os.ReadFile(filepath.Join(dir, "manifest.canon"))
	if err != nil || string(got) != string(f.ManifestCanonical) {
		t.Errorf("manifest.canon round-trip failed")
	}
}
