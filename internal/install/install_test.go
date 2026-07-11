// Copyright 2026 Jerry David Chan, Konareef.ai
// SPDX-License-Identifier: Apache-2.0

package install

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
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
	"github.com/digitsu/konareef/internal/publish"
)

// samplePodTOML is a minimal-but-valid pod.toml, mirroring the
// publish package's own writeSamplePod fixture — the content-tarball
// tests below need a real pod directory that publish.Prepare will
// accept, not just the hand-rolled canonical bytes fixture() uses.
const samplePodTOML = `pod_spec_version = "0.1"

[pod]
name = "research-bot"
version = "1.0.0"

[runtime]
kind = "lobster"

[directive]
template = "./prompts/system.md"
`

// writeSamplePod scaffolds samplePodTOML plus the prompt file it
// references into a fresh temp directory.
func writeSamplePod(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "pod.toml"), []byte(samplePodTOML), 0o644); err != nil {
		t.Fatalf("write pod.toml: %v", err)
	}
	prompts := filepath.Join(dir, "prompts")
	if err := os.MkdirAll(prompts, 0o755); err != nil {
		t.Fatalf("mkdir prompts: %v", err)
	}
	if err := os.WriteFile(filepath.Join(prompts, "system.md"), []byte("hello"), 0o644); err != nil {
		t.Fatalf("write system.md: %v", err)
	}
	return dir
}

// fixtureWithContent runs the real publish.Prepare pipeline over a
// sample pod directory and lifts the result into a FetchedPod, so
// manifest, hash, signature, and content tarball are all genuinely
// consistent — exactly as a real fetch response would be. It returns
// the pod directory too, so tamper tests can mutate a file on disk
// and repack rather than flip tarball bytes directly (which just
// breaks gunzip instead of exercising the hash-reproduction check).
func fixtureWithContent(t *testing.T) (*FetchedPod, string) {
	t.Helper()
	podDir := writeSamplePod(t)
	id, err := identity.Generate("alice")
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	prep, err := publish.Prepare(podDir, id)
	if err != nil {
		t.Fatalf("Prepare: %v", err)
	}
	return &FetchedPod{
		Handle:             prep.Handle,
		PodName:            prep.PodName,
		PodVersion:         prep.PodVersion,
		PodHash:            prep.PodHash,
		ManifestCanonical:  prep.CanonicalBytes,
		Signature:          prep.Signature,
		PublisherPubkeyHex: prep.PublicKeyHex,
		ContentTarball:     prep.ContentTarball,
	}, podDir
}

// fixture returns a real signed FetchedPod for tests: a fresh
// secp256k1 keypair, a small canonical-shaped manifest, and an
// actual signature over those bytes. Tests then tamper individual
// fields to exercise the rejection paths. It carries no
// ContentTarball — the legacy (pre-B2-server) fetch shape.
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
// fetch wire JSON for any request path. content_tarball is omitted
// entirely when f.ContentTarball is nil, matching a legacy server
// that predates the field.
func serveFixture(t *testing.T, f *FetchedPod) *httptest.Server {
	t.Helper()
	pubBytes, err := hex.DecodeString(f.PublisherPubkeyHex)
	if err != nil {
		t.Fatalf("decode pubkey hex: %v", err)
	}
	wire := map[string]string{
		"handle":             f.Handle,
		"pod_name":           f.PodName,
		"pod_version":        f.PodVersion,
		"pod_hash":           hex.EncodeToString(f.PodHash[:]),
		"manifest_canonical": base64.StdEncoding.EncodeToString(f.ManifestCanonical),
		"signature":          base64.StdEncoding.EncodeToString(f.Signature),
		"publisher_pubkey":   base64.StdEncoding.EncodeToString(pubBytes),
	}
	if f.ContentTarball != nil {
		wire["content_tarball"] = base64.StdEncoding.EncodeToString(f.ContentTarball)
	}
	body, _ := json.Marshal(wire)
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

func TestFetchCarriesContentTarball(t *testing.T) {
	f, _ := fixtureWithContent(t)
	server := serveFixture(t, f)
	defer server.Close()

	got, err := Fetch(server.URL, f.Handle, f.PodName, "")
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if string(got.ContentTarball) != string(f.ContentTarball) {
		t.Errorf("ContentTarball mismatch")
	}
}

func TestFetchAbsentContentTarballIsNil(t *testing.T) {
	f := fixture(t) // legacy fixture: no ContentTarball
	server := serveFixture(t, f)
	defer server.Close()

	got, err := Fetch(server.URL, f.Handle, f.PodName, "")
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if got.ContentTarball != nil {
		t.Errorf("ContentTarball = %v, want nil when the wire response omits it", got.ContentTarball)
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

func TestVerifyAcceptsGenuineContentTarball(t *testing.T) {
	f, _ := fixtureWithContent(t)
	if err := Verify(f); err != nil {
		t.Errorf("Verify rejected a content tarball that reproduces pod_hash: %v", err)
	}
}

func TestVerifyRejectsTamperedContentTarball(t *testing.T) {
	f, podDir := fixtureWithContent(t)
	// Tamper a file on disk *after* Prepare ran, then repack. Flipping
	// bytes in the compressed tarball directly would just break
	// gunzip — this instead exercises the actual invariant under test:
	// the extracted content no longer reproduces pod_hash.
	if err := os.WriteFile(filepath.Join(podDir, "prompts", "system.md"), []byte("tampered"), 0o644); err != nil {
		t.Fatalf("tamper system.md: %v", err)
	}
	tampered, err := publish.PackTarball(podDir)
	if err != nil {
		t.Fatalf("PackTarball: %v", err)
	}
	f.ContentTarball = tampered

	err = Verify(f)
	if err == nil {
		t.Fatalf("Verify accepted a content tarball that does not reproduce pod_hash")
	}
	if !errors.Is(err, ErrContentHashMismatch) {
		t.Errorf("Verify error is not ErrContentHashMismatch: %v", err)
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

func TestCacheWritesContentWhenTarballPresent(t *testing.T) {
	f, _ := fixtureWithContent(t)
	home := t.TempDir()
	dir, err := Cache(home, f)
	if err != nil {
		t.Fatalf("Cache: %v", err)
	}
	contentDir := filepath.Join(dir, "content")

	gotTOML, err := os.ReadFile(filepath.Join(contentDir, "pod.toml"))
	if err != nil {
		t.Fatalf("content/pod.toml not written: %v", err)
	}
	if string(gotTOML) != samplePodTOML {
		t.Errorf("content/pod.toml mismatch")
	}
	gotPrompt, err := os.ReadFile(filepath.Join(contentDir, "prompts", "system.md"))
	if err != nil {
		t.Fatalf("content/prompts/system.md not written: %v", err)
	}
	if string(gotPrompt) != "hello" {
		t.Errorf("content/prompts/system.md mismatch")
	}
}

func TestCacheLegacyFetchHasNoContentDir(t *testing.T) {
	f := fixture(t) // legacy fixture: no ContentTarball
	home := t.TempDir()
	dir, err := Cache(home, f)
	if err != nil {
		t.Fatalf("Cache: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "content")); !os.IsNotExist(err) {
		t.Errorf("content dir exists (or Stat errored oddly: %v) for a legacy fetch with no tarball", err)
	}
}

// tarWithHiddenEntry builds a raw gzip tar carrying a single top-level
// `.evil` entry, bypassing publish.PackTarball entirely (its walk
// would never emit such an entry). Mirrors the publish package's own
// tarWithEntry helper — install can't reach that unexported helper
// across the package boundary, so it gets its own copy of the minimal
// construction it needs.
func tarWithHiddenEntry(t *testing.T, content string) []byte {
	t.Helper()
	var buf bytes.Buffer
	gw := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gw)
	hdr := &tar.Header{
		Name:     ".evil",
		Typeflag: tar.TypeReg,
		Mode:     0o644,
		Size:     int64(len(content)),
	}
	if err := tw.WriteHeader(hdr); err != nil {
		t.Fatalf("write tar header: %v", err)
	}
	if _, err := tw.Write([]byte(content)); err != nil {
		t.Fatalf("write tar content: %v", err)
	}
	if err := tw.Close(); err != nil {
		t.Fatalf("close tar writer: %v", err)
	}
	if err := gw.Close(); err != nil {
		t.Fatalf("close gzip writer: %v", err)
	}
	return buf.Bytes()
}

// TestVerifyRejectsHiddenEntryContentTarball proves install inherits
// publish's hidden-entry rejection (Hermes MR !42 blocker 1): a
// tarball carrying a `.evil` entry was never produced by PackTarball,
// so ExtractTarball rejects it during Verify's content re-hash step,
// and that rejection must propagate rather than be swallowed.
func TestVerifyRejectsHiddenEntryContentTarball(t *testing.T) {
	f := fixture(t)
	f.ContentTarball = tarWithHiddenEntry(t, "boom")

	err := Verify(f)
	if err == nil {
		t.Fatalf("Verify accepted a content tarball with a hidden entry")
	}
	if !errors.Is(err, publish.ErrTarballHiddenEntry) {
		t.Errorf("Verify error is not ErrTarballHiddenEntry: %v", err)
	}
}

// TestCacheRejectsHiddenEntryContentTarball covers the same rejection
// on Cache's own extraction path directly — Cache trusts its input
// per its doc comment ("callers SHOULD only call Cache after Verify
// returns nil"), but a hidden-entry tarball must still fail closed
// rather than land unverified files in the executable content/ dir,
// and must leave no content/ dir behind at all.
func TestCacheRejectsHiddenEntryContentTarball(t *testing.T) {
	f := fixture(t)
	f.ContentTarball = tarWithHiddenEntry(t, "boom")
	home := t.TempDir()

	_, err := Cache(home, f)
	if err == nil {
		t.Fatalf("Cache accepted a content tarball with a hidden entry")
	}
	if !errors.Is(err, publish.ErrTarballHiddenEntry) {
		t.Errorf("Cache error is not ErrTarballHiddenEntry: %v", err)
	}

	versionDir := filepath.Join(home, ".konareef", "installed", f.Handle, f.PodName, f.PodVersion)
	if _, statErr := os.Stat(filepath.Join(versionDir, "content")); !os.IsNotExist(statErr) {
		t.Errorf("content dir exists (or Stat errored oddly: %v) after a rejected hidden-entry tarball", statErr)
	}
	// No leftover scratch directory either — extractContentClean's
	// temp dir is a sibling of content/, so a stray "content-tmp-*"
	// would otherwise sit in versionDir forever.
	entries, readErr := os.ReadDir(versionDir)
	if readErr != nil {
		t.Fatalf("ReadDir(versionDir): %v", readErr)
	}
	for _, e := range entries {
		if e.Name() != "manifest.canon" && e.Name() != "signature.bin" && e.Name() != "meta.json" {
			t.Errorf("unexpected leftover entry in versionDir: %s", e.Name())
		}
	}
}

// TestCacheReplacesStaleContentOnReCache is the regression test for
// Hermes MR !42 blocker 2: content/ is extracted by overlay onto
// whatever is already there, so a second Cache call with a tarball
// that no longer includes a previously-cached file must not leave
// that file behind — content/ is executed directly by `pod run`, so
// a stale file there is stale *executable* content.
//
// Constructing two genuinely same-pod_hash tarballs that differ in
// file membership isn't possible (the hash covers the content), so
// this drives Cache directly with two tarballs at the same version
// dir — the scenario Cache itself must guard regardless of whether a
// real publish/install round-trip could produce it today.
func TestCacheReplacesStaleContentOnReCache(t *testing.T) {
	f, podDir := fixtureWithContent(t)
	home := t.TempDir()

	dir, err := Cache(home, f)
	if err != nil {
		t.Fatalf("first Cache: %v", err)
	}
	contentDir := filepath.Join(dir, "content")
	if _, err := os.Stat(filepath.Join(contentDir, "prompts", "system.md")); err != nil {
		t.Fatalf("prompts/system.md missing after first Cache: %v", err)
	}

	// Shrink the pod: drop the prompt file, repack, re-Cache at the
	// same version dir.
	if err := os.Remove(filepath.Join(podDir, "prompts", "system.md")); err != nil {
		t.Fatalf("remove system.md: %v", err)
	}
	shrunk, err := publish.PackTarball(podDir)
	if err != nil {
		t.Fatalf("PackTarball (shrunk): %v", err)
	}
	f.ContentTarball = shrunk

	if _, err := Cache(home, f); err != nil {
		t.Fatalf("second Cache: %v", err)
	}
	if _, err := os.Stat(filepath.Join(contentDir, "prompts", "system.md")); !os.IsNotExist(err) {
		t.Errorf("prompts/system.md survived a re-Cache with a tarball that omits it (err = %v)", err)
	}
	if _, err := os.Stat(filepath.Join(contentDir, "pod.toml")); err != nil {
		t.Errorf("content/pod.toml missing after re-Cache: %v", err)
	}
}
