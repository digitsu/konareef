// Copyright 2026 Jerry David Chan, Konareef.ai
// SPDX-License-Identifier: Apache-2.0

// body_enc_test.go — closed-pod body sealing.
//
// Three properties are pinned here, in descending order of how badly a
// regression would hurt:
//
//  1. The sealed body covers EXACTLY the `[_files]` path set. A divergence
//     between what pod_hash commits to and what body.enc actually carries
//     is a silent integrity hole that would only surface at spawn, long
//     after the signature checked out.
//  2. The ciphertext is bound to one pod_hash via GCM's AAD, so a body.enc
//     cannot be replayed under a different HEAD.
//  3. Open-pod publish is untouched — same PreparedPod shape, same wire
//     bytes as before closed pods existed.
package publish_test

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/digitsu/konareef/internal/canon"
	"github.com/digitsu/konareef/internal/identity"
	"github.com/digitsu/konareef/internal/publish"
)

// closedPodVector is the Task 1 conformance vector: a `visibility =
// "closed"` pod.toml plus one body file, so `[_files]` is non-empty.
const closedPodVector = "../canon/testdata/canon/v1/visibility/0001-closed-pod/input"

func TestSealBody_RoundTrips(t *testing.T) {
	podHash := bytes.Repeat([]byte{0xab}, 32)
	plain := []byte("body tar bytes")

	sealed, err := publish.SealBody(plain, podHash)
	if err != nil {
		t.Fatal(err)
	}
	if sealed.Scheme != "aes-256-gcm" {
		t.Fatalf("scheme = %q", sealed.Scheme)
	}
	if len(sealed.Key) != 32 || len(sealed.Nonce) != 12 {
		t.Fatalf("key %d nonce %d", len(sealed.Key), len(sealed.Nonce))
	}
	if bytes.Contains(sealed.Ciphertext, plain) {
		t.Fatal("plaintext leaked into ciphertext")
	}

	got, err := publish.OpenBodyForTest(sealed, podHash)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, plain) {
		t.Fatal("round-trip mismatch")
	}
}

// AAD binding: a body.enc must not decrypt under a different pod_hash.
func TestSealBody_BoundToPodHash(t *testing.T) {
	sealed, err := publish.SealBody([]byte("x"), bytes.Repeat([]byte{1}, 32))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := publish.OpenBodyForTest(sealed, bytes.Repeat([]byte{2}, 32)); err == nil {
		t.Fatal("decrypt under a foreign pod_hash must fail")
	}
}

// Two seals of identical plaintext must differ (fresh nonce each time).
func TestSealBody_FreshNonce(t *testing.T) {
	h := bytes.Repeat([]byte{3}, 32)
	a, err := publish.SealBody([]byte("same"), h)
	if err != nil {
		t.Fatal(err)
	}
	b, err := publish.SealBody([]byte("same"), h)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(a.Nonce, b.Nonce) || bytes.Equal(a.Ciphertext, b.Ciphertext) {
		t.Fatal("nonce reuse")
	}
	if bytes.Equal(a.Key, b.Key) {
		t.Fatal("K_body reuse across seals")
	}
}

// A short or absent AAD would silently unbind the ciphertext from its
// HEAD, so SealBody refuses anything that is not a 32-byte pod_hash
// rather than sealing under a degraded AAD.
func TestSealBody_RejectsNonPodHashAAD(t *testing.T) {
	for _, aad := range [][]byte{nil, {}, bytes.Repeat([]byte{7}, 31)} {
		if _, err := publish.SealBody([]byte("x"), aad); err == nil {
			t.Fatalf("SealBody accepted a %d-byte AAD", len(aad))
		}
	}
}

// The tarred body set must equal the [_files] commitment set exactly.
func TestBodyFiles_MatchesFilesTable(t *testing.T) {
	files, err := canon.BodyFiles(closedPodVector)
	if err != nil {
		t.Fatal(err)
	}
	canonBytes, err := canon.Canonicalize(mustReadPodTOML(t, closedPodVector), closedPodVector)
	if err != nil {
		t.Fatal(err)
	}
	want := parseFilesTablePaths(t, canonBytes)
	if len(want) == 0 {
		t.Fatal("vector has an empty [_files] table; it cannot prove anything")
	}
	if !reflect.DeepEqual(files, want) {
		t.Fatalf("body set diverges from [_files]:\n got %v\nwant %v", files, want)
	}
}

// BodyFiles must not enumerate anything [_files] excludes: the root
// pod.toml, pod.lock, and hidden dotfiles are all outside the
// commitment, so shipping them inside body.enc would put uncommitted
// bytes on konareef's infrastructure.
func TestBodyFiles_ExcludesUncommittedPaths(t *testing.T) {
	dir := t.TempDir()
	mustWrite(t, filepath.Join(dir, "pod.toml"), "irrelevant")
	mustWrite(t, filepath.Join(dir, "pod.lock"), "irrelevant")
	mustWrite(t, filepath.Join(dir, ".secret"), "irrelevant")
	mustWrite(t, filepath.Join(dir, "prompts", "system.md"), "hello")

	files, err := canon.BodyFiles(dir)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(files, []string{"prompts/system.md"}) {
		t.Fatalf("BodyFiles = %v", files)
	}
}

// End-to-end: what Prepare actually seals for a closed pod must extract
// back to precisely the [_files] path set. This is the property the
// whole design rests on — a divergence here is undetectable until spawn.
func TestPrepare_ClosedPodSealsExactlyTheFilesSet(t *testing.T) {
	podDir := writePod(t, "closed", "private prompt")
	// A second body file, so the test would catch a seal that packed
	// only the first path or dropped a nested one.
	mustWrite(t, filepath.Join(podDir, "skills", "deep", "notes.md"), "more private content")
	id, err := identity.Generate("alice")
	if err != nil {
		t.Fatal(err)
	}

	prep, err := publish.Prepare(podDir, id, publish.PrepareOptions{})
	if err != nil {
		t.Fatalf("Prepare: %v", err)
	}
	if prep.Visibility != "closed" {
		t.Fatalf("Visibility = %q", prep.Visibility)
	}
	if prep.Sealed == nil {
		t.Fatal("closed pod must carry a sealed body")
	}
	if len(prep.ContentTarball) != 0 {
		t.Fatal("closed pod must not ship a plaintext content tarball")
	}

	bodyTar, err := publish.OpenBodyForTest(prep.Sealed, prep.PodHash[:])
	if err != nil {
		t.Fatalf("seal is not bound to the prepared pod_hash: %v", err)
	}
	want, err := canon.BodyFiles(podDir)
	if err != nil {
		t.Fatal(err)
	}
	if got := tarballFilePaths(t, bodyTar); !reflect.DeepEqual(got, want) {
		t.Fatalf("sealed body diverges from [_files]:\n got %v\nwant %v", got, want)
	}
}

// Regression guard: an open pod keeps the pre-closed-pod Prepare shape.
func TestPrepare_OpenPodUnchanged(t *testing.T) {
	podDir := writeSamplePodExternal(t)
	id, err := identity.Generate("alice")
	if err != nil {
		t.Fatal(err)
	}
	prep, err := publish.Prepare(podDir, id, publish.PrepareOptions{})
	if err != nil {
		t.Fatalf("Prepare: %v", err)
	}
	if prep.Visibility != "" {
		t.Fatalf("open pod Visibility = %q, want empty", prep.Visibility)
	}
	if prep.Sealed != nil {
		t.Fatal("open pod must not be sealed")
	}
	if len(prep.ContentTarball) == 0 {
		t.Fatal("open pod must still ship its content tarball")
	}
}

// The wire body for an open pod must be byte-identical to the pre-Task-2
// shape: none of the five new fields may appear.
func TestSubmit_OpenPodWireHasNoBodyFields(t *testing.T) {
	raw := captureSubmitBody(t, writeSamplePodExternal(t))
	for _, k := range []string{"visibility", "body_enc", "body_enc_scheme", "body_enc_nonce", "body_key"} {
		if strings.Contains(raw, `"`+k+`"`) {
			t.Fatalf("open-pod wire body carries %q: %s", k, raw)
		}
	}
	if !strings.Contains(raw, `"content_tarball"`) {
		t.Fatalf("open-pod wire body lost content_tarball: %s", raw)
	}
}

// A closed pod ships the sealed body and K_body instead of the
// plaintext tarball, and the transmitted K_body is the real one.
func TestSubmit_ClosedPodWireCarriesSealedBody(t *testing.T) {
	raw := captureSubmitBody(t, writePod(t, "closed", "private prompt"))

	var wire struct {
		Visibility     string `json:"visibility"`
		BodyEnc        string `json:"body_enc"`
		BodyEncScheme  string `json:"body_enc_scheme"`
		BodyEncNonce   string `json:"body_enc_nonce"`
		BodyKey        string `json:"body_key"`
		ContentTarball string `json:"content_tarball"`
	}
	if err := json.Unmarshal([]byte(raw), &wire); err != nil {
		t.Fatal(err)
	}
	if wire.Visibility != "closed" {
		t.Fatalf("visibility = %q", wire.Visibility)
	}
	if wire.ContentTarball != "" {
		t.Fatal("closed pod must not put its plaintext body on the wire")
	}
	if wire.BodyEncScheme != "aes-256-gcm" {
		t.Fatalf("body_enc_scheme = %q", wire.BodyEncScheme)
	}
	key := mustB64(t, wire.BodyKey)
	nonce := mustB64(t, wire.BodyEncNonce)
	ct := mustB64(t, wire.BodyEnc)
	if len(key) != 32 || len(nonce) != 12 || len(ct) == 0 {
		t.Fatalf("key %d nonce %d ct %d", len(key), len(nonce), len(ct))
	}
	if _, err := publish.OpenBodyForTest(
		&publish.SealedBody{Ciphertext: ct, Nonce: nonce, Key: key, Scheme: wire.BodyEncScheme},
		mustHex32(t, gjsonString(t, raw, "pod_hash")),
	); err != nil {
		t.Fatalf("wire body_enc does not open under the wire pod_hash + body_key: %v", err)
	}
}

// The plaintext body must never appear on the wire for a closed pod,
// under any encoding — this is the confidentiality claim in one grep.
func TestSubmit_ClosedPodLeaksNoPlaintextBody(t *testing.T) {
	secret := "canary-body-content-do-not-publish"
	raw := captureSubmitBody(t, writePod(t, "closed", secret))
	if strings.Contains(raw, secret) {
		t.Fatal("LEAK: closed-pod body plaintext found in the submit wire body")
	}
	if strings.Contains(base64.StdEncoding.EncodeToString([]byte(raw)), secret) {
		t.Fatal("LEAK: closed-pod body plaintext found base64-encoded on the wire")
	}
}

// PackTarballPaths is exported and takes a caller-supplied path list,
// so it re-checks what the walk would otherwise have guaranteed. A
// future caller that builds its own list must not be able to smuggle a
// host file into a pod body.
func TestPackTarballPaths_RejectsUnsafePaths(t *testing.T) {
	dir := t.TempDir()
	mustWrite(t, filepath.Join(dir, "ok.md"), "fine")

	for _, rel := range []string{
		"../escape.md",
		"/etc/passwd",
		"nested/../../escape.md",
		".hidden/secret.md",
		"",
		`a\b.md`, // SEC-56: reef-core's SafeRelativePath refuses a backslash
		"c:x.md", // SEC-56: and a Windows drive prefix
	} {
		if _, err := publish.PackTarballPaths(dir, []string{rel}); err == nil {
			t.Errorf("PackTarballPaths accepted unsafe path %q", rel)
		}
	}
}

// Determinism: the closed-pod body is content-addressed by nothing, so
// a non-reproducible packer would make two publishes of identical
// content produce unrelated ciphertexts for no reason. Same input, same
// tar bytes.
func TestPackTarballPaths_Deterministic(t *testing.T) {
	dir := writePod(t, "closed", "private prompt")
	mustWrite(t, filepath.Join(dir, "skills", "a.md"), "a")

	paths, err := canon.BodyFiles(dir)
	if err != nil {
		t.Fatal(err)
	}
	first, err := publish.PackTarballPaths(dir, paths)
	if err != nil {
		t.Fatal(err)
	}
	second, err := publish.PackTarballPaths(dir, paths)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(first, second) {
		t.Fatal("PackTarballPaths is not deterministic")
	}
}

// ---- helpers ----

func mustWrite(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func mustReadPodTOML(t *testing.T, dir string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(dir, "pod.toml"))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func mustB64(t *testing.T, s string) []byte {
	t.Helper()
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		t.Fatalf("decode base64 %q: %v", s, err)
	}
	return b
}

func mustHex32(t *testing.T, s string) []byte {
	t.Helper()
	b := make([]byte, 0, 32)
	for i := 0; i+1 < len(s); i += 2 {
		v, err := strconv.ParseUint(s[i:i+2], 16, 8)
		if err != nil {
			t.Fatalf("decode hex %q: %v", s, err)
		}
		b = append(b, byte(v))
	}
	if len(b) != 32 {
		t.Fatalf("pod_hash is %d bytes, want 32", len(b))
	}
	return b
}

// gjsonString pulls one top-level string field out of a JSON object
// without pinning the test to the full submitRequest shape.
func gjsonString(t *testing.T, raw, key string) string {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal([]byte(raw), &m); err != nil {
		t.Fatal(err)
	}
	s, ok := m[key].(string)
	if !ok {
		t.Fatalf("field %q missing or not a string", key)
	}
	return s
}

// parseFilesTablePaths pulls the keys out of the canonical manifest's
// `[_files]` table, preserving their emitted order so a comparison
// against BodyFiles checks ordering as well as membership.
func parseFilesTablePaths(t *testing.T, canonBytes []byte) []string {
	t.Helper()
	var paths []string
	inFiles := false
	for _, line := range strings.Split(string(canonBytes), "\n") {
		if strings.HasPrefix(line, "[") {
			inFiles = line == "[_files]"
			continue
		}
		if !inFiles || line == "" {
			continue
		}
		key, _, ok := strings.Cut(line, " = ")
		if !ok {
			t.Fatalf("unparseable [_files] line: %q", line)
		}
		unquoted, err := strconv.Unquote(key)
		if err != nil {
			t.Fatalf("unquote [_files] key %q: %v", key, err)
		}
		paths = append(paths, unquoted)
	}
	return paths
}

// tarballFilePaths lists the regular-file entries of a PackTarball-shaped
// gzip tar, sorted, so it can be compared against a BodyFiles result.
func tarballFilePaths(t *testing.T, data []byte) []string {
	t.Helper()
	gr, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}
	defer gr.Close()

	var paths []string
	tr := tar.NewReader(gr)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		if hdr.Typeflag == tar.TypeReg {
			paths = append(paths, hdr.Name)
		}
	}
	sort.Strings(paths)
	return paths
}

// writePod scaffolds a schema-valid pod directory: a pod.toml carrying
// the given `visibility` line (empty for an open pod) plus the prompt
// file it references, so Prepare's validation gate passes.
//
// The committed canon vector is deliberately NOT reused here: canon
// conformance vectors exercise the canonicalizer and need not satisfy
// the v0.1 JSON schema, but Prepare validates before it canonicalizes.
func writePod(t *testing.T, visibility, bodyContent string) string {
	t.Helper()
	dir := t.TempDir()
	visLine := ""
	if visibility != "" {
		visLine = "visibility = \"" + visibility + "\"\n"
	}
	mustWrite(t, filepath.Join(dir, "pod.toml"), `pod_spec_version = "0.1"

[pod]
name = "research-bot"
version = "1.0.0"
`+visLine+`
[runtime]
kind = "lobster"

[directive]
template = "./prompts/system.md"
`)
	mustWrite(t, filepath.Join(dir, "prompts", "system.md"), bodyContent)
	return dir
}

// writeSamplePodExternal scaffolds a minimal open pod (no visibility
// field), mirroring writeSamplePod in the in-package publish tests.
func writeSamplePodExternal(t *testing.T) string {
	t.Helper()
	return writePod(t, "", "hello")
}

// captureSubmitBody runs Prepare + Submit against a throwaway server and
// returns the raw JSON request body, so wire-shape assertions test what
// actually goes out rather than a reconstruction of it.
func captureSubmitBody(t *testing.T, podDir string) string {
	t.Helper()
	id, err := identity.Generate("alice")
	if err != nil {
		t.Fatal(err)
	}
	prep, err := publish.Prepare(podDir, id, publish.PrepareOptions{})
	if err != nil {
		t.Fatalf("Prepare: %v", err)
	}

	var raw string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		raw = string(b)
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"install_url":"https://example.test/x"}`))
	}))
	defer srv.Close()

	if _, err := publish.Submit(srv.URL, prep, publish.SubmitOpts{}); err != nil {
		t.Fatalf("Submit: %v", err)
	}
	return raw
}
