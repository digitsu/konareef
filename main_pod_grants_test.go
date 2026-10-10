// Copyright 2026 Jerry David Chan, Konareef.ai
// SPDX-License-Identifier: Apache-2.0

// main_pod_grants_test.go — end-to-end CLI tests for sealed closed-pod
// grants (MCP-C01): `pod grants init`, `pod validate`, a real `pod
// publish` against a fake reef-core, the capability refusals, always-emit,
// the install line and the commission refusal (IB-00 D16).
//
// Every test scans CLI output and every public upload field for the
// fixture canaries; a canary may appear only inside the sealed body.
package main_test

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/digitsu/konareef/internal/pod"
	"github.com/digitsu/konareef/internal/publish"
)

// sealedFixtureRoot is the vendored MCP-C00 fixture directory.
const sealedFixtureRoot = "internal/pod/testdata/sealed_grants/v1"

// sealedCanaries are the fixture canaries (cases.json "canaries").
var sealedCanaries = []string{"cnry-c00k7q", "cnryc00k7q", "CNRY_C00K7Q", "cnry_a"}

// assertNoCanary fails when text contains any canary, case-insensitively.
func assertNoCanary(t *testing.T, where, text string) {
	t.Helper()
	lowered := strings.ToLower(text)
	for _, canary := range sealedCanaries {
		if strings.Contains(lowered, strings.ToLower(canary)) {
			t.Errorf("%s contains canary %q", where, canary)
		}
	}
}

// writeSealedPod builds a pod directory from a fixture head and an
// optional fixture grants file (grantsRel == "" means no grants file).
func writeSealedPod(t *testing.T, headRel, grantsRel string) string {
	t.Helper()
	dir := t.TempDir()
	head, err := os.ReadFile(filepath.Join(sealedFixtureRoot, headRel))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "pod.toml"), head, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(dir, "prompts"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "prompts", "task.md"), []byte("Do the task.\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if grantsRel != "" {
		grants, err := os.ReadFile(filepath.Join(sealedFixtureRoot, grantsRel))
		if err != nil {
			t.Fatal(err)
		}
		if err := os.MkdirAll(filepath.Join(dir, "sealed"), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "sealed", "grants.toml"), grants, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

// sealedFakeServer is a fake reef-core with a configurable capability
// advertisement and a capturing /api/pods.
type sealedFakeServer struct {
	server      *httptest.Server
	captured    []byte
	podsCalls   int
	capabilitie string
}

// newSealedFakeServer starts the fake server. capabilities is the JSON
// body for /api/health, or "" to answer 404.
func newSealedFakeServer(t *testing.T, capabilities string) *sealedFakeServer {
	t.Helper()
	fake := &sealedFakeServer{capabilitie: capabilities}
	mux := http.NewServeMux()
	mux.HandleFunc("/api/health", func(w http.ResponseWriter, r *http.Request) {
		if fake.capabilitie == "" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, fake.capabilitie)
	})
	mux.HandleFunc("/api/pods", func(w http.ResponseWriter, r *http.Request) {
		fake.podsCalls++
		fake.captured, _ = io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(podsResp{InstallURL: "https://example.test/p", RegisteredAt: "2026-09-24T00:00:00Z"})
	})
	fake.server = httptest.NewServer(mux)
	t.Cleanup(fake.server.Close)
	return fake
}

const (
	capabilitiesEnabled  = `{"status":"ok","capabilities":{"sealed_grants":["konareef-sealed-grants/v1"],"closed_grants_enabled":true}}`
	capabilitiesDisabled = `{"status":"ok","capabilities":{"sealed_grants":["konareef-sealed-grants/v1"],"closed_grants_enabled":false}}`
)

// publishedRequest is the slice of the POST /api/pods body these tests
// inspect.
type publishedRequest map[string]interface{}

// decodePublished decodes the captured POST body.
func decodePublished(t *testing.T, raw []byte) publishedRequest {
	t.Helper()
	var request publishedRequest
	if err := json.Unmarshal(raw, &request); err != nil {
		t.Fatalf("decode POST body: %v\n%s", err, raw)
	}
	return request
}

// field returns a string field of the request, base64-decoded when b64.
func (request publishedRequest) field(t *testing.T, name string, b64 bool) []byte {
	t.Helper()
	value, _ := request[name].(string)
	if !b64 {
		return []byte(value)
	}
	decoded, err := base64.StdEncoding.DecodeString(value)
	if err != nil {
		t.Fatalf("field %s is not base64: %v", name, err)
	}
	return decoded
}

// untarGzip returns the files of a gzip tar as path -> bytes.
func untarGzip(t *testing.T, data []byte) map[string][]byte {
	t.Helper()
	gz, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}
	reader := tar.NewReader(gz)
	files := map[string][]byte{}
	for {
		header, err := reader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		if header.Typeflag != tar.TypeReg {
			continue
		}
		content, _ := io.ReadAll(reader)
		files[header.Name] = content
	}
	return files
}

// TestPodGrantsInit covers the helper: it creates a 0600 file with a
// fresh salt, adds the marker, validates, and refuses a second run and an
// open pod.
func TestPodGrantsInit(t *testing.T) {
	bin := buildKonareef(t)
	dir := writeSealedPod(t, "heads/closed-no-marker.toml", "")
	stdout, stderr, code := runCLI(t, bin, nil, "pod", "grants", "init", dir)
	if code != 0 {
		t.Fatalf("grants init exit %d: %s %s", code, stdout, stderr)
	}
	info, err := os.Stat(filepath.Join(dir, "sealed", "grants.toml"))
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("grants file mode: %v %v", err, info)
	}
	head, _ := os.ReadFile(filepath.Join(dir, "pod.toml"))
	if !strings.Contains(string(head), `sealed_grants = "konareef-sealed-grants/v1"`) {
		t.Fatalf("marker not added:\n%s", head)
	}
	if _, stderr, code := runCLI(t, bin, nil, "pod", "validate", filepath.Join(dir, "pod.toml")); code != 0 {
		t.Fatalf("validate after init: exit %d: %s", code, stderr)
	}
	if _, stderr, code := runCLI(t, bin, nil, "pod", "grants", "init", dir); code != 1 || !strings.Contains(stderr, "already exists") {
		t.Fatalf("second init: exit %d: %s", code, stderr)
	}
	open := writeSealedPod(t, "heads/closed-no-marker.toml", "")
	openHead, _ := os.ReadFile(filepath.Join(open, "pod.toml"))
	_ = os.WriteFile(filepath.Join(open, "pod.toml"), bytes.Replace(openHead, []byte(`"closed"`), []byte(`"open"`), 1), 0o644)
	if _, stderr, code := runCLI(t, bin, nil, "pod", "grants", "init", open); code != 1 || !strings.Contains(stderr, "closed pods") {
		t.Fatalf("open pod init: exit %d: %s", code, stderr)
	}
}

// TestPodValidateCLI_SealedGrants runs `pod validate` on pod dirs built
// from the fixtures and checks exit code, code, and that no canary leaks
// into the output.
func TestPodValidateCLI_SealedGrants(t *testing.T) {
	bin := buildKonareef(t)
	cases := []struct {
		head, grants string
		exitCode     int
		code         string
	}{
		{"heads/closed-sealed.toml", "grants/valid-one.toml", 0, ""},
		{"heads/closed-sealed.toml", "", 1, pod.CodeSealedGrantsFileMissing},
		{"heads/closed-no-marker.toml", "grants/valid-one.toml", 1, pod.CodeSealedGrantsMarkerMissing},
		{"heads/closed-sealed.toml", "grants/secret-listed-public.toml", 1, pod.CodeSealedGrantSecretPublic},
		{"heads/closed-sealed.toml", "grants/sanitized-tool-collision.toml", 1, pod.CodeGatewayMCPToolNameCollision},
		{"heads/closed-sealed.toml", "grants/host-in-wildcard-egress.toml", 1, pod.CodeGatewayMCPHostAlsoEgress},
		{"heads/closed-sealed.toml", "grants/toml-invalid.toml", 1, pod.CodeSealedGrantsTOML},
		{"heads/closed-sealed.toml", "grants/mcp-name-trailing-newline.toml", 1, pod.CodeSealedGrantsSchema},
	}
	for _, tc := range cases {
		dir := writeSealedPod(t, tc.head, tc.grants)
		stdout, stderr, code := runCLI(t, bin, nil, "pod", "validate", filepath.Join(dir, "pod.toml"))
		if code != tc.exitCode {
			t.Errorf("%s + %s: exit %d, want %d\n%s", tc.head, tc.grants, code, tc.exitCode, stderr)
		}
		if tc.code != "" && !strings.Contains(stderr, tc.code) {
			t.Errorf("%s + %s: stderr lacks %s:\n%s", tc.head, tc.grants, tc.code, stderr)
		}
		assertNoCanary(t, "validate output for "+tc.grants, stdout+stderr)
	}
}

// TestPodPublishCLI_SealedGrantsPackaging is the acceptance test: a real
// `pod publish` of a closed pod with a sealed grant to a fake reef-core.
// The public upload fields hold no canary; the sealed body round-trips to
// the exact grants file, whose salt was rotated, and whose hash is the
// [_files] entry the signed head commits to.
func TestPodPublishCLI_SealedGrantsPackaging(t *testing.T) {
	bin := buildKonareef(t)
	home := setupTempIdentity(t)
	fake := newSealedFakeServer(t, capabilitiesEnabled)
	dir := writeSealedPod(t, "heads/closed-sealed.toml", "grants/valid-one.toml")
	original, _ := os.ReadFile(filepath.Join(dir, "sealed", "grants.toml"))

	stdout, stderr, code := runCLI(t, bin, []string{"HOME=" + home}, "pod", "publish", dir, "--server", fake.server.URL)
	if code != 0 {
		t.Fatalf("publish exit %d\nstdout: %s\nstderr: %s", code, stdout, stderr)
	}
	assertNoCanary(t, "publish output", stdout+stderr)
	if strings.Contains(stdout+stderr, "grant(s)") {
		t.Fatalf("publish output states a grant count:\n%s", stdout)
	}
	if fake.podsCalls != 1 {
		t.Fatalf("POST /api/pods called %d times", fake.podsCalls)
	}

	request := decodePublished(t, fake.captured)
	for name, value := range request {
		if name == "body_enc" {
			continue
		}
		text, _ := json.Marshal(value)
		assertNoCanary(t, "upload field "+name, string(text))
	}
	manifest := request.field(t, "manifest_canonical", true)
	assertNoCanary(t, "manifest_canonical", string(manifest))
	if !bytes.Contains(manifest, []byte(`sealed_grants = "konareef-sealed-grants/v1"`)) {
		t.Fatalf("manifest lacks the marker:\n%s", manifest)
	}

	onDisk, _ := os.ReadFile(filepath.Join(dir, "sealed", "grants.toml"))
	if bytes.Equal(onDisk, original) {
		t.Fatalf("salt was not rotated")
	}
	digest := sha256.Sum256(onDisk)
	if !bytes.Contains(manifest, []byte(`"sealed/grants.toml" = "sha256:`+hex.EncodeToString(digest[:])+`"`)) {
		t.Fatalf("[_files] does not commit to the rotated grants file")
	}

	podHash := sha256.Sum256(manifest)
	if got := string(request.field(t, "pod_hash", false)); got != hex.EncodeToString(podHash[:]) {
		t.Fatalf("pod_hash %s != sha256(manifest)", got)
	}
	sealed := &publish.SealedBody{
		Ciphertext: request.field(t, "body_enc", true),
		Nonce:      request.field(t, "body_enc_nonce", true),
		Key:        request.field(t, "body_key", true),
		Scheme:     string(request.field(t, "body_enc_scheme", false)),
	}
	plain, err := publish.OpenBodyForTest(sealed, podHash[:])
	if err != nil {
		t.Fatalf("open sealed body: %v", err)
	}
	files := untarGzip(t, plain)
	if !bytes.Equal(files["sealed/grants.toml"], onDisk) {
		t.Fatalf("sealed body does not carry the exact grants file")
	}

	// Swap and tamper: the body does not open under another head, and
	// a flipped ciphertext byte fails authentication.
	otherHash := sha256.Sum256(append(append([]byte(nil), manifest...), '\n'))
	if _, err := publish.OpenBodyForTest(sealed, otherHash[:]); err == nil {
		t.Fatalf("body opened under a different pod_hash")
	}
	sealed.Ciphertext[0] ^= 0x01
	if _, err := publish.OpenBodyForTest(sealed, podHash[:]); err == nil {
		t.Fatalf("tampered ciphertext opened")
	}
}

// TestPodPublishCLI_SealedGrantsCapabilityRefusals covers section 11.2
// and rollout step 6: an old server (404) and a server with closed grants
// off both refuse a pod with grants before any POST; a zero-grant marker
// pod still publishes to a server with the carrier but grants off.
func TestPodPublishCLI_SealedGrantsCapabilityRefusals(t *testing.T) {
	bin := buildKonareef(t)
	home := setupTempIdentity(t)
	cases := []struct {
		name, capabilities, grants string
		wantCode                   int
		wantText                   string
	}{
		{"old server", "", "grants/valid-one.toml", 1, "SEALED_GRANTS_SERVER_UNSUPPORTED"},
		{"no carrier", `{"status":"ok","capabilities":{"sealed_grants":[],"closed_grants_enabled":true}}`, "grants/valid-one.toml", 1, "SEALED_GRANTS_SERVER_UNSUPPORTED"},
		{"grants off", capabilitiesDisabled, "grants/valid-one.toml", 1, "SEALED_GRANTS_SERVER_NOT_ENABLED"},
		{"zero grants while off", capabilitiesDisabled, "grants/valid-zero.toml", 0, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fake := newSealedFakeServer(t, tc.capabilities)
			dir := writeSealedPod(t, "heads/closed-sealed.toml", tc.grants)
			stdout, stderr, code := runCLI(t, bin, []string{"HOME=" + home}, "pod", "publish", dir, "--server", fake.server.URL)
			if code != tc.wantCode {
				t.Fatalf("exit %d, want %d\n%s\n%s", code, tc.wantCode, stdout, stderr)
			}
			if tc.wantCode != 0 {
				if fake.podsCalls != 0 {
					t.Fatalf("refused publish still POSTed")
				}
				if !strings.Contains(stderr, tc.wantText) {
					t.Fatalf("stderr lacks %s: %s", tc.wantText, stderr)
				}
			}
			assertNoCanary(t, "publish output", stdout+stderr)
		})
	}
}

// TestPodPublishCLI_SealedGrantsMalformedRefusedBeforePublish checks that a
// grants file breaking a rule stops the publish before any POST, with the
// rule code and without the sealed values.
func TestPodPublishCLI_SealedGrantsMalformedRefusedBeforePublish(t *testing.T) {
	bin := buildKonareef(t)
	home := setupTempIdentity(t)
	for _, grants := range []string{"grants/secret-listed-public.toml", "grants/unknown-grant-key.toml", "grants/duplicate-authority-public-http.toml"} {
		fake := newSealedFakeServer(t, capabilitiesEnabled)
		dir := writeSealedPod(t, "heads/closed-sealed.toml", grants)
		stdout, stderr, code := runCLI(t, bin, []string{"HOME=" + home}, "pod", "publish", dir, "--server", fake.server.URL)
		if code != 1 || fake.podsCalls != 0 {
			t.Fatalf("%s: exit %d, posts %d\n%s", grants, code, fake.podsCalls, stderr)
		}
		assertNoCanary(t, "publish output for "+grants, stdout+stderr)
	}
	// ZK plus sealed grants (G15) is refused before any network call.
	dir := writeSealedPod(t, "heads/closed-sealed.toml", "grants/valid-one.toml")
	_, stderr, code := runCLI(t, bin, []string{"HOME=" + home}, "pod", "publish", dir, "--dry-run", "--zk", "--circuit-id", "konareef-pod-step-v1", "--disclosure-policy", "C")
	if code != 1 || !strings.Contains(stderr, pod.CodeSealedGrantsZKUnsupported) {
		t.Fatalf("zk: exit %d: %s", code, stderr)
	}
}

// TestPodPublishCLI_SealedGrantsAlwaysEmit checks D3 = a: with closed
// grants enabled, a legacy closed pod gets the marker and an empty grants
// file; with them off it publishes unchanged, as before.
func TestPodPublishCLI_SealedGrantsAlwaysEmit(t *testing.T) {
	bin := buildKonareef(t)
	home := setupTempIdentity(t)

	enabled := newSealedFakeServer(t, capabilitiesEnabled)
	dir := writeSealedPod(t, "heads/closed-no-marker.toml", "")
	stdout, stderr, code := runCLI(t, bin, []string{"HOME=" + home}, "pod", "publish", dir, "--server", enabled.server.URL)
	if code != 0 {
		t.Fatalf("exit %d\n%s\n%s", code, stdout, stderr)
	}
	manifest := decodePublished(t, enabled.captured).field(t, "manifest_canonical", true)
	if !bytes.Contains(manifest, []byte(`sealed_grants = "konareef-sealed-grants/v1"`)) || !bytes.Contains(manifest, []byte(`"sealed/grants.toml" = "sha256:`)) {
		t.Fatalf("always-emit did not add the carrier:\n%s", manifest)
	}

	disabled := newSealedFakeServer(t, capabilitiesDisabled)
	legacy := writeSealedPod(t, "heads/closed-no-marker.toml", "")
	if _, stderr, code := runCLI(t, bin, []string{"HOME=" + home}, "pod", "publish", legacy, "--server", disabled.server.URL); code != 0 {
		t.Fatalf("legacy publish exit %d: %s", code, stderr)
	}
	legacyManifest := decodePublished(t, disabled.captured).field(t, "manifest_canonical", true)
	if bytes.Contains(legacyManifest, []byte("sealed_grants")) || bytes.Contains(legacyManifest, []byte("sealed/grants.toml")) {
		t.Fatalf("carrier added while closed grants are off:\n%s", legacyManifest)
	}
	if _, err := os.Stat(filepath.Join(legacy, "sealed")); !os.IsNotExist(err) {
		t.Fatalf("sealed/ created while closed grants are off")
	}
}

// TestCommissionDraftRefusesSealedGrantsPod checks IB-00 D16 on the
// client: a marker-bearing pod is not commissionable.
func TestCommissionDraftRefusesSealedGrantsPod(t *testing.T) {
	bin := buildKonareef(t)
	dir := writeSealedPod(t, "heads/closed-sealed.toml", "grants/valid-one.toml")
	stdout, stderr, code := runCLI(t, bin, []string{"HOME=" + t.TempDir()}, "commission", "draft", "dave/sealed-grants-fixture@1.0.0", "--pod-dir", dir)
	if code != 1 || !strings.Contains(stderr, "commission_sealed_grants_unsupported") {
		t.Fatalf("draft did not refuse: exit %d\n%s\n%s", code, stdout, stderr)
	}
	assertNoCanary(t, "commission output", stdout+stderr)
}
