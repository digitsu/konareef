// Copyright 2026 Jerry David Chan, Konareef.ai
// SPDX-License-Identifier: Apache-2.0

// main_zk_publish_test.go — black-box CLI exec test for the P1.3 ZK
// publish flag surface. Builds the konareef binary once per `go test`
// invocation, then drives it against an httptest.Server stub of
// reef-core's /api/pods endpoint plus /api/discovery + /.well-known/
// circuits/*/vkey routes.
package main_test

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
)

// buildKonareefWithTags compiles the konareef binary with the given
// build tags (in addition to the always-on `testhooks` tag) and
// returns the path to the binary. The `testhooks` tag activates the
// env-var seams used throughout this test file:
//
//   - KONAREEF_TEST_ANCHOR_HASH_HEX   (main_anchor_backend_testhook.go)
//   - KONAREEF_TEST_VKEY_BASE_URL     (main_resolver_testhook.go)
//
// Production release binaries are built WITHOUT `testhooks` and the
// env vars above have no effect; the corresponding `!testhooks` files
// fail closed (see MR !21 round-2 B1 / note 677).
//
// Tests that need additional tag-gated instrumentation
// (e.g. `test_dump_submit_opts`) should call this helper directly;
// all other tests should use the buildKonareef wrapper.
func buildKonareefWithTags(t *testing.T, tags ...string) string {
	t.Helper()
	bin := filepath.Join(t.TempDir(), "konareef-test-bin")
	// `testhooks` is always present; callers append extra tags on top.
	allTags := append([]string{"testhooks"}, tags...)
	args := []string{"build", "-o", bin, "-tags", strings.Join(allTags, ","), "."}
	cmd := exec.Command("go", args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("go build failed: %v\n%s", err, out)
	}
	return bin
}

// buildKonareef compiles the konareef binary with the always-on
// `testhooks` build tag (no other tags). Most CLI tests should use
// this wrapper.
func buildKonareef(t *testing.T) string {
	return buildKonareefWithTags(t)
}

// discoveryCircuit describes one circuit entry in the discovery
// manifest.
type discoveryCircuit struct {
	CircuitID  string `json:"circuit_id"`
	VkeySha256 string `json:"vkey_sha256"`
}

// discoveryResp models the JSON body served at /api/discovery. Using
// a typed struct + json.NewEncoder.Encode guarantees a valid JSON
// payload (no backslash-escaped quote pitfalls inside raw-string
// templates).
type discoveryResp struct {
	PaygateZKDomain string             `json:"paygate_zk_domain"`
	Circuits        []discoveryCircuit `json:"circuits"`
}

// podsResp models the 201/200 body served by the stub /api/pods route.
type podsResp struct {
	InstallURL   string `json:"install_url"`
	RegisteredAt string `json:"registered_at"`
	Idempotent   bool   `json:"idempotent,omitempty"`
}

// vkeyFixtureSha256Hex returns the SHA-256 hex of 256 × 0x42 — the
// same constant used by the publish-package pin-check fixtures. The
// literal value below is sha256 of 256 bytes of 0x42. Reproduce via:
//
//	python3 -c "import hashlib; print(hashlib.sha256(bytes([0x42]*256)).hexdigest())"
//	# → b0102e3e5f3ced3b4bd1e9d1a08ef35c5fce216b024beea399c4a51b95ece8e7
func vkeyFixtureSha256Hex() string {
	return "b0102e3e5f3ced3b4bd1e9d1a08ef35c5fce216b024beea399c4a51b95ece8e7"
}

// publisherDomainFromURL extracts a discovery-manifest-shaped
// paygate_zk_domain string from an httptest.Server URL. The Tier-1
// backend's BaseURLOverride path re-routes to the test server's URL,
// but ResolveRequest.Validate() still applies strict DNS rules on
// PublisherDomain. A bare server host `127.0.0.1:PORT` would fail
// validation (contains ':'), so we always return a synthetic
// placeholder ("paygate-zk.publisher.example") in the service-host
// shape reef-core's /api/discovery returns; the publish path strips
// the `paygate-zk.` prefix via PublisherBaseDomain (MR !21 round-2 B2
// / note 680) before handing the base domain to the resolver.
func publisherDomainFromURL(_ string) string {
	return "paygate-zk.publisher.example"
}

// newDiscoveryAwareTestServer mounts /api/discovery + /api/pods +
// /.well-known/circuits/<id>/vkey on a single httptest.Server. The
// discovery JSON's paygate_zk_domain is bare placeholder text (the
// Tier-1 backend's BaseURLOverride re-routes the actual vkey fetch
// to this server regardless of the published domain). The publish
// body capture only fires on the /api/pods route.
func newDiscoveryAwareTestServer(t *testing.T, capture *[]byte) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	matchingPin := vkeyFixtureSha256Hex()
	var host string
	mux.HandleFunc("/api/discovery", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(discoveryResp{
			PaygateZKDomain: host,
			Circuits: []discoveryCircuit{
				{CircuitID: "konareef-pod-step-v1", VkeySha256: matchingPin},
			},
		})
	})
	mux.HandleFunc("/.well-known/circuits/konareef-pod-step-v1/vkey",
		func(w http.ResponseWriter, r *http.Request) {
			body := make([]byte, 256)
			for i := range body {
				body[i] = 0x42
			}
			_, _ = w.Write(body)
		})
	mux.HandleFunc("/api/pods", func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		*capture = body
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(podsResp{
			InstallURL:   "https://example.test/p",
			RegisteredAt: "2026-06-10T00:00:00Z",
		})
	})
	srv := httptest.NewServer(mux)
	host = publisherDomainFromURL(srv.URL)
	return srv
}

// stubDiscoveryAndReefCore is the parameterised variant used by the
// pin-mismatch / lowercase-policy tests. Same shape as
// newDiscoveryAwareTestServer but takes `matchingPin` as an argument.
func stubDiscoveryAndReefCore(t *testing.T, capture *[]byte, matchingPin string) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	var host string
	mux.HandleFunc("/api/discovery", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(discoveryResp{
			PaygateZKDomain: host,
			Circuits: []discoveryCircuit{
				{CircuitID: "konareef-pod-step-v1", VkeySha256: matchingPin},
			},
		})
	})
	mux.HandleFunc("/.well-known/circuits/konareef-pod-step-v1/vkey",
		func(w http.ResponseWriter, r *http.Request) {
			body := make([]byte, 256)
			for i := range body {
				body[i] = 0x42
			}
			_, _ = w.Write(body)
		})
	mux.HandleFunc("/api/pods", func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		*capture = body
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(podsResp{
			InstallURL:   "https://example.test/p",
			RegisteredAt: "2026-06-10T00:00:00Z",
		})
	})
	srv := httptest.NewServer(mux)
	host = publisherDomainFromURL(srv.URL)
	return srv
}

// runCLI invokes the konareef test binary with args + extra env. The
// child's $HOME / $KONAREEF_STATE_DIR / $KONAREEF_TEST_*  knobs can
// be overridden via env entries. Test seams baked in:
//
//   - KONAREEF_ALLOW_PLAINTEXT_SALT=1 — force the plain-file
//     saltstore backend (the OS keychain isn't usable from a Go test
//     child process on most hosts).
//   - KONAREEF_TEST_VKEY_BASE_URL is auto-populated from --server when
//     the caller did not set it explicitly. This makes the Tier-1
//     vkey fetch route back to the test httptest.Server (via
//     BaseURLOverride) instead of hitting the real
//     `https://paygate-zk.publisher.example` host.
// confirmPublishFlagArg mirrors main's confirmFlagPublish. This file is
// package main_test, so it cannot see the unexported constant. A rename
// there fails loudly here: the gate refuses and every publish test goes red.
const confirmPublishFlagArg = "--confirm-publish"

// withPublishConfirmation adds --confirm-publish to a bare `pod publish`.
//
// A live publish now refuses without either a terminal to ask or that flag,
// and these subprocesses have neither. This is the same hermetic seam as the
// Keychain override below: a real automated publisher passes the flag, so
// these tests pass it too.
//
// Scoped deliberately. It fires only on `pod publish`, never on
// `pod listing publish`, which has no such flag and would fail on an unknown
// one. A `--dry-run` publish is free and ungated, so it is left alone.
//
// The gate's own behaviour is covered in main_confirm_gate_test.go. Nothing
// here should be read as testing it.
func withPublishConfirmation(args []string) []string {
	if len(args) < 2 || args[0] != "pod" || args[1] != "publish" {
		return args
	}
	for _, a := range args {
		if a == "--dry-run" || a == "-dry-run" || a == confirmPublishFlagArg {
			return args
		}
	}
	return append(append([]string{}, args...), confirmPublishFlagArg)
}

func runCLI(t *testing.T, bin string, env []string, args ...string) (stdout, stderr string, code int) {
	t.Helper()
	args = withPublishConfirmation(args)
	cmd := exec.Command(bin, args...)
	cmd.Env = append(os.Environ(), env...)
	cmd.Env = append(cmd.Env, "KONAREEF_ALLOW_PLAINTEXT_SALT=1")
	// Hermetic seam: drop the macOS Keychain backend so the
	// resolver cannot pop a UI prompt that would block this
	// non-interactive subprocess. See defaultResolveOpts wiring.
	cmd.Env = append(cmd.Env, "KONAREEF_DISABLE_KEYCHAIN_BACKEND=1")
	// Auto-route the Tier-1 vkey fetch to the --server URL if the
	// caller has not pre-set KONAREEF_TEST_VKEY_BASE_URL.
	hasVkeyOverride := false
	var serverArg string
	for _, kv := range env {
		if strings.HasPrefix(kv, "KONAREEF_TEST_VKEY_BASE_URL=") {
			hasVkeyOverride = true
		}
	}
	for i, a := range args {
		if a == "--server" && i+1 < len(args) {
			serverArg = args[i+1]
			break
		}
	}
	if !hasVkeyOverride && serverArg != "" {
		cmd.Env = append(cmd.Env, "KONAREEF_TEST_VKEY_BASE_URL="+serverArg)
	}
	var outBuf, errBuf bytes.Buffer
	cmd.Stdout = &outBuf
	cmd.Stderr = &errBuf
	err := cmd.Run()
	if exitErr, ok := err.(*exec.ExitError); ok {
		code = exitErr.ExitCode()
	}
	return outBuf.String(), errBuf.String(), code
}

// setupTempIdentity creates a temp $HOME and runs `konareef pod
// identity create` so the publish path can load a real identity.
//
// Hermetic: runs exactly one identity-create command with the temp
// HOME set via cmd.Env. Never mutates the host's identity.
func setupTempIdentity(t *testing.T) string {
	t.Helper()
	home := t.TempDir()
	bin := buildKonareef(t)
	cmd := exec.Command(bin, "pod", "identity", "create", "--handle", "alice")
	cmd.Env = append(os.Environ(), "HOME="+home)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("identity create: %v\n%s", err, out)
	}
	return home
}

// --- Parse-time fail-closed matrix ---

func TestCLIRejectsZKWithoutCircuitID(t *testing.T) {
	bin := buildKonareef(t)
	podDir := "internal/publish/testdata/pod-sample-zk"
	_, stderr, code := runCLI(t, bin, nil, "pod", "publish", podDir, "--zk", "--disclosure-policy", "C")
	if code != 2 {
		t.Errorf("exit = %d, want 2", code)
	}
	if !strings.Contains(stderr, "ERR_ZK_REQUIRES_CIRCUIT_ID") {
		t.Errorf("stderr missing code; got %s", stderr)
	}
}

func TestCLIRejectsZKWithoutDisclosurePolicy(t *testing.T) {
	bin := buildKonareef(t)
	podDir := "internal/publish/testdata/pod-sample-zk"
	_, stderr, code := runCLI(t, bin, nil, "pod", "publish", podDir, "--zk", "--circuit-id", "konareef-pod-step-v1")
	if code != 2 {
		t.Errorf("exit = %d, want 2", code)
	}
	if !strings.Contains(stderr, "ERR_ZK_REQUIRES_DISCLOSURE_POLICY") {
		t.Errorf("stderr missing code; got %s", stderr)
	}
}

func TestCLIRejectsInvalidDisclosurePolicyValue(t *testing.T) {
	bin := buildKonareef(t)
	podDir := "internal/publish/testdata/pod-sample-zk"
	_, stderr, code := runCLI(t, bin, nil, "pod", "publish", podDir, "--zk",
		"--circuit-id", "c1", "--disclosure-policy", "X")
	if code != 2 {
		t.Errorf("exit = %d, want 2", code)
	}
	if !strings.Contains(stderr, "ERR_INVALID_DISCLOSURE_POLICY") {
		t.Errorf("stderr missing code; got %s", stderr)
	}
}

func TestCLIAcceptsFullZKQuadAndWiresWireBody(t *testing.T) {
	bin := buildKonareef(t)
	var captured []byte
	srv := newDiscoveryAwareTestServer(t, &captured)
	defer srv.Close()

	tmpHome := setupTempIdentity(t)

	podDir := "internal/publish/testdata/pod-sample-zk"
	_, stderr, code := runCLI(t, bin,
		[]string{"HOME=" + tmpHome},
		"pod", "publish", podDir,
		"--server", srv.URL,
		"--zk", "--circuit-id", "konareef-pod-step-v1",
		"--disclosure-policy", "C")
	if code != 0 {
		t.Fatalf("exit = %d, want 0\nstderr:\n%s", code, stderr)
	}

	var got map[string]any
	if err := json.Unmarshal(captured, &got); err != nil {
		t.Fatalf("decode wire body: %v\nraw=%s", err, captured)
	}
	if got["circuit_id"] != "konareef-pod-step-v1" {
		t.Errorf("circuit_id = %v", got["circuit_id"])
	}
	if got["zk_enabled"] != true {
		t.Errorf("zk_enabled = %v", got["zk_enabled"])
	}
	if got["disclosure_policy"] != "C" {
		t.Errorf("disclosure_policy = %v", got["disclosure_policy"])
	}
}

// --- Pin-mismatch / idempotent / case-insensitive ---

func TestCLIPinMismatchPreventsSubmit(t *testing.T) {
	bin := buildKonareef(t)
	var captured []byte
	srv := stubDiscoveryAndReefCore(t, &captured,
		"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	defer srv.Close()

	tmpHome := setupTempIdentity(t)
	podDir := "internal/publish/testdata/pod-sample-zk"
	_, stderr, code := runCLI(t, bin,
		[]string{"HOME=" + tmpHome},
		"pod", "publish", podDir,
		"--server", srv.URL,
		"--zk", "--circuit-id", "konareef-pod-step-v1",
		"--disclosure-policy", "C")
	if code == 0 {
		t.Fatalf("exit = 0, want non-zero on pin mismatch; stderr=%s", stderr)
	}
	if !strings.Contains(stderr, "ERR_CIRCUIT_PIN_MISMATCH") {
		t.Errorf("stderr missing ERR_CIRCUIT_PIN_MISMATCH; got %s", stderr)
	}
	if captured != nil {
		t.Errorf("publish.Submit was reached on pin mismatch: body=%s", captured)
	}
}

func TestCLIRepublishIsIdempotent(t *testing.T) {
	bin := buildKonareef(t)
	tmpHome := setupTempIdentity(t)
	podDir := "internal/publish/testdata/pod-sample-zk"
	matchingPin := vkeyFixtureSha256Hex()

	var podsCount atomic.Int32
	var host string
	mux := http.NewServeMux()
	mux.HandleFunc("/api/discovery", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(discoveryResp{
			PaygateZKDomain: host,
			Circuits: []discoveryCircuit{
				{CircuitID: "konareef-pod-step-v1", VkeySha256: matchingPin},
			},
		})
	})
	mux.HandleFunc("/.well-known/circuits/konareef-pod-step-v1/vkey",
		func(w http.ResponseWriter, r *http.Request) {
			_, _ = w.Write(bytes.Repeat([]byte{0x42}, 256))
		})
	mux.HandleFunc("/api/pods", func(w http.ResponseWriter, r *http.Request) {
		n := podsCount.Add(1)
		w.Header().Set("Content-Type", "application/json")
		if n == 1 {
			w.WriteHeader(http.StatusCreated)
		} else {
			w.WriteHeader(http.StatusOK)
		}
		_ = json.NewEncoder(w).Encode(podsResp{
			InstallURL:   "https://example.test/p",
			RegisteredAt: "2026-06-10T00:00:00Z",
			Idempotent:   true,
		})
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()
	host = publisherDomainFromURL(srv.URL)

	for _, label := range []string{"first", "second-noop"} {
		_, stderr, code := runCLI(t, bin,
			[]string{"HOME=" + tmpHome},
			"pod", "publish", podDir,
			"--server", srv.URL,
			"--zk", "--circuit-id", "konareef-pod-step-v1",
			"--disclosure-policy", "C")
		if code != 0 {
			t.Fatalf("[%s] exit = %d, want 0; stderr=%s", label, code, stderr)
		}
	}
	if got := podsCount.Load(); got != 2 {
		t.Errorf("expected 2 /api/pods POSTs, got %d", got)
	}
}

func TestCLIAcceptsLowercaseDisclosurePolicy(t *testing.T) {
	for _, in := range []string{"c", "C", "d", "D"} {
		t.Run("input-"+in, func(t *testing.T) {
			bin := buildKonareef(t)
			var captured []byte
			matchingPin := vkeyFixtureSha256Hex()
			srv := stubDiscoveryAndReefCore(t, &captured, matchingPin)
			defer srv.Close()
			tmpHome := setupTempIdentity(t)
			stateDir := t.TempDir()
			podDir := "internal/publish/testdata/pod-sample-zk"
			_, stderr, code := runCLI(t, bin,
				[]string{"HOME=" + tmpHome, "KONAREEF_STATE_DIR=" + stateDir},
				"pod", "publish", podDir,
				"--server", srv.URL,
				"--zk", "--circuit-id", "konareef-pod-step-v1",
				"--disclosure-policy", in)
			if code != 0 {
				t.Fatalf("exit = %d, want 0; stderr=%s", code, stderr)
			}
			var got map[string]any
			if err := json.Unmarshal(captured, &got); err != nil {
				t.Fatalf("decode wire body: %v", err)
			}
			wantPolicy := strings.ToUpper(in)
			if got["disclosure_policy"] != wantPolicy {
				t.Errorf("disclosure_policy = %v, want %s", got["disclosure_policy"], wantPolicy)
			}
		})
	}
}

// --- --pin-circuit-vkey ---

func TestCLIPinCircuitVkeyRequiresCircuitID(t *testing.T) {
	bin := buildKonareef(t)
	var hits int32
	mux := http.NewServeMux()
	fail := func(route string) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			atomic.AddInt32(&hits, 1)
			t.Errorf("UNEXPECTED %s hit on parse-time-failed run", route)
		}
	}
	mux.HandleFunc("/api/discovery", fail("/api/discovery"))
	mux.HandleFunc("/api/pods", fail("/api/pods"))
	mux.HandleFunc("/.well-known/circuits/", fail("/.well-known/circuits/..."))
	srv := httptest.NewServer(mux)
	defer srv.Close()

	tmpHome := setupTempIdentity(t)
	podDir := "internal/publish/testdata/pod-sample-zk"
	_, stderr, code := runCLI(t, bin,
		[]string{"HOME=" + tmpHome},
		"pod", "publish", podDir,
		"--server", srv.URL,
		"--pin-circuit-vkey") // NB: no --circuit-id
	if code == 0 {
		t.Fatalf("exit = 0, want non-zero on missing --circuit-id; stderr=%s", stderr)
	}
	if !strings.Contains(stderr, "ERR_CIRCUIT_ID_REQUIRED_FOR_PIN_CIRCUIT_VKEY") {
		t.Errorf("stderr missing ERR_CIRCUIT_ID_REQUIRED_FOR_PIN_CIRCUIT_VKEY; got %s", stderr)
	}
	if got := atomic.LoadInt32(&hits); got != 0 {
		t.Errorf("HTTP hits = %d, want 0 (parse-time failure must precede any network IO)", got)
	}
}

func TestCLIPinCircuitVkeyAlreadyAnchoredIsNoop(t *testing.T) {
	bin := buildKonareef(t)
	var captured []byte
	srv := newDiscoveryAwareTestServer(t, &captured)
	defer srv.Close()

	tmpHome := setupTempIdentity(t)
	podDir := "internal/publish/testdata/pod-sample-zk"

	stdout, stderr, code := runCLI(t, bin,
		[]string{
			"HOME=" + tmpHome,
			"KONAREEF_TEST_ANCHOR_HASH_HEX=" + vkeyFixtureSha256Hex(),
		},
		"pod", "publish", podDir,
		"--server", srv.URL,
		"--circuit-id", "konareef-pod-step-v1",
		"--pin-circuit-vkey")
	if code != 0 {
		t.Fatalf("exit = %d, want 0 (already-anchored no-op); stderr=%s", code, stderr)
	}
	if !strings.Contains(stdout, "existing on-chain anchor verified (no-op)") {
		t.Errorf("stdout missing no-op confirmation; got %s", stdout)
	}
	if captured != nil {
		t.Errorf("publish.Submit was reached on --pin-circuit-vkey no-op path: body=%s", captured)
	}
}

func TestCLIPinCircuitVkeyMismatchedAnchorFails(t *testing.T) {
	bin := buildKonareef(t)
	var captured []byte
	srv := newDiscoveryAwareTestServer(t, &captured)
	defer srv.Close()

	tmpHome := setupTempIdentity(t)
	podDir := "internal/publish/testdata/pod-sample-zk"

	const mismatchedAnchorHex = "1bd3a04c6fa4e3a4d4d5f3a2e3b3d6e0c6b2f3a4d4d5f3a2e3b3d6e0c6b2f3a4"
	if mismatchedAnchorHex == vkeyFixtureSha256Hex() {
		t.Fatal("test bug: mismatchedAnchorHex must NOT equal vkeyFixtureSha256Hex()")
	}

	_, stderr, code := runCLI(t, bin,
		[]string{
			"HOME=" + tmpHome,
			"KONAREEF_TEST_ANCHOR_HASH_HEX=" + mismatchedAnchorHex,
		},
		"pod", "publish", podDir,
		"--server", srv.URL,
		"--circuit-id", "konareef-pod-step-v1",
		"--pin-circuit-vkey")
	if code == 0 {
		t.Fatalf("exit = 0, want non-zero on Tier-2 anchor-hash mismatch; stderr=%s", stderr)
	}
	if !strings.Contains(stderr, "ERR_CIRCUIT_PIN_MISMATCH") {
		t.Errorf("stderr missing ERR_CIRCUIT_PIN_MISMATCH; got %s", stderr)
	}
	if captured != nil {
		t.Errorf("publish.Submit was reached on anchor mismatch: body=%s", captured)
	}
}

// --- Type-D saltstore wiring ---

func TestCLITypeDPublishCallsEnsureSalt(t *testing.T) {
	bin := buildKonareef(t)
	var captured []byte
	matchingPin := vkeyFixtureSha256Hex()
	srv := stubDiscoveryAndReefCore(t, &captured, matchingPin)
	defer srv.Close()

	tmpHome := setupTempIdentity(t)
	stateDir := t.TempDir()
	podDir := "internal/publish/testdata/pod-sample-zk"

	stdout, stderr, code := runCLI(t, bin,
		[]string{
			"HOME=" + tmpHome,
			"KONAREEF_STATE_DIR=" + stateDir,
		},
		"pod", "publish", podDir,
		"--server", srv.URL,
		"--zk", "--circuit-id", "konareef-pod-step-v1",
		"--disclosure-policy", "D")
	if code != 0 {
		t.Fatalf("exit = %d, want 0 (Type-D successful publish); stdout=%s stderr=%s", code, stdout, stderr)
	}
	if captured == nil {
		t.Fatal("publish.Submit was NOT reached on Type-D happy path")
	}
	var got map[string]any
	if err := json.Unmarshal(captured, &got); err != nil {
		t.Fatalf("decode wire body: %v", err)
	}
	if got["disclosure_policy"] != "D" {
		t.Errorf("disclosure_policy = %v, want D", got["disclosure_policy"])
	}
	lineageID, ok := got["lineage_id"].(string)
	if !ok || lineageID == "" {
		t.Errorf("wire body missing lineage_id; round-4 B1 wiring not applied; body=%s", captured)
	} else if len(lineageID) != 32 {
		t.Errorf("wire lineage_id = %q, want 32-char hex", lineageID)
	}
	if _, ok := got["salt"]; ok {
		t.Errorf("wire body MUST NOT contain salt (PRD 4 § B.2); body=%s", captured)
	}
	// Canonical P1.7.1 plain-file path.
	saltPath := filepath.Join(stateDir, "typed",
		"abababababababababababababababab", "salt.bin")
	info, err := os.Stat(saltPath)
	if err != nil {
		t.Errorf("saltstore did NOT write %s; err=%v", saltPath, err)
	} else if info.Size() == 0 {
		t.Errorf("saltstore wrote empty %s", saltPath)
	}
	if !strings.Contains(stdout, "Type-D salt provisioned + persisted via saltstore") {
		t.Errorf("stdout missing salt-provisioned trace; got stdout=%s stderr=%s", stdout, stderr)
	}
}

func TestCLITypeDPublishFailsClosedOnSaltError(t *testing.T) {
	bin := buildKonareef(t)
	var captured []byte
	matchingPin := vkeyFixtureSha256Hex()
	srv := stubDiscoveryAndReefCore(t, &captured, matchingPin)
	defer srv.Close()

	tmpHome := setupTempIdentity(t)
	// Engineer an unavailable saltstore. A read-only directory does NOT
	// work under CI (the runner executes as root, which bypasses
	// permission bits). Instead point KONAREEF_STATE_DIR *under a regular
	// file*: every MkdirAll/open beneath it fails with ENOTDIR, which is a
	// structural error root cannot bypass — so the file-backed backend
	// fails for every user.
	notDir := filepath.Join(t.TempDir(), "not-a-dir")
	if err := os.WriteFile(notDir, []byte("x"), 0o600); err != nil {
		t.Fatalf("write not-a-dir: %v", err)
	}
	stateDir := filepath.Join(notDir, "state") // parent is a file → ENOTDIR

	podDir := "internal/publish/testdata/pod-sample-zk"
	_, stderr, code := runCLI(t, bin,
		[]string{
			"HOME=" + tmpHome,
			"KONAREEF_STATE_DIR=" + stateDir,
		},
		"pod", "publish", podDir,
		"--server", srv.URL,
		"--zk", "--circuit-id", "konareef-pod-step-v1",
		"--disclosure-policy", "D")
	if code == 0 {
		t.Fatalf("exit = 0, want non-zero on saltstore failure; stderr=%s", stderr)
	}
	// MUST NOT reach publish.Submit.
	if captured != nil {
		t.Errorf("publish.Submit was reached on saltstore failure: body=%s", captured)
	}
}

func TestCLITypeCPublishSkipsSaltstore(t *testing.T) {
	bin := buildKonareef(t)
	var captured []byte
	matchingPin := vkeyFixtureSha256Hex()
	srv := stubDiscoveryAndReefCore(t, &captured, matchingPin)
	defer srv.Close()

	tmpHome := setupTempIdentity(t)
	stateDir := t.TempDir()
	podDir := "internal/publish/testdata/pod-sample-zk"

	_, stderr, code := runCLI(t, bin,
		[]string{
			"HOME=" + tmpHome,
			"KONAREEF_STATE_DIR=" + stateDir,
		},
		"pod", "publish", podDir,
		"--server", srv.URL,
		"--zk", "--circuit-id", "konareef-pod-step-v1",
		"--disclosure-policy", "C")
	if code != 0 {
		t.Fatalf("exit = %d, want 0 (Type-C happy path); stderr=%s", code, stderr)
	}
	if captured == nil {
		t.Fatal("publish.Submit not reached on Type-C happy path")
	}
	var got map[string]any
	if err := json.Unmarshal(captured, &got); err != nil {
		t.Fatalf("decode wire body: %v", err)
	}
	if got["disclosure_policy"] != "C" {
		t.Errorf("disclosure_policy = %v, want C", got["disclosure_policy"])
	}
	typedDir := filepath.Join(stateDir, "typed")
	if _, err := os.Stat(typedDir); !os.IsNotExist(err) {
		t.Errorf("Type-C publish created typed/ subtree at %s (err=%v)", typedDir, err)
	}
	specificSaltPath := filepath.Join(stateDir, "typed", "abababababababababababababababab", "salt.bin")
	if _, err := os.Stat(specificSaltPath); !os.IsNotExist(err) {
		t.Errorf("Type-C publish created fixture-lineage salt.bin at %s (err=%v)", specificSaltPath, err)
	}
}

func TestCLITypeDPublishPassesSealedWitnessToSubmit(t *testing.T) {
	bin := buildKonareefWithTags(t, "test_dump_submit_opts")
	var captured []byte
	matchingPin := vkeyFixtureSha256Hex()
	srv := stubDiscoveryAndReefCore(t, &captured, matchingPin)
	defer srv.Close()

	tmpHome := setupTempIdentity(t)
	stateDir := t.TempDir()
	podDir := "internal/publish/testdata/pod-sample-zk"

	dumpPath := filepath.Join(t.TempDir(), "submit-opts.json")

	stdout, stderr, code := runCLI(t, bin,
		[]string{
			"HOME=" + tmpHome,
			"KONAREEF_STATE_DIR=" + stateDir,
			"KONAREEF_TEST_DUMP_SUBMIT_OPTS=" + dumpPath,
		},
		"pod", "publish", podDir,
		"--server", srv.URL,
		"--zk", "--circuit-id", "konareef-pod-step-v1",
		"--disclosure-policy", "D")
	if code != 0 {
		t.Fatalf("exit = %d, want 0 (Type-D happy path); stdout=%s stderr=%s", code, stdout, stderr)
	}

	if captured == nil {
		t.Fatal("publish.Submit not reached on Type-D happy path")
	}

	raw, err := os.ReadFile(dumpPath)
	if err != nil {
		t.Fatalf("read SubmitOpts dump: %v", err)
	}
	var got struct {
		CircuitID        string `json:"circuit_id"`
		ZkEnabled        bool   `json:"zk_enabled"`
		DisclosurePolicy string `json:"disclosure_policy"`
		Witness          *struct {
			LineageID        string `json:"lineage_id"`
			Salt             string `json:"salt"`
			Sealed           bool   `json:"sealed"`
			DisclosurePolicy string `json:"disclosure_policy"`
		} `json:"witness"`
	}
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatalf("decode SubmitOpts dump: %v (raw=%s)", err, raw)
	}

	if got.Witness == nil {
		t.Fatalf("SubmitOpts.Witness == nil; round-4 B1 fix not applied; got=%s", raw)
	}
	if got.Witness.LineageID == "" || got.Witness.LineageID == strings.Repeat("0", 32) {
		t.Errorf("SubmitOpts.Witness.LineageID is zero/empty: %q", got.Witness.LineageID)
	}
	if len(got.Witness.LineageID) != 32 {
		t.Errorf("SubmitOpts.Witness.LineageID = %q, want 32-char hex", got.Witness.LineageID)
	}
	if got.Witness.Salt == "" || got.Witness.Salt == strings.Repeat("0", 64) {
		t.Errorf("SubmitOpts.Witness.Salt is zero/empty: %q", got.Witness.Salt)
	}
	if len(got.Witness.Salt) != 64 {
		t.Errorf("SubmitOpts.Witness.Salt = %q, want 64-char hex", got.Witness.Salt)
	}
	if !got.Witness.Sealed {
		t.Error("SubmitOpts.Witness.Sealed = false; SealDisclosurePolicy did NOT run before Submit")
	}
	if got.Witness.DisclosurePolicy != "D" {
		t.Errorf("SubmitOpts.Witness.DisclosurePolicy = %q, want D", got.Witness.DisclosurePolicy)
	}

	var wire map[string]any
	if err := json.Unmarshal(captured, &wire); err != nil {
		t.Fatalf("decode wire body: %v", err)
	}
	if wire["lineage_id"] != got.Witness.LineageID {
		t.Errorf("wire lineage_id = %v, want %s", wire["lineage_id"], got.Witness.LineageID)
	}
	if _, ok := wire["salt"]; ok {
		t.Errorf("wire body MUST NOT contain salt (PRD 4 § B.2 — salt is publisher-local); got %s", captured)
	}
}

// newDiscoveryAwareTestServerWithDomain is a variant of
// newDiscoveryAwareTestServer whose /api/discovery returns a literal
// paygate_zk_domain string (not the publisherDomainFromURL
// placeholder). Used by the round-2 B2 acceptance test below.
func newDiscoveryAwareTestServerWithDomain(t *testing.T, capture *[]byte, paygateZKDomain string) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	matchingPin := vkeyFixtureSha256Hex()
	mux.HandleFunc("/api/discovery", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(discoveryResp{
			PaygateZKDomain: paygateZKDomain,
			Circuits: []discoveryCircuit{
				{CircuitID: "konareef-pod-step-v1", VkeySha256: matchingPin},
			},
		})
	})
	mux.HandleFunc("/.well-known/circuits/konareef-pod-step-v1/vkey",
		func(w http.ResponseWriter, r *http.Request) {
			body := make([]byte, 256)
			for i := range body {
				body[i] = 0x42
			}
			_, _ = w.Write(body)
		})
	mux.HandleFunc("/api/pods", func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		*capture = body
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(podsResp{
			InstallURL:   "https://example.test/p",
			RegisteredAt: "2026-06-10T00:00:00Z",
		})
	})
	return httptest.NewServer(mux)
}

// buildKonareefProduction compiles the konareef binary WITHOUT the
// `testhooks` build tag, mirroring a release build. Used by the
// round-2 B1 negative tests to confirm the env-var seams
// (KONAREEF_TEST_ANCHOR_HASH_HEX, KONAREEF_TEST_VKEY_BASE_URL) are
// unreachable from production binaries.
func buildKonareefProduction(t *testing.T) string {
	t.Helper()
	bin := filepath.Join(t.TempDir(), "konareef-prod-bin")
	cmd := exec.Command("go", "build", "-o", bin, ".")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("go build (no testhooks) failed: %v\n%s", err, out)
	}
	return bin
}

// runCLIProduction is the production-build counterpart of runCLI: it
// runs a binary that has NOT been built with `-tags testhooks` and
// does NOT auto-inject KONAREEF_TEST_VKEY_BASE_URL. The caller may
// still set KONAREEF_TEST_* env vars to prove they are inert.
func runCLIProduction(t *testing.T, bin string, env []string, args ...string) (stdout, stderr string, code int) {
	t.Helper()
	args = withPublishConfirmation(args)
	cmd := exec.Command(bin, args...)
	cmd.Env = append(os.Environ(), env...)
	cmd.Env = append(cmd.Env, "KONAREEF_ALLOW_PLAINTEXT_SALT=1")
	cmd.Env = append(cmd.Env, "KONAREEF_DISABLE_KEYCHAIN_BACKEND=1")
	var outBuf, errBuf bytes.Buffer
	cmd.Stdout = &outBuf
	cmd.Stderr = &errBuf
	err := cmd.Run()
	if exitErr, ok := err.(*exec.ExitError); ok {
		code = exitErr.ExitCode()
	}
	return outBuf.String(), errBuf.String(), code
}

// TestProductionBinaryIgnoresAnchorHashEnv is the round-2 B1
// (note 677) negative regression: when the production binary (no
// `testhooks` tag) is invoked with KONAREEF_TEST_ANCHOR_HASH_HEX set,
// the env var MUST NOT bypass the fail-closed
// ErrAnchorNotFound -> ErrAnchorBroadcastUnsupported path. The
// observable proof is that the publish fails with
// ERR_ANCHOR_BROADCAST_UNSUPPORTED — exactly the same error the
// production binary would produce with no env var at all.
func TestProductionBinaryIgnoresAnchorHashEnv(t *testing.T) {
	bin := buildKonareefProduction(t)
	var captured []byte
	srv := newDiscoveryAwareTestServerWithDomain(t, &captured, "paygate-zk.publisher.example")
	defer srv.Close()

	tmpHome := setupTempIdentity(t)
	podDir := "internal/publish/testdata/pod-sample-zk"

	// The production binary's resolver does NOT honour
	// KONAREEF_TEST_VKEY_BASE_URL either, so the Tier-1 fetch will
	// fail with ErrVkeyUnavailable before reaching the anchor lookup
	// in the happy path. To isolate the anchor-hash assertion we set
	// both env vars; the production binary must ignore BOTH.
	//
	// What we observe: a non-zero exit and an error code that is NOT
	// the "already-anchored no-op" success path. Specifically the
	// stderr must NOT show "existing on-chain anchor verified" — that
	// would prove KONAREEF_TEST_ANCHOR_HASH_HEX bypassed
	// ErrAnchorNotFound.
	stdout, stderr, code := runCLIProduction(t, bin,
		[]string{
			"HOME=" + tmpHome,
			"KONAREEF_TEST_ANCHOR_HASH_HEX=" + vkeyFixtureSha256Hex(),
			"KONAREEF_TEST_VKEY_BASE_URL=" + srv.URL,
		},
		"pod", "publish", podDir,
		"--server", srv.URL,
		"--circuit-id", "konareef-pod-step-v1",
		"--pin-circuit-vkey")
	if code == 0 {
		t.Fatalf("exit = 0 (env hook bypassed production fail-closed); stdout=%s; stderr=%s",
			stdout, stderr)
	}
	if strings.Contains(stdout, "existing on-chain anchor verified (no-op)") {
		t.Errorf("production binary honoured KONAREEF_TEST_ANCHOR_HASH_HEX; stdout=%s", stdout)
	}
	if captured != nil {
		t.Errorf("publish.Submit was reached: body=%s", captured)
	}
}

// TestCLIPinCircuitVkeyAcceptsPaygateZKPrefixedDomain is the round-2
// B2 (note 680) acceptance regression. reef-core's /api/discovery
// returns `paygate_zk_domain: "paygate-zk.example.com"` per the public
// contract (the service host, not a publisher base domain). The
// publish path strips the `paygate-zk.` prefix via PublisherBaseDomain
// before handing the base ("example.com") to
// vkeystore.ResolveRequest.PublisherDomain — without that strip the
// resolver rejects the input with ErrDomainAlreadyPrefixed and the
// publish fails. This test exercises the --pin-circuit-vkey path with
// the literal acceptance vector from note 680 and asserts success.
func TestCLIPinCircuitVkeyAcceptsPaygateZKPrefixedDomain(t *testing.T) {
	bin := buildKonareef(t)
	var captured []byte
	srv := newDiscoveryAwareTestServerWithDomain(t, &captured, "paygate-zk.example.com")
	defer srv.Close()

	tmpHome := setupTempIdentity(t)
	podDir := "internal/publish/testdata/pod-sample-zk"

	stdout, stderr, code := runCLI(t, bin,
		[]string{
			"HOME=" + tmpHome,
			"KONAREEF_TEST_ANCHOR_HASH_HEX=" + vkeyFixtureSha256Hex(),
		},
		"pod", "publish", podDir,
		"--server", srv.URL,
		"--circuit-id", "konareef-pod-step-v1",
		"--pin-circuit-vkey")
	if code != 0 {
		t.Fatalf("exit = %d, want 0 (paygate-zk.<base> must resolve); stderr=%s", code, stderr)
	}
	if !strings.Contains(stdout, "existing on-chain anchor verified (no-op)") {
		t.Errorf("stdout missing no-op confirmation; got %s", stdout)
	}
	// Resolver rejection would surface ERR_DOMAIN_ALREADY_PREFIXED in
	// stderr — assert the negative.
	if strings.Contains(stderr, "ERR_DOMAIN_ALREADY_PREFIXED") {
		t.Errorf("stderr contains ERR_DOMAIN_ALREADY_PREFIXED — PublisherBaseDomain strip failed; stderr=%s", stderr)
	}
	if captured != nil {
		t.Errorf("publish.Submit was reached on --pin-circuit-vkey no-op path: body=%s", captured)
	}
}

// TestCLIPinCircuitVkeyRejectsBaseDomainFromDiscovery asserts the
// negative half of the round-2 B2 contract: if reef-core returns a
// bare base domain (no `paygate-zk.` prefix), the CLI fails closed
// rather than passing the wrong value forward. The fix is contract-
// enforcing in both directions.
func TestCLIPinCircuitVkeyRejectsBaseDomainFromDiscovery(t *testing.T) {
	bin := buildKonareef(t)
	var captured []byte
	srv := newDiscoveryAwareTestServerWithDomain(t, &captured, "example.com")
	defer srv.Close()

	tmpHome := setupTempIdentity(t)
	podDir := "internal/publish/testdata/pod-sample-zk"

	_, stderr, code := runCLI(t, bin,
		[]string{
			"HOME=" + tmpHome,
			"KONAREEF_TEST_ANCHOR_HASH_HEX=" + vkeyFixtureSha256Hex(),
		},
		"pod", "publish", podDir,
		"--server", srv.URL,
		"--circuit-id", "konareef-pod-step-v1",
		"--pin-circuit-vkey")
	if code == 0 {
		t.Fatalf("exit = 0, want non-zero on bare base domain (missing paygate-zk. prefix); stderr=%s", stderr)
	}
	if !strings.Contains(stderr, "ERR_PAYGATE_ZK_DOMAIN_MISSING_PREFIX") {
		t.Errorf("stderr missing ERR_PAYGATE_ZK_DOMAIN_MISSING_PREFIX; got %s", stderr)
	}
	if captured != nil {
		t.Errorf("publish.Submit was reached on contract-violating discovery: body=%s", captured)
	}
}
