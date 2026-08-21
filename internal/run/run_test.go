// Copyright 2026 Jerry David Chan, Konareef.ai
// SPDX-License-Identifier: Apache-2.0

package run

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/digitsu/konareef/internal/api"
)

func mustWriteFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("mkdir %s: %v", filepath.Dir(path), err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

// (a) files map contains every cached content file keyed "./relative/path".
func TestLoadContentFiles(t *testing.T) {
	contentDir := filepath.Join(t.TempDir(), "content")
	mustWriteFile(t, filepath.Join(contentDir, "pod.toml"), "name = \"voice-forge\"\n")
	mustWriteFile(t, filepath.Join(contentDir, "prompts", "system.md"), "# System\n")
	mustWriteFile(t, filepath.Join(contentDir, "prompts", "nested", "extra.md"), "# Extra\n")

	podToml, files, err := LoadContentFiles(contentDir)
	if err != nil {
		t.Fatalf("LoadContentFiles: %v", err)
	}
	if podToml != "name = \"voice-forge\"\n" {
		t.Fatalf("unexpected pod_toml: %q", podToml)
	}

	want := map[string]string{
		"./pod.toml":                "name = \"voice-forge\"\n",
		"./prompts/system.md":       "# System\n",
		"./prompts/nested/extra.md": "# Extra\n",
	}
	if len(files) != len(want) {
		t.Fatalf("unexpected file count: got %d want %d (%v)", len(files), len(want), files)
	}
	for k, v := range want {
		if got, ok := files[k]; !ok || got != v {
			t.Errorf("files[%q] = %q (ok=%v), want %q", k, got, ok, v)
		}
	}
}

func TestLoadContentFilesMissingPodToml(t *testing.T) {
	contentDir := filepath.Join(t.TempDir(), "content")
	mustWriteFile(t, filepath.Join(contentDir, "prompts", "system.md"), "# System\n")

	if _, _, err := LoadContentFiles(contentDir); err == nil {
		t.Fatal("expected error for content dir with no pod.toml")
	}
}

// (b) --input k=v parsing: error on missing "=", repeated flags accumulate.
func TestParseInputs(t *testing.T) {
	got, err := ParseInputs([]string{
		"youtube_url=https://youtu.be/XXXX",
		"speak_text=Welcome to Konareef.",
	})
	if err != nil {
		t.Fatalf("ParseInputs: %v", err)
	}
	want := map[string]string{
		"youtube_url": "https://youtu.be/XXXX",
		"speak_text":  "Welcome to Konareef.",
	}
	if len(got) != len(want) {
		t.Fatalf("unexpected inputs: %+v", got)
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("inputs[%q] = %q, want %q", k, got[k], v)
		}
	}
}

func TestParseInputsMissingEquals(t *testing.T) {
	_, err := ParseInputs([]string{"not-a-kv-pair"})
	if err == nil {
		t.Fatal("expected error for an --input with no '='")
	}
	if !strings.Contains(err.Error(), "not-a-kv-pair") {
		t.Errorf("error should name the offending entry: %v", err)
	}
}

func TestInputFlagsAccumulate(t *testing.T) {
	var flags InputFlags
	if err := flags.Set("youtube_url=https://youtu.be/XXXX"); err != nil {
		t.Fatalf("Set: %v", err)
	}
	if err := flags.Set("speak_text=hi"); err != nil {
		t.Fatalf("Set: %v", err)
	}
	if len(flags) != 2 || flags[0] != "youtube_url=https://youtu.be/XXXX" || flags[1] != "speak_text=hi" {
		t.Fatalf("repeated --input flags did not accumulate: %+v", flags)
	}
}

// (d) missing content cache -> actionable error naming `konareef install`.
func TestRunMissingContentCache(t *testing.T) {
	err := Run(Config{
		BaseURL:      "http://unused.invalid",
		SessionToken: "tok",
		Home:         t.TempDir(),
		Handle:       "jerry",
		PodName:      "voice-forge",
		Version:      "0.1.0",
		OutDir:       t.TempDir(),
	})
	if err == nil {
		t.Fatal("expected error for missing content cache")
	}
	if !strings.Contains(err.Error(), "konareef install") {
		t.Fatalf("error is not actionable, missing `konareef install`: %v", err)
	}
}

func TestRunRequiresSessionToken(t *testing.T) {
	err := Run(Config{BaseURL: "http://unused.invalid", Version: "0.1.0"})
	if err == nil {
		t.Fatal("expected error for empty session token")
	}
}

func TestRunRequiresExplicitVersion(t *testing.T) {
	err := Run(Config{BaseURL: "http://unused.invalid", SessionToken: "tok"})
	if err == nil {
		t.Fatal("expected error for empty version (no @latest against the install cache)")
	}
}

// (c) deliverables land in --out byte-exact, download URL carries the
// "output/" prefix verbatim; (e) cached attestation attached to the
// spawn body when present.
func TestRunFullFlow(t *testing.T) {
	home := t.TempDir()
	handle, podName, version := "jerry", "voice-forge", "0.1.0"

	versionDir := filepath.Join(home, ".konareef", "installed", handle, podName, version)
	contentDir := filepath.Join(versionDir, "content")
	mustWriteFile(t, filepath.Join(contentDir, "pod.toml"), "name = \"voice-forge\"\nversion = \"0.1.0\"\n")
	mustWriteFile(t, filepath.Join(contentDir, "prompts", "system.md"), "# System\n")

	podHash := strings.Repeat("ab", 32)
	pubkeyHex := "02" + strings.Repeat("cd", 32)
	mustWriteFile(t, filepath.Join(versionDir, "meta.json"),
		fmt.Sprintf(`{"pod_hash":%q,"publisher_pubkey_hex":%q}`, podHash, pubkeyHex))
	if err := os.WriteFile(filepath.Join(versionDir, "signature.bin"), []byte{0xde, 0xad, 0xbe, 0xef}, 0o644); err != nil {
		t.Fatalf("write signature.bin: %v", err)
	}

	mp3Bytes := []byte("fake-mp3-bytes")
	reportBytes := []byte("# Report\n")
	nestedBytes := []byte("nested-binary-blob")

	var spawnAssertErr error
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if auth := r.Header.Get("Authorization"); auth != "Bearer test-tok" {
			t.Errorf("unexpected Authorization header: %q", auth)
		}
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/api/pods/spawn":
			var body api.SpawnPodRequest
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Fatalf("decode spawn body: %v", err)
			}
			if body.PodToml == "" || body.Files["./pod.toml"] != body.PodToml {
				spawnAssertErr = fmt.Errorf("pod_toml/files mismatch: pod_toml=%q files=%+v", body.PodToml, body.Files)
			}
			if body.Files["./prompts/system.md"] != "# System\n" {
				spawnAssertErr = fmt.Errorf("files map missing ./prompts/system.md: %+v", body.Files)
			}
			if body.Inputs["speak_text"] != "hello" {
				spawnAssertErr = fmt.Errorf("unexpected inputs: %+v", body.Inputs)
			}
			if body.PodAttestation == nil {
				spawnAssertErr = fmt.Errorf("expected pod_attestation to be attached")
			} else if body.PodAttestation.PodHash != podHash || body.PodAttestation.PublisherID != handle {
				spawnAssertErr = fmt.Errorf("unexpected attestation: %+v", body.PodAttestation)
			}
			w.WriteHeader(http.StatusCreated)
			json.NewEncoder(w).Encode(api.SpawnResponse{
				AgentID: "agent-1", PodID: "pod-1", TaskID: "task-1",
				SnapshotID: "snap-1", BundleHash: "deadbeef", BundleFileCount: 2,
			})
		case r.Method == http.MethodGet && r.URL.Path == "/api/proofs":
			json.NewEncoder(w).Encode(api.ProofsResponse{
				Proofs: []api.Proof{{ProofType: "custody", Hash: "proofhash123", Txid: "txid456"}},
			})
		case r.Method == http.MethodGet && r.URL.Path == "/api/agents/agent-1/deliverables":
			json.NewEncoder(w).Encode(api.DeliverablesResponse{
				Deliverables: []api.Deliverable{
					{Path: "output/speech.mp3", Size: int64(len(mp3Bytes))},
					{Path: "output/report.md", Size: int64(len(reportBytes))},
					{Path: "output/sub/file.bin", Size: int64(len(nestedBytes))},
				},
			})
		case r.Method == http.MethodGet && r.URL.Path == "/api/agents/agent-1/deliverables/output/speech.mp3":
			w.Write(mp3Bytes)
		case r.Method == http.MethodGet && r.URL.Path == "/api/agents/agent-1/deliverables/output/report.md":
			w.Write(reportBytes)
		case r.Method == http.MethodGet && r.URL.Path == "/api/agents/agent-1/deliverables/output/sub/file.bin":
			w.Write(nestedBytes)
		default:
			t.Fatalf("unexpected request: %s %s", r.Method, r.URL.Path)
		}
	}))
	defer srv.Close()

	outDir := t.TempDir()
	err := Run(Config{
		BaseURL:      srv.URL,
		SessionToken: "test-tok",
		Home:         home,
		Handle:       handle,
		PodName:      podName,
		Version:      version,
		Inputs:       map[string]string{"speak_text": "hello"},
		OutDir:       outDir,
		Timeout:      5 * time.Second,
		PollInterval: 10 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if spawnAssertErr != nil {
		t.Fatal(spawnAssertErr)
	}

	gotMP3, err := os.ReadFile(filepath.Join(outDir, "speech.mp3"))
	if err != nil || !bytes.Equal(gotMP3, mp3Bytes) {
		t.Fatalf("speech.mp3 mismatch: err=%v got=%q want=%q", err, gotMP3, mp3Bytes)
	}
	gotReport, err := os.ReadFile(filepath.Join(outDir, "report.md"))
	if err != nil || !bytes.Equal(gotReport, reportBytes) {
		t.Fatalf("report.md mismatch: err=%v got=%q want=%q", err, gotReport, reportBytes)
	}
	// (c) a normal nested deliverable path still round-trips byte-exact.
	gotNested, err := os.ReadFile(filepath.Join(outDir, "sub", "file.bin"))
	if err != nil || !bytes.Equal(gotNested, nestedBytes) {
		t.Fatalf("sub/file.bin mismatch: err=%v got=%q want=%q", err, gotNested, nestedBytes)
	}
}

// (a) a server-reported deliverable path with a ".." component must
// not be honored: Run fails with an unsafe-path error, no download is
// attempted, and nothing is written outside --out.
func TestRunRejectsPathTraversalDeliverable(t *testing.T) {
	home := t.TempDir()
	handle, podName, version := "jerry", "voice-forge", "0.1.0"
	contentDir := filepath.Join(home, ".konareef", "installed", handle, podName, version, "content")
	mustWriteFile(t, filepath.Join(contentDir, "pod.toml"), "name = \"voice-forge\"\n")

	// outDir sits two levels under a throwaway root; "output/../../evil.txt"
	// (stripped to "../../evil.txt") would land right at that root if honored.
	root := t.TempDir()
	outDir := filepath.Join(root, "nested", "out")
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		t.Fatalf("mkdir outDir: %v", err)
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/api/pods/spawn":
			w.WriteHeader(http.StatusCreated)
			json.NewEncoder(w).Encode(api.SpawnResponse{AgentID: "agent-1"})
		case r.Method == http.MethodGet && r.URL.Path == "/api/proofs":
			json.NewEncoder(w).Encode(api.ProofsResponse{
				Proofs: []api.Proof{{ProofType: "custody", Hash: "h"}},
			})
		case r.Method == http.MethodGet && r.URL.Path == "/api/agents/agent-1/deliverables":
			json.NewEncoder(w).Encode(api.DeliverablesResponse{
				Deliverables: []api.Deliverable{{Path: "output/../../evil.txt", Size: 4}},
			})
		default:
			// A download must never be attempted for an unsafe path —
			// safeLocalPath has to reject it before any network call.
			t.Errorf("unexpected request reached the server: %s %s", r.Method, r.URL.Path)
		}
	}))
	defer srv.Close()

	err := Run(Config{
		BaseURL:      srv.URL,
		SessionToken: "tok",
		Home:         home,
		Handle:       handle,
		PodName:      podName,
		Version:      version,
		OutDir:       outDir,
		Timeout:      5 * time.Second,
		PollInterval: 10 * time.Millisecond,
	})
	if err == nil {
		t.Fatal("expected an error for a traversal deliverable path")
	}
	if !strings.Contains(err.Error(), "unsafe deliverable path") {
		t.Fatalf("error should name the unsafe path, got: %v", err)
	}

	if _, statErr := os.Stat(filepath.Join(root, "evil.txt")); statErr == nil {
		t.Fatal("evil.txt was written outside --out")
	}
	entries, err := os.ReadDir(outDir)
	if err != nil {
		t.Fatalf("read outDir: %v", err)
	}
	if len(entries) != 0 {
		t.Fatalf("expected outDir to remain empty, got %+v", entries)
	}
}

// (b) an absolute server-reported deliverable path must be rejected
// the same way as a "..": Run fails, no download, nothing written.
func TestRunRejectsAbsoluteDeliverablePath(t *testing.T) {
	home := t.TempDir()
	handle, podName, version := "jerry", "voice-forge", "0.1.0"
	contentDir := filepath.Join(home, ".konareef", "installed", handle, podName, version, "content")
	mustWriteFile(t, filepath.Join(contentDir, "pod.toml"), "name = \"voice-forge\"\n")

	outDir := t.TempDir()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/api/pods/spawn":
			w.WriteHeader(http.StatusCreated)
			json.NewEncoder(w).Encode(api.SpawnResponse{AgentID: "agent-1"})
		case r.Method == http.MethodGet && r.URL.Path == "/api/proofs":
			json.NewEncoder(w).Encode(api.ProofsResponse{
				Proofs: []api.Proof{{ProofType: "custody", Hash: "h"}},
			})
		case r.Method == http.MethodGet && r.URL.Path == "/api/agents/agent-1/deliverables":
			json.NewEncoder(w).Encode(api.DeliverablesResponse{
				Deliverables: []api.Deliverable{{Path: "/etc/passwd", Size: 4}},
			})
		default:
			t.Errorf("unexpected request reached the server: %s %s", r.Method, r.URL.Path)
		}
	}))
	defer srv.Close()

	err := Run(Config{
		BaseURL:      srv.URL,
		SessionToken: "tok",
		Home:         home,
		Handle:       handle,
		PodName:      podName,
		Version:      version,
		OutDir:       outDir,
		Timeout:      5 * time.Second,
		PollInterval: 10 * time.Millisecond,
	})
	if err == nil {
		t.Fatal("expected an error for an absolute deliverable path")
	}
	if !strings.Contains(err.Error(), "unsafe deliverable path") {
		t.Fatalf("error should name the unsafe path, got: %v", err)
	}
	entries, err := os.ReadDir(outDir)
	if err != nil {
		t.Fatalf("read outDir: %v", err)
	}
	if len(entries) != 0 {
		t.Fatalf("expected outDir to remain empty, got %+v", entries)
	}
}

// No attestation cached (unsigned/dev pod) -> spawn still succeeds,
// with a nil pod_attestation attached. Complements TestRunFullFlow's
// "attached when present" coverage with the absent case.
func TestRunNoAttestationCached(t *testing.T) {
	home := t.TempDir()
	handle, podName, version := "jerry", "voice-forge", "0.1.0"

	contentDir := filepath.Join(home, ".konareef", "installed", handle, podName, version, "content")
	mustWriteFile(t, filepath.Join(contentDir, "pod.toml"), "name = \"voice-forge\"\n")

	var sawAttestation *api.PodAttestation
	sawNonNil := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/api/pods/spawn":
			var body api.SpawnPodRequest
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Fatalf("decode spawn body: %v", err)
			}
			sawAttestation = body.PodAttestation
			sawNonNil = body.PodAttestation != nil
			w.WriteHeader(http.StatusCreated)
			json.NewEncoder(w).Encode(api.SpawnResponse{AgentID: "agent-1", PodID: "pod-1"})
		case r.Method == http.MethodGet && r.URL.Path == "/api/proofs":
			json.NewEncoder(w).Encode(api.ProofsResponse{
				Proofs: []api.Proof{{ProofType: "custody", Hash: "h"}},
			})
		case r.Method == http.MethodGet && r.URL.Path == "/api/agents/agent-1/deliverables":
			json.NewEncoder(w).Encode(api.DeliverablesResponse{})
		default:
			t.Fatalf("unexpected request: %s %s", r.Method, r.URL.Path)
		}
	}))
	defer srv.Close()

	err := Run(Config{
		BaseURL:      srv.URL,
		SessionToken: "tok",
		Home:         home,
		Handle:       handle,
		PodName:      podName,
		Version:      version,
		OutDir:       t.TempDir(),
		Timeout:      5 * time.Second,
		PollInterval: 10 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if sawNonNil {
		t.Fatalf("expected nil pod_attestation with no cached meta.json, got %+v", sawAttestation)
	}
}

// headOnlyInstallCache builds the cache layout `konareef install`
// leaves behind for a CLOSED pod: manifest.canon, signature.bin and a
// meta.json carrying `visibility` — and deliberately no content/ dir,
// because a closed pod's body never reaches the commissioner.
func headOnlyInstallCache(t *testing.T, home, handle, podName, version, podHash string) string {
	t.Helper()
	versionDir := filepath.Join(home, ".konareef", "installed", handle, podName, version)
	mustWriteFile(t, filepath.Join(versionDir, "manifest.canon"), "pod_spec_version = \"0.1\"\n")
	mustWriteFile(t, filepath.Join(versionDir, "meta.json"), fmt.Sprintf(
		`{"handle":%q,"pod_name":%q,"pod_version":%q,"pod_hash":%q,"publisher_pubkey_hex":%q,"visibility":"closed"}`,
		handle, podName, version, podHash, "02"+strings.Repeat("cd", 32)))
	if err := os.WriteFile(filepath.Join(versionDir, "signature.bin"), []byte{0xde, 0xad}, 0o644); err != nil {
		t.Fatalf("write signature.bin: %v", err)
	}
	return versionDir
}

// spawnCaptureServer stands in for reef-core: it records the spawn
// body (typed and raw) and then answers the rest of the run flow with
// a completed, deliverable-free agent. The real mode-C server side is
// being built concurrently, so nothing here talks to a live reef-core.
func spawnCaptureServer(t *testing.T, got *api.SpawnPodRequest, rawBody *[]byte) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/api/pods/spawn":
			body, err := io.ReadAll(r.Body)
			if err != nil {
				t.Errorf("read spawn body: %v", err)
				return
			}
			*rawBody = body
			if err := json.Unmarshal(body, got); err != nil {
				t.Errorf("decode spawn body: %v", err)
				return
			}
			w.WriteHeader(http.StatusCreated)
			json.NewEncoder(w).Encode(api.SpawnResponse{AgentID: "agent-1", PodID: "pod-1"})
		case r.Method == http.MethodGet && r.URL.Path == "/api/proofs":
			json.NewEncoder(w).Encode(api.ProofsResponse{
				Proofs: []api.Proof{{ProofType: "custody", Hash: "h"}},
			})
		case r.Method == http.MethodGet && r.URL.Path == "/api/agents/agent-1/deliverables":
			json.NewEncoder(w).Encode(api.DeliverablesResponse{})
		default:
			t.Errorf("unexpected request: %s %s", r.Method, r.URL.Path)
		}
	}))
}

// A closed pod spawns by reference and transmits no pod content: the
// commissioner does not hold the body, which is the whole point.
func TestRunClosedPodSpawnsByRef(t *testing.T) {
	var got api.SpawnPodRequest
	var raw []byte
	srv := spawnCaptureServer(t, &got, &raw)
	defer srv.Close()

	home := t.TempDir()
	podHash := strings.Repeat("ab", 32)
	headOnlyInstallCache(t, home, "bob", "secret-pod", "0.1.0", podHash)

	err := Run(Config{
		BaseURL:      srv.URL,
		SessionToken: "tok",
		Home:         home,
		Handle:       "bob",
		PodName:      "secret-pod",
		Version:      "0.1.0",
		Inputs:       map[string]string{"speak_text": "hello"},
		OutDir:       t.TempDir(),
		Timeout:      5 * time.Second,
		PollInterval: 10 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}

	if got.PodRef == nil {
		t.Fatal("closed pod must spawn by pod_ref")
	}
	// The locally verified pod_hash, not a name the server re-resolves:
	// install already signature-checked this exact HEAD.
	if got.PodRef.PodHash != podHash {
		t.Fatalf("pod_ref.pod_hash = %q, want %q", got.PodRef.PodHash, podHash)
	}
	if got.PodToml != "" || len(got.Files) != 0 {
		t.Fatalf("closed pod must transmit no pod content: pod_toml=%q files=%+v", got.PodToml, got.Files)
	}
	if got.Inputs["speak_text"] != "hello" {
		t.Fatalf("inputs must still ride along: %+v", got.Inputs)
	}

	// reef-core rejects a body carrying both pod_ref and inline content,
	// so the keys must be absent on the wire, not merely empty.
	var keys map[string]json.RawMessage
	if err := json.Unmarshal(raw, &keys); err != nil {
		t.Fatalf("unmarshal raw spawn body: %v", err)
	}
	for _, key := range []string{"pod_toml", "files"} {
		if _, present := keys[key]; present {
			t.Errorf("mode-C body must not carry %q: %s", key, raw)
		}
	}
}

// Regression guard: an open pod keeps the inline spawn path exactly as
// it was before mode C existed.
func TestRunOpenPodStillSpawnsInline(t *testing.T) {
	var got api.SpawnPodRequest
	var raw []byte
	srv := spawnCaptureServer(t, &got, &raw)
	defer srv.Close()

	home := t.TempDir()
	contentDir := filepath.Join(home, ".konareef", "installed", "jerry", "voice-forge", "0.1.0", "content")
	mustWriteFile(t, filepath.Join(contentDir, "pod.toml"), "name = \"voice-forge\"\n")
	mustWriteFile(t, filepath.Join(contentDir, "prompts", "system.md"), "# System\n")

	err := Run(Config{
		BaseURL:      srv.URL,
		SessionToken: "tok",
		Home:         home,
		Handle:       "jerry",
		PodName:      "voice-forge",
		Version:      "0.1.0",
		OutDir:       t.TempDir(),
		Timeout:      5 * time.Second,
		PollInterval: 10 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if got.PodRef != nil {
		t.Fatalf("open pod must not spawn by reference: %+v", got.PodRef)
	}
	if got.PodToml != "name = \"voice-forge\"\n" {
		t.Fatalf("open pod must still send pod_toml inline, got %q", got.PodToml)
	}
	if got.Files["./prompts/system.md"] != "# System\n" {
		t.Fatalf("open pod must still send its files inline: %+v", got.Files)
	}
}

// A pod that was never installed must be told to install, not told
// its "content cache" is missing — a closed pod never has one by
// design, so that wording would send the user chasing a file that is
// not supposed to exist.
func TestRunNotInstalledErrorPointsAtInstall(t *testing.T) {
	err := Run(Config{
		BaseURL:      "http://unused.invalid",
		SessionToken: "tok",
		Home:         t.TempDir(),
		Handle:       "bob",
		PodName:      "secret-pod",
		Version:      "0.1.0",
		OutDir:       t.TempDir(),
	})
	if err == nil {
		t.Fatal("expected an error for a pod that is not installed")
	}
	if strings.Contains(err.Error(), "content cache") {
		t.Fatalf("error must not blame a missing content cache: %v", err)
	}
	if !strings.Contains(err.Error(), "konareef install") {
		t.Fatalf("error is not actionable, missing `konareef install`: %v", err)
	}
}

// A closed pod's cached meta.json is the dispatch input, so a corrupt
// one must fail loud rather than silently degrade to the inline path
// (which would leak nothing, but would fail confusingly against a
// pod that has no content dir).
func TestRunClosedPodRejectsCorruptMeta(t *testing.T) {
	home := t.TempDir()
	versionDir := filepath.Join(home, ".konareef", "installed", "bob", "secret-pod", "0.1.0")
	mustWriteFile(t, filepath.Join(versionDir, "meta.json"), "{not json")

	err := Run(Config{
		BaseURL:      "http://unused.invalid",
		SessionToken: "tok",
		Home:         home,
		Handle:       "bob",
		PodName:      "secret-pod",
		Version:      "0.1.0",
		OutDir:       t.TempDir(),
	})
	if err == nil {
		t.Fatal("expected an error for a corrupt meta.json")
	}
	if !strings.Contains(err.Error(), "meta.json") {
		t.Fatalf("error should name meta.json, got: %v", err)
	}
}

func TestSafeLocalPath(t *testing.T) {
	outDir := "/out"

	cases := []struct {
		name       string
		remotePath string
		wantErr    bool
		wantLocal  string
	}{
		{"normal file", "output/speech.mp3", false, "/out/speech.mp3"},
		{"nested file", "output/sub/file.bin", false, "/out/sub/file.bin"},
		{"traversal component", "output/../../evil.txt", true, ""},
		{"traversal in nested position", "output/sub/../../evil.txt", true, ""},
		{"absolute path", "/etc/passwd", true, ""},
		{"absolute path with output prefix", "output//etc/passwd", true, ""},
		{"dotdot-prefixed filename is legal", "output/..foo", false, "/out/..foo"},
		{"trailing-dotdot filename is legal", "output/foo..", false, "/out/foo.."},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			local, err := safeLocalPath(outDir, c.remotePath)
			if c.wantErr {
				if err == nil {
					t.Fatalf("safeLocalPath(%q) = %q, nil; want error", c.remotePath, local)
				}
				return
			}
			if err != nil {
				t.Fatalf("safeLocalPath(%q): unexpected error: %v", c.remotePath, err)
			}
			if local != c.wantLocal {
				t.Fatalf("safeLocalPath(%q) = %q, want %q", c.remotePath, local, c.wantLocal)
			}
		})
	}
}

func TestHumanSize(t *testing.T) {
	cases := []struct {
		bytes int64
		want  string
	}{
		{100, "100 B"},
		{48211, "47 KiB"},
		{2 * 1024 * 1024, "2.0 MiB"},
	}
	for _, c := range cases {
		if got := humanSize(c.bytes); got != c.want {
			t.Errorf("humanSize(%d) = %q, want %q", c.bytes, got, c.want)
		}
	}
}
