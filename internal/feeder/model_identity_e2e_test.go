// Copyright 2026 Jerry David Chan, Konareef.ai
// SPDX-License-Identifier: Apache-2.0

// model_identity_e2e_test.go — one model-bearing konareef-toml/v2 pod
// carried through publish, install, commission and the feeder, with a
// fixed provider identity (IB-03, konareef#21).
//
// Real code at every step except the prover and reef-core ingest, which
// are httptest stubs. The PS-1 stub applies PS-1's model membership rule
// (paygate-zk-prove assemble.rs) and nothing else, so this test does NOT
// show that a genuine proof verifies. That acceptance needs a live PS-1
// (see ps1_smoke_test.go, gated on KONAREEF_PS1_SMOKE_URL) and is recorded
// as pending in the MR.
package feeder_test

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/digitsu/konareef/internal/canon"
	"github.com/digitsu/konareef/internal/commission"
	"github.com/digitsu/konareef/internal/feeder"
	"github.com/digitsu/konareef/internal/identity"
	"github.com/digitsu/konareef/internal/install"
	"github.com/digitsu/konareef/internal/pod"
	"github.com/digitsu/konareef/internal/publish"
)

// modelBearingPodTOML declares the model reef-core's golden seam file
// (testdata/reefcore_model_id/qualified_model_id.json) names, and the one
// tool that file's tool_log calls.
const modelBearingPodTOML = `pod_spec_version = "0.1"

[pod]
name = "model-identity-e2e"
version = "1.0.0"

[runtime]
kind = "lobster"

[model]
provider = "anthropic"
name = "claude-sonnet-4-5"

[[context.tools]]
source = "bash"

[budget]
max_sats = 5000

[directive]
template = "./prompts/system.md"
`

// declaredModelID is the fixed provider identity this test commits.
const declaredModelID = "anthropic/claude-sonnet-4-5"

// publishAndInstall runs the real --zk publish over modelBearingPodTOML,
// verifies and caches the result the way `konareef install` does, and
// returns the home directory, the pod coordinates and the canonical bytes.
func publishAndInstall(t *testing.T) (home string, f *install.FetchedPod) {
	t.Helper()
	podDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(podDir, "pod.toml"), []byte(modelBearingPodTOML), 0o644); err != nil {
		t.Fatalf("write pod.toml: %v", err)
	}
	if err := os.MkdirAll(filepath.Join(podDir, "prompts"), 0o755); err != nil {
		t.Fatalf("mkdir prompts: %v", err)
	}
	if err := os.WriteFile(filepath.Join(podDir, "prompts", "system.md"), []byte("hello"), 0o644); err != nil {
		t.Fatalf("write system.md: %v", err)
	}
	id, err := identity.Generate("alice")
	if err != nil {
		t.Fatalf("identity.Generate: %v", err)
	}
	prep, err := publish.Prepare(podDir, id, publish.PrepareOptions{ZK: true})
	if err != nil {
		t.Fatalf("publish.Prepare(ZK): %v", err)
	}
	f = &install.FetchedPod{
		Handle:             prep.Handle,
		PodName:            prep.PodName,
		PodVersion:         prep.PodVersion,
		PodHash:            prep.PodHash,
		ManifestCanonical:  prep.CanonicalBytes,
		Signature:          prep.Signature,
		PublisherPubkeyHex: prep.PublicKeyHex,
		ContentTarball:     prep.ContentTarball,
	}
	if err := install.Verify(f); err != nil {
		t.Fatalf("install.Verify: %v", err)
	}
	home = t.TempDir()
	if _, err := install.Cache(home, f); err != nil {
		t.Fatalf("install.Cache: %v", err)
	}
	return home, f
}

// copyGoldenSeam copies a vendored reef-core seam file, unchanged, into a
// fresh workspace as step-disclosure.json. edit, when non-nil, is applied
// to the bytes first.
func copyGoldenSeam(t *testing.T, name string, edit func(string) string) (seam, witness string) {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", "reefcore_model_id", name))
	if err != nil {
		t.Fatalf("read %s: %v", name, err)
	}
	body := string(raw)
	if edit != nil {
		body = edit(body)
	}
	ws := t.TempDir()
	seam = filepath.Join(ws, "step-disclosure.json")
	if err := os.WriteFile(seam, []byte(body), 0o644); err != nil {
		t.Fatalf("write seam: %v", err)
	}
	return seam, filepath.Join(ws, "witness.json")
}

// TestModelIdentityPublishInstallCommissionFeeder is the successful
// control. It checks that every stage names the same qualified model:
// the publish commitment, the install read-back, the commission envelope,
// the witness, the PodRecord sent to PS-1, and zk_stamp.model_id sent to
// reef-core.
func TestModelIdentityPublishInstallCommissionFeeder(t *testing.T) {
	home, f := publishAndInstall(t)

	// Publish committed a v2 trailer.
	if _, err := canon.ParseCommitFieldsRoot(f.ManifestCanonical); err != nil {
		t.Fatalf("publish output has no parseable [_commit] trailer: %v", err)
	}

	// Install read-back: the committed root is recomputed and must match.
	mp, err := install.LoadManifestParams(home, f.Handle, f.PodName, f.PodVersion)
	if err != nil {
		t.Fatalf("install.LoadManifestParams: %v", err)
	}
	if !slices.Equal(mp.Models, []string{declaredModelID}) {
		t.Fatalf("install Models = %q, want [%q]", mp.Models, declaredModelID)
	}

	// Commission envelope derived from the same installed bytes.
	spec, err := pod.Parse(mp.Manifest)
	if err != nil {
		t.Fatalf("pod.Parse(manifest.canon): %v", err)
	}
	env, err := commission.FromSpec(spec)
	if err != nil {
		t.Fatalf("commission.FromSpec: %v", err)
	}
	if !slices.Equal(env.Models, mp.Models) {
		t.Fatalf("commission Models = %q, install Models = %q; the two derivations disagree", env.Models, mp.Models)
	}

	// Feeder: reef-core's golden qualified seam, unchanged.
	seam, witnessPath := copyGoldenSeam(t, "qualified_model_id.json", nil)
	if err := feeder.WriteWitness(seam, mp, witnessPath); err != nil {
		t.Fatalf("feeder.WriteWitness: %v", err)
	}

	var sentModel string
	ps1 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			PodRecord feeder.PodRecord `json:"pod_record"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Errorf("PS-1 stub: decode: %v", err)
		}
		sentModel = req.PodRecord.Model
		// PS-1's rule (assemble.rs): the model must be a declared model.
		if !slices.Contains(req.PodRecord.Models, req.PodRecord.Model) {
			http.Error(w, "model not in models", http.StatusBadRequest)
			return
		}
		e2eOKSpartanResponse(w)
	}))
	defer ps1.Close()

	var ingestBody map[string]any
	ingest := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		if err := json.Unmarshal(raw, &ingestBody); err != nil {
			t.Errorf("ingest stub: decode: %v", err)
		}
		w.WriteHeader(http.StatusCreated)
	}))
	defer ingest.Close()

	if err := feeder.Run(context.Background(), feeder.Opts{
		WitnessPath: witnessPath, PaygateURL: ps1.URL, IngestURL: ingest.URL,
		IngestToken: "t", CircuitID: "konareef-pod-step-v1",
	}); err != nil {
		t.Fatalf("feeder.Run: %v", err)
	}
	if sentModel != declaredModelID {
		t.Fatalf("PodRecord.model sent to PS-1 = %q, want %q", sentModel, declaredModelID)
	}
	zk, _ := ingestBody["zk_stamp"].(map[string]any)
	if got := zk["model_id"]; got != declaredModelID {
		t.Fatalf("zk_stamp.model_id sent to reef-core = %v, want %q", got, declaredModelID)
	}
}

// TestModelIdentityTamperRefusedBeforeProver is the model-tamper negative
// over the same real install. Each seam differs from the golden file only
// in its model fields. The feeder must refuse it and write no witness.
func TestModelIdentityTamperRefusedBeforeProver(t *testing.T) {
	home, f := publishAndInstall(t)
	mp, err := install.LoadManifestParams(home, f.Handle, f.PodName, f.PodVersion)
	if err != nil {
		t.Fatalf("install.LoadManifestParams: %v", err)
	}
	cases := []struct {
		name string
		file string
		edit func(string) string
		want error
	}{
		{"provider only", "qualified_model_id.json", func(s string) string {
			return strings.Replace(s, `"model_id":"anthropic/`, `"model_id":"openai/`, 1)
		}, feeder.ErrModelNotDeclared},
		{"name only", "qualified_model_id.json", func(s string) string {
			return strings.Replace(s, `"model_id":"anthropic/claude-sonnet-4-5"`, `"model_id":"anthropic/claude-opus-4-6"`, 1)
		}, feeder.ErrModelIDInconsistent},
		{"legacy seam without model_id", "legacy_bare_model.json", nil, feeder.ErrModelIDMissing},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			seam, witnessPath := copyGoldenSeam(t, tc.file, tc.edit)
			err := feeder.WriteWitness(seam, mp, witnessPath)
			if !errors.Is(err, tc.want) {
				t.Fatalf("WriteWitness = %v, want %v", err, tc.want)
			}
			if _, statErr := os.Stat(witnessPath); statErr == nil {
				t.Fatal("witness.json was written for a refused seam")
			}
		})
	}
}
