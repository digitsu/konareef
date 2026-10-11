// Copyright 2026 Jerry David Chan, Konareef.ai
// SPDX-License-Identifier: Apache-2.0

// model_identity_test.go — the feeder's qualified model identity gate
// (IB-03, konareef#21), tested against the fixtures reef-core publishes for
// the same contract (IB-02, reef-core#50). The fixtures are vendored byte
// for byte under testdata/reefcore_model_id; see the README there.
package feeder

import (
	"context"
	"crypto/sha1"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/digitsu/konareef/internal/canon"
)

// reefcoreFixtureDir holds the vendored reef-core fixtures.
const reefcoreFixtureDir = "testdata/reefcore_model_id"

// vendoredFixtureBlobs pins each vendored file to the git blob ID it had in
// reef-core. A local edit changes the blob ID and fails
// TestVendoredReefCoreFixturesAreUnmodified, so the files cannot drift from
// the reef-core contract without a visible re-vendor.
var vendoredFixtureBlobs = map[string]string{
	"vectors.json":            "712036398ae089a588da035570c0f64f53817f0c",
	"qualified_model_id.json": "2ed5b6231d68ed922bf1d27c71c191ebda9b5301",
	"legacy_bare_model.json":  "a5a2f6a9be2c4c07e2013065b72077317c549293",
}

// gitBlobID returns the git blob object ID of content: the hex SHA-1 of
// "blob <len>\x00" followed by the bytes. Input: file bytes. Output: the
// 40-character ID `git hash-object` prints. Computing it here keeps the
// check independent of a git binary or a surrounding repository (exported
// source trees, containers with a detached worktree).
func gitBlobID(content []byte) string {
	h := sha1.New()
	fmt.Fprintf(h, "blob %d\x00", len(content))
	h.Write(content)
	return hex.EncodeToString(h.Sum(nil))
}

// TestVendoredReefCoreFixturesAreUnmodified checks each vendored fixture
// against its reef-core git blob ID. Input: the files on disk. Output: a
// test failure naming any file whose content differs from what was copied.
func TestVendoredReefCoreFixturesAreUnmodified(t *testing.T) {
	for name, want := range vendoredFixtureBlobs {
		content, err := os.ReadFile(filepath.Join(reefcoreFixtureDir, name))
		if err != nil {
			t.Fatalf("read %s: %v", name, err)
		}
		if got := gitBlobID(content); got != want {
			t.Fatalf("%s: blob %s, want %s — the vendored reef-core fixture was edited; "+
				"re-vendor it from reef-core instead (see %s/README.md)", name, got, want, reefcoreFixtureDir)
		}
	}
}

// modelIDVectors is the subset of reef-core's vectors.json this package
// reads.
type modelIDVectors struct {
	QualifiedID struct {
		Accept []struct {
			Provider string `json:"provider"`
			Name     string `json:"name"`
			ID       string `json:"id"`
		} `json:"accept"`
		Reject []struct {
			Provider     *string `json:"provider"`
			Name         *string `json:"name"`
			Error        string  `json:"error"`
			KonareefCode *string `json:"konareef_code"`
		} `json:"reject"`
	} `json:"qualified_id"`
	RuntimeSelection struct {
		Accept []struct {
			ModelProvider *string `json:"model_provider"`
			Model         *string `json:"model"`
			WireModel     string  `json:"wire_model"`
		} `json:"accept"`
	} `json:"runtime_selection"`
}

// loadModelIDVectors reads the vendored vectors.json.
func loadModelIDVectors(t *testing.T) modelIDVectors {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(reefcoreFixtureDir, "vectors.json"))
	if err != nil {
		t.Fatalf("read vectors.json: %v", err)
	}
	var v modelIDVectors
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatalf("parse vectors.json: %v", err)
	}
	if len(v.QualifiedID.Accept) == 0 || len(v.QualifiedID.Reject) == 0 || len(v.RuntimeSelection.Accept) == 0 {
		t.Fatal("vectors.json has an empty vector list; the comparison below would be vacuous")
	}
	return v
}

// derefOrEmpty maps a JSON null to "", which is how Go callers pass an
// absent part to canon.ModelID.
func derefOrEmpty(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

// TestQualifiedIDVectorsMatchCanonModelID proves konareef's canon.ModelID
// and reef-core's ModelSelection.qualified_id form the same ID from the
// same pair, and that the feeder accepts exactly that ID when the manifest
// declares it.
func TestQualifiedIDVectorsMatchCanonModelID(t *testing.T) {
	v := loadModelIDVectors(t)
	for _, a := range v.QualifiedID.Accept {
		got, err := canon.ModelID(a.Provider, a.Name)
		if err != nil {
			t.Fatalf("canon.ModelID(%q, %q): %v", a.Provider, a.Name, err)
		}
		if got != a.ID {
			t.Fatalf("canon.ModelID(%q, %q) = %q, reef-core vector says %q", a.Provider, a.Name, got, a.ID)
		}
		sd := StepDisclosure{Model: a.Name, ModelID: a.ID}
		model, err := witnessModelID(sd, []string{a.ID})
		if err != nil {
			t.Fatalf("witnessModelID(%q) with it declared: %v", a.ID, err)
		}
		if model != a.ID {
			t.Fatalf("witness model = %q, want the disclosed %q unchanged", model, a.ID)
		}
	}
	for _, r := range v.QualifiedID.Reject {
		provider, name := derefOrEmpty(r.Provider), derefOrEmpty(r.Name)
		_, err := canon.ModelID(provider, name)
		if r.KonareefCode == nil {
			// reef-core refuses a provider that contains "/" as ambiguous.
			// canon.ModelID accepts it, because the string alone cannot show
			// where the provider ends. The feeder therefore cannot refuse it
			// from the seam; the membership check against the declared set
			// is what binds it. Pin that difference so a change on either
			// side is visible.
			if err != nil {
				t.Fatalf("vector %q: canon.ModelID now refuses it (%v); update the vector note and this test", r.Error, err)
			}
			continue
		}
		var ce *canon.Error
		if !errors.As(err, &ce) || ce.Code != *r.KonareefCode {
			t.Fatalf("canon.ModelID(%q, %q) error = %v, want code %s", provider, name, err, *r.KonareefCode)
		}
	}
}

// TestRuntimeSelectionVectorsFeedTheWitness drives every reef-core runtime
// selection that reef-core accepts through the feeder: the disclosed
// wire_model becomes the witness model unchanged.
func TestRuntimeSelectionVectorsFeedTheWitness(t *testing.T) {
	v := loadModelIDVectors(t)
	for _, a := range v.RuntimeSelection.Accept {
		// reef-core discloses the bare Config.model next to model_id. For the
		// default-model vector the bare value is null.
		sd := StepDisclosure{Model: derefOrEmpty(a.Model), ModelID: a.WireModel}
		got, err := witnessModelID(sd, []string{a.WireModel})
		if err != nil {
			t.Fatalf("selection %+v: %v", a, err)
		}
		if got != a.WireModel {
			t.Fatalf("witness model = %q, want %q", got, a.WireModel)
		}
	}
}

// TestWitnessModelIDRefusals covers each refusal of the model gate. Every
// case must fail with the named sentinel error.
func TestWitnessModelIDRefusals(t *testing.T) {
	declared := []string{"anthropic/claude-sonnet-4-5"}
	cases := []struct {
		name     string
		sd       StepDisclosure
		declared []string
		want     error
	}{
		{"legacy seam: bare model only", StepDisclosure{Model: "claude-sonnet-4-5"}, declared, ErrModelIDMissing},
		{"legacy seam: nothing at all", StepDisclosure{}, declared, ErrModelIDMissing},
		{"bare name in model_id", StepDisclosure{Model: "claude-sonnet-4-5", ModelID: "claude-sonnet-4-5"}, declared, ErrModelIDMalformed},
		{"empty provider", StepDisclosure{ModelID: "/claude-sonnet-4-5"}, declared, ErrModelIDMalformed},
		{"empty name", StepDisclosure{ModelID: "anthropic/"}, declared, ErrModelIDMalformed},
		{"bare model disagrees with model_id", StepDisclosure{Model: "claude-opus-4-6", ModelID: "anthropic/claude-sonnet-4-5"}, declared, ErrModelIDInconsistent},
		{"only the provider changed", StepDisclosure{Model: "claude-sonnet-4-5", ModelID: "openai/claude-sonnet-4-5"}, declared, ErrModelNotDeclared},
		{"same name, other provider in the declared set", StepDisclosure{Model: "gpt-4o", ModelID: "azure/gpt-4o"}, []string{"openai/gpt-4o"}, ErrModelNotDeclared},
		{"case differs (no folding)", StepDisclosure{Model: "claude-sonnet-4-5", ModelID: "Anthropic/claude-sonnet-4-5"}, declared, ErrModelNotDeclared},
		{"empty declared set", StepDisclosure{Model: "claude-sonnet-4-5", ModelID: "anthropic/claude-sonnet-4-5"}, nil, ErrModelNotDeclared},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := witnessModelID(tc.sd, tc.declared)
			if !errors.Is(err, tc.want) {
				t.Fatalf("witnessModelID = (%q, %v), want error %v", got, err, tc.want)
			}
		})
	}
}

// copyVendoredSeam copies a vendored reef-core seam file into dir as
// step-disclosure.json, unchanged, and returns its path.
func copyVendoredSeam(t *testing.T, name, dir string) string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(reefcoreFixtureDir, name))
	if err != nil {
		t.Fatalf("read %s: %v", name, err)
	}
	path := filepath.Join(dir, "step-disclosure.json")
	if err := os.WriteFile(path, raw, 0o644); err != nil {
		t.Fatalf("write seam: %v", err)
	}
	return path
}

// TestWriteWitnessConsumesReefCoreQualifiedSeam is the successful control:
// reef-core's golden qualified seam file, read unchanged, produces a
// witness whose Model is the disclosed qualified ID, not the bare name and
// not a value copied from the declared set.
func TestWriteWitnessConsumesReefCoreQualifiedSeam(t *testing.T) {
	dir := t.TempDir()
	seam := copyVendoredSeam(t, "qualified_model_id.json", dir)
	out := filepath.Join(dir, "witness.json")

	if err := WriteWitness(seam, validManifestParams(), out); err != nil {
		t.Fatalf("WriteWitness: %v", err)
	}
	raw, err := os.ReadFile(out)
	if err != nil {
		t.Fatalf("read witness: %v", err)
	}
	var w Witness
	if err := json.Unmarshal(raw, &w); err != nil {
		t.Fatalf("parse witness: %v", err)
	}
	if w.Model != "anthropic/claude-sonnet-4-5" {
		t.Fatalf("witness Model = %q, want the qualified anthropic/claude-sonnet-4-5", w.Model)
	}
	if len(w.ToolLog) != 1 || w.ToolLog[0].Tool != "bash" || w.ToolLog[0].Ts != 42 {
		t.Fatalf("tool_log not carried from the golden seam: %+v", w.ToolLog)
	}
	if string(w.P) != "say hello" || string(w.R) != "done" || w.C != 1234 {
		t.Fatalf("P/R/C not carried from the golden seam: p=%q r=%q c=%d", w.P, w.R, w.C)
	}
}

// TestWriteWitnessRefusesReefCoreLegacySeam proves the feeder does not
// fall back to the bare model: reef-core's golden legacy seam file (the
// same run without model_id) is refused, and no witness file is written.
func TestWriteWitnessRefusesReefCoreLegacySeam(t *testing.T) {
	dir := t.TempDir()
	seam := copyVendoredSeam(t, "legacy_bare_model.json", dir)
	out := filepath.Join(dir, "witness.json")

	err := WriteWitness(seam, validManifestParams(), out)
	if !errors.Is(err, ErrModelIDMissing) {
		t.Fatalf("WriteWitness(legacy seam) = %v, want ErrModelIDMissing", err)
	}
	if _, statErr := os.Stat(out); statErr == nil {
		t.Fatal("witness.json was written for a refused seam")
	}
}

// TestWriteWitnessRefusesProviderOnlyChange changes only the provider in
// the golden seam file. The bare model, P, R and tool log stay the same, so
// only the model gate can refuse it. No witness file may be written.
func TestWriteWitnessRefusesProviderOnlyChange(t *testing.T) {
	dir := t.TempDir()
	raw, err := os.ReadFile(filepath.Join(reefcoreFixtureDir, "qualified_model_id.json"))
	if err != nil {
		t.Fatalf("read golden seam: %v", err)
	}
	tampered := strings.Replace(string(raw), `"model_id":"anthropic/`, `"model_id":"openai/`, 1)
	if tampered == string(raw) {
		t.Fatal("golden seam no longer contains the anthropic model_id this test edits")
	}
	seam := filepath.Join(dir, "step-disclosure.json")
	if err := os.WriteFile(seam, []byte(tampered), 0o644); err != nil {
		t.Fatalf("write seam: %v", err)
	}
	out := filepath.Join(dir, "witness.json")

	err = WriteWitness(seam, validManifestParams(), out)
	if !errors.Is(err, ErrModelNotDeclared) {
		t.Fatalf("WriteWitness(provider changed) = %v, want ErrModelNotDeclared", err)
	}
	if _, statErr := os.Stat(out); statErr == nil {
		t.Fatal("witness.json was written for a refused seam")
	}
}

// TestAssemblePodRecordRefusesAnUndeclaredModel covers the path that skips
// WriteWitness: `konareef feeder` without --step-disclosure reads a
// pre-written witness.json. AssemblePodRecord must still refuse a model
// outside the declared set, as PS-1 does (paygate-zk assemble.rs), so the
// run fails before the prover call.
func TestAssemblePodRecordRefusesAnUndeclaredModel(t *testing.T) {
	w := Witness{
		Model:       "claude-sonnet-4-5",
		Models:      []string{"anthropic/claude-sonnet-4-5"},
		SigManifest: validSigLane(),
		PkPub:       validPubKeyBytes(),
	}
	if _, err := AssemblePodRecord(w); !errors.Is(err, ErrModelNotDeclared) {
		t.Fatalf("AssemblePodRecord(bare model) = %v, want ErrModelNotDeclared", err)
	}
	w.Model = "anthropic/claude-sonnet-4-5"
	if _, err := AssemblePodRecord(w); err != nil {
		t.Fatalf("AssemblePodRecord(declared model): %v", err)
	}
}

// TestPostArtifactCarriesTheQualifiedModelIDVerbatim checks the last hop:
// the ingest body's zk_stamp.model_id is the witness model byte for byte,
// including the "/" and a name that itself contains "/". Nothing between
// the witness and reef-core shortens it to the bare name.
func TestPostArtifactCarriesTheQualifiedModelIDVerbatim(t *testing.T) {
	for _, id := range []string{"anthropic/claude-sonnet-4-5", "openrouter/anthropic/claude-3"} {
		var raw []byte
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			raw, _ = io.ReadAll(r.Body)
			w.WriteHeader(http.StatusCreated)
		}))
		scr := &SpartanCompressResult{VkeyHash: make([]byte, 32), CircuitID: "konareef-pod-step-v1"}
		err := PostArtifact(context.Background(), srv.URL, "tok", scr, Witness{Model: id})
		srv.Close()
		if err != nil {
			t.Fatalf("PostArtifact(%q): %v", id, err)
		}
		var body struct {
			ZKStamp struct {
				ModelID string `json:"model_id"`
			} `json:"zk_stamp"`
		}
		if err := json.Unmarshal(raw, &body); err != nil {
			t.Fatalf("decode ingest body: %v", err)
		}
		if body.ZKStamp.ModelID != id {
			t.Fatalf("zk_stamp.model_id = %q, want %q", body.ZKStamp.ModelID, id)
		}
	}
}
