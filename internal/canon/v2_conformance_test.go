// Copyright 2026 Jerry David Chan, Konareef.ai
// SPDX-License-Identifier: Apache-2.0

// v2_conformance_test.go — the konareef-toml/v2 MANIFEST-LEVEL golden-vector
// conformance suite. Mirrors canon_test.go's TestConformance house style:
// every directory under testdata/canon/v2/<case>/ is one test vector,
// discovered and run by walking the tree.
//
// A case is either:
//
//   - a positive case — has expected.canonical (the exact v2 bytes
//     CanonicalizeV2 must produce) and expected.json (the models_root,
//     tools_root, fields_root, and h_manifest the chain pod.toml → v2 bytes
//     → fields_root must pin), or
//   - a reject case — has expected.error (the stable §7 error code
//     CanonicalizeV2 must fail with).
//
// Every case has an input/pod.toml (the author document + pod directory
// CanonicalizeV2 is called against — the directory holds ONLY pod.toml, so
// [_files] is always empty and cannot contaminate the pinned bytes) and a
// params.json (the CommitParams to commit — see commitParamsFixture below).
//
// Scope: this suite exercises exactly what CanonicalizeV2/FieldsRoot can
// raise on their own — RESERVED_KEY_COMMIT (canonicalBody's AST gate) and
// the FieldsRoot structural gates (COMMIT_OVER_CAP, COMMIT_DUPLICATE_ENTRY,
// COMMIT_EMPTY_ID, COMMIT_INVALID_UTF8_ID). The remaining task-10 codes —
// COMMIT_BUDGET_REQUIRED, COMMIT_MODEL_PROVIDER_MISSING,
// COMMIT_TOOL_AUTHORITY_UNCOMMITTED, COMMIT_NON_NFC_ID, and
// COMMIT_MEMORY_RESOLUTION_UNAVAILABLE — are raised by
// internal/publish.DeriveCommitParams, one layer up from canon, and are
// pinned in internal/publish/v2_manifest_conformance_test.go instead: canon
// has no manifest-sourcing logic of its own (R-V2.9) to raise them from.
//
// The golden files are bootstrapped with `go test -run TestConformanceV2
// -update` (reusing canon_test.go's -update flag), then read by hand
// against the spec before being committed — see the task-10 report for
// what was checked in each one.
package canon

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/digitsu/konareef/internal/poseidon"
)

// commitParamsFixture is the on-disk JSON shape of a case's params.json.
// Models/Tools carry plain UTF-8 string ids; ModelsB64/ToolsB64 (mutually
// exclusive with Models/Tools within the same list) carry base64-encoded
// raw bytes for the one vector that must commit a byte sequence JSON
// cannot spell directly as a string — an invalid-UTF-8 id.
type commitParamsFixture struct {
	Models    []string `json:"models,omitempty"`
	Tools     []string `json:"tools,omitempty"`
	ModelsB64 []string `json:"models_b64,omitempty"`
	ToolsB64  []string `json:"tools_b64,omitempty"`
	CMax      uint64   `json:"c_max"`
	RInit     string   `json:"r_init"`
}

// loadCommitParams reads and decodes a case's params.json into a
// CommitParams. b64 entries, when present, take precedence over the
// plain-string list of the same field.
func loadCommitParams(t *testing.T, dir string) CommitParams {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(dir, "params.json"))
	if err != nil {
		t.Fatalf("read params.json: %v", err)
	}
	var f commitParamsFixture
	if err := json.Unmarshal(raw, &f); err != nil {
		t.Fatalf("parse params.json: %v", err)
	}

	models := f.Models
	if len(f.ModelsB64) > 0 {
		models = make([]string, len(f.ModelsB64))
		for i, b := range f.ModelsB64 {
			decoded, err := base64.StdEncoding.DecodeString(b)
			if err != nil {
				t.Fatalf("params.json models_b64[%d]: %v", i, err)
			}
			models[i] = string(decoded)
		}
	}
	tools := f.Tools
	if len(f.ToolsB64) > 0 {
		tools = make([]string, len(f.ToolsB64))
		for i, b := range f.ToolsB64 {
			decoded, err := base64.StdEncoding.DecodeString(b)
			if err != nil {
				t.Fatalf("params.json tools_b64[%d]: %v", i, err)
			}
			tools[i] = string(decoded)
		}
	}

	var rInit [32]byte
	if f.RInit != "" {
		decoded, err := hex.DecodeString(f.RInit)
		if err != nil || len(decoded) != 32 {
			t.Fatalf("params.json r_init: bad hex %q", f.RInit)
		}
		copy(rInit[:], decoded)
	}

	return CommitParams{Models: models, Tools: tools, CMax: f.CMax, RInit: rInit}
}

// TestConformanceV2 discovers and runs every vector under
// testdata/canon/v2.
func TestConformanceV2(t *testing.T) {
	root := filepath.Join("testdata", "canon", "v2")
	cases, err := os.ReadDir(root)
	if err != nil {
		t.Fatalf("read suite root %s: %v", root, err)
	}
	ran := 0
	for _, vector := range cases {
		if !vector.IsDir() || strings.HasPrefix(vector.Name(), ".") {
			continue
		}
		name := vector.Name()
		caseDir := filepath.Join(root, name)
		t.Run(name, func(t *testing.T) { runVectorV2(t, caseDir) })
		ran++
	}
	if ran == 0 {
		t.Fatalf("no v2 conformance vectors found under %s", root)
	}
}

// runVectorV2 executes a single v2 test vector directory.
func runVectorV2(t *testing.T, dir string) {
	inputDir := filepath.Join(dir, "input")
	podTOML, err := os.ReadFile(filepath.Join(inputDir, "pod.toml"))
	if err != nil {
		t.Fatalf("read input/pod.toml: %v", err)
	}
	params := loadCommitParams(t, dir)

	if wantCode, isReject := readRejectV2(t, dir); isReject {
		runRejectVectorV2(t, podTOML, inputDir, params, wantCode)
		return
	}
	runPositiveVectorV2(t, dir, podTOML, inputDir, params)
}

// readRejectV2 returns the expected error code and true when dir is a
// reject vector (it has an expected.error file).
func readRejectV2(t *testing.T, dir string) (string, bool) {
	raw, err := os.ReadFile(filepath.Join(dir, "expected.error"))
	if err != nil {
		return "", false
	}
	return strings.TrimSpace(string(raw)), true
}

// runRejectVectorV2 asserts that CanonicalizeV2 fails with exactly the
// expected stable error code — and produces no output.
func runRejectVectorV2(t *testing.T, podTOML []byte, inputDir string, params CommitParams, wantCode string) {
	out, err := CanonicalizeV2(podTOML, inputDir, params)
	if err == nil {
		t.Fatalf("expected rejection %s, got %d bytes of output", wantCode, len(out))
	}
	if out != nil {
		t.Errorf("rejection produced %d bytes of output; CanonicalizeV2 must be all-or-nothing", len(out))
	}
	if got := Code(err); got != wantCode {
		t.Fatalf("expected error code %s, got %s (%v)", wantCode, got, err)
	}
}

// commitFieldsRootJSON is the on-disk JSON shape of a positive case's
// expected.json: every root the pod.toml -> v2 bytes -> fields_root chain
// commits, hex-encoded.
type commitFieldsRootJSON struct {
	ModelsRoot string `json:"models_root"`
	ToolsRoot  string `json:"tools_root"`
	FieldsRoot string `json:"fields_root"`
	HManifest  string `json:"h_manifest"`
}

// runPositiveVectorV2 asserts byte-exact canonical v2 output, and pins
// models_root, tools_root, fields_root, and h_manifest — cross-checking
// every one of them against an INDEPENDENT recomputation rather than
// merely trusting whatever CanonicalizeV2 emitted (the task-10 "read the
// golden value" rule):
//
//   - models_root / tools_root are recomputed via idTreeRoot directly
//     (the same unexported helper FieldsRoot itself calls) and then
//     recombined by hand into a fields_root, which must equal...
//   - ...the fields_root a SEPARATE, direct call to the exported
//     FieldsRoot(params...) returns, which must equal...
//   - ...the fields_root ParseCommitFieldsRoot extracts back out of the
//     emitted [_commit] trailer (R-V2.23 link (b), read-back direction).
//
// h_manifest is SHA-256 of the emitted bytes (R-V2.23 link (a)).
func runPositiveVectorV2(t *testing.T, dir string, podTOML []byte, inputDir string, params CommitParams) {
	got, err := CanonicalizeV2(podTOML, inputDir, params)
	if err != nil {
		t.Fatalf("CanonicalizeV2: %v", err)
	}

	canonicalPath := filepath.Join(dir, "expected.canonical")
	jsonPath := filepath.Join(dir, "expected.json")

	// Independent recomputation of models_root/tools_root via the SAME
	// building block FieldsRoot uses, then hand-recombined per the
	// documented fields_root construction (fieldsroot.go).
	p := poseidon.Default()
	modelsRoot, err := idTreeRoot(p, params.Models, MaxModels, modelLeaf)
	if err != nil {
		t.Fatalf("independent models_root: %v", err)
	}
	toolsRoot, err := idTreeRoot(p, params.Tools, MaxTools, toolLeaf)
	if err != nil {
		t.Fatalf("independent tools_root: %v", err)
	}
	var cMaxWord [32]byte
	putUint64LE(cMaxWord[:8], params.CMax)
	cMaxLeaf, err := p.LeafHash(cMaxWord)
	if err != nil {
		t.Fatalf("independent c_max leaf: %v", err)
	}
	rInitLeaf, err := p.LeafHash(params.RInit)
	if err != nil {
		t.Fatalf("independent r_init leaf: %v", err)
	}
	left, err := p.InternalHash(modelsRoot, toolsRoot)
	if err != nil {
		t.Fatalf("independent left node: %v", err)
	}
	right, err := p.InternalHash(cMaxLeaf, rInitLeaf)
	if err != nil {
		t.Fatalf("independent right node: %v", err)
	}
	recombinedFieldsRoot, err := p.InternalHash(left, right)
	if err != nil {
		t.Fatalf("independent fields_root: %v", err)
	}

	// Cross-check against a direct, separate FieldsRoot(...) call — the
	// same one CanonicalizeV2 made internally.
	directFieldsRoot, err := FieldsRoot(params.Models, params.Tools, params.CMax, params.RInit)
	if err != nil {
		t.Fatalf("direct FieldsRoot: %v", err)
	}
	if directFieldsRoot != recombinedFieldsRoot {
		t.Fatalf("hand-recombined fields_root %x disagrees with direct FieldsRoot %x",
			recombinedFieldsRoot, directFieldsRoot)
	}

	// Cross-check against the value actually emitted in [_commit],
	// read back through the verifier-side parser (R-V2.23 link (b)).
	parsedFieldsRoot, err := ParseCommitFieldsRoot(got)
	if err != nil {
		t.Fatalf("ParseCommitFieldsRoot(emitted output): %v", err)
	}
	if parsedFieldsRoot != directFieldsRoot {
		t.Fatalf("[_commit].fields_root %x (parsed back) disagrees with FieldsRoot %x",
			parsedFieldsRoot, directFieldsRoot)
	}

	hManifest := sha256.Sum256(got)

	if *updateGolden {
		if err := os.WriteFile(canonicalPath, got, 0o644); err != nil {
			t.Fatalf("write %s: %v", canonicalPath, err)
		}
		out := commitFieldsRootJSON{
			ModelsRoot: hex.EncodeToString(modelsRoot[:]),
			ToolsRoot:  hex.EncodeToString(toolsRoot[:]),
			FieldsRoot: hex.EncodeToString(directFieldsRoot[:]),
			HManifest:  hex.EncodeToString(hManifest[:]),
		}
		raw, err := json.MarshalIndent(out, "", "  ")
		if err != nil {
			t.Fatalf("marshal expected.json: %v", err)
		}
		raw = append(raw, '\n')
		if err := os.WriteFile(jsonPath, raw, 0o644); err != nil {
			t.Fatalf("write %s: %v", jsonPath, err)
		}
	}

	wantCanonical, err := os.ReadFile(canonicalPath)
	if err != nil {
		t.Fatalf("read expected.canonical (run -update to create it): %v", err)
	}
	if string(got) != string(wantCanonical) {
		t.Errorf("canonical v2 output mismatch\n--- got (%d bytes) ---\n%s\n--- want (%d bytes) ---\n%s",
			len(got), got, len(wantCanonical), wantCanonical)
	}

	rawWant, err := os.ReadFile(jsonPath)
	if err != nil {
		t.Fatalf("read expected.json (run -update to create it): %v", err)
	}
	var want commitFieldsRootJSON
	if err := json.Unmarshal(rawWant, &want); err != nil {
		t.Fatalf("parse expected.json: %v", err)
	}

	if got := hex.EncodeToString(modelsRoot[:]); got != want.ModelsRoot {
		t.Errorf("models_root = %s, want %s", got, want.ModelsRoot)
	}
	if got := hex.EncodeToString(toolsRoot[:]); got != want.ToolsRoot {
		t.Errorf("tools_root = %s, want %s", got, want.ToolsRoot)
	}
	if got := hex.EncodeToString(directFieldsRoot[:]); got != want.FieldsRoot {
		t.Errorf("fields_root = %s, want %s", got, want.FieldsRoot)
	}
	if got := hex.EncodeToString(hManifest[:]); got != want.HManifest {
		t.Errorf("h_manifest = %s, want %s", got, want.HManifest)
	}
}

// putUint64LE writes v as 8 little-endian bytes into dst, mirroring
// fieldsroot.go's FieldsRoot inline packing (binary.LittleEndian.PutUint64)
// without importing encoding/binary a second time for one call site.
func putUint64LE(dst []byte, v uint64) {
	for i := 0; i < 8; i++ {
		dst[i] = byte(v >> (8 * i))
	}
}
