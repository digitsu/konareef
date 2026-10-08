// Copyright 2026 Jerry David Chan, Konareef.ai
// SPDX-License-Identifier: Apache-2.0

// v2_manifest_conformance_test.go — the konareef-toml/v2 manifest-level
// conformance vectors for the five §7 codes that DeriveCommitParams raises,
// not canon (task-10 brief). canon.CanonicalizeV2/FieldsRoot have no
// manifest-sourcing logic of their own (R-V2.9: "canon performs no
// resolution of its own") — they only structurally validate the
// CommitParams a caller hands them. The manifest-sourcing refusals live
// entirely in DeriveCommitParams (commitparams.go), so that is where these
// five vectors are pinned:
//
//   - COMMIT_BUDGET_REQUIRED            — no [budget].max_sats
//   - COMMIT_MODEL_PROVIDER_MISSING     — [model] declares no provider/name
//   - COMMIT_TOOL_AUTHORITY_UNCOMMITTED — tools_allowed names an uncommitted tool
//   - COMMIT_NON_NFC_ID                 — a [[context.tools]] source not in NFC
//   - COMMIT_MEMORY_RESOLUTION_UNAVAILABLE — [[context.memory]] present
//
// This is a companion suite to internal/canon/v2_conformance_test.go, which
// pins the five codes canon itself raises (RESERVED_KEY_COMMIT,
// COMMIT_DUPLICATE_ENTRY, COMMIT_OVER_CAP, COMMIT_EMPTY_ID,
// COMMIT_INVALID_UTF8_ID) against real pod.toml + CommitParams fixtures.
// Together the two suites cover every task-10 error code, each at the
// layer that actually raises it.
//
// commitparams_test.go already exercises these same five refusals with
// inline TOML string literals (TestDeriveCommitParams,
// TestMemoryBearingPodIsRefused); this suite adds pod.toml FILE fixtures
// under testdata/v2/ so the manifest-level vectors are discoverable and
// reviewable the same way the canon-side suite's are, per the task-10
// brief's request for file-based vectors "one per error code."
package publish

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/digitsu/konareef/internal/canon"
	"github.com/digitsu/konareef/internal/pod"
)

// TestConformanceV2Manifest discovers and runs every vector under
// testdata/v2: each case's pod.toml is parsed and passed to
// DeriveCommitParams, and the resulting canon.Code(err) must equal the
// case's expected.error.
func TestConformanceV2Manifest(t *testing.T) {
	root := filepath.Join("testdata", "v2")
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
		t.Run(name, func(t *testing.T) { runManifestVector(t, caseDir) })
		ran++
	}
	if ran == 0 {
		t.Fatalf("no v2 manifest conformance vectors found under %s", root)
	}
}

// runManifestVector parses one case's pod.toml, calls DeriveCommitParams,
// and asserts it fails with exactly the case's expected.error code.
// Every current vector in this suite is a rejection — DeriveCommitParams
// raising a code is what task-10 is pinning here — but a future positive
// case (an expected.json instead of expected.error) is deliberately left
// room for by checking for expected.error explicitly rather than assuming
// every case rejects.
func runManifestVector(t *testing.T, dir string) {
	podTOML, err := os.ReadFile(filepath.Join(dir, "pod.toml"))
	if err != nil {
		t.Fatalf("read pod.toml: %v", err)
	}
	rawWant, err := os.ReadFile(filepath.Join(dir, "expected.error"))
	if err != nil {
		t.Fatalf("read expected.error (this suite has no positive cases yet): %v", err)
	}
	wantCode := strings.TrimSpace(string(rawWant))

	spec, meta, err := pod.ParseWithMeta(podTOML)
	if err != nil {
		t.Fatalf("parse pod.toml: %v", err)
	}

	_, derr := DeriveCommitParams(spec, meta)
	if derr == nil {
		t.Fatalf("expected rejection %s, got a successful DeriveCommitParams", wantCode)
	}
	if got := canon.Code(derr); got != wantCode {
		t.Fatalf("expected error code %s, got %s (%v)", wantCode, got, derr)
	}
}
