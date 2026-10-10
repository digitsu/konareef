// Copyright 2026 Jerry David Chan, Konareef.ai
// SPDX-License-Identifier: Apache-2.0

package commission

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/BurntSushi/toml"
	"github.com/digitsu/konareef/internal/canon"
	"github.com/digitsu/konareef/internal/pod"
)

// TestDerivationMatchesCommittedFieldsRoot proves this package's derivation
// agrees with the fields_root already committed in a published manifest. If
// it fails, the derivation disagrees with whatever produced that commitment
// and MUST NOT be shipped — a future promotion of a dimension into the
// circuit would be incoherent.
//
// It compares three of the four dimensions, and it can only compare a
// dimension the fixture set actually exercises. Until 2026-09-21 the only
// canonical v2 fixture declared no [model], so the models dimension was
// never compared — and that is exactly the dimension where the three Go
// derivations had silently diverged (spec §4.1; commission and install
// emitted "gpt-4o" while publish committed "openai/gpt-4o"). The test was
// green because it was blind. testdata/corpus/v2_zk_model_bearing_pod.toml
// now carries a [model], and the checkedWithModel guard below fails the
// test rather than letting that blindness return.
func TestDerivationMatchesCommittedFieldsRoot(t *testing.T) {
	// Both levels are globbed. testdata/ itself holds no .toml files and
	// never has — every fixture lives in testdata/corpus/ — so globbing only
	// the top level made the loop body unreachable, and the skip below fired
	// unconditionally rather than for the reason it stated. Adding a
	// committed manifest to the obvious place would not have changed that.
	var paths []string
	for _, pattern := range []string{"testdata/*.toml", "testdata/corpus/*.toml"} {
		found, _ := filepath.Glob(pattern)
		paths = append(paths, found...)
	}
	cov, err := compareDerivationToCommittedRoots(paths)
	// The counts are reported on success and on failure, so a reviewer can
	// see how much of the fixture set the comparison actually covered.
	t.Logf("fields_root coverage: %d manifest fixture(s) read, %d canonical v2 compared, "+
		"%d of those declare a [model]", cov.read, cov.checked, cov.checkedWithModel)
	if err != nil {
		t.Fatal(err)
	}
}

// fieldsRootCoverage counts what compareDerivationToCommittedRoots
// compared: read is every path given, checked is the canonical v2
// manifests whose committed fields_root was compared, and checkedWithModel
// is the subset of checked that declares a [model].
type fieldsRootCoverage struct {
	read, checked, checkedWithModel int
}

// compareDerivationToCommittedRoots derives each canonical v2 manifest's
// envelope with FromSpec and compares canon.FieldsRoot over it against the
// manifest's committed [_commit].fields_root.
//
// Input: manifest paths. A path that is not a canonical v2 manifest with a
// trailer is read and counted but not compared. Output: the coverage
// counts, and an error when any comparison disagrees, when no path was
// given, when no v2 manifest was compared, or when none of the compared
// manifests declares a [model]. The last two are errors, not skips: an
// empty comparison passed silently before 2026-09-24 (IB-03,
// konareef#21), and a comparison that never sees a [model] is how the three
// Go model-ID derivations diverged unnoticed (spec §4.1).
func compareDerivationToCommittedRoots(paths []string) (fieldsRootCoverage, error) {
	cov := fieldsRootCoverage{read: len(paths)}
	if len(paths) == 0 {
		return cov, fmt.Errorf("no manifest fixtures found under testdata/; this test cannot run at all, " +
			"which is the failure mode it previously hid behind a skip")
	}
	for _, path := range paths {
		raw, err := os.ReadFile(path)
		if err != nil {
			return cov, fmt.Errorf("%s: read: %w", path, err)
		}
		committed, err := canon.ParseCommitFieldsRoot(raw)
		if err != nil {
			continue // not a canonical v2 manifest with a [_commit] trailer
		}
		var s pod.Spec
		if _, err := toml.Decode(string(raw), &s); err != nil {
			return cov, fmt.Errorf("%s: decode manifest: %w", path, err)
		}
		e, err := FromSpec(s)
		if err != nil {
			return cov, fmt.Errorf("%s: %w", path, err)
		}
		// r_init is not an envelope dimension. Zero it here: this comparison
		// validates the three derived dimensions, and a mismatch caused by
		// r_init alone would be a different finding.
		var rInit [32]byte
		got, err := canon.FieldsRoot(e.Models, e.Tools, e.CMax, rInit)
		if err != nil {
			return cov, fmt.Errorf("%s: FieldsRoot: %w", path, err)
		}
		if got != committed {
			return cov, fmt.Errorf("%s: derivation disagrees with committed fields_root:\n got %x\nwant %x", path, got, committed)
		}
		cov.checked++
		if s.Model != nil {
			cov.checkedWithModel++
		}
	}
	if cov.checked == 0 {
		return cov, fmt.Errorf("FINDING: %d manifest fixture(s) were read, but none is a canonical v2 "+
			"manifest with a [_commit] trailer, so the envelope derivation was compared against no "+
			"real commitment. This is a failure, not a skip (IB-03, konareef#21): a vacuous "+
			"comparison must not pass. Restore a committed v2 fixture under testdata/corpus/.",
			cov.read)
	}
	// A fixture set that compares only tools and c_max leaves the models
	// dimension unexercised, which is how the three Go derivations of the
	// model id were able to disagree (spec §4.1) while this test stayed
	// green. At least one compared fixture MUST declare a [model], or the
	// guard is blind again.
	if cov.checkedWithModel == 0 {
		return cov, fmt.Errorf("FINDING: %d canonical v2 fixture(s) were compared, but none declares a "+
			"[model], so the models dimension of fields_root was never compared. Add a "+
			"fixture with a [model] section; until then this guard cannot see a models "+
			"derivation that disagrees with what publish committed.", cov.checked)
	}
	return cov, nil
}

// TestCompareDerivationRefusesAVacuousFixtureSet proves the comparison
// above fails, rather than skips, when the fixture set loses its
// committed v2 manifests (IB-03, konareef#21). Each case removes fixtures
// from the real corpus and checks the error.
func TestCompareDerivationRefusesAVacuousFixtureSet(t *testing.T) {
	const (
		v1VoiceForge  = "testdata/corpus/demo_pods_voice-forge_pod.toml"
		v2MemoryFree  = "testdata/corpus/v2_zk_memory_free_pod.toml"
		v2ModelBearer = "testdata/corpus/v2_zk_model_bearing_pod.toml"
	)
	cases := []struct {
		name    string
		paths   []string
		wantErr string
	}{
		{"no fixtures at all", nil, "no manifest fixtures"},
		{"every v2 fixture removed", []string{v1VoiceForge}, "none is a canonical v2"},
		{"model-bearing v2 fixture removed", []string{v1VoiceForge, v2MemoryFree}, "none declares a [model]"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := compareDerivationToCommittedRoots(tc.paths)
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("compareDerivationToCommittedRoots(%q) = %v, want an error containing %q",
					tc.paths, err, tc.wantErr)
			}
		})
	}
	// Control: the model-bearing fixture alone is enough to pass.
	cov, err := compareDerivationToCommittedRoots([]string{v2ModelBearer})
	if err != nil || cov.checked != 1 || cov.checkedWithModel != 1 {
		t.Fatalf("control: coverage %+v, err %v; want 1 compared with a [model]", cov, err)
	}
}
