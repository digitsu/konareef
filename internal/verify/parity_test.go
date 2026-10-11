// Copyright 2026 Jerry David Chan, Konareef.ai
// SPDX-License-Identifier: Apache-2.0

package verify

import (
	"strings"
	"testing"
)

// TestVerifyParityVectorRealReefCore loads a bundle produced by
// reef-core's Bundle.pack/2 (committed at
// testdata/parity-real-1.bundle.json) and asserts that the Go
// Verify pipeline returns OK with no divergences. This is the only
// test in the suite whose input was NOT constructed by Go — every
// other test builds its bundle in-process. A failure here means a
// reef-core/Go primitive divergence; treat it as a wire-format bug
// regardless of which side seems "more correct" and reconcile.
//
// Regenerate the fixture when reef-core's Hash.compute,
// MerkleTree.build, compute_access_log_hash, or Bundle.pack format
// changes:
//
//	cd ~/work/reef-core
//	WRITE_PARITY_FIXTURE=1 \
//	PARITY_FIXTURE_PATH=$HOME/work/konareef/internal/verify/testdata/parity-real-1.bundle.json \
//	mix test test/pod/proofs/bundle_test.exs
//
// The bundle's chain timestamps + random hashes drift on every
// regen, so this test asserts behaviour (Verify == OK), not bytes.
func TestVerifyParityVectorRealReefCore(t *testing.T) {
	b, err := Load("testdata/parity-real-1.bundle.json")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if b.Version != BundleVersion {
		t.Fatalf("fixture version = %q, want %q (regenerate the fixture)", b.Version, BundleVersion)
	}

	r := Verify(b)
	if !r.OK {
		t.Errorf(
			"Verify rejected a reef-core-generated bundle — Go/Elixir primitive divergence:\n  %s",
			strings.Join(r.Divergences, "\n  "),
		)
	}
	if r.ChainLength == 0 {
		t.Errorf("fixture had an empty chain — regenerate it")
	}
}
