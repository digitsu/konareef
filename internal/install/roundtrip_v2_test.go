// Copyright 2026 Jerry David Chan, Konareef.ai
// SPDX-License-Identifier: Apache-2.0

// roundtrip_v2_test.go — the R-V2.16 round-trip guard.
//
// Spec §8.3 states the requirement: "A v2 pod survives publish → install →
// re-canonicalize with the same PodHash, exercising all four §6.2 sites.
// The test MUST fail if any site is left on the v1 path."
//
// The first version of this test lived in internal/publish and drove
// canon.Recanonicalize for its re-canonicalization leg. install does not
// call Recanonicalize — Rulings 7 and 9 removed both candidate call sites —
// so the test could not fail for the reason R-V2.16 requires. A reviewer
// mutation-verified it: reverting install.go's CanonicalizeLike call to
// canon.Canonicalize left that test PASSING. It was a guard over a function
// no production path used.
//
// This version drives the production path only: publish.Prepare for the
// publish site, and install.Verify — which re-canonicalizes the extracted
// tarball through verifyContentTarball — for the install sites. It lives in
// package install because that is where those sites are; internal/install
// already imports internal/publish, so the whole round trip is reachable
// from here and nothing is imitated by hand.
package install

import (
	"bytes"
	"crypto/sha256"
	"os"
	"path/filepath"
	"testing"

	"github.com/digitsu/konareef/internal/canon"
	"github.com/digitsu/konareef/internal/publish"
)

// TestV2PodSurvivesPublishInstallRoundTrip proves R-V2.16 over the real
// call sites, in the order a buyer meets them:
//
//  1. publish — publish.Prepare(..., PrepareOptions{ZK: true}) produces the
//     signed CanonicalBytes/PodHash and the deterministic content tarball,
//     the same two artifacts `konareef pod publish --zk` hands to
//     reef-core. (§6.2 site internal/publish/publish.go.)
//  2. install — Verify runs the manifest-hash and signature checks, then
//     verifyContentTarball extracts the tarball and RE-CANONICALIZES the
//     extracted author tree at the manifest's own version, requiring the
//     result to hash to PodHash. (§6.2 sites internal/install/install.go.)
//  3. cache and re-read — Cache writes manifest.canon and the cached bytes
//     are hashed again, which is the form every later consumer reads.
//
// Any of those sites left on the v1 canonicalizer fails this test: the v1
// canonicalizer re-emits bytes without the `[_commit]` trailer (and rejects
// the v2 magic line outright), so the hash cannot match. That is the
// property R-V2.16 asks for, and the throwaway-worktree mutation recorded
// in the fix report confirms it — reverting install.go's
// canon.CanonicalizeLike to canon.Canonicalize fails this test with
// CONTENT_HASH_MISMATCH.
func TestV2PodSurvivesPublishInstallRoundTrip(t *testing.T) {
	f, _ := fixtureWithZKContent(t)

	if !bytes.HasPrefix(f.ManifestCanonical, []byte("#!konareef-toml/v2\n")) {
		t.Fatal("a --zk publish must emit v2 canonical bytes; this fixture is not exercising v2")
	}
	if f.ContentTarball == nil {
		t.Fatal("an open pod must ship a content tarball; ContentTarball is nil")
	}

	// Step 2. Verify is the production entry point, and it is the ONLY
	// thing driving the re-canonicalization here — no hand-rolled
	// recomputation stands in for it.
	if err := Verify(f); err != nil {
		t.Fatalf("install rejected a v2 pod that publish had just produced: %v", err)
	}

	// Step 3. The cached manifest is what `konareef zk`, `pod run` and
	// `commission verify` read later; it must still be the PodHash
	// pre-image, byte for byte.
	home := t.TempDir()
	dir, err := Cache(home, f)
	if err != nil {
		t.Fatalf("Cache: %v", err)
	}
	cached, err := os.ReadFile(filepath.Join(dir, "manifest.canon"))
	if err != nil {
		t.Fatalf("read cached manifest.canon: %v", err)
	}
	if sha256.Sum256(cached) != f.PodHash {
		t.Fatal("PodHash did not reproduce from the cached manifest")
	}
	if _, err := canon.ParseCommitFieldsRoot(cached); err != nil {
		t.Fatalf("the cached manifest lost its [_commit] trailer: %v", err)
	}
}

// TestV2RoundTripFailsWhenTheTarballDivergesFromTheManifest is the
// discrimination control for the test above (R-V2.17). A round-trip test
// that only ever sees consistent artifacts cannot show that it is checking
// anything: it would pass just as happily against a verifyContentTarball
// that returned nil unconditionally.
//
// Here the tarball's author tree is changed after Prepare committed to it,
// so the re-canonicalization step must produce different bytes and Verify
// must refuse. This is deliberately a different mutation from
// TestInstallRejectsATamperedV2Tarball's — that one edits a referenced
// file, this one edits pod.toml itself, so the `[_files]` section stays
// valid and only the author tree moves.
func TestV2RoundTripFailsWhenTheTarballDivergesFromTheManifest(t *testing.T) {
	f, podDir := fixtureWithZKContent(t)

	body, err := os.ReadFile(filepath.Join(podDir, "pod.toml"))
	if err != nil {
		t.Fatalf("read pod.toml: %v", err)
	}
	changed := bytes.Replace(body, []byte("max_sats = 1000"), []byte("max_sats = 999000"), 1)
	if bytes.Equal(changed, body) {
		t.Fatal("the fixture no longer contains the budget line this test rewrites")
	}
	if err := os.WriteFile(filepath.Join(podDir, "pod.toml"), changed, 0o644); err != nil {
		t.Fatalf("rewrite pod.toml: %v", err)
	}
	repacked, err := publish.PackTarball(podDir)
	if err != nil {
		t.Fatalf("PackTarball: %v", err)
	}
	f.ContentTarball = repacked

	if err := Verify(f); err == nil {
		t.Fatal("Verify accepted a tarball whose pod.toml no longer matches the signed manifest")
	}
}
