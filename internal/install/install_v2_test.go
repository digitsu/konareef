// Copyright 2026 Jerry David Chan, Konareef.ai
// SPDX-License-Identifier: Apache-2.0

// install_v2_test.go — install-time verification of konareef-toml/v2 pods.
//
// Task 9 (spec §6.2): a site left on the v1 canonicalization path fails a
// v2 pod at INSTALL, not at build — the highest-risk failure mode in the
// v2 rollout, because it surfaces only against a real --zk-published pod,
// long after the canonicalizer itself was proven correct in isolation.
// verifyContentTarball (internal/install/install.go) is exactly that site:
// before this task it unconditionally called canon.Canonicalize (v1) over
// the tarball's extracted pod.toml, which rejects a v2 pod's magic line
// before ever comparing hashes. TestInstallAcceptsAV2Pod is the test that
// would have caught that — it fails with WRONG_VERSION against the
// pre-fix code and passes once verifyContentTarball dispatches on
// f.ManifestCanonical's own version via canon.CanonicalizeLike.
package install

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/digitsu/konareef/internal/identity"
	"github.com/digitsu/konareef/internal/publish"
)

// zkSamplePodTOML mirrors validMemoryFreePodTOML in
// internal/publish/publish_test.go: a manifest that clears every
// DeriveCommitParams gate (a fully-named [model], an explicit
// [budget].max_sats, no [[context.memory]]), so it is eligible for a
// --zk / konareef-toml/v2 publish.
const zkSamplePodTOML = `pod_spec_version = "0.1"

[pod]
name = "research-bot"
version = "1.0.0"

[runtime]
kind = "lobster"

[model]
provider = "openai"
name = "gpt-4o"

[budget]
max_sats = 1000

[directive]
template = "./prompts/system.md"
`

// writeZKSamplePod scaffolds zkSamplePodTOML plus the prompt file it
// references into a fresh temp directory.
func writeZKSamplePod(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "pod.toml"), []byte(zkSamplePodTOML), 0o644); err != nil {
		t.Fatalf("write pod.toml: %v", err)
	}
	prompts := filepath.Join(dir, "prompts")
	if err := os.MkdirAll(prompts, 0o755); err != nil {
		t.Fatalf("mkdir prompts: %v", err)
	}
	if err := os.WriteFile(filepath.Join(prompts, "system.md"), []byte("hello"), 0o644); err != nil {
		t.Fatalf("write system.md: %v", err)
	}
	return dir
}

// fixtureWithZKContent is fixtureWithContent's v2 counterpart: it runs
// the real publish.Prepare(..., PrepareOptions{ZK: true}) pipeline over a
// ZK-eligible pod directory and lifts the result into a FetchedPod, the
// same way fixtureWithContent does for the v1 (non-ZK) case. Using the
// real Prepare/CanonicalizeV2 pipeline — rather than hand-built v2 bytes —
// is what makes this an end-to-end fixture: manifest, hash, signature,
// [_commit] trailer, and content tarball are all genuinely consistent, so
// a bug anywhere between publish and install would show up here.
func fixtureWithZKContent(t *testing.T) (*FetchedPod, string) {
	t.Helper()
	podDir := writeZKSamplePod(t)
	id, err := identity.Generate("alice")
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	prep, err := publish.Prepare(podDir, id, publish.PrepareOptions{ZK: true})
	if err != nil {
		t.Fatalf("Prepare: %v", err)
	}
	return &FetchedPod{
		Handle:             prep.Handle,
		PodName:            prep.PodName,
		PodVersion:         prep.PodVersion,
		PodHash:            prep.PodHash,
		ManifestCanonical:  prep.CanonicalBytes,
		Signature:          prep.Signature,
		PublisherPubkeyHex: prep.PublicKeyHex,
		ContentTarball:     prep.ContentTarball,
	}, podDir
}

// TestInstallAcceptsAV2Pod is the test the corrected Task 9 design exists
// to satisfy: a v2 pod prepared with PrepareOptions{ZK: true} — signed
// manifest, [_commit] trailer, and content tarball all genuinely
// produced by the real publish pipeline — must pass install's full
// Verify (pod_hash, signature, AND content-tarball reproduction).
//
// Before the fix, verifyContentTarball called canon.Canonicalize (v1)
// unconditionally over the tarball's extracted pod.toml, which rejects
// any input whose magic line is not exactly "#!konareef-toml/v1" —
// including the v2 magic line this fixture's manifest carries — with a
// WRONG_VERSION error, before hashes are ever compared. That is the
// exact "fails at install, not at build" failure spec §6.2 warns about.
func TestInstallAcceptsAV2Pod(t *testing.T) {
	f, _ := fixtureWithZKContent(t)
	if err := Verify(f); err != nil {
		t.Fatalf("install rejected a valid v2 pod: %v", err)
	}
}

// TestInstallStillAcceptsAV1PodUnchanged is the companion control: a
// plain (non-ZK) pod prepared through the identical fixture shape must
// still install cleanly. Without this, a fix that happened to special-
// case v2 and broke the v1 default path would slip through unnoticed.
func TestInstallStillAcceptsAV1PodUnchanged(t *testing.T) {
	f, _ := fixtureWithContent(t)
	if err := Verify(f); err != nil {
		t.Fatalf("install rejected a valid v1 pod: %v", err)
	}
}

// TestInstallRejectsATamperedV2Tarball is the v2 analogue of
// TestVerifyRejectsTamperedContentTarball: tampering with the tarball's
// actual pod.toml content after Prepare ran, then repacking, must still
// be caught for a v2 pod — CanonicalizeLike reusing the reference's
// [_commit] trailer must not let a tampered author tree pass.
func TestInstallRejectsATamperedV2Tarball(t *testing.T) {
	f, podDir := fixtureWithZKContent(t)
	if err := os.WriteFile(filepath.Join(podDir, "prompts", "system.md"), []byte("tampered"), 0o644); err != nil {
		t.Fatalf("tamper system.md: %v", err)
	}
	tampered, err := publish.PackTarball(podDir)
	if err != nil {
		t.Fatalf("PackTarball: %v", err)
	}
	f.ContentTarball = tampered

	if err := Verify(f); err == nil {
		t.Fatal("Verify accepted a v2 content tarball that does not reproduce pod_hash")
	}
}
