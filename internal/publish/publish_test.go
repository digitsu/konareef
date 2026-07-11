// Copyright 2026 Jerry David Chan, Konareef.ai
// SPDX-License-Identifier: Apache-2.0

package publish

import (
	"crypto/sha256"
	"os"
	"path/filepath"
	"testing"

	"github.com/digitsu/konareef/internal/canon"
	"github.com/digitsu/konareef/internal/identity"
)

const validPodTOML = `pod_spec_version = "0.1"

[pod]
name = "research-bot"
version = "1.0.0"

[runtime]
kind = "lobster"

[directive]
template = "./prompts/system.md"
`

// writeSamplePod scaffolds a minimal-but-valid pod directory in a
// t.TempDir(): a pod.toml plus the prompt file it references, both
// already conforming to the v0.1 schema and the canonicalizer.
func writeSamplePod(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "pod.toml"), []byte(validPodTOML), 0o644); err != nil {
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

func TestPrepareHappyPath(t *testing.T) {
	podDir := writeSamplePod(t)
	id, err := identity.Generate("alice")
	if err != nil {
		t.Fatalf("Generate identity: %v", err)
	}

	prep, err := Prepare(podDir, id)
	if err != nil {
		t.Fatalf("Prepare: %v", err)
	}

	if prep.Handle != "alice" {
		t.Errorf("Handle = %q, want alice", prep.Handle)
	}
	if prep.PodName != "research-bot" {
		t.Errorf("PodName = %q, want research-bot", prep.PodName)
	}
	if prep.PodVersion != "1.0.0" {
		t.Errorf("PodVersion = %q, want 1.0.0", prep.PodVersion)
	}
	if len(prep.CanonicalBytes) == 0 {
		t.Errorf("CanonicalBytes is empty")
	}
	if prep.PodHash == [32]byte{} {
		t.Errorf("PodHash is zero")
	}
	if len(prep.Signature) < 64 {
		t.Errorf("Signature is %d bytes; DER ECDSA is 64–72", len(prep.Signature))
	}
	if prep.PublicKeyHex != id.PublicKeyHex {
		t.Errorf("PublicKeyHex differs from the source identity")
	}

	ok, err := identity.Verify(id.PublicKeyHex, prep.CanonicalBytes, prep.Signature)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if !ok {
		t.Errorf("the prepared signature did not verify against the identity's pubkey")
	}

	if len(prep.ContentTarball) == 0 {
		t.Fatal("ContentTarball is empty")
	}
	// The tarball must reproduce pod_hash on extraction — the exact
	// check `konareef install` performs (Task B3).
	out := t.TempDir()
	if err := ExtractTarball(prep.ContentTarball, out); err != nil {
		t.Fatalf("extract: %v", err)
	}
	body, _ := os.ReadFile(filepath.Join(out, "pod.toml"))
	canonBytes, err := canon.Canonicalize(body, out)
	if err != nil {
		t.Fatalf("re-canonicalize: %v", err)
	}
	if sha256.Sum256(canonBytes) != prep.PodHash {
		t.Fatal("extracted tarball does not reproduce pod_hash")
	}
}

func TestPrepareRejectsInvalidPod(t *testing.T) {
	dir := t.TempDir()
	// Missing pod_spec_version + missing required [runtime] table.
	invalid := "[pod]\nname = \"x\"\nversion = \"1.0.0\"\n"
	if err := os.WriteFile(filepath.Join(dir, "pod.toml"), []byte(invalid), 0o644); err != nil {
		t.Fatalf("write pod.toml: %v", err)
	}
	id, _ := identity.Generate("alice")
	if _, err := Prepare(dir, id); err == nil {
		t.Errorf("Prepare accepted a schema-invalid pod.toml")
	}
}

func TestPrepareRejectsMissingPodTOML(t *testing.T) {
	dir := t.TempDir()
	id, _ := identity.Generate("alice")
	if _, err := Prepare(dir, id); err == nil {
		t.Errorf("Prepare succeeded with no pod.toml present")
	}
}

func TestPrepareIsDeterministic(t *testing.T) {
	podDir := writeSamplePod(t)
	id, _ := identity.Generate("alice")

	first, err := Prepare(podDir, id)
	if err != nil {
		t.Fatalf("Prepare (first): %v", err)
	}
	second, err := Prepare(podDir, id)
	if err != nil {
		t.Fatalf("Prepare (second): %v", err)
	}
	// Canonical bytes + pod_hash MUST match. Signatures may differ
	// across calls because secp256k1 ECDSA mixes in a fresh nonce —
	// what matters is that the second signature also verifies.
	if string(first.CanonicalBytes) != string(second.CanonicalBytes) {
		t.Errorf("CanonicalBytes drift between Prepare calls")
	}
	if first.PodHash != second.PodHash {
		t.Errorf("PodHash drift between Prepare calls")
	}
}
