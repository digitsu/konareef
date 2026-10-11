// Copyright 2026 Jerry David Chan, Konareef.ai
// SPDX-License-Identifier: Apache-2.0

// attestation_test.go — round-trip test for the cached-pod
// attestation helper.

package install

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"
)

// Cache writes manifest.canon, signature.bin, meta.json into
// ~/<home>/.konareef/installed/<handle>/<pod>/<version>/. The
// helper must invert that — read the three files back and assemble
// the wire-shape attestation reef-core's POST /api/agents accepts.
func TestLoadCachedAttestation_RoundTrip(t *testing.T) {
	home := t.TempDir()

	manifest := []byte("manifest bytes — pre-image of pod_hash")
	hash := sha256.Sum256(manifest)
	sig := []byte{0x30, 0x44, 0xAA, 0xBB}
	pub := []byte{0x02, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB,
		0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
		0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x77} // 33 bytes

	fp := &FetchedPod{
		Handle:             "alice",
		PodName:            "bot",
		PodVersion:         "1.2.3",
		PodHash:            hash,
		ManifestCanonical:  manifest,
		Signature:          sig,
		PublisherPubkeyHex: hex.EncodeToString(pub),
	}

	if _, err := Cache(home, fp); err != nil {
		t.Fatalf("Cache: %v", err)
	}

	att, err := LoadCachedAttestation(home, "alice", "bot", "1.2.3")
	if err != nil {
		t.Fatalf("LoadCachedAttestation: %v", err)
	}

	// pod_hash is hex-lowercase, matching reef-core's parser.
	if att.PodHash != hex.EncodeToString(hash[:]) {
		t.Errorf("PodHash = %q", att.PodHash)
	}
	if att.PodVersion != "1.2.3" {
		t.Errorf("PodVersion = %q", att.PodVersion)
	}
	if att.PublisherID != "alice" {
		t.Errorf("PublisherID = %q", att.PublisherID)
	}
	// publisher_signature is base64-encoded bytes from signature.bin.
	if att.PublisherSignature != base64.StdEncoding.EncodeToString(sig) {
		t.Errorf("PublisherSignature mismatch")
	}
	// publisher_pubkey is base64-encoded compressed pubkey.
	if att.PublisherPubkey != base64.StdEncoding.EncodeToString(pub) {
		t.Errorf("PublisherPubkey mismatch")
	}
}

func TestLoadCachedAttestation_MissingCacheDir(t *testing.T) {
	home := t.TempDir()
	_, err := LoadCachedAttestation(home, "alice", "bot", "9.9.9")
	if err == nil {
		t.Fatal("expected error for missing cache dir, got nil")
	}
}

// A cache dir missing one of the three files (signature.bin in this
// case — most likely failure mode in a partially-restored backup) is
// a fatal error, NOT a silently zero-populated attestation. The
// spawn endpoint would reject a request with an empty signature,
// but failing fast at the read step gives a clearer error.
func TestLoadCachedAttestation_PartiallyDamaged_Errors(t *testing.T) {
	home := t.TempDir()
	dir := filepath.Join(home, ".konareef", "installed", "alice", "bot", "1.0.0")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "manifest.canon"), []byte("m"), 0o644); err != nil {
		t.Fatal(err)
	}
	// meta.json present
	if err := os.WriteFile(filepath.Join(dir, "meta.json"),
		[]byte(`{"pod_hash":"deadbeef","publisher_pubkey_hex":"02"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	// signature.bin deliberately absent

	_, err := LoadCachedAttestation(home, "alice", "bot", "1.0.0")
	if err == nil {
		t.Fatal("expected error for missing signature.bin, got nil")
	}
}
