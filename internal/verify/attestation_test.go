// Copyright 2026 Jerry David Chan, Konareef.ai
// SPDX-License-Identifier: Apache-2.0

// attestation_test.go — WI-P0-002 publisher-attestation crypto
// checks. Tampering any of the four signed fields (manifest,
// pod_hash, publisher_signature, publisher_pubkey) must make
// Verify return OK=false.

package verify

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/digitsu/konareef/internal/identity"
)

// signedAttestation generates a real keypair, signs the canonical
// manifest with it, and returns the envelope strings the bundle
// JSON would carry. Used by tampering tests to start from a known-
// good attestation and mutate one field at a time.
func signedAttestation(t *testing.T) (manifest, podHashHex, sigB64, pubB64 string) {
	t.Helper()
	id, err := identity.Generate("alice")
	if err != nil {
		t.Fatalf("Generate identity: %v", err)
	}

	manifest = "publisher-canonical-manifest-bytes-for-bundle-test"
	hash := sha256.Sum256([]byte(manifest))
	podHashHex = hex.EncodeToString(hash[:])

	sig, err := id.Sign([]byte(manifest))
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	sigB64 = base64.StdEncoding.EncodeToString(sig)

	pubBytes, err := hex.DecodeString(id.PublicKeyHex)
	if err != nil {
		t.Fatalf("decode pubkey: %v", err)
	}
	pubB64 = base64.StdEncoding.EncodeToString(pubBytes)
	return
}

// buildSignedBundle starts from buildValidBundle (structural
// soundness) and attaches a fully populated publisher attestation
// to the envelope. Verify on this MUST return OK with no
// divergences.
func buildSignedBundle(t *testing.T) *Bundle {
	t.Helper()
	b := buildValidBundle()
	manifest, podHashHex, sigB64, pubB64 := signedAttestation(t)
	manifestB64 := base64.StdEncoding.EncodeToString([]byte(manifest))
	version := "1.2.3"
	pubID := "alice"

	b.PodHash = &podHashHex
	b.PodVersion = &version
	b.PublisherID = &pubID
	b.PublisherSignature = &sigB64
	b.PublisherPubkey = &pubB64
	b.Manifest = &manifestB64
	return b
}

func TestVerifySignedBundle_OK(t *testing.T) {
	b := buildSignedBundle(t)
	r := Verify(b)
	if !r.OK {
		t.Fatalf("Verify rejected a fully-signed bundle:\n  %s",
			strings.Join(r.Divergences, "\n  "))
	}
}

// Manifest mutated: SHA-256(manifest) no longer matches pod_hash.
func TestVerifySignedBundle_TamperedManifest(t *testing.T) {
	b := buildSignedBundle(t)
	mutated := base64.StdEncoding.EncodeToString([]byte("tampered manifest"))
	b.Manifest = &mutated
	r := Verify(b)
	if r.OK {
		t.Fatal("Verify accepted a bundle with a tampered manifest")
	}
	if !containsAny(r.Divergences, "manifest") {
		t.Errorf("expected a manifest divergence, got: %v", r.Divergences)
	}
}

// pod_hash mutated: SHA-256(manifest) no longer matches.
func TestVerifySignedBundle_TamperedPodHash(t *testing.T) {
	b := buildSignedBundle(t)
	mutated := strings.Repeat("00", 32)
	b.PodHash = &mutated
	r := Verify(b)
	if r.OK {
		t.Fatal("Verify accepted a bundle with a tampered pod_hash")
	}
}

// Signature bytes mutated: verifies as invalid under publisher_pubkey.
func TestVerifySignedBundle_TamperedSignature(t *testing.T) {
	b := buildSignedBundle(t)
	mutated := base64.StdEncoding.EncodeToString(
		append([]byte{0x30, 0x44}, []byte(strings.Repeat("\xaa", 70))...))
	b.PublisherSignature = &mutated
	r := Verify(b)
	if r.OK {
		t.Fatal("Verify accepted a bundle with a tampered publisher_signature")
	}
	if !containsAny(r.Divergences, "signature") {
		t.Errorf("expected a signature divergence, got: %v", r.Divergences)
	}
}

// Pubkey swapped to a different keypair: the same signature no
// longer verifies under the new pubkey.
func TestVerifySignedBundle_TamperedPubkey(t *testing.T) {
	b := buildSignedBundle(t)
	other, _ := identity.Generate("eve")
	otherBytes, _ := hex.DecodeString(other.PublicKeyHex)
	mutated := base64.StdEncoding.EncodeToString(otherBytes)
	b.PublisherPubkey = &mutated
	r := Verify(b)
	if r.OK {
		t.Fatal("Verify accepted a bundle with a tampered publisher_pubkey")
	}
}

// Legacy (unsigned) bundle: no attestation envelope at all.
// Default mode: passes (back-compat with v0 bundles).
// Strict mode: fails.
func TestVerifyLegacyUnsignedBundle_DefaultPasses(t *testing.T) {
	b := buildValidBundle() // no attestation attached
	r := Verify(b)
	if !r.OK {
		t.Fatalf("default Verify rejected a legacy unsigned bundle:\n  %s",
			strings.Join(r.Divergences, "\n  "))
	}
}

func TestVerifyLegacyUnsignedBundle_StrictRejects(t *testing.T) {
	b := buildValidBundle()
	r := VerifyStrict(b)
	if r.OK {
		t.Fatal("VerifyStrict accepted a bundle with no publisher attestation")
	}
	if !containsAny(r.Divergences, "attestation") {
		t.Errorf("expected a missing-attestation divergence, got: %v", r.Divergences)
	}
}

// WI-P0-007: a partial attestation envelope (some signed fields
// present, some absent) is neither a legacy unsigned bundle nor a
// fully verifiable signed bundle. Default mode used to silently
// pass this; the reviewer's "ambiguous green" critique flipped the
// rule. Now both default and strict mode reject partials, named in
// the divergence so the producer can fix it.

func TestVerifySignedBundle_PartialAttestation_DefaultRejects(t *testing.T) {
	b := buildSignedBundle(t)
	b.Manifest = nil
	r := Verify(b)
	if r.OK {
		t.Fatal("Verify accepted a partial attestation (missing manifest) in default mode")
	}
	if !containsAny(r.Divergences, "incomplete") {
		t.Errorf("expected an incomplete-attestation divergence, got: %v", r.Divergences)
	}
}

func TestVerifySignedBundle_PartialAttestation_StrictRejects(t *testing.T) {
	b := buildSignedBundle(t)
	b.Manifest = nil
	r := VerifyStrict(b)
	if r.OK {
		t.Fatal("VerifyStrict accepted a partial attestation")
	}
}

// Per-field "missing one" tests. Each removes a single attestation
// field and confirms the bundle is rejected in default mode. The
// envelope is all-or-nothing: a producer that supplies any one of
// the six fields must supply all six.
func TestVerifySignedBundle_MissingPodHash_Rejects(t *testing.T) {
	b := buildSignedBundle(t)
	b.PodHash = nil
	r := Verify(b)
	if r.OK {
		t.Fatal("Verify accepted partial attestation (missing pod_hash)")
	}
}

func TestVerifySignedBundle_MissingPodVersion_Rejects(t *testing.T) {
	b := buildSignedBundle(t)
	b.PodVersion = nil
	r := Verify(b)
	if r.OK {
		t.Fatal("Verify accepted partial attestation (missing pod_version)")
	}
}

func TestVerifySignedBundle_MissingPublisherID_Rejects(t *testing.T) {
	b := buildSignedBundle(t)
	b.PublisherID = nil
	r := Verify(b)
	if r.OK {
		t.Fatal("Verify accepted partial attestation (missing publisher_id)")
	}
}

func TestVerifySignedBundle_MissingPublisherSignature_Rejects(t *testing.T) {
	b := buildSignedBundle(t)
	b.PublisherSignature = nil
	r := Verify(b)
	if r.OK {
		t.Fatal("Verify accepted partial attestation (missing publisher_signature)")
	}
}

func TestVerifySignedBundle_MissingPublisherPubkey_Rejects(t *testing.T) {
	b := buildSignedBundle(t)
	b.PublisherPubkey = nil
	r := Verify(b)
	if r.OK {
		t.Fatal("Verify accepted partial attestation (missing publisher_pubkey)")
	}
}

// AttestationStatus classification tests. The verifier reports
// which class the bundle fell into so a CLI can show
// `legacy unsigned` (explicitly) vs `publisher attested` instead of
// just a generic green check.
func TestVerifyResult_LegacyBundle_StatusLegacyUnsigned(t *testing.T) {
	b := buildValidBundle()
	r := Verify(b)
	if r.AttestationStatus != "legacy_unsigned" {
		t.Errorf("AttestationStatus = %q, want %q", r.AttestationStatus, "legacy_unsigned")
	}
}

func TestVerifyResult_SignedBundle_StatusAttested(t *testing.T) {
	b := buildSignedBundle(t)
	r := Verify(b)
	if r.AttestationStatus != "attested" {
		t.Errorf("AttestationStatus = %q, want %q", r.AttestationStatus, "attested")
	}
}

func TestVerifyResult_PartialBundle_StatusIncomplete(t *testing.T) {
	b := buildSignedBundle(t)
	b.Manifest = nil
	r := Verify(b)
	if r.AttestationStatus != "incomplete" {
		t.Errorf("AttestationStatus = %q, want %q", r.AttestationStatus, "incomplete")
	}
}
