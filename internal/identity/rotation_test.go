// Copyright 2026 Jerry David Chan, Konareef.ai
// SPDX-License-Identifier: Apache-2.0

// rotation_test.go — TDD coverage for the rotation-attestation
// primitives. The Canonical bytes are pinned to a hand-built string
// rather than a Marshal round-trip because the byte sequence is the
// load-bearing surface: it has to match reef-core's
// ReefCore.PublishedPods.RotationCanonical.encode/1 exactly or
// signatures fail across implementations.

package identity

import "testing"

// ── Canonical ─────────────────────────────────────────────────────

func TestCanonical_FullAttestation_MatchesElixirEncoder(t *testing.T) {
	att := RotationAttestation{
		Kind:         "konareef-key-rotation/v1",
		Handle:       "alice",
		OldPubkeyHex: "02a3f9b4",
		NewPubkeyHex: "0389abcd",
		RotatedAt:    "2026-05-19T11:22:00.000000Z",
		Reason:       "scheduled key rotation",
	}

	want := `{"handle":"alice","kind":"konareef-key-rotation/v1","new_pubkey_hex":"0389abcd","old_pubkey_hex":"02a3f9b4","reason":"scheduled key rotation","rotated_at":"2026-05-19T11:22:00.000000Z"}`

	got := string(Canonical(att))
	if got != want {
		t.Fatalf("canonical bytes mismatch.\n got: %s\nwant: %s", got, want)
	}
}

// `reason` is omitted entirely (not emitted as `"reason":null` or
// `"reason":""`) — matches RotationCanonical's Enum.reject(is_nil/1).
// An empty-string reason behaves the same as omitted: it is dropped
// rather than serialized as a zero-length string. This keeps the Go
// signer's canonical form identical when the producer leaves reason
// unset (which is the common case).
func TestCanonical_EmptyReason_IsOmitted(t *testing.T) {
	att := RotationAttestation{
		Kind:         "konareef-key-rotation/v1",
		Handle:       "alice",
		OldPubkeyHex: "02a3",
		NewPubkeyHex: "0389",
		RotatedAt:    "2026-05-19T11:22:00.000000Z",
		// Reason intentionally left as zero value.
	}

	want := `{"handle":"alice","kind":"konareef-key-rotation/v1","new_pubkey_hex":"0389","old_pubkey_hex":"02a3","rotated_at":"2026-05-19T11:22:00.000000Z"}`
	got := string(Canonical(att))
	if got != want {
		t.Fatalf("canonical (no reason) mismatch.\n got: %s\nwant: %s", got, want)
	}
}

// JSON escape rules MUST match Jason / encoding/json so the bytes
// round-trip across the two implementations. A quote inside the
// reason field is the most common observable difference between
// encoders that escape `<`, `>`, `&` and those that don't —
// encoding/json escapes the same way Jason does.
func TestCanonical_ReasonWithQuote_EscapedConsistently(t *testing.T) {
	att := RotationAttestation{
		Kind:         "konareef-key-rotation/v1",
		Handle:       "alice",
		OldPubkeyHex: "02",
		NewPubkeyHex: "03",
		RotatedAt:    "2026-05-19T11:22:00.000000Z",
		Reason:       `she said "ok"`,
	}

	want := `{"handle":"alice","kind":"konareef-key-rotation/v1","new_pubkey_hex":"03","old_pubkey_hex":"02","reason":"she said \"ok\"","rotated_at":"2026-05-19T11:22:00.000000Z"}`
	got := string(Canonical(att))
	if got != want {
		t.Fatalf("escaped-reason canonical mismatch.\n got: %s\nwant: %s", got, want)
	}
}

// Jason and encoding/json's defaults diverge on `<`, `>`, `&`:
// encoding/json escapes them as `<>&` (HTML-safe
// default), Jason emits them verbatim. The rotation encoder MUST
// disable Go's HTML escaping so the byte form matches Jason. A
// reason of `"a<b&c>"` is the cheapest exercise of every divergent
// character at once.
func TestCanonical_ReasonWithHTMLChars_NotHTMLEscaped(t *testing.T) {
	att := RotationAttestation{
		Kind:         "konareef-key-rotation/v1",
		Handle:       "alice",
		OldPubkeyHex: "02",
		NewPubkeyHex: "03",
		RotatedAt:    "2026-05-19T11:22:00.000000Z",
		Reason:       "a<b&c>",
	}

	want := `{"handle":"alice","kind":"konareef-key-rotation/v1","new_pubkey_hex":"03","old_pubkey_hex":"02","reason":"a<b&c>","rotated_at":"2026-05-19T11:22:00.000000Z"}`
	got := string(Canonical(att))
	if got != want {
		t.Fatalf("HTML-char canonical mismatch.\n got: %s\nwant: %s", got, want)
	}
}

// ── SignRotation / VerifyRotation ─────────────────────────────────

func TestSignRotation_VerifiesUnderOwnPubkey(t *testing.T) {
	id, err := Generate("alice")
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}

	att := RotationAttestation{
		Kind:         "konareef-key-rotation/v1",
		Handle:       "alice",
		OldPubkeyHex: id.PublicKeyHex,
		NewPubkeyHex: "0389abcd",
		RotatedAt:    "2026-05-19T11:22:00.000000Z",
	}

	sig, err := id.SignRotation(att)
	if err != nil {
		t.Fatalf("SignRotation: %v", err)
	}
	if len(sig) == 0 {
		t.Fatal("signature is empty")
	}

	ok, err := VerifyRotationSignature(id.PublicKeyHex, att, sig)
	if err != nil {
		t.Fatalf("VerifyRotationSignature err: %v", err)
	}
	if !ok {
		t.Fatal("signature did not verify under its own public key")
	}
}

func TestVerifyRotationSignature_RejectsForeignKey(t *testing.T) {
	alice, err := Generate("alice")
	if err != nil {
		t.Fatal(err)
	}
	bob, err := Generate("bob")
	if err != nil {
		t.Fatal(err)
	}

	att := RotationAttestation{
		Kind:         "konareef-key-rotation/v1",
		Handle:       "alice",
		OldPubkeyHex: alice.PublicKeyHex,
		NewPubkeyHex: "0389abcd",
		RotatedAt:    "2026-05-19T11:22:00.000000Z",
	}
	sig, err := alice.SignRotation(att)
	if err != nil {
		t.Fatal(err)
	}

	ok, err := VerifyRotationSignature(bob.PublicKeyHex, att, sig)
	if err != nil {
		t.Fatalf("VerifyRotationSignature err: %v", err)
	}
	if ok {
		t.Fatal("signature verified under bob's key — should not")
	}
}

// A flipped byte in the attestation must invalidate the signature —
// confirms the canonical encoder really feeds the signer, not some
// looser representation.
func TestVerifyRotationSignature_RejectsTamperedAttestation(t *testing.T) {
	alice, err := Generate("alice")
	if err != nil {
		t.Fatal(err)
	}
	att := RotationAttestation{
		Kind:         "konareef-key-rotation/v1",
		Handle:       "alice",
		OldPubkeyHex: alice.PublicKeyHex,
		NewPubkeyHex: "0389abcd",
		RotatedAt:    "2026-05-19T11:22:00.000000Z",
		Reason:       "original",
	}
	sig, err := alice.SignRotation(att)
	if err != nil {
		t.Fatal(err)
	}

	tampered := att
	tampered.Reason = "modified"

	ok, err := VerifyRotationSignature(alice.PublicKeyHex, tampered, sig)
	if err != nil {
		t.Fatalf("VerifyRotationSignature err: %v", err)
	}
	if ok {
		t.Fatal("signature verified for tampered attestation — should not")
	}
}

// Sanity: malformed pubkey hex returns an error, not silent false.
// Matches the (bool, error) split in identity.Verify.
func TestVerifyRotationSignature_BadPubkeyHex_Errors(t *testing.T) {
	att := RotationAttestation{
		Kind:         "konareef-key-rotation/v1",
		Handle:       "alice",
		OldPubkeyHex: "02",
		NewPubkeyHex: "03",
		RotatedAt:    "2026-05-19T11:22:00.000000Z",
	}
	_, err := VerifyRotationSignature("not-hex-zz", att, []byte{0x30, 0x00})
	if err == nil {
		t.Fatal("expected error for malformed pubkey hex, got nil")
	}
}
