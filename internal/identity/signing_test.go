// Copyright 2026 Jerry David Chan, Konareef.ai
// SPDX-License-Identifier: Apache-2.0

package identity

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"testing"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/decred/dcrd/dcrec/secp256k1/v4/ecdsa"
)

// newTestKeypair generates a fresh secp256k1 keypair for tests.
// Returns the private key and the compressed public key as a hex string.
func newTestKeypair(t *testing.T) (*secp256k1.PrivateKey, string) {
	t.Helper()
	priv, err := secp256k1.GeneratePrivateKey()
	if err != nil {
		t.Fatalf("newTestKeypair: GeneratePrivateKey: %v", err)
	}
	pubHex := hex.EncodeToString(priv.PubKey().SerializeCompressed())
	return priv, pubHex
}

// signDigest signs the raw 32-byte digest with priv and returns a DER-encoded
// ECDSA signature. Does NOT re-hash — digest is passed directly to ecdsa.Sign.
func signDigest(t *testing.T, priv *secp256k1.PrivateKey, digest []byte) []byte {
	t.Helper()
	sig := ecdsa.Sign(priv, digest)
	return sig.Serialize()
}

func TestSignProducesDERSignature(t *testing.T) {
	id, err := Generate("alice")
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	sig, err := id.Sign([]byte("hello world"))
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if len(sig) < 64 || len(sig) > 72 {
		t.Errorf("DER signature length = %d, expected 64–72 bytes", len(sig))
	}
	if sig[0] != 0x30 {
		t.Errorf("DER signature first byte = 0x%02x, want 0x30 (SEQUENCE)", sig[0])
	}
}

func TestVerifyAcceptsValidSignature(t *testing.T) {
	id, _ := Generate("alice")
	msg := []byte("hello world")
	sig, err := id.Sign(msg)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	ok, err := Verify(id.PublicKeyHex, msg, sig)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if !ok {
		t.Errorf("Verify rejected a valid signature")
	}
}

func TestVerifyRejectsTamperedMessage(t *testing.T) {
	id, _ := Generate("alice")
	sig, _ := id.Sign([]byte("hello"))
	ok, _ := Verify(id.PublicKeyHex, []byte("hello!"), sig)
	if ok {
		t.Errorf("Verify accepted a tampered message")
	}
}

func TestVerifyRejectsWrongPubkey(t *testing.T) {
	alice, _ := Generate("alice")
	bob, _ := Generate("bob")
	msg := []byte("hello")
	sig, _ := alice.Sign(msg)
	ok, _ := Verify(bob.PublicKeyHex, msg, sig)
	if ok {
		t.Errorf("Verify accepted Alice's signature against Bob's pubkey")
	}
}

func TestVerifyRejectsCorruptedSignature(t *testing.T) {
	id, _ := Generate("alice")
	sig, _ := id.Sign([]byte("hello"))
	// Flip the final byte: with DER this typically corrupts the trailing
	// integer and either fails to parse or fails to verify — both are
	// rejection paths the test accepts.
	sig[len(sig)-1] ^= 0xff
	ok, err := Verify(id.PublicKeyHex, []byte("hello"), sig)
	if ok && err == nil {
		t.Errorf("Verify accepted a corrupted signature (ok=true, err=nil)")
	}
}

func TestVerifyRejectsMalformedPubkey(t *testing.T) {
	id, _ := Generate("alice")
	sig, _ := id.Sign([]byte("hello"))
	ok, err := Verify("not-hex", []byte("hello"), sig)
	if ok {
		t.Errorf("Verify reported ok=true on a malformed pubkey hex")
	}
	if err == nil {
		t.Errorf("Verify did not surface an error for a malformed pubkey hex")
	}
}

// TestVerify_RejectsHighSSignature_WhenStrictGateEnabled exercises the
// full Verify path against the shared P1.4 high-S conformance vector.
// The expected outcome is (false, ErrDerGateReject) — production
// callers can treat the err sentinel as the rejection reason without
// re-parsing the signature.
func TestVerify_RejectsHighSSignature_WhenStrictGateEnabled(t *testing.T) {
	orig := StrictDerGateEnabled
	StrictDerGateEnabled = true
	t.Cleanup(func() { StrictDerGateEnabled = orig })

	m := loadVectors(t)
	var sigHex string
	for _, v := range m.Vectors {
		if v.ID == "der-gate-high-s-reject" {
			sigHex = v.SigHex
		}
	}
	if sigHex == "" {
		t.Fatal("der-gate-high-s-reject not present in vectors.json")
	}
	sig, err := hex.DecodeString(sigHex)
	if err != nil {
		t.Fatalf("decode high-s sig hex: %v", err)
	}
	msg := []byte(m.DigestPreimageUTF8)

	ok, err := Verify(m.PubkeyCompressedHex, msg, sig)
	if ok {
		t.Fatalf("Verify accepted a high-S signature under the strict gate")
	}
	if !errors.Is(err, ErrDerGateReject) {
		t.Fatalf("want ErrDerGateReject, got %v", err)
	}
}

// TestVerifyDigest_AcceptsSigOverRawDigest verifies that VerifyDigest accepts
// a valid DER signature produced directly over a 32-byte SHA-256 digest
// without any re-hashing on the verify side.
func TestVerifyDigest_AcceptsSigOverRawDigest(t *testing.T) {
	priv, pubHex := newTestKeypair(t)
	digest := sha256.Sum256([]byte("any manifest bytes"))
	sig := signDigest(t, priv, digest[:])
	ok, err := VerifyDigest(pubHex, digest[:], sig)
	if err != nil || !ok {
		t.Fatalf("VerifyDigest = (%v,%v), want (true,nil)", ok, err)
	}
}

// TestVerifyDigest_RejectsWrongDigest verifies that VerifyDigest rejects a
// signature produced over a different digest than the one presented for
// verification.
func TestVerifyDigest_RejectsWrongDigest(t *testing.T) {
	priv, pubHex := newTestKeypair(t)
	d1 := sha256.Sum256([]byte("manifest A"))
	d2 := sha256.Sum256([]byte("manifest B"))
	sig := signDigest(t, priv, d1[:])
	ok, _ := VerifyDigest(pubHex, d2[:], sig)
	if ok {
		t.Fatal("VerifyDigest accepted a signature over a different digest")
	}
}
