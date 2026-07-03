// signing.go — secp256k1 ECDSA over SHA-256 for the publisher identity.
//
// Sign and Verify wrap decred/dcrec's secp256k1 primitives in the
// shape the publish path needs: DER-encoded signatures over the
// SHA-256 digest of the canonicalized pod manifest (per publisher-
// signing-design v0 §D1). They are the *only* signing surface; future
// BRC-100 wallet-backed identities replace Sign internally but keep
// the same external contract.
//
// VerifyDigest is a companion to Verify for callers that already hold
// a 32-byte SHA-256 digest (e.g. h_manifest in PRD 3 §11.2 Check 4)
// and must NOT re-hash it.

package identity

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/decred/dcrd/dcrec/secp256k1/v4/ecdsa"
)

// Sign returns the DER-encoded secp256k1 ECDSA signature of
// SHA-256(msg) under id's private key. The output is the byte form
// that flows through `pod publish`, the `signature` column of the
// reef-core `pods` table, and the spawn-time verifier — bit-exact
// across every consumer.
//
// Errors here mean the identity itself is malformed (private key is
// not 32 hex-encoded bytes); a fresh Generate() never produces one.
func (id *Identity) Sign(msg []byte) ([]byte, error) {
	privBytes, err := hex.DecodeString(id.PrivateKeyHex)
	if err != nil {
		return nil, fmt.Errorf("decode private key hex: %w", err)
	}
	if len(privBytes) != 32 {
		return nil, fmt.Errorf("private key is %d bytes, want 32", len(privBytes))
	}
	priv := secp256k1.PrivKeyFromBytes(privBytes)
	digest := sha256.Sum256(msg)
	sig := ecdsa.Sign(priv, digest[:])
	return sig.Serialize(), nil
}

// Verify reports whether sig is a valid secp256k1 ECDSA signature of
// SHA-256(msg) under the 33-byte compressed public key encoded as
// pubKeyHex.
//
// The (bool, error) split is deliberate:
//
//   - (true,  nil)     — signature checks out.
//   - (false, nil)     — inputs parsed fine; the signature is wrong.
//   - (false, non-nil) — inputs themselves are malformed (bad hex,
//     unparseable DER, non-secp256k1 pubkey). Callers that only care
//     "is this signature good?" can treat both false cases as failure.
//
// This is the verification step `pod install` runs locally before
// accepting a manifest, and that reef-core re-runs server-side as
// authentication for `POST /api/pods` (no separate auth header is
// needed — the signature *is* the credential).
func Verify(pubKeyHex string, msg, sig []byte) (bool, error) {
	pubBytes, err := hex.DecodeString(pubKeyHex)
	if err != nil {
		return false, fmt.Errorf("decode public key hex: %w", err)
	}
	pub, err := secp256k1.ParsePubKey(pubBytes)
	if err != nil {
		return false, fmt.Errorf("parse public key: %w", err)
	}

	// P1.4 — strict-DER + low-S gate. When enabled, every signature
	// MUST pass the byte-level structural rules + s ≤ n/2 BEFORE we
	// hand it to ecdsa.ParseDERSignature, which is permissive (it
	// accepts non-minimal lengths and high-S signatures). We do not
	// normalise; rejection is the only permitted outcome.
	if StrictDerGateEnabled {
		if _, _, err := ParseStrict(sig); err != nil {
			return false, err
		}
	}

	parsedSig, err := ecdsa.ParseDERSignature(sig)
	if err != nil {
		return false, fmt.Errorf("parse DER signature: %w", err)
	}
	digest := sha256.Sum256(msg)
	return parsedSig.Verify(digest[:], pub), nil
}

// VerifyDigest verifies a DER ECDSA signature sig directly over the
// raw 32-byte digest (NOT over a preimage) under the compressed
// secp256k1 public key pubKeyHex. Used by PRD 3 §11.2 Check 4, where
// the signed message IS h_manifest (already a SHA-256 digest), so
// re-hashing (as Verify does at line 84) would produce the wrong result.
//
// The digest argument MUST be exactly 32 bytes; any other length is
// rejected immediately to prevent accidental preimage misuse.
//
// When StrictDerGateEnabled, the same strict-DER + low-S gate as Verify
// is applied before the ECDSA check (via ParseStrict in der_gate.go).
// The (bool, error) semantics are identical to Verify:
//
//   - (true,  nil)     — signature checks out.
//   - (false, nil)     — inputs parsed fine; the signature is wrong.
//   - (false, non-nil) — inputs are malformed or the gate rejected.
func VerifyDigest(pubKeyHex string, digest, sig []byte) (bool, error) {
	if len(digest) != 32 {
		return false, fmt.Errorf("digest must be 32 bytes, got %d", len(digest))
	}
	pubBytes, err := hex.DecodeString(pubKeyHex)
	if err != nil {
		return false, fmt.Errorf("decode public key hex: %w", err)
	}
	pub, err := secp256k1.ParsePubKey(pubBytes)
	if err != nil {
		return false, fmt.Errorf("parse public key: %w", err)
	}
	// P1.4 — same strict-DER + low-S gate as Verify. When enabled, every
	// signature MUST pass byte-level structural rules + s ≤ n/2 BEFORE
	// ecdsa.ParseDERSignature (which is permissive). We do not normalise;
	// rejection is the only permitted outcome.
	if StrictDerGateEnabled {
		if _, _, err := ParseStrict(sig); err != nil {
			return false, err // strict_der_invalid / high_s / rs_out_of_range
		}
	}
	parsedSig, err := ecdsa.ParseDERSignature(sig)
	if err != nil {
		return false, fmt.Errorf("parse DER signature: %w", err)
	}
	// Verify directly over the raw digest — NO sha256.Sum256 call here.
	return parsedSig.Verify(digest, pub), nil
}
