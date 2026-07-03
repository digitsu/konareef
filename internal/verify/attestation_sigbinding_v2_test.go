// attestation_sigbinding_v2_test.go — CL-6 (MR !30) regression: the
// publisher envelope signature in checkAttestationV2 MUST be bound to the
// disclosed manifest via SHA-256(b.Manifest) == h_manifest
// (first_step_public_inputs[160:192]), for EVERY disclosure mode that
// permits a signature.
//
// Before the fix, checkAttestationV2 verified the ECDSA over the raw
// h_manifest lane and set SignatureValid=true without ever checking that
// the signed lane was the SHA-256 of the disclosed manifest bytes. That
// let a bundle whose manifest/pod_hash were internally consistent
// (SHA-256(manifest)==pod_hash) carry a valid signature over an ARBITRARY
// h_manifest, detaching the signature from the disclosed manifest. The
// only verifier-side binding lived in the v2-gated CL-5a block of
// checkTypeCCommitments (Type-C #!konareef-toml/v2 only); Type-D and
// non-v2 Type-C envelope paths were unprotected.
//
// These tests construct an envelope whose ECDSA is a genuine, strict-DER,
// low-S signature over the (changed) h_manifest lane under the envelope
// pubkey, with manifest/pod_hash internally consistent, and assert the
// verdict is SignatureValid==false + ErrSignatureInvalid + overall not OK.

package verify

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"testing"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/decred/dcrd/dcrec/secp256k1/v4/ecdsa"
	"github.com/fxamacker/cbor/v2"
)

// signDigestDirect returns the strict-DER, low-S secp256k1 ECDSA
// signature over the raw 32-byte digest (NO re-hash) under priv, matching
// exactly what checkAttestationV2's parsed.Verify(hManifest, pub) checks.
// ecdsa.Sign emits canonical low-S signatures, so the result passes the
// strict-DER gate — isolating the manifest-binding precondition as the
// sole reason the verdict fails.
func signDigestDirect(t *testing.T, priv *secp256k1.PrivateKey, digest []byte) []byte {
	t.Helper()
	if len(digest) != 32 {
		t.Fatalf("digest must be 32 bytes, got %d", len(digest))
	}
	return ecdsa.Sign(priv, digest).Serialize()
}

// TestCheckAttestationV2_DetachedSignatureRejected is the load-bearing
// CL-6 regression. It builds a consistent canonical-v2 Type-C bundle
// (manifest/pod_hash/h_manifest all agree), then CHANGES the h_manifest
// lane to a different value and attaches a VALID ECDSA envelope signature
// over that different value under a real keypair. Because SHA-256(manifest)
// no longer equals h_manifest, the signature is detached from the disclosed
// manifest and MUST be rejected: SignatureValid==false, an ErrSignatureInvalid
// divergence, and overall not OK.
func TestCheckAttestationV2_DetachedSignatureRejected(t *testing.T) {
	// Start from a fully-consistent Type-C v2 bundle: SHA-256(manifest)
	// == pod_hash == h_manifest@160 and genesis_fields_root agrees.
	fr := fr0120()
	bundleBytes := buildV2FieldsRootBundle(t, fr, fr[:], true, false)
	decoded, err := decodeBundleV2(bundleBytes)
	if err != nil {
		t.Fatalf("decode base bundle: %v", err)
	}

	// Sanity: manifest <-> pod_hash binding is internally consistent.
	mh := sha256.Sum256(decoded.Manifest)
	if hex.EncodeToString(mh[:]) != hex.EncodeToString(decoded.PodHash) {
		t.Fatalf("precondition: SHA-256(manifest) != pod_hash in base bundle")
	}

	// Change h_manifest @160:192 to a DIFFERENT value (not SHA-256(manifest)).
	fspi := decoded.SpartanCompressResult.FirstStepPublicInputs
	if len(fspi) < 192 {
		t.Fatalf("first_step_public_inputs too short: %d", len(fspi))
	}
	var changed [32]byte
	for i := range changed {
		changed[i] = 0xAB // distinct from any SHA-256(manifest)
	}
	copy(fspi[160:192], changed[:])
	decoded.SpartanCompressResult.FirstStepPublicInputs = fspi

	// Attach a genuine envelope: valid ECDSA over the CHANGED h_manifest
	// under a real keypair. This is the attack the fix must defeat — the
	// signature is cryptographically valid, just not bound to the manifest.
	priv, err := secp256k1.GeneratePrivateKey()
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	decoded.PublisherPubkey = priv.PubKey().SerializeCompressed()
	decoded.PublisherSignature = signDigestDirect(t, priv, changed[:])

	bundle := reencodeBundleV2(t, decoded)
	r := VerifyV2(bundle, WithAcceptingVerifierForTests())

	if r.V2Verdict == nil {
		t.Fatal("v2 verdict missing")
	}
	if r.V2Verdict.SignatureValid {
		t.Error("SignatureValid=true on detached-signature bundle; CL-6 binding broken")
	}
	if r.OK {
		t.Error("overall OK=true on detached-signature bundle; CL-6 binding broken")
	}
	if !errors.Is(divergenceErr(r, ErrSignatureInvalid), ErrSignatureInvalid) {
		t.Errorf("expected ErrSignatureInvalid divergence; got: %v", divergenceStrings(r))
	}
}

// TestCheckAttestationV2_ManifestBindingPrecondition asserts the binding
// precondition directly and disclosure-mode-agnostically: an envelope is
// present and SHA-256(manifest) != h_manifest, so SignatureValid MUST be
// false regardless of the ECDSA bytes. The signature here is arbitrary
// (the precondition fires before the ECDSA check), proving the binding is
// enforced inside checkAttestationV2 itself and not via the v2-gated
// CL-5a commitments block.
func TestCheckAttestationV2_ManifestBindingPrecondition(t *testing.T) {
	fr := fr0120()
	bundleBytes := buildV2FieldsRootBundle(t, fr, fr[:], true, false)
	decoded, err := decodeBundleV2(bundleBytes)
	if err != nil {
		t.Fatalf("decode base bundle: %v", err)
	}

	// Diverge h_manifest from SHA-256(manifest); attach an arbitrary
	// (non-empty) envelope. The manifest-binding precondition must reject.
	fspi := decoded.SpartanCompressResult.FirstStepPublicInputs
	for i := 160; i < 192; i++ {
		fspi[i] ^= 0xFF
	}
	decoded.SpartanCompressResult.FirstStepPublicInputs = fspi
	decoded.PublisherPubkey = []byte{0x02, 0xCA, 0xFE}
	decoded.PublisherSignature = []byte{0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01}

	bundle := reencodeBundleV2(t, decoded)
	r := VerifyV2(bundle, WithAcceptingVerifierForTests())

	if r.V2Verdict == nil {
		t.Fatal("v2 verdict missing")
	}
	if r.V2Verdict.SignatureValid {
		t.Error("SignatureValid=true when SHA-256(manifest) != h_manifest; precondition broken")
	}
	if r.OK {
		t.Error("overall OK=true when signature not bound to manifest")
	}
	if !signatureInvalidDiverged(r) {
		t.Errorf("expected ErrSignatureInvalid divergence; got: %v", divergenceStrings(r))
	}
}

// TestCheckAttestationV2_LegitEnvelopeStillVerifies is the positive guard,
// reworked for the public-input-signature model (Check 4 is the sole
// SignatureValid authority; the envelope is an identity cross-check). A
// legit envelope is one that MATCHES the proof-bound public-input lane —
// "one signature, two encodings" (§11.2): publisher_pubkey == pk_pub,
// pod_hash == h_manifest, publisher_signature == DER(sig_manifest). When the
// manifest binds (SHA-256(manifest) == h_manifest), Check 4 validates the
// public-input signature and the matching envelope upgrades identity to
// PISBound. This proves the binding does not reject a legitimate, fully
// consistent envelope.
func TestCheckAttestationV2_LegitEnvelopeStillVerifies(t *testing.T) {
	fr := fr0120()
	// buildV2FieldsRootBundle injects a valid public-input sig_manifest@224 +
	// pk_pub over h_manifest@160 (== SHA-256(manifest), setManifestSlot=true).
	bundleBytes := buildV2FieldsRootBundle(t, fr, fr[:], true, false)
	decoded, err := decodeBundleV2(bundleBytes)
	if err != nil {
		t.Fatalf("decode base bundle: %v", err)
	}

	// Reconstruct the envelope so it MATCHES the public-input lane exactly
	// (the bound case our model accepts), rather than an unrelated key.
	scr := decoded.SpartanCompressResult
	fspi := scr.FirstStepPublicInputs
	hManifest := append([]byte(nil), fspi[160:192]...)
	derLen := int(fspi[224])
	der := append([]byte(nil), fspi[225:225+derLen]...)
	decoded.PublisherPubkey = append([]byte(nil), scr.PkPub...)
	decoded.PublisherSignature = der
	decoded.PodHash = hManifest

	bundle := reencodeBundleV2(t, decoded)
	r := VerifyV2(bundle, WithAcceptingVerifierForTests())

	if !r.OK {
		t.Fatalf("legit manifest-bound envelope rejected: %v", divergenceStrings(r))
	}
	if r.V2Verdict == nil || !r.V2Verdict.SignatureValid {
		t.Error("SignatureValid=false on legit manifest-bound envelope")
	}
	if r.V2Verdict != nil && r.V2Verdict.PublisherIdentityStatus != PISBound {
		t.Errorf("PublisherIdentityStatus=%v, want PISBound", r.V2Verdict.PublisherIdentityStatus)
	}
}

// reencodeBundleV2 re-encodes a BundleV2 with the canonical
// core-deterministic CBOR encoder (mirrors the helpers in the parity and
// fields-root tests).
func reencodeBundleV2(t *testing.T, b *BundleV2) []byte {
	t.Helper()
	enc, err := cbor.CoreDetEncOptions().EncMode()
	if err != nil {
		t.Fatalf("enc mode: %v", err)
	}
	out, err := enc.Marshal(b)
	if err != nil {
		t.Fatalf("re-encode bundle: %v", err)
	}
	return out
}

// divergenceErr returns the first divergence error that Is(target), or nil.
func divergenceErr(r *ResultV2, target error) error {
	for _, d := range r.Divergences {
		if errors.Is(d.Err, target) {
			return d.Err
		}
	}
	return nil
}
