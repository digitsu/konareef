// round1_blockers_test.go — Hermes MR !19 round-1 blocker regressions.
//
// Three blocker classes are exercised here:
//
//   - B1: Type-D commitment gate rejects missing / wrong-length pod_hash.
//   - B2: Publisher attestation envelope (signature OR pubkey) fails
//     closed until P1.4 strict-DER + ECDSA verification lands.
//   - B3: Deterministic CBOR decoder rejects non-canonical map-key
//     ordering and non-shortest integer / length encodings.
//
// Each test asserts the negative outcome (rejection + the load-bearing
// error code) so the regression cannot silently re-open.

package verify

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/fxamacker/cbor/v2"
)

// -----------------------------------------------------------------------------
// B1 — Type-D pod_hash length gate
// -----------------------------------------------------------------------------

// b1LoadTypeD reads the Type-D parity artifact, decodes it, and returns
// a mutable BundleV2 the test can mutate before re-encoding.
func b1LoadTypeD(t *testing.T) *BundleV2 {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", "parity-v2-typed.cbor"))
	if err != nil {
		t.Skipf("parity Type-D artifact missing: %v", err)
	}
	decoded, err := decodeBundleV2(raw)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	// Strip the publisher signature envelope so the B2 fail-closed gate
	// does not mask the B1-specific divergence we want to assert.
	decoded.PublisherSignature = nil
	decoded.PublisherPubkey = nil
	return decoded
}

func b1Reencode(t *testing.T, b *BundleV2) []byte {
	t.Helper()
	enc, err := cbor.CoreDetEncOptions().EncMode()
	if err != nil {
		t.Fatalf("enc mode: %v", err)
	}
	out, err := enc.Marshal(b)
	if err != nil {
		t.Fatalf("re-encode: %v", err)
	}
	return out
}

// TestB1_TypeD_MissingPodHashRejected asserts a Type-D bundle with
// pod_hash entirely absent now fails with ErrCommitmentMismatch instead
// of leaking CommitmentsValid=true.
func TestB1_TypeD_MissingPodHashRejected(t *testing.T) {
	decoded := b1LoadTypeD(t)
	decoded.PodHash = nil
	r := VerifyV2(b1Reencode(t, decoded), WithAcceptingVerifierForTests())
	if r.OK {
		t.Fatal("Type-D bundle with missing pod_hash accepted; Round-1 B1 gate is broken")
	}
	if r.V2Verdict == nil || r.V2Verdict.CommitmentsValid {
		t.Error("CommitmentsValid=true on Type-D bundle with missing pod_hash")
	}
	if !errorsIsCommitmentMismatch(r) {
		t.Errorf("expected ErrCommitmentMismatch; got: %v", divergenceStrings(r))
	}
}

// TestB1_TypeD_ShortPodHashRejected asserts a 24-byte pod_hash is
// rejected with ErrCommitmentMismatch.
func TestB1_TypeD_ShortPodHashRejected(t *testing.T) {
	decoded := b1LoadTypeD(t)
	decoded.PodHash = make([]byte, 24)
	r := VerifyV2(b1Reencode(t, decoded), WithAcceptingVerifierForTests())
	if r.OK {
		t.Fatal("Type-D bundle with 24-byte pod_hash accepted; Round-1 B1 gate is broken")
	}
	if r.V2Verdict == nil || r.V2Verdict.CommitmentsValid {
		t.Error("CommitmentsValid=true on Type-D bundle with 24-byte pod_hash")
	}
	if !errorsIsCommitmentMismatch(r) {
		t.Errorf("expected ErrCommitmentMismatch; got: %v", divergenceStrings(r))
	}
}

// TestB1_TypeD_LongPodHashRejected asserts a 40-byte pod_hash is
// rejected with ErrCommitmentMismatch.
func TestB1_TypeD_LongPodHashRejected(t *testing.T) {
	decoded := b1LoadTypeD(t)
	decoded.PodHash = make([]byte, 40)
	r := VerifyV2(b1Reencode(t, decoded), WithAcceptingVerifierForTests())
	if r.OK {
		t.Fatal("Type-D bundle with 40-byte pod_hash accepted; Round-1 B1 gate is broken")
	}
	if r.V2Verdict == nil || r.V2Verdict.CommitmentsValid {
		t.Error("CommitmentsValid=true on Type-D bundle with 40-byte pod_hash")
	}
	if !errorsIsCommitmentMismatch(r) {
		t.Errorf("expected ErrCommitmentMismatch; got: %v", divergenceStrings(r))
	}
}

// -----------------------------------------------------------------------------
// B2 — Publisher attestation envelope fails closed
// -----------------------------------------------------------------------------

// TestB2_NoEnvelopeNoPkPubFailsClosed asserts a v2 bundle without any
// attestation envelope (publisher_signature/publisher_pubkey stripped) and no
// pk_pub in SpartanCompressResult is rejected overall — a parity bundle with
// no envelope AND no pk_pub in the SCR correctly FAILS Check 4 (fail-closed).
// SignatureValid=false, r.OK=false, ErrSignatureInvalid divergence.
//
// The parity-v2-typec.cbor artifact pre-dates the CL-5a pk_pub carrier.
// Task 6 will regenerate it with a real pk_pub; until then the correct
// verdict is: Check 4 fails closed: pk_pub absent in SCR.
func TestB2_NoEnvelopeNoPkPubFailsClosed(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("testdata", "parity-v2-typec.cbor"))
	if err != nil {
		t.Skipf("parity Type-C artifact missing: %v", err)
	}
	decoded, err := decodeBundleV2(raw)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	decoded.PublisherSignature = nil
	decoded.PublisherPubkey = nil
	enc, _ := cbor.CoreDetEncOptions().EncMode()
	stripped, err := enc.Marshal(decoded)
	if err != nil {
		t.Fatalf("re-encode: %v", err)
	}
	r := VerifyV2(stripped, WithAcceptingVerifierForTests())
	// Check 4 fails closed: pk_pub absent in SCR → SignatureValid=false, r.OK=false.
	if r.OK {
		t.Fatal("no-pk_pub bundle accepted; Check 4 fail-closed is broken")
	}
	if r.V2Verdict == nil {
		t.Fatal("v2 verdict missing")
	}
	if r.V2Verdict.SignatureValid {
		t.Error("SignatureValid=true on bundle with no pk_pub; Check 4 must fail closed")
	}
	if !signatureInvalidDiverged(r) {
		t.Errorf("expected ErrSignatureInvalid divergence; got: %v", divergenceStrings(r))
	}
}

// TestB2_SignatureOnlyFailsClosed asserts a bundle carrying just a
// publisher_signature (no pubkey) still causes r.OK=false with an
// ErrSignatureInvalid divergence.
//
// Post-Check-4 (fail-closed) semantics: pk_pub absent in
// SpartanCompressResult causes Check 4 to fail closed (SignatureValid=false,
// ErrSignatureInvalid). The attestation-envelope cross-check (Task 5) also
// fires. Both enforce r.OK=false + ErrSignatureInvalid.
func TestB2_SignatureOnlyFailsClosed(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("testdata", "parity-v2-typec.cbor"))
	if err != nil {
		t.Skipf("parity Type-C artifact missing: %v", err)
	}
	decoded, err := decodeBundleV2(raw)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	decoded.PublisherPubkey = nil
	if len(decoded.PublisherSignature) == 0 {
		decoded.PublisherSignature = []byte{0xDE, 0xAD, 0xBE, 0xEF}
	}
	enc, _ := cbor.CoreDetEncOptions().EncMode()
	tampered, err := enc.Marshal(decoded)
	if err != nil {
		t.Fatalf("re-encode: %v", err)
	}
	r := VerifyV2(tampered, WithAcceptingVerifierForTests())
	if r.OK {
		t.Fatal("envelope-bearing bundle accepted; Round-1 B2 fail-closed broken")
	}
	if r.V2Verdict == nil || r.V2Verdict.SignatureValid {
		t.Error("SignatureValid must be false on a fail-closed bundle with signature only")
	}
	if !signatureInvalidDiverged(r) {
		t.Errorf("expected ErrSignatureInvalid; got: %v", divergenceStrings(r))
	}
}

// TestB2_PubkeyOnlyFailsClosed mirrors TestB2_SignatureOnlyFailsClosed
// for the publisher_pubkey-only carry shape.
//
// Post-Check-4 (fail-closed) semantics: same as TestB2_SignatureOnlyFailsClosed
// above — r.OK=false + ErrSignatureInvalid divergence is the enforced
// invariant. Check 4 fails closed (pk_pub absent in SCR); the envelope
// cross-check (Task 5) also fires.
func TestB2_PubkeyOnlyFailsClosed(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("testdata", "parity-v2-typec.cbor"))
	if err != nil {
		t.Skipf("parity Type-C artifact missing: %v", err)
	}
	decoded, err := decodeBundleV2(raw)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	decoded.PublisherSignature = nil
	if len(decoded.PublisherPubkey) == 0 {
		decoded.PublisherPubkey = []byte{0x02, 0xCA, 0xFE}
	}
	enc, _ := cbor.CoreDetEncOptions().EncMode()
	tampered, err := enc.Marshal(decoded)
	if err != nil {
		t.Fatalf("re-encode: %v", err)
	}
	r := VerifyV2(tampered, WithAcceptingVerifierForTests())
	if r.OK {
		t.Fatal("pubkey-bearing bundle accepted; Round-1 B2 fail-closed broken")
	}
	if r.V2Verdict == nil || r.V2Verdict.SignatureValid {
		t.Error("SignatureValid must be false on a fail-closed bundle with pubkey only")
	}
	if !signatureInvalidDiverged(r) {
		t.Errorf("expected ErrSignatureInvalid; got: %v", divergenceStrings(r))
	}
}

func signatureInvalidDiverged(r *ResultV2) bool {
	for _, d := range r.Divergences {
		if errors.Is(d.Err, ErrSignatureInvalid) {
			return true
		}
	}
	return false
}

// -----------------------------------------------------------------------------
// B3 — Canonical CBOR (shortest forms + map key order)
// -----------------------------------------------------------------------------

// TestB3_NonMinimalUintEncodingRejected asserts a CBOR map whose value
// encodes the integer 23 in the redundant 1-byte form (0x18 0x17)
// instead of the head-only form (0x17) is rejected with
// ErrMalformedCBOR.
func TestB3_NonMinimalUintEncodingRejected(t *testing.T) {
	// {"version": "konareef-bundle/v2", "x": 23 (non-minimal)}.
	// Map head: 0xA2 (map of 2 entries).
	// Key 1: tstr-7 "version" + payload.
	// Val 1: tstr-18 "konareef-bundle/v2" + payload.
	// Key 2: tstr-1 "x".
	// Val 2: uint, ai 24 (1-byte trailing), value 23 — NON-MINIMAL.
	//        Canonical would be 0x17 (ai==23 directly).
	bs := []byte{0xA2}
	bs = append(bs, 0x67) // tstr length 7
	bs = append(bs, []byte("version")...)
	bs = append(bs, 0x72) // tstr length 18
	bs = append(bs, []byte("konareef-bundle/v2")...)
	bs = append(bs, 0x61) // tstr length 1
	bs = append(bs, 'x')
	bs = append(bs, 0x18, 0x17) // uint ai 24, value 23 — non-minimal
	_, err := decodeBundleV2(bs)
	if !errors.Is(err, ErrMalformedCBOR) {
		t.Fatalf("non-minimal uint encoding accepted: err=%v", err)
	}
}

// TestB3_NonMinimalLengthEncodingRejected asserts a tstr length encoded
// in the redundant 2-byte form (ai 25) for a length that fits in 1 byte
// is rejected.
func TestB3_NonMinimalLengthEncodingRejected(t *testing.T) {
	// Top-level map { "version": tstr(18) }, but encode the tstr length
	// as ai=25 (2-byte) carrying 0x0012 (=18). Canonical would be 0x72.
	bs := []byte{0xA1}
	bs = append(bs, 0x67) // tstr length 7 (key)
	bs = append(bs, []byte("version")...)
	bs = append(bs, 0x79, 0x00, 0x12) // tstr major (3) | ai 25 | 0x0012 length
	bs = append(bs, []byte("konareef-bundle/v2")...)
	_, err := decodeBundleV2(bs)
	if !errors.Is(err, ErrMalformedCBOR) {
		t.Fatalf("non-minimal length encoding accepted: err=%v", err)
	}
}

// TestB3_MapKeysOutOfOrderRejected asserts a top-level map whose keys
// are in non-canonical order is rejected with ErrMalformedCBOR.
func TestB3_MapKeysOutOfOrderRejected(t *testing.T) {
	// Canonical order: "version" (0x67 ...) MUST sort before "z" (0x61 ...).
	// Wait: actually under bytewise lex on CBOR head+payload,
	//   "z"        encodes to 0x61 0x7A — first byte 0x61 (tstr length 1).
	//   "version"  encodes to 0x67 ... — first byte 0x67 (tstr length 7).
	// 0x61 < 0x67 so canonical order is "z" first, then "version".
	// We emit them in the WRONG order: "version" first, "z" second.
	bs := []byte{0xA2}
	bs = append(bs, 0x67) // tstr length 7
	bs = append(bs, []byte("version")...)
	bs = append(bs, 0x72)
	bs = append(bs, []byte("konareef-bundle/v2")...)
	bs = append(bs, 0x61) // tstr length 1 — would have sorted first
	bs = append(bs, 'z')
	bs = append(bs, 0x01) // any value
	_, err := decodeBundleV2(bs)
	if !errors.Is(err, ErrMalformedCBOR) {
		t.Fatalf("non-canonical map key order accepted: err=%v", err)
	}
}

// TestB3_CanonicalPassThrough asserts a canonical CBOR encoding of a
// minimal valid v2 bundle skeleton still decodes cleanly — guards
// against the canonicality walker introducing a false-positive reject.
func TestB3_CanonicalPassThrough(t *testing.T) {
	encMode, err := cbor.CoreDetEncOptions().EncMode()
	if err != nil {
		t.Fatalf("enc mode: %v", err)
	}
	m := map[string]any{
		"version":    "konareef-bundle/v2",
		"circuit_id": "konareef-pod-step-v1",
		"disclosure": "D",
		"chain": []map[string]any{{
			"proof_type": "custody",
			"hash":       make([]byte, 32),
			"scrubbed":   true,
			"timestamp":  "2026-08-19T12:00:00+00:00",
		}},
		"spartan_compress_result": map[string]any{
			"spartan_snark":            make([]byte, 64),
			"first_step_public_inputs": make([]byte, 256),
			"last_step_public_inputs":  make([]byte, 32),
			"vkey_hash":                make([]byte, 32),
			"circuit_id":               "konareef-pod-step-v1",
		},
	}
	encoded, err := encMode.Marshal(m)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	// Sanity: verify the canonicality walker accepts the canonical bytes.
	if err := validateCanonicalCBOR(encoded); err != nil {
		t.Fatalf("canonicality walker false-positive on canonical input: %v", err)
	}
	// And decode path should also succeed.
	if _, err := decodeBundleV2(encoded); err != nil {
		t.Fatalf("canonical pass-through decode failed: %v", err)
	}
}

// errorContains is a small helper that exists only so this file does
// not silently grow a parallel divergence search — keep the visible
// surface area small.
func errorContains(r *ResultV2, target error) bool {
	for _, d := range r.Divergences {
		if errors.Is(d.Err, target) {
			return true
		}
	}
	return false
}

// silence unused-import warnings if the helpers above shrink later.
var _ = bytes.Equal
var _ = errorContains
