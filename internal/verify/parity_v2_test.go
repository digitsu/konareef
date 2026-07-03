package verify

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/fxamacker/cbor/v2"
)

// TestParity_V2_RoundTrip_TypeC asserts the Type-C parity artifact
// packed by reef-core's `ReefCore.Proofs.Bundle.V2.pack/2` fails
// Check 4 (pk_pub absent in SCR) and is rejected overall. The parity
// artifact pre-dates the CL-5a pk_pub carrier; Task 6 will regenerate
// it with a real pk_pub + matching signature so it verifies BOUND. Until
// then the correct verdict is Check 4 fails closed: pk_pub absent in SCR.
func TestParity_V2_RoundTrip_TypeC(t *testing.T) {
	bytes := loadParityEnvelopeStripped(t, "parity-v2-typec.cbor")
	r := VerifyV2(bytes, WithAcceptingVerifierForTests())
	// Check 4 fails closed: pk_pub absent in SCR → SignatureValid=false, r.OK=false.
	if r.OK {
		t.Errorf("Type-C parity (no pk_pub) accepted; Check 4 fail-closed is broken")
	}
	if r.V2Verdict == nil {
		t.Fatal("v2 verdict missing")
	}
	if r.V2Verdict.SignatureValid {
		t.Error("SignatureValid=true on Type-C parity with no pk_pub; Check 4 must fail closed")
	}
	if !signatureInvalidDiverged(r) {
		t.Errorf("expected ErrSignatureInvalid divergence; got: %v", divergenceStrings(r))
	}
}

// TestParity_V2_RoundTrip_TypeD mirrors the Type-C test for Type-D.
// The parity artifact pre-dates the CL-5a pk_pub carrier; until Task 6
// regenerates it with a real pk_pub, Check 4 fails closed: pk_pub absent in SCR.
func TestParity_V2_RoundTrip_TypeD(t *testing.T) {
	bytes := loadParityEnvelopeStripped(t, "parity-v2-typed.cbor")
	r := VerifyV2(bytes, WithAcceptingVerifierForTests())
	// Check 4 fails closed: pk_pub absent in SCR → SignatureValid=false, r.OK=false.
	if r.OK {
		t.Errorf("Type-D parity (no pk_pub) accepted; Check 4 fail-closed is broken")
	}
	if r.V2Verdict == nil {
		t.Fatal("v2 verdict missing")
	}
	if r.V2Verdict.SignatureValid {
		t.Error("SignatureValid=true on Type-D parity with no pk_pub; Check 4 must fail closed")
	}
	if !signatureInvalidDiverged(r) {
		t.Errorf("expected ErrSignatureInvalid divergence; got: %v", divergenceStrings(r))
	}
}

// loadParityEnvelopeStripped reads a parity CBOR artifact, decodes it
// into BundleV2, removes the cryptographic envelope fields
// (publisher_signature, publisher_pubkey) ONLY, re-encodes with the
// canonical core-deterministic encoder, and returns the resulting
// bytes. Used by the round-trip tests so they cover proof + disclosure
// + chain semantics without the P1.4-pending signature path.
//
// pod_hash + manifest stay intact in both Type-C and Type-D so the
// Type-D salt-binding commitment (Round-1 B1 fix) still exercises end
// to end.
func loadParityEnvelopeStripped(t *testing.T, fname string) []byte {
	t.Helper()
	path := filepath.Join("testdata", fname)
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Skipf("parity artifact missing: %v", err)
	}
	decoded, err := decodeBundleV2(raw)
	if err != nil {
		t.Fatalf("decode parity artifact %s: %v", fname, err)
	}
	decoded.PublisherSignature = nil
	decoded.PublisherPubkey = nil
	enc, err := cbor.CoreDetEncOptions().EncMode()
	if err != nil {
		t.Fatalf("enc mode: %v", err)
	}
	out, err := enc.Marshal(decoded)
	if err != nil {
		t.Fatalf("re-encode parity %s: %v", fname, err)
	}
	return out
}

// TestSnarkPhase_AttestationEnvelopeFailsClosed asserts that a v2 bundle
// carrying publisher_signature/publisher_pubkey in the attestation envelope
// (but without a valid pk_pub in SpartanCompressResult) is rejected overall
// (r.OK=false) with an ErrSignatureInvalid divergence.
//
// Post-Check-4 (fail-closed) semantics: pk_pub absent in SpartanCompressResult
// causes Check 4 to fail closed (SignatureValid=false, ErrSignatureInvalid).
// The attestation envelope cross-check (Task 5) also fires. Both sources
// produce ErrSignatureInvalid divergences; r.OK=false is enforced by both.
// The parity-v2-typec.cbor artifact pre-dates the CL-5a pk_pub carrier.
func TestSnarkPhase_AttestationEnvelopeFailsClosed(t *testing.T) {
	path := filepath.Join("testdata", "parity-v2-typec.cbor")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Skipf("parity artifact missing: %v", err)
	}
	r := VerifyV2(raw, WithAcceptingVerifierForTests())
	if r.OK {
		t.Fatal("envelope-bearing v2 bundle accepted; attestation envelope gate is broken")
	}
	if r.V2Verdict == nil {
		t.Fatal("v2 verdict missing")
	}
	// Check 4 fails closed: pk_pub absent in SCR → SignatureValid=false.
	if r.V2Verdict.SignatureValid {
		t.Error("SignatureValid=true on bundle with no pk_pub; Check 4 must fail closed")
	}
	// At least one ErrSignatureInvalid divergence must be present (from Check 4
	// and/or the envelope cross-check).
	found := false
	for _, d := range r.Divergences {
		if errors.Is(d.Err, ErrSignatureInvalid) {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected ErrSignatureInvalid divergence; got: %v", divergenceStrings(r))
	}
}

// TestParity_V2_HeaderTamperRejects asserts a tampered version string
// is rejected with ErrUnknownVersion — the load-bearing structural
// invariant that protects against bundle-class confusion attacks.
// Tampering with opaque bstr payloads (spartan_snark, etc.) is not a
// useful tamper test under the accepting verifier stub; those land in
// targeted negative tests (h_p, h_r, t_root, manifest) instead.
func TestParity_V2_HeaderTamperRejects(t *testing.T) {
	path := filepath.Join("testdata", "parity-v2-typec.cbor")
	bytes, err := os.ReadFile(path)
	if err != nil {
		t.Skipf("parity artifact missing: %v", err)
	}
	// Locate the version-string bytes and flip a byte inside them.
	// The CBOR tstr for "konareef-bundle/v2" appears once; flip a byte
	// near the middle of that string.
	idx := -1
	target := []byte("konareef-bundle/v2")
	for i := 0; i+len(target) <= len(bytes); i++ {
		match := true
		for j := range target {
			if bytes[i+j] != target[j] {
				match = false
				break
			}
		}
		if match {
			idx = i + len(target)/2
			break
		}
	}
	if idx < 0 {
		t.Skip("version string not located in parity artifact")
	}
	tampered := append([]byte(nil), bytes...)
	tampered[idx] ^= 0xFF
	r := VerifyV2(tampered, WithAcceptingVerifierForTests())
	if r.OK {
		t.Errorf("expected reject after version-byte flip; got OK")
	}
}
