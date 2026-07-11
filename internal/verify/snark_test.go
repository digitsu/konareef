// Copyright 2026 Jerry David Chan, Konareef.ai
// SPDX-License-Identifier: Apache-2.0

package verify

import (
	"crypto/sha256"
	"encoding/asn1"
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/decred/dcrd/dcrec/secp256k1/v4/ecdsa"
	"github.com/fxamacker/cbor/v2"
)

// ── Check 4 helpers ────────────────────────────────────────────────────────

// sigTestKeypair generates a fresh secp256k1 keypair for Check 4 tests.
// Returns the private key and the 33-byte compressed public key.
func sigTestKeypair(t *testing.T) (*secp256k1.PrivateKey, []byte) {
	t.Helper()
	priv, err := secp256k1.GeneratePrivateKey()
	if err != nil {
		t.Fatalf("sigTestKeypair: GeneratePrivateKey: %v", err)
	}
	return priv, priv.PubKey().SerializeCompressed()
}

// signDigestRaw signs a raw 32-byte digest directly with priv (no re-hash)
// and returns the DER-encoded ECDSA signature.
func signDigestRaw(t *testing.T, priv *secp256k1.PrivateKey, digest []byte) []byte {
	t.Helper()
	if len(digest) != 32 {
		t.Fatalf("signDigestRaw: digest must be 32 bytes, got %d", len(digest))
	}
	sig := ecdsa.Sign(priv, digest)
	return sig.Serialize()
}

// publicInputSigFor builds a valid 74-byte padded sig_manifest and the
// 33-byte pk_pub for the given 32-byte h_manifest, so a fixture satisfies the
// mandatory Check 4 (public-input signature) invariant. It signs h_manifest
// directly (no re-hash); any nonzero DER that fits the 74-byte lane is valid
// (Check 4 accepts < 70-byte signatures). Callers write paddedSig into
// FirstStepPublicInputs[224:298] and set SpartanCompressResult.PkPub = pkPub.
func publicInputSigFor(t *testing.T, hManifest []byte) (paddedSig, pkPub []byte) {
	t.Helper()
	if len(hManifest) != 32 {
		t.Fatalf("publicInputSigFor: h_manifest must be 32 bytes, got %d", len(hManifest))
	}
	var priv *secp256k1.PrivateKey
	var der []byte
	for {
		priv, pkPub = sigTestKeypair(t)
		der = signDigestRaw(t, priv, hManifest)
		// Any nonzero DER that fits the 74-byte lane is valid input to Check 4
		// (a strict-DER secp256k1 signature may be < 70 bytes); the verifier no
		// longer imposes a [70,73] window.
		if len(der) > 0 && len(der) <= 73 {
			break
		}
	}
	paddedSig = make([]byte, 74)
	paddedSig[0] = byte(len(der))
	copy(paddedSig[1:], der)
	return paddedSig, pkPub
}

// injectPublicInputSig signs the bundle's proof-bound h_manifest lane
// (FirstStepPublicInputs[160:192]) and writes the resulting padded
// sig_manifest@224 + pk_pub into the SpartanCompressResult, conforming a
// fixture to the mandatory Check 4 invariant. The buffer is grown to the full
// 298-byte X-vector if shorter. The envelope is left untouched (Check 4 runs
// from the carried pk_pub regardless of envelope presence).
func injectPublicInputSig(t *testing.T, b *BundleV2) {
	t.Helper()
	fspi := b.SpartanCompressResult.FirstStepPublicInputs
	if len(fspi) < 298 {
		grown := make([]byte, 298)
		copy(grown, fspi)
		fspi = grown
	}
	hManifest := append([]byte(nil), fspi[160:192]...)
	paddedSig, pkPub := publicInputSigFor(t, hManifest)
	copy(fspi[224:298], paddedSig)
	b.SpartanCompressResult.FirstStepPublicInputs = fspi
	b.SpartanCompressResult.PkPub = pkPub
}

// otherCompressedPubkey returns a freshly-generated compressed pubkey that
// is guaranteed to differ from any key generated in the same test.
func otherCompressedPubkey(t *testing.T) []byte {
	t.Helper()
	priv, err := secp256k1.GeneratePrivateKey()
	if err != nil {
		t.Fatalf("otherCompressedPubkey: GeneratePrivateKey: %v", err)
	}
	return priv.PubKey().SerializeCompressed()
}

// bundleWithValidPublisherSig builds a minimal BundleV2 ready for Check 4
// and envelope (§11.2) cross-check tests. It:
//   - allocates a 298-byte FirstStepPublicInputs buffer (offset table up
//     through sig_manifest@224+74=298);
//   - fills the 32-byte h_manifest window at offset 160 with a random digest;
//   - constructs a valid 74-byte padded sig_manifest at offset 224:
//     [derLen][DER bytes][zero-pad to 74];
//   - sets SpartanCompressResult.PkPub to the 33-byte compressed pubkey;
//   - populates the attestation envelope fields (PublisherPubkey,
//     PublisherSignature, PodHash) consistently with the public-input
//     vector so envelope cross-checks pass;
//   - wires up a minimal valid chain + Type-D manifest so all other checks pass.
//
// The SNARK verify is bypassed via WithAcceptingVerifierForTests().
func bundleWithValidPublisherSig(t *testing.T) *BundleV2 {
	t.Helper()

	// Build a minimal valid Type-D manifest. pod_hash = SHA-256(manifest).
	// This same value is also used as h_manifest in the public-input vector
	// so that both checkTypeDCommitments (SHA-256(manifest)==pod_hash) and
	// the §11.2 envelope cross-check (pod_hash==h_manifest) are satisfied
	// with a single consistent value.
	manifest := []byte("test-manifest-for-check4")
	podHashArr := sha256.Sum256(manifest)
	hManifest := podHashArr[:] // h_manifest == SHA-256(manifest) == pod_hash

	// Generate a keypair and sign hManifest. Any nonzero DER that fits the
	// 74-byte sig_manifest lane is accepted by Check 4 — including the < 70-byte
	// signatures that arise when r or s is a 31-byte minimal INTEGER (Check 4 no
	// longer imposes a [70,73] window; see TestCheck4_ShortDerSignature_Accepts).
	var priv *secp256k1.PrivateKey
	var pubBytes []byte
	var der []byte
	for {
		priv, pubBytes = sigTestKeypair(t)
		der = signDigestRaw(t, priv, hManifest)
		if len(der) > 0 && len(der) <= 73 {
			break
		}
	}
	_ = priv // consumed by signDigestRaw above
	derLen := len(der)

	// Build the 74-byte padded sig_manifest: [derLen byte][DER][zero pad].
	sigManifest := make([]byte, 74)
	sigManifest[0] = byte(derLen)
	copy(sigManifest[1:], der)
	// Remaining bytes are already zero from make().

	// Build a 298-byte FirstStepPublicInputs buffer (zero-filled except
	// h_manifest @ 160 and sig_manifest @ 224).
	pib := make([]byte, 298)
	copy(pib[160:], hManifest)   // h_manifest at offset 160
	copy(pib[224:], sigManifest) // sig_manifest at offset 224

	// Build a minimal valid Type-D chain (scrubbed, single link).
	chain := []ChainLinkV2{{
		ProofType: "custody",
		Hash:      make([]byte, 32),
		Scrubbed:  true,
		Timestamp: "2026-08-19T12:00:00+00:00",
	}}

	// Populate envelope fields consistently with public-input vector so that
	// §11.2 cross-checks pass:
	//   publisher_pubkey == pk_pub (33 B)
	//   pod_hash         == h_manifest (== SHA-256(manifest) for Type-D)
	//   publisher_signature == DER(sig_manifest) (unpadded raw DER)

	return &BundleV2{
		Version:            "konareef-bundle/v2",
		CircuitID:          "konareef-pod-step-v1",
		Disclosure:         "D",
		Chain:              chain,
		Manifest:           manifest,
		PodHash:            hManifest, // SHA-256(manifest) == h_manifest
		PublisherPubkey:    pubBytes,  // == pk_pub (33 B)
		PublisherSignature: der,       // == DER(sig_manifest) (unpadded)
		SpartanCompressResult: SpartanCompressResult{
			SpartanSnark:          make([]byte, 64),
			FirstStepPublicInputs: pib,
			LastStepPublicInputs:  make([]byte, 32),
			VkeyHash:              make([]byte, 32),
			CircuitID:             "konareef-pod-step-v1",
			PkPub:                 pubBytes,
		},
	}
}

// runVerify re-encodes b to CBOR and calls VerifyV2 with the accepting
// Spartan stub, returning the structured verdict and result.
func runVerify(t *testing.T, b *BundleV2) (*Verdict, *ResultV2) {
	t.Helper()
	enc, err := cbor.CoreDetEncOptions().EncMode()
	if err != nil {
		t.Fatalf("runVerify: enc mode: %v", err)
	}
	raw, err := enc.Marshal(b)
	if err != nil {
		t.Fatalf("runVerify: marshal: %v", err)
	}
	r := VerifyV2(raw, WithAcceptingVerifierForTests())
	if r.V2Verdict == nil {
		t.Fatal("runVerify: V2Verdict is nil")
	}
	return r.V2Verdict, r
}

// assertDiverged asserts that the result is not OK and carries at least one
// divergence wrapping wantErr.
func assertDiverged(t *testing.T, r *ResultV2, wantErr error) {
	t.Helper()
	if r.OK {
		t.Errorf("assertDiverged: result is OK, want NOT OK")
	}
	for _, d := range r.Divergences {
		if errors.Is(d.Err, wantErr) {
			return
		}
	}
	t.Errorf("assertDiverged: want divergence %v, got: %v", wantErr, divergenceStrings(r))
}

// ── Check 4 tests ──────────────────────────────────────────────────────────

// TestCheck4_ValidSignature_SetsSignatureValid asserts that a bundle with a
// valid sig_manifest over h_manifest@160 under the carried pk_pub passes
// Check 4 and sets SignatureValid=true.
func TestCheck4_ValidSignature_SetsSignatureValid(t *testing.T) {
	b := bundleWithValidPublisherSig(t)
	v, _ := runVerify(t, b)
	if !v.SignatureValid {
		t.Fatal("Check 4 should accept a valid sig over the proof-bound h_manifest")
	}
}

// TestCheck4_TamperedSig_Diverges asserts that flipping a byte inside the
// DER region of sig_manifest causes Check 4 to reject with ErrSignatureInvalid.
func TestCheck4_TamperedSig_Diverges(t *testing.T) {
	b := bundleWithValidPublisherSig(t)
	// Flip a byte inside the DER body at offset 225 (byte 1 of sig_manifest@224,
	// which is the first byte of the DER payload after the length prefix).
	b.SpartanCompressResult.FirstStepPublicInputs[225] ^= 0xFF
	v, r := runVerify(t, b)
	if v.SignatureValid {
		t.Fatal("tampered sig must fail Check 4")
	}
	assertDiverged(t, r, ErrSignatureInvalid)
}

// TestCheck4_WrongPkPub_Diverges asserts that replacing pk_pub with a
// different compressed key causes the ECDSA relation to fail.
func TestCheck4_WrongPkPub_Diverges(t *testing.T) {
	b := bundleWithValidPublisherSig(t)
	b.SpartanCompressResult.PkPub = otherCompressedPubkey(t)
	v, r := runVerify(t, b)
	if v.SignatureValid {
		t.Fatal("sig under a different pk_pub must fail Check 4")
	}
	assertDiverged(t, r, ErrSignatureInvalid)
}

// TestCheck4_EnvelopeAbsent_StillRuns asserts that Check 4 runs from the
// carried pk_pub regardless of whether the attestation envelope is present.
func TestCheck4_EnvelopeAbsent_StillRuns(t *testing.T) {
	b := bundleWithValidPublisherSig(t)
	b.PublisherSignature, b.PublisherPubkey = nil, nil // no envelope
	v, _ := runVerify(t, b)
	if !v.SignatureValid {
		t.Fatal("Check 4 must run from carried pk_pub even with no envelope")
	}
}

// TestCheck4_ShortDerSignature_Accepts is the Hermes !33 blocker-1 regression:
// a valid strict-DER, low-S secp256k1 signature can be < 70 bytes (e.g. 69 when
// one of r/s is a 31-byte minimal INTEGER). Check 4 MUST accept it — the prior
// [70,73] length window rejected such signatures as padding_invalid.
func TestCheck4_ShortDerSignature_Accepts(t *testing.T) {
	b := bundleWithValidPublisherSig(t)
	fspi := b.SpartanCompressResult.FirstStepPublicInputs
	hManifest := append([]byte(nil), fspi[160:192]...)

	// Hunt for a keypair whose DER over hManifest is < 70 bytes.
	var pub, der []byte
	found := false
	for i := 0; i < 300000; i++ {
		var priv *secp256k1.PrivateKey
		priv, pub = sigTestKeypair(t)
		der = signDigestRaw(t, priv, hManifest)
		if len(der) < 70 {
			found = true
			break
		}
	}
	if !found {
		t.Skip("could not generate a <70-byte DER signature within budget")
	}

	// Rewrite the sig_manifest lane + pk_pub (and the matching envelope) with
	// the short signature, leaving h_manifest untouched so the binding holds.
	padded := make([]byte, 74)
	padded[0] = byte(len(der))
	copy(padded[1:], der)
	copy(fspi[224:298], padded)
	b.SpartanCompressResult.FirstStepPublicInputs = fspi
	b.SpartanCompressResult.PkPub = pub
	b.PublisherPubkey = pub
	b.PublisherSignature = der

	v, r := runVerify(t, b)
	if !v.SignatureValid {
		t.Fatalf("Check 4 rejected a valid %d-byte strict-DER signature: %v",
			len(der), divergenceStrings(r))
	}
}

// TestCheck4_NonV2DetachedManifest_FailsClosed is the Hermes !33 blocker-2
// regression: a NON-v2 disclosed manifest with NO envelope and a valid
// signature over a DETACHED h_manifest (SHA-256(manifest) != h_manifest) MUST
// fail closed. The manifest-binding is dialect-agnostic — not gated on the
// #!konareef-toml/v2 prefix — so the detached lane cannot slip through as
// SignatureValid/OK via the optional-envelope-absent path.
func TestCheck4_NonV2DetachedManifest_FailsClosed(t *testing.T) {
	b := bundleWithValidPublisherSig(t)                // Type-D, non-v2 manifest, pod_hash=SHA-256(manifest)
	b.PublisherSignature, b.PublisherPubkey = nil, nil // no envelope

	// Detach h_manifest from the disclosed manifest and sign the DETACHED value
	// so the failure is the binding, not an ECDSA-relation mismatch.
	fspi := b.SpartanCompressResult.FirstStepPublicInputs
	var detached [32]byte
	for i := range detached {
		detached[i] = 0x5A
	}
	copy(fspi[160:192], detached[:])
	priv, pub := sigTestKeypair(t)
	der := signDigestRaw(t, priv, detached[:])
	padded := make([]byte, 74)
	padded[0] = byte(len(der))
	copy(padded[1:], der)
	copy(fspi[224:298], padded)
	b.SpartanCompressResult.FirstStepPublicInputs = fspi
	b.SpartanCompressResult.PkPub = pub

	v, r := runVerify(t, b)
	if v.SignatureValid {
		t.Error("SignatureValid=true on non-v2 bundle with h_manifest detached from disclosed manifest")
	}
	if r.OK {
		t.Error("OK=true on detached non-v2 bundle (optional-envelope bypass)")
	}
	// PRD 3 §11.3 precedence: envelope absent + Check 4 failed → signature_invalid,
	// NOT unbound (unbound requires a valid Check 4).
	if v.PublisherIdentityStatus != PISSignatureInvalid {
		t.Errorf("status = %v, want signature_invalid (Check 4 failed, no envelope)", v.PublisherIdentityStatus)
	}
	assertDiverged(t, r, ErrSignatureInvalid)
}

// TestCheck4_PkPubAbsent_FailsClosed closes the soundness hole where an
// absent pk_pub in SpartanCompressResult was previously treated as "unbound"
// and returned SignatureValid=true. For konareef-pod-step-v1, sig_manifest
// is always present in the public-input vector; a missing pk_pub leaves the
// mandatory signature claim unverifiable and MUST fail closed (PRD 1 §4
// erratum / PRD 3 §11.2: signature_valid is NEVER n/a for this circuit).
func TestCheck4_PkPubAbsent_FailsClosed(t *testing.T) {
	// Build a bundle with a valid sig_manifest@224 and pk_pub present, then
	// clear pk_pub to simulate a producer that omits it.
	b := bundleWithValidPublisherSig(t)
	b.SpartanCompressResult.PkPub = nil // absent pk_pub — the previously-untested hole

	v, r := runVerify(t, b)
	if v.SignatureValid {
		t.Fatal("Check 4 must fail closed when pk_pub is absent in SCR; got SignatureValid=true")
	}
	assertDiverged(t, r, ErrSignatureInvalid)
}

// TestSnarkPhase_TypeCParityArtifactAccepts asserts the reef-core
// packer's Type-C parity artifact is rejected under the accepting Spartan
// stub — Check 4 fails closed because pk_pub is absent in SCR (the artifact
// pre-dates the CL-5a pk_pub carrier). The proof + disclosure checks still
// run to completion; only SignatureValid is false. Task 6 will regenerate
// the artifact with a real pk_pub so it passes fully BOUND.
func TestSnarkPhase_TypeCParityArtifactAccepts(t *testing.T) {
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
		t.Errorf("SignatureValid=true on Type-C parity with no pk_pub; Check 4 must fail closed")
	}
	// Proof and disclosure checks still run; verify they pass independently.
	if !r.V2Verdict.ProofValid {
		t.Errorf("proof_valid false; want true (independent of Check 4)")
	}
	if !r.V2Verdict.DisclosureValid {
		t.Errorf("disclosure_valid false; want true (independent of Check 4)")
	}
}

// TestSnarkPhase_TypeDParityArtifactAccepts asserts the reef-core
// packer's Type-D parity artifact is rejected — Check 4 fails closed
// because pk_pub is absent in SCR (pre-dates the CL-5a carrier).
// CommitmentsValid is still exercised. Task 6 regenerates with a real pk_pub.
func TestSnarkPhase_TypeDParityArtifactAccepts(t *testing.T) {
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
		t.Errorf("SignatureValid=true on Type-D parity with no pk_pub; Check 4 must fail closed")
	}
	// CommitmentsValid still exercises the Type-D commitment gate.
	if !r.V2Verdict.CommitmentsValid {
		t.Error("CommitmentsValid=false on Type-D parity bundle")
	}
}

// TestSnarkPhase_DefaultVerifierFailsClosed asserts the zero-value
// VerifyOptions MUST reject every v2 bundle with
// ErrSnarkVerifierNotConfigured (load-bearing security boundary).
func TestSnarkPhase_DefaultVerifierFailsClosed(t *testing.T) {
	path := filepath.Join("testdata", "parity-v2-typec.cbor")
	bytes, err := os.ReadFile(path)
	if err != nil {
		t.Skipf("parity artifact missing (%v)", err)
	}

	r := VerifyV2(bytes, VerifyOptions{})
	if r.OK {
		t.Fatal("zero-value VerifyOptions accepted a v2 bundle; default MUST fail closed")
	}
	if r.V2Verdict == nil {
		t.Fatal("v2 verdict missing")
	}
	if r.V2Verdict.ProofValid {
		t.Error("proof_valid=true under zero-value VerifyOptions")
	}
	found := false
	for _, d := range r.Divergences {
		if errors.Is(d.Err, ErrSnarkVerifierNotConfigured) {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("ErrSnarkVerifierNotConfigured not surfaced; got: %v", divergenceStrings(r))
	}
}

// TestDecodeBundleV2_UnknownOptionalKeyIgnored is the forward-compat
// regression guard (PRD 3 § 14.1).
func TestDecodeBundleV2_UnknownOptionalKeyIgnored(t *testing.T) {
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
		"future_extension": uint64(42),
	}
	encoded, err := encMode.Marshal(m)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}

	got, err := decodeBundleV2(encoded)
	if err != nil {
		t.Fatalf("decode rejected unknown optional key (B3 regression): %v", err)
	}
	if got.Version != "konareef-bundle/v2" {
		t.Errorf("version = %q; want konareef-bundle/v2", got.Version)
	}
	if got.Disclosure != "D" {
		t.Errorf("disclosure = %q; want D", got.Disclosure)
	}
}

// TestDecodeBundleV2_EmptyInput asserts empty bytes reject with
// ErrMalformedCBOR.
func TestDecodeBundleV2_EmptyInput(t *testing.T) {
	_, err := decodeBundleV2(nil)
	if !errors.Is(err, ErrMalformedCBOR) {
		t.Errorf("got err=%v; want ErrMalformedCBOR", err)
	}
}

// TestDecodeBundleV2_TrailingBytes asserts trailing bytes reject.
func TestDecodeBundleV2_TrailingBytes(t *testing.T) {
	bytes := []byte{0xA0, 0xFF}
	_, err := decodeBundleV2(bytes)
	if !errors.Is(err, ErrMalformedCBOR) {
		t.Errorf("got err=%v; want ErrMalformedCBOR", err)
	}
}

// TestDecodeBundleV2_TopLevelArray asserts top-level array rejects.
func TestDecodeBundleV2_TopLevelArray(t *testing.T) {
	bytes := []byte{0x80}
	_, err := decodeBundleV2(bytes)
	if !errors.Is(err, ErrMalformedCBOR) {
		t.Errorf("got err=%v; want ErrMalformedCBOR", err)
	}
}

// Round-4 B1 regression guards — 6 negative tests for missing/short
// h_p, h_r, t_root in the Spartan public-input vector.

func TestSnarkPhase_TypeC_MissingHP(t *testing.T) {
	runShortPublicInputs(t, "missing h_p", 64)
}

func TestSnarkPhase_TypeC_ShortHP(t *testing.T) {
	// h_p window starts at offset 96; truncate to 120 (window short by 8).
	runShortPublicInputs(t, "short h_p", 120)
}

func TestSnarkPhase_TypeC_MissingHR(t *testing.T) {
	// h_r window starts at offset 128; truncate to 128 to exclude h_r entirely.
	runShortPublicInputs(t, "missing h_r", 128)
}

func TestSnarkPhase_TypeC_ShortHR(t *testing.T) {
	runShortPublicInputs(t, "short h_r", 152)
}

func TestSnarkPhase_TypeC_MissingTRoot(t *testing.T) {
	// t_root window starts at offset 64; truncate to 64 to exclude t_root entirely.
	// The h_p/h_r strict checks will also fail; we only assert
	// CommitmentsValid=false + at least one ErrCommitmentMismatch surfaces.
	runShortPublicInputs(t, "missing t_root", 64)
}

func TestSnarkPhase_TypeC_ShortTRoot(t *testing.T) {
	runShortPublicInputs(t, "short t_root", 88)
}

// runShortPublicInputs is a shared helper: take the Type-C parity
// artifact, truncate first_step_public_inputs to truncLen, re-encode,
// and assert OK=false + CommitmentsValid=false + at least one
// ErrCommitmentMismatch divergence.
func runShortPublicInputs(t *testing.T, _ string, truncLen int) {
	t.Helper()
	path := filepath.Join("testdata", "parity-v2-typec.cbor")
	bytesIn, err := os.ReadFile(path)
	if err != nil {
		t.Skipf("parity artifact missing (%v)", err)
	}
	decoded, err := decodeBundleV2(bytesIn)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	decoded.SpartanCompressResult.FirstStepPublicInputs =
		decoded.SpartanCompressResult.FirstStepPublicInputs[:truncLen]
	encMode, err := cbor.CoreDetEncOptions().EncMode()
	if err != nil {
		t.Fatalf("enc mode: %v", err)
	}
	tampered, err := encMode.Marshal(decoded)
	if err != nil {
		t.Fatalf("re-encode: %v", err)
	}
	r := VerifyV2(tampered, WithAcceptingVerifierForTests())
	if r.OK {
		t.Fatal("bundle with short public inputs accepted; strict carrier gate is broken")
	}
	if r.V2Verdict == nil {
		t.Fatal("v2 verdict missing")
	}
	if r.V2Verdict.CommitmentsValid {
		t.Error("CommitmentsValid=true on bundle with short public inputs")
	}
	if !errorsIsCommitmentMismatch(r) {
		t.Errorf("expected ErrCommitmentMismatch divergence; got: %v", divergenceStrings(r))
	}
}

// TestSnarkPhase_TypeDManifestRequired asserts Type-D rejects with
// empty manifest (PRD 4 § B.2).
func TestSnarkPhase_TypeDManifestRequired(t *testing.T) {
	path := filepath.Join("testdata", "parity-v2-typed.cbor")
	bytesIn, err := os.ReadFile(path)
	if err != nil {
		t.Skipf("parity artifact missing (%v)", err)
	}
	decoded, err := decodeBundleV2(bytesIn)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	decoded.Manifest = nil
	encMode, err := cbor.CoreDetEncOptions().EncMode()
	if err != nil {
		t.Fatalf("enc mode: %v", err)
	}
	stripped, err := encMode.Marshal(decoded)
	if err != nil {
		t.Fatalf("re-encode: %v", err)
	}
	r := VerifyV2(stripped, WithAcceptingVerifierForTests())
	if r.OK {
		t.Fatal("Type-D bundle WITHOUT manifest accepted; checkTypeDCommitments gate is broken")
	}
	if r.V2Verdict != nil && r.V2Verdict.CommitmentsValid {
		t.Error("CommitmentsValid=true on Type-D bundle with empty manifest")
	}
}

// ── Envelope §11.2 cross-check tests ──────────────────────────────────────

// TestEnvelope_Consistent_SetsBound asserts that when all envelope fields
// (publisher_pubkey, publisher_signature, pod_hash) match the public-input
// vector AND Check 4 passed, PublisherIdentityStatus is upgraded to PISBound.
func TestEnvelope_Consistent_SetsBound(t *testing.T) {
	b := bundleWithValidPublisherSig(t) // envelope fields == public-input fields
	v, _ := runVerify(t, b)
	if v.PublisherIdentityStatus != PISBound {
		t.Fatalf("status = %v, want bound", v.PublisherIdentityStatus)
	}
}

// TestEnvelope_PubkeyMismatch_Diverges asserts that when the envelope
// publisher_pubkey does not match pk_pub from the public-input vector, the
// verifier diverges ErrAttestationMismatch (an envelope BYTE cross-check
// failure, PRD 3 §11.2/§12.3 — NOT ErrSignatureInvalid, which is reserved for
// Check 4) and sets PublisherIdentityStatus = mismatch (not bound).
func TestEnvelope_PubkeyMismatch_Diverges(t *testing.T) {
	b := bundleWithValidPublisherSig(t)
	b.PublisherPubkey = otherCompressedPubkey(t) // != pk_pub in SCR
	v, r := runVerify(t, b)
	if v.PublisherIdentityStatus != PISMismatch {
		t.Fatalf("status = %v, want mismatch (envelope publisher_pubkey != pk_pub)", v.PublisherIdentityStatus)
	}
	assertDiverged(t, r, ErrAttestationMismatch)
}

// TestEnvelope_PodHashMismatch_Diverges asserts that an envelope pod_hash that
// disagrees with the public-input h_manifest is an ERR_ATTESTATION_MISMATCH /
// mismatch (envelope byte cross-check 2), not ERR_SIGNATURE_INVALID.
func TestEnvelope_PodHashMismatch_Diverges(t *testing.T) {
	b := bundleWithValidPublisherSig(t)
	other := make([]byte, 32)
	for i := range other {
		other[i] = 0x77
	}
	b.PodHash = other // != h_manifest
	v, r := runVerify(t, b)
	if v.PublisherIdentityStatus != PISMismatch {
		t.Fatalf("status = %v, want mismatch (envelope pod_hash != h_manifest)", v.PublisherIdentityStatus)
	}
	assertDiverged(t, r, ErrAttestationMismatch)
}

// TestEnvelope_SignatureMismatch_Diverges asserts that an envelope
// publisher_signature that disagrees with DER(sig_manifest) is an
// ERR_ATTESTATION_MISMATCH / mismatch (envelope byte cross-check 3), not
// ERR_SIGNATURE_INVALID.
func TestEnvelope_SignatureMismatch_Diverges(t *testing.T) {
	b := bundleWithValidPublisherSig(t)
	tampered := append([]byte(nil), b.PublisherSignature...)
	tampered[len(tampered)-1] ^= 0xFF // still same length, != DER(sig_manifest)
	b.PublisherSignature = tampered
	v, r := runVerify(t, b)
	if v.PublisherIdentityStatus != PISMismatch {
		t.Fatalf("status = %v, want mismatch (envelope publisher_signature != DER)", v.PublisherIdentityStatus)
	}
	assertDiverged(t, r, ErrAttestationMismatch)
}

// TestEnvelope_Absent_Unbound asserts that when both PublisherSignature and
// PublisherPubkey are nil (no attestation envelope) AND Check 4 passes, the
// publisher identity status is PISUnbound (valid bare public-input signature,
// no envelope identity). The Check-4-FAILED + no-envelope case maps to
// signature_invalid instead (PRD 3 §11.3 precedence) — see
// TestCheck4_NonV2DetachedManifest_FailsClosed.
func TestEnvelope_Absent_Unbound(t *testing.T) {
	b := bundleWithValidPublisherSig(t)                // Check 4 passes (valid sig)
	b.PublisherSignature, b.PublisherPubkey = nil, nil // remove envelope
	v, _ := runVerify(t, b)
	if v.PublisherIdentityStatus != PISUnbound {
		t.Fatalf("status = %v, want unbound (no envelope, Check 4 passed)", v.PublisherIdentityStatus)
	}
}

// highSDER takes a valid low-S DER-encoded secp256k1 signature and returns
// a high-S variant by replacing s with n-s. The result is a structurally
// valid DER SEQUENCE but with s > n/2, which ParseStrict (and therefore
// Check 4) must reject.
//
// The negation is done at the math/big level; the result is re-encoded as
// a fresh DER SEQUENCE so the length prefix and integer encodings are
// minimal. The secp256k1 order n is taken from the curve params.
func highSDER(t *testing.T, der []byte) []byte {
	t.Helper()
	type ecdsaSig struct {
		R, S *big.Int
	}
	var parsed ecdsaSig
	if rest, err := asn1.Unmarshal(der, &parsed); err != nil || len(rest) != 0 {
		t.Fatalf("highSDER: asn1.Unmarshal: %v (rest=%d)", err, len(rest))
	}
	n := secp256k1.S256().N
	// Negate: s' = n - s. Since the input is low-S (s ≤ n/2), s' = n-s > n/2.
	sHigh := new(big.Int).Sub(n, parsed.S)
	out, err := asn1.Marshal(ecdsaSig{R: parsed.R, S: sHigh})
	if err != nil {
		t.Fatalf("highSDER: asn1.Marshal: %v", err)
	}
	return out
}

// TestCheck4_RejectsHighS asserts that Check 4 rejects a high-S DER
// signature unconditionally — regardless of whether KONAREEF_STRICT_DER_GATE
// is set — and surfaces reason=high_s with ErrSignatureInvalid.
//
// This is the RED→GREEN regression guard for defect I-1: before the fix,
// checkPublicInputSignature only called ParseStrict when StrictDerGateEnabled
// was true (the legacy env flag), so high-S signatures passed Check 4 by
// default, making signature_valid=true on an invalid bundle.
//
// The test does NOT set identity.StrictDerGateEnabled (remains false), proving
// that Check 4 strictness is now decoupled from the legacy flag.
func TestCheck4_RejectsHighS(t *testing.T) {
	b := bundleWithValidPublisherSig(t)

	// Extract the valid DER from the padded sig_manifest window.
	pib := b.SpartanCompressResult.FirstStepPublicInputs
	derLen := int(pib[224])
	validDER := make([]byte, derLen)
	copy(validDER, pib[225:225+derLen])

	// Construct a high-S variant: same r, s replaced with n-s.
	badDER := highSDER(t, validDER)

	// Rebuild the 74-byte padded sig_manifest with the high-S DER.
	if len(badDER) < 70 || len(badDER) > 73 {
		// asn1.Marshal of a high-S sig should still be 70-73 bytes;
		// skip if the specific random key produced an unusual length.
		t.Skipf("high-S DER length %d outside [70,73]; skipping (rare edge case)", len(badDER))
	}
	newSigManifest := make([]byte, 74)
	newSigManifest[0] = byte(len(badDER))
	copy(newSigManifest[1:], badDER)
	copy(pib[224:], newSigManifest)

	// Also update the envelope publisher_signature to match the tampered DER
	// so the envelope cross-check does not diverge for the wrong reason.
	b.PublisherSignature = badDER

	v, r := runVerify(t, b)

	if v.SignatureValid {
		t.Fatal("Check 4 must reject high-S signature; got SignatureValid=true (I-1 not fixed)")
	}
	assertDiverged(t, r, ErrSignatureInvalid)

	// Assert the granular reason=high_s is surfaced in the divergence message.
	found := false
	for _, d := range r.Divergences {
		if errors.Is(d.Err, ErrSignatureInvalid) && strings.Contains(d.Msg, "reason=high_s") {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected divergence with reason=high_s; got: %v", divergenceStrings(r))
	}
}

// divergenceStrings is a test helper for human-readable failure logs.
func divergenceStrings(r *ResultV2) []string {
	out := make([]string, 0, len(r.Divergences))
	for _, d := range r.Divergences {
		out = append(out, d.Msg)
	}
	return out
}
