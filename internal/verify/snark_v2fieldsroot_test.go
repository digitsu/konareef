// Copyright 2026 Jerry David Chan, Konareef.ai
// SPDX-License-Identifier: Apache-2.0

package verify

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"

	"github.com/fxamacker/cbor/v2"
)

// buildV2FieldsRootBundle starts from the consistent Type-C parity
// artifact (so h_p/h_r/t_root already pass), swaps in a real
// canonical-v2 manifest committing fieldsRoot, and wires the h_manifest
// public-input slot + genesis_fields_root carriage per the caller's
// mutators. It returns the re-encoded bundle bytes.
//
// setManifestSlot controls whether the h_manifest slot [160:192] is set
// to SHA-256(manifest) (true) or left as the artifact's original bytes
// (false, to exercise the h_manifest mismatch path).
func buildV2FieldsRootBundle(t *testing.T, fieldsRoot [32]byte, genesisFieldsRoot []byte, setManifestSlot bool, dropCommit bool) []byte {
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

	manifest := "#!konareef-toml/v2\n[pod]\nid = \"x\"\n[_files]\n"
	if !dropCommit {
		manifest += "[_commit]\nfields_root = \"poseidon:" + hex.EncodeToString(fieldsRoot[:]) + "\"\n"
	}
	decoded.Manifest = []byte(manifest)
	// pod_hash must equal SHA-256(manifest) so the existing pod_hash
	// check stays green for the swapped manifest.
	podHash := sha256.Sum256([]byte(manifest))
	decoded.PodHash = podHash[:]

	if setManifestSlot {
		hm := sha256.Sum256([]byte(manifest))
		fspi := decoded.SpartanCompressResult.FirstStepPublicInputs
		if len(fspi) < 192 {
			t.Fatalf("first_step_public_inputs too short: %d", len(fspi))
		}
		copy(fspi[160:192], hm[:])
		decoded.SpartanCompressResult.FirstStepPublicInputs = fspi
	}

	decoded.SpartanCompressResult.GenesisFieldsRoot = genesisFieldsRoot

	// z0 is MANDATORY on the canonical-v2 surface: inject a full 736-byte
	// fold-IO vector whose Z_FIELDS_ROOT lane (z0[672:704]) equals
	// genesis_fields_root, so the (c) binding
	// (genesis_fields_root == z0[Z_FIELDS_ROOT]) is satisfied for the
	// positive path and the tests here exercise the (a)/(b) bindings
	// rather than tripping the z0-presence gate. Tests that need a
	// missing/short z0 set it explicitly after this helper returns.
	z0 := make([]byte, 23*32) // 736 (Z_ARITY = 23 post-CL-6)
	if len(genesisFieldsRoot) == 32 {
		copy(z0[21*32:], genesisFieldsRoot) // lane 21 == genesis_fields_root
	}
	decoded.SpartanCompressResult.Z0 = z0

	// Conform to the mandatory Check 4 invariant: sign the proof-bound
	// h_manifest lane and carry pk_pub so the public-input signature path
	// passes. Our model runs Check 4 from the carried sig_manifest@224 /
	// pk_pub (NOT the envelope); the parity artifact ships a zero-filled
	// sig_manifest, which would otherwise fail Check 4 closed and mask the
	// fields_root assertions under test. The envelope is dropped (Check 4
	// runs from pk_pub regardless), so no envelope cross-check can interfere.
	decoded.PublisherSignature = nil
	decoded.PublisherPubkey = nil
	injectPublicInputSig(t, decoded)

	encMode, err := cbor.CoreDetEncOptions().EncMode()
	if err != nil {
		t.Fatalf("enc mode: %v", err)
	}
	out, err := encMode.Marshal(decoded)
	if err != nil {
		t.Fatalf("re-encode: %v", err)
	}
	return out
}

func fr0120() [32]byte {
	var fr [32]byte
	for i := range fr {
		fr[i] = byte(i + 1) // 0x01..0x20
	}
	return fr
}

// TestSnarkPhase_V2FieldsRoot_Accepts is the positive path: a real
// canonical-v2 Type-C bundle with the h_manifest slot bound and
// genesis_fields_root == [_commit].fields_root verifies OK.
func TestSnarkPhase_V2FieldsRoot_Accepts(t *testing.T) {
	fr := fr0120()
	bundle := buildV2FieldsRootBundle(t, fr, fr[:], true, false)
	r := VerifyV2(bundle, WithAcceptingVerifierForTests())
	if !r.OK {
		t.Fatalf("expected accept; got divergences:\n%v", divergenceStrings(r))
	}
	if r.V2Verdict == nil || !r.V2Verdict.CommitmentsValid {
		t.Errorf("CommitmentsValid=false on consistent v2 fields_root bundle")
	}
}

// TestSnarkPhase_V2FieldsRoot_GenesisMismatch — genesis_fields_root set
// to different bytes than [_commit].fields_root → ErrFieldsRootMismatch.
func TestSnarkPhase_V2FieldsRoot_GenesisMismatch(t *testing.T) {
	fr := fr0120()
	var other [32]byte
	for i := range other {
		other[i] = 0xFF
	}
	bundle := buildV2FieldsRootBundle(t, fr, other[:], true, false)
	r := VerifyV2(bundle, WithAcceptingVerifierForTests())
	assertFieldsRootRejected(t, r)
}

// TestSnarkPhase_V2FieldsRoot_HManifestMismatch — the h_manifest slot is
// left as the artifact's original bytes (not SHA-256(manifest)) →
// ErrCommitmentMismatch.
func TestSnarkPhase_V2FieldsRoot_HManifestMismatch(t *testing.T) {
	fr := fr0120()
	bundle := buildV2FieldsRootBundle(t, fr, fr[:], false, false)
	r := VerifyV2(bundle, WithAcceptingVerifierForTests())
	if r.OK {
		t.Fatal("bundle with unbound h_manifest accepted; v2 binding broken")
	}
	if r.V2Verdict != nil && r.V2Verdict.CommitmentsValid {
		t.Error("CommitmentsValid=true on h_manifest-mismatch bundle")
	}
	if !errorsIsCommitmentMismatch(r) {
		t.Errorf("expected ErrCommitmentMismatch divergence; got: %v", divergenceStrings(r))
	}
}

// TestSnarkPhase_V2FieldsRoot_CommitParseError — the [_commit] section
// is removed so ParseCommitFieldsRoot fails → ErrFieldsRootMismatch.
func TestSnarkPhase_V2FieldsRoot_CommitParseError(t *testing.T) {
	fr := fr0120()
	bundle := buildV2FieldsRootBundle(t, fr, fr[:], true, true)
	r := VerifyV2(bundle, WithAcceptingVerifierForTests())
	assertFieldsRootRejected(t, r)
}

// TestSnarkPhase_V2FieldsRoot_GenesisShort — genesis_fields_root nil →
// ErrFieldsRootMismatch (width check).
func TestSnarkPhase_V2FieldsRoot_GenesisShort(t *testing.T) {
	fr := fr0120()
	bundle := buildV2FieldsRootBundle(t, fr, nil, true, false)
	r := VerifyV2(bundle, WithAcceptingVerifierForTests())
	assertFieldsRootRejected(t, r)
}

// TestSnarkPhase_V2FieldsRoot_NonV2Regression asserts the Type-C parity
// artifact (a konareef-manifest-v1 manifest) verifies OK — the v2-gated
// fields-root / CL-6 blocks MUST NOT fire on a non-v2 manifest. Under the
// mandatory-Check-4 model the raw artifact (zero sig_manifest@224, no pk_pub)
// fails closed, which would mask this regression; so we conform it by
// injecting a valid public-input signature over its (v1, zero) h_manifest
// lane. With Check 4 satisfied, an OK verdict proves no v2 block spuriously
// fired on the v1 artifact. (The raw-artifact fail-closed behaviour is
// covered by TestParity_V2_RoundTrip_TypeC.)
func TestSnarkPhase_V2FieldsRoot_NonV2Regression(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("testdata", "parity-v2-typec.cbor"))
	if err != nil {
		t.Skipf("parity artifact missing: %v", err)
	}
	decoded, err := decodeBundleV2(raw)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	decoded.PublisherSignature = nil
	decoded.PublisherPubkey = nil
	// Bind h_manifest@160 to the disclosed manifest (the Check 4 manifest-
	// binding is dialect-agnostic — Hermes !33 blocker 2 — so a valid non-v2
	// fixture must have SHA-256(manifest) == h_manifest), then inject the sig.
	if fspi := decoded.SpartanCompressResult.FirstStepPublicInputs; len(fspi) >= 192 && len(decoded.Manifest) > 0 {
		hm := sha256.Sum256(decoded.Manifest)
		copy(fspi[160:192], hm[:])
		decoded.SpartanCompressResult.FirstStepPublicInputs = fspi
	}
	injectPublicInputSig(t, decoded)
	enc, err := cbor.CoreDetEncOptions().EncMode()
	if err != nil {
		t.Fatalf("enc mode: %v", err)
	}
	bundle, err := enc.Marshal(decoded)
	if err != nil {
		t.Fatalf("re-encode: %v", err)
	}
	r := VerifyV2(bundle, WithAcceptingVerifierForTests())
	if !r.OK {
		t.Fatalf("non-v2 parity artifact rejected after v2 gate added: %v", divergenceStrings(r))
	}
	if r.V2Verdict == nil || !r.V2Verdict.CommitmentsValid {
		t.Error("CommitmentsValid=false on unmodified non-v2 parity artifact")
	}
}

// assertFieldsRootRejected asserts OK=false, CommitmentsValid=false, and
// at least one ErrFieldsRootMismatch divergence surfaced.
func assertFieldsRootRejected(t *testing.T, r *ResultV2) {
	t.Helper()
	if r.OK {
		t.Fatal("bundle accepted; fields_root soundness gate broken")
	}
	if r.V2Verdict != nil && r.V2Verdict.CommitmentsValid {
		t.Error("CommitmentsValid=true on fields_root-mismatch bundle")
	}
	found := false
	for _, d := range r.Divergences {
		if d.Err == ErrFieldsRootMismatch {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected ErrFieldsRootMismatch divergence; got: %v", divergenceStrings(r))
	}
}
