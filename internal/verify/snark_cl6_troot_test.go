// Copyright 2026 Jerry David Chan, Konareef.ai
// SPDX-License-Identifier: Apache-2.0

// snark_cl6_troot_test.go — CL-6 regression guards for the disclosed
// T_log → proof-bound t_root binding (PRD 1 § 5.4, § 4.2 offset 64).
//
// checkTLogRoot (snark.go) recomputes the Poseidon t_root over the
// disclosed WitnessDisclosure.TLogRecords and compares it to the
// t_root carried at first_step_public_inputs[64:96]. These tests
// assert that:
//
//   - A honest Type-C bundle (TLogRecords consistent with t_root)
//     continues to pass CommitmentsValid=true (positive / regression guard).
//   - A bundle whose TLogRecords are corrupted so the recomputed root
//     diverges from t_root@64 is rejected with CommitmentsValid=false
//     and an ErrCommitmentMismatch divergence (negative / soundness gate).
//   - A bundle whose t_root public-input carrier is entirely absent
//     (public inputs truncated to offset 64) is also rejected
//     (carrier-missing negative path).
package verify

import (
	"crypto/sha256"
	"os"
	"path/filepath"
	"testing"

	"github.com/fxamacker/cbor/v2"
)

// tRootLoadTypeC reads the Type-C parity artifact, decodes it, strips
// the publisher attestation envelope so the B2 fail-closed gate does
// not mask the t_root divergence under test, and returns a mutable
// *BundleV2.
func tRootLoadTypeC(t *testing.T) *BundleV2 {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", "parity-v2-typec.cbor"))
	if err != nil {
		t.Skipf("parity Type-C artifact missing: %v", err)
	}
	decoded, err := decodeBundleV2(raw)
	if err != nil {
		t.Fatalf("decode parity Type-C: %v", err)
	}
	// Conform to the mandatory Check 4 invariant so we can isolate the t_root
	// path under test: drop the envelope, bind h_manifest@160 to the disclosed
	// manifest (the parity artifact ships a deliberately-zero h_manifest, but
	// the Check 4 manifest-binding is now dialect-agnostic — Hermes !33 blocker
	// 2 — so a production-representative fixture must have SHA-256(manifest) ==
	// h_manifest), then inject a valid public-input sig_manifest@224 + pk_pub
	// over that lane so Check 4 passes from the carried pk_pub.
	decoded.PublisherSignature = nil
	decoded.PublisherPubkey = nil
	if fspi := decoded.SpartanCompressResult.FirstStepPublicInputs; len(fspi) >= 192 && len(decoded.Manifest) > 0 {
		hm := sha256.Sum256(decoded.Manifest)
		copy(fspi[160:192], hm[:])
		decoded.SpartanCompressResult.FirstStepPublicInputs = fspi
	}
	injectPublicInputSig(t, decoded)
	return decoded
}

// tRootReencode re-encodes a *BundleV2 with the canonical deterministic
// encoder and returns the resulting bytes.
func tRootReencode(t *testing.T, b *BundleV2) []byte {
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

// TestTypeC_TRootHonestBundlePasses is the positive regression guard:
// the envelope-stripped parity Type-C bundle (whose TLogRecords are
// consistent with the proof-bound t_root) must still pass with
// CommitmentsValid=true. A failure here means the checkTLogRoot check
// is either missing or incorrectly rejects an honest bundle.
func TestTypeC_TRootHonestBundlePasses(t *testing.T) {
	b := tRootLoadTypeC(t)
	encoded := tRootReencode(t, b)
	r := VerifyV2(encoded, WithAcceptingVerifierForTests())
	if !r.OK {
		t.Errorf("honest Type-C bundle rejected; divergences: %v", divergenceStrings(r))
	}
	if r.V2Verdict == nil {
		t.Fatal("v2 verdict missing")
	}
	if !r.V2Verdict.CommitmentsValid {
		t.Errorf("CommitmentsValid=false on honest bundle; divergences: %v", divergenceStrings(r))
	}
}

// TestTypeC_TRootMismatchRejected is the CL-6 soundness gate: a bundle
// whose WitnessDisclosure.TLogRecords are corrupted so the recomputed
// Poseidon root diverges from the proof-bound t_root at public-input
// offset 64 MUST be rejected with CommitmentsValid=false and at least
// one ErrCommitmentMismatch divergence. Corruption is a single-byte
// XOR on the first byte of TLogRecords[0] (a raw record_bytes slice),
// which changes the Poseidon leaf for that record and therefore the
// tree root.
func TestTypeC_TRootMismatchRejected(t *testing.T) {
	b := tRootLoadTypeC(t)

	wd := b.WitnessDisclosure
	if wd == nil || len(wd.TLogRecords) == 0 {
		t.Skip("parity Type-C artifact has no TLogRecords; cannot exercise t_root mismatch path")
	}

	// Corrupt the first byte of the first record so the recomputed
	// Poseidon root no longer matches t_root@64.
	rec := make([]byte, len(wd.TLogRecords[0]))
	copy(rec, wd.TLogRecords[0])
	rec[0] ^= 0xFF
	wd.TLogRecords[0] = rec

	r := VerifyV2(tRootReencode(t, b), WithAcceptingVerifierForTests())
	if r.OK {
		t.Fatal("corrupted-TLogRecords bundle accepted; CL-6 t_root mismatch gate is broken")
	}
	if r.V2Verdict == nil {
		t.Fatal("v2 verdict missing")
	}
	if r.V2Verdict.CommitmentsValid {
		t.Error("CommitmentsValid=true on bundle with corrupted TLogRecords; want false")
	}
	if !errorsIsCommitmentMismatch(r) {
		t.Errorf("expected ErrCommitmentMismatch divergence; got: %v", divergenceStrings(r))
	}
}

// TestTypeC_TRootCarrierMissingRejected asserts the carrier-missing
// path: when first_step_public_inputs is truncated to exactly offset 64
// (the t_root window is absent), checkTLogRoot must fail closed with
// CommitmentsValid=false and ErrCommitmentMismatch. This mirrors the
// existing TestSnarkPhase_TypeC_MissingTRoot but is scoped to the
// checkTLogRoot carrier check rather than the h_p/h_r path.
func TestTypeC_TRootCarrierMissingRejected(t *testing.T) {
	b := tRootLoadTypeC(t)

	// Truncate first_step_public_inputs to offset 64 so the t_root
	// window [64:96] is entirely absent. h_p and h_r windows are also
	// absent; the test only asserts the all-or-none outcome.
	if len(b.SpartanCompressResult.FirstStepPublicInputs) < 64 {
		t.Skip("parity artifact first_step_public_inputs shorter than 64 bytes; cannot truncate")
	}
	b.SpartanCompressResult.FirstStepPublicInputs =
		b.SpartanCompressResult.FirstStepPublicInputs[:64]

	r := VerifyV2(tRootReencode(t, b), WithAcceptingVerifierForTests())
	if r.OK {
		t.Fatal("bundle with truncated public inputs (t_root window absent) accepted; carrier gate broken")
	}
	if r.V2Verdict == nil {
		t.Fatal("v2 verdict missing")
	}
	if r.V2Verdict.CommitmentsValid {
		t.Error("CommitmentsValid=true on bundle with absent t_root carrier window")
	}
	if !errorsIsCommitmentMismatch(r) {
		t.Errorf("expected ErrCommitmentMismatch divergence; got: %v", divergenceStrings(r))
	}
}
