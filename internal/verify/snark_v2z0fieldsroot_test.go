// Copyright 2026 Jerry David Chan, Konareef.ai
// SPDX-License-Identifier: Apache-2.0

package verify

// MR !41 blocker-3 hybrid fix — Go-side negative tests for the
// genesis_fields_root <-> z0[Z_FIELDS_ROOT] binding and for the
// digest offsets the Rust verify binary explicitly de-scopes
// (h_manifest@160, h_p@96, t_root@64). These tests prove the Go
// verifier catches exactly what the Rust binary no longer claims to
// check, so the de-scope is sound rather than a hole.
//
// The fixtures inject a full 736-byte z0 (Z_ARITY = 23 post-CL-6) whose
// Z_FIELDS_ROOT lane (z0[672:704], lane 21 in both layouts) agrees with
// genesis_fields_root, then each test mutates ONE datum (leaving the
// SNARK/z0 structurally intact) and asserts the bundle is rejected.

import (
	"testing"

	"github.com/fxamacker/cbor/v2"
)

const (
	zFieldsRootLaneTest = 21
	zLaneWidthTest      = 32
	z0FullWidthTest     = 23 * zLaneWidthTest // 736 (Z_ARITY = 23 post-CL-6)
)

// buildV2Z0FieldsRootBundle builds a canonical-v2 Type-C bundle from the
// parity artifact with:
//   - a real [_commit].fields_root manifest committing fieldsRoot,
//   - the h_manifest slot [160:192] bound to SHA-256(manifest),
//   - genesis_fields_root carriage,
//   - a full 736-byte z0 whose Z_FIELDS_ROOT lane == z0FieldsRootLane.
//
// `mutate` runs against the decoded bundle just before re-encoding, so a
// test can tamper exactly one datum. Pass nil for the all-consistent
// positive path.
func buildV2Z0FieldsRootBundle(
	t *testing.T,
	fieldsRoot [32]byte,
	genesisFieldsRoot []byte,
	z0FieldsRootLane []byte,
	mutate func(b *BundleV2),
) []byte {
	t.Helper()
	// Reuse the existing helper for everything except z0: it returns
	// re-encoded bytes, so decode it once more to inject z0 + run mutate.
	base := buildV2FieldsRootBundle(t, fieldsRoot, genesisFieldsRoot, true, false)
	decoded, err := decodeBundleV2(base)
	if err != nil {
		t.Fatalf("decode base: %v", err)
	}

	// Inject a full 736-byte z0 with the Z_FIELDS_ROOT lane set.
	z0 := make([]byte, z0FullWidthTest)
	if len(z0FieldsRootLane) == zLaneWidthTest {
		copy(z0[zFieldsRootLaneTest*zLaneWidthTest:], z0FieldsRootLane)
	}
	decoded.SpartanCompressResult.Z0 = z0

	if mutate != nil {
		mutate(decoded)
	}

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

// TestSnarkPhase_Z0FieldsRoot_Accepts — all three links consistent
// ([_commit].fields_root == genesis_fields_root == z0[Z_FIELDS_ROOT]) →
// OK with CommitmentsValid.
func TestSnarkPhase_Z0FieldsRoot_Accepts(t *testing.T) {
	fr := v2FieldsRoot(t)
	bundle := buildV2Z0FieldsRootBundle(t, fr, fr[:], fr[:], nil)
	r := VerifyV2(bundle, WithAcceptingVerifierForTests())
	if !r.OK {
		t.Fatalf("expected accept; got divergences:\n%v", divergenceStrings(r))
	}
	if r.V2Verdict == nil || !r.V2Verdict.CommitmentsValid {
		t.Errorf("CommitmentsValid=false on consistent z0-fields_root bundle")
	}
}

// TestSnarkPhase_Z0FieldsRoot_Z0LaneMismatch — z0[Z_FIELDS_ROOT] tampered
// to differ from genesis_fields_root (which still matches the manifest)
// → ErrFieldsRootMismatch. This is the lane the Rust binary de-scopes.
func TestSnarkPhase_Z0FieldsRoot_Z0LaneMismatch(t *testing.T) {
	fr := v2FieldsRoot(t)
	var otherLane [32]byte
	for i := range otherLane {
		otherLane[i] = 0xAB
	}
	bundle := buildV2Z0FieldsRootBundle(t, fr, fr[:], otherLane[:], nil)
	r := VerifyV2(bundle, WithAcceptingVerifierForTests())
	assertFieldsRootRejected(t, r)
}

// TestSnarkPhase_Z0FieldsRoot_GenesisTamper — genesis_fields_root tampered
// AFTER z0 injection so it disagrees with BOTH the manifest and the z0
// lane → rejected (the existing (b) binding AND the new (c) binding fail).
func TestSnarkPhase_Z0FieldsRoot_GenesisTamper(t *testing.T) {
	fr := v2FieldsRoot(t)
	bundle := buildV2Z0FieldsRootBundle(t, fr, fr[:], fr[:], func(b *BundleV2) {
		tampered := make([]byte, 32)
		for i := range tampered {
			tampered[i] = 0x99
		}
		b.SpartanCompressResult.GenesisFieldsRoot = tampered
	})
	r := VerifyV2(bundle, WithAcceptingVerifierForTests())
	assertFieldsRootRejected(t, r)
}

// TestSnarkPhase_Z0FieldsRoot_Z0ShortRejected — a present-but-short z0
// (e.g. 64 bytes) is fail-closed even though genesis_fields_root matches
// the manifest. A truncated z0 cannot have been the proven vector.
func TestSnarkPhase_Z0FieldsRoot_Z0ShortRejected(t *testing.T) {
	fr := v2FieldsRoot(t)
	bundle := buildV2Z0FieldsRootBundle(t, fr, fr[:], fr[:], func(b *BundleV2) {
		b.SpartanCompressResult.Z0 = make([]byte, 64) // present but < 736
	})
	r := VerifyV2(bundle, WithAcceptingVerifierForTests())
	assertFieldsRootRejected(t, r)
}

// TestSnarkPhase_Z0FieldsRoot_Z0AbsentRejected — an absent (nil) z0 on a
// canonical-v2 bundle is fail-closed even though genesis_fields_root
// matches the manifest. z0 is MANDATORY on the canonical-v2 surface: the
// [_commit].fields_root == genesis_fields_root == z0[Z_FIELDS_ROOT] chain
// (last link SNARK-proven) is only enforceable when z0 is present and
// exactly 736 bytes. Without this gate a canonical-v2 bundle that simply
// omits z0 would slip through on the (b) binding alone.
func TestSnarkPhase_Z0FieldsRoot_Z0AbsentRejected(t *testing.T) {
	fr := v2FieldsRoot(t)
	bundle := buildV2Z0FieldsRootBundle(t, fr, fr[:], fr[:], func(b *BundleV2) {
		b.SpartanCompressResult.Z0 = nil // absent
	})
	r := VerifyV2(bundle, WithAcceptingVerifierForTests())
	assertFieldsRootRejected(t, r)
}

// TestSnarkPhase_Z0FieldsRoot_Z0OversizedRejected — a present-but-oversized
// z0 (737 bytes, lane 21 still correct) must fail the exact-736 carrier gate.
// The C1 contract is an exact 23-lane fold-IO vector; trailing bytes are
// malformed, and the production Spartan subprocess likewise requires
// len(z0)==736, so the Go verifier must reject oversized carriers too.
func TestSnarkPhase_Z0FieldsRoot_Z0OversizedRejected(t *testing.T) {
	fr := v2FieldsRoot(t)
	bundle := buildV2Z0FieldsRootBundle(t, fr, fr[:], fr[:], func(b *BundleV2) {
		// helper already injected a valid 736-byte z0 (lane 21 == fr);
		// append one trailing byte so only the LENGTH is wrong.
		b.SpartanCompressResult.Z0 = append(b.SpartanCompressResult.Z0, 0x00)
	})
	r := VerifyV2(bundle, WithAcceptingVerifierForTests())
	assertFieldsRootRejected(t, r)
}

// TestSnarkPhase_Z0FieldsRoot_HManifestTamper — mutate first_step[160]
// (h_manifest, a Rust-de-scoped offset) → CommitmentsValid=false via the
// CL-5a SHA-256(manifest)==h_manifest check. Proves the Go layer catches
// the offset the Rust binary no longer validates.
func TestSnarkPhase_Z0FieldsRoot_HManifestTamper(t *testing.T) {
	fr := v2FieldsRoot(t)
	bundle := buildV2Z0FieldsRootBundle(t, fr, fr[:], fr[:], func(b *BundleV2) {
		b.SpartanCompressResult.FirstStepPublicInputs[160] ^= 0xFF
	})
	r := VerifyV2(bundle, WithAcceptingVerifierForTests())
	if r.OK {
		t.Fatal("h_manifest tamper accepted; Go-side CL-5a binding broken")
	}
	if r.V2Verdict != nil && r.V2Verdict.CommitmentsValid {
		t.Error("CommitmentsValid=true on h_manifest-tampered bundle")
	}
	if !errorsIsCommitmentMismatch(r) {
		t.Errorf("expected ErrCommitmentMismatch divergence; got: %v", divergenceStrings(r))
	}
}

// TestSnarkPhase_Z0FieldsRoot_HpTamper — mutate first_step[96] (h_p, a
// Rust-de-scoped offset) → CommitmentsValid=false via
// checkTypeCWitnessHashes (SHA-256(P) == h_p). Proves the Go layer binds
// the disclosed P bytes to the offset the Rust binary de-scopes.
func TestSnarkPhase_Z0FieldsRoot_HpTamper(t *testing.T) {
	fr := v2FieldsRoot(t)
	bundle := buildV2Z0FieldsRootBundle(t, fr, fr[:], fr[:], func(b *BundleV2) {
		b.SpartanCompressResult.FirstStepPublicInputs[96] ^= 0xFF
	})
	r := VerifyV2(bundle, WithAcceptingVerifierForTests())
	if r.OK {
		t.Fatal("h_p tamper accepted; Go-side witness-hash binding broken")
	}
	if r.V2Verdict != nil && r.V2Verdict.CommitmentsValid {
		t.Error("CommitmentsValid=true on h_p-tampered bundle")
	}
	if !errorsIsCommitmentMismatch(r) {
		t.Errorf("expected ErrCommitmentMismatch divergence; got: %v", divergenceStrings(r))
	}
}

// TestSnarkPhase_Z0FieldsRoot_TRootTamper — mutate first_step[64]
// (t_root, a Rust-de-scoped offset) → CommitmentsValid=false via
// checkTLogRoot (Poseidon(T_log_records) == t_root). Proves the Go layer
// binds the disclosed T_log to the offset the Rust binary de-scopes.
func TestSnarkPhase_Z0FieldsRoot_TRootTamper(t *testing.T) {
	fr := v2FieldsRoot(t)
	bundle := buildV2Z0FieldsRootBundle(t, fr, fr[:], fr[:], func(b *BundleV2) {
		b.SpartanCompressResult.FirstStepPublicInputs[64] ^= 0xFF
	})
	r := VerifyV2(bundle, WithAcceptingVerifierForTests())
	if r.OK {
		t.Fatal("t_root tamper accepted; Go-side T_log root binding broken")
	}
	if r.V2Verdict != nil && r.V2Verdict.CommitmentsValid {
		t.Error("CommitmentsValid=true on t_root-tampered bundle")
	}
	if !errorsIsCommitmentMismatch(r) {
		t.Errorf("expected ErrCommitmentMismatch divergence; got: %v", divergenceStrings(r))
	}
}
