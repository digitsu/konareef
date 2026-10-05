// Copyright 2026 Jerry David Chan, Konareef.ai
// SPDX-License-Identifier: Apache-2.0

// rv223_chain_test.go — task-10's dedicated fixtures for the R-V2.23
// three-step chain that makes a Type-C proof unforgeable
// (checkTypeCCommitments, snark.go's v2-gated block):
//
//	(a) SHA-256(manifest)               == h_manifest          (public input)
//	(b) ParseCommitFieldsRoot(manifest) == genesis_fields_root  (carried lane)
//	(c) genesis_fields_root             == z0[Z_FIELDS_ROOT]    (SNARK-proven)
//
// An implementation that checks only ONE link must fail this suite: link
// (a) alone lets a prover disclose a manifest with any fields_root it
// likes as long as genesis_fields_root/z0 agree with EACH OTHER, since
// nothing ties them back to the disclosed manifest's own commitment
// (that binding is link (b)); links (a)+(b) alone let a prover fold over
// a fields_root the SNARK never actually proved (that binding is link
// (c)). Only all three together close the chain end-to-end. None of the
// three fixtures below needs a salt or any memory contents — that is the
// property being pinned, and it is why a third party can verify a
// memory-bearing pod it cannot recompute.
//
// The fixtures reuse buildV2Z0FieldsRootBundle (snark_v2z0fieldsroot_test.go),
// which already builds a real canonical-v2 Type-C bundle from the
// checked-in parity artifact with link (a) bound
// (setManifestSlot=true inside buildV2FieldsRootBundle) and a full
// 736-byte z0. Each test here only chooses whether link (b) or link (c)
// agrees, mirroring (not duplicating the assertions of) the existing
// TestSnarkPhase_Z0FieldsRoot_* tests: those pin the individual tamper
// cases across many offsets; these three pin exactly the three named
// links the task-10 brief calls out, together, as one coherent chain.
package verify

import "testing"

// TestRV223_AllLinksAgree is the all-consistent fixture: (a), (b), and
// (c) all hold —
//
//	SHA-256(manifest) == h_manifest == [_commit].fields_root (via (b)'s
//	genesis_fields_root) == z0[Z_FIELDS_ROOT].
//
// A bundle in this state is exactly what an honest Type-C publisher
// produces, and MUST verify OK.
func TestRV223_AllLinksAgree(t *testing.T) {
	fr := v2FieldsRoot(t)
	bundle := buildV2Z0FieldsRootBundle(t, fr, fr[:], fr[:], nil)
	r := VerifyV2(bundle, WithAcceptingVerifierForTests())
	if !r.OK {
		t.Fatalf("all three R-V2.23 links agree but verification rejected it:\n%v", divergenceStrings(r))
	}
	if r.V2Verdict == nil || !r.V2Verdict.CommitmentsValid {
		t.Fatal("CommitmentsValid=false with all three R-V2.23 links agreeing")
	}
}

// TestRV223_FieldsRootLinkDisagrees breaks link (b) only: the manifest's
// own [_commit].fields_root (via ParseCommitFieldsRoot) disagrees with
// genesis_fields_root, while link (a) (h_manifest) and link (c)
// (genesis_fields_root == z0[Z_FIELDS_ROOT]) both still hold — the
// z0 lane is set to agree with the (wrong) genesis_fields_root, isolating
// the break to link (b) alone. A verifier that skips link (b) — trusting
// the SNARK-proven genesis_fields_root/z0 agreement without ever
// checking it against the DISCLOSED manifest's own commitment — would
// wrongly accept this: the prover could disclose any manifest it likes
// as long as the genesis lane and z0 agree with each other. This MUST be
// rejected.
func TestRV223_FieldsRootLinkDisagrees(t *testing.T) {
	fr := v2FieldsRoot(t) // committed in the manifest's [_commit].fields_root
	var genesis [32]byte
	for i := range genesis {
		genesis[i] = 0xFF // disagrees with fr, so link (b) breaks
	}
	bundle := buildV2Z0FieldsRootBundle(t, fr, genesis[:], genesis[:], nil)
	r := VerifyV2(bundle, WithAcceptingVerifierForTests())
	assertFieldsRootRejected(t, r)
}

// TestRV223_Z0LinkDisagrees breaks link (c) only: genesis_fields_root
// agrees with the manifest's own [_commit].fields_root (link (b) holds)
// and h_manifest is bound (link (a) holds), but the SNARK-proven z0 lane
// (z0[Z_FIELDS_ROOT]) disagrees with genesis_fields_root. A verifier that
// skips link (c) — trusting the carried genesis_fields_root without
// checking it against what the SNARK actually folded over in z0 — would
// wrongly accept a proof that never proved the disclosed fields_root at
// all. This MUST be rejected.
func TestRV223_Z0LinkDisagrees(t *testing.T) {
	fr := v2FieldsRoot(t)
	var z0Lane [32]byte
	for i := range z0Lane {
		z0Lane[i] = 0xAB // disagrees with fr/genesis_fields_root, so link (c) breaks
	}
	bundle := buildV2Z0FieldsRootBundle(t, fr, fr[:], z0Lane[:], nil)
	r := VerifyV2(bundle, WithAcceptingVerifierForTests())
	assertFieldsRootRejected(t, r)
}
