// Copyright 2026 Jerry David Chan, Konareef.ai
// SPDX-License-Identifier: Apache-2.0

// snark_typec_link_hash_test.go — regression tests for
// checkTypeCLinkHashes (MCP-K04 residual R2).
//
// Before the check, a Type-C link whose data no longer hashed to its
// stored hash gave no divergence: the v2 chain policy checks only
// prev_hash continuity, and assessCustodyV2 quietly showed not_verified
// for an unbound custody link. Each test builds an honest canonical-v2
// Type-C bundle with buildV2Z0FieldsRootBundle, changes one link, and
// checks the verdict.
package verify

import (
	"encoding/hex"
	"errors"
	"strings"
	"testing"
)

// verifyTypeCWithLinkMutation builds an honest Type-C bundle, applies
// mutate to its chain, and verifies it with the accepting SNARK stub.
//
// Inputs: t; mutate, which edits the decoded bundle (nil for none).
// Output: the verification result.
func verifyTypeCWithLinkMutation(t *testing.T, mutate func(b *BundleV2)) *ResultV2 {
	t.Helper()
	fr := v2FieldsRoot(t)
	bundle := buildV2Z0FieldsRootBundle(t, fr, fr[:], fr[:], mutate)
	return VerifyV2(bundle, WithAcceptingVerifierForTests())
}

// chainBrokenCount returns how many ErrChainBroken divergences r has.
func chainBrokenCount(r *ResultV2) int {
	n := 0
	for _, d := range r.Divergences {
		if errors.Is(d.Err, ErrChainBroken) {
			n++
		}
	}
	return n
}

// requireOnlyLinkHashFailure asserts that r failed on a link hash and on
// nothing else: OK and ChainPolicyValid are false, every other verdict
// bool still holds, and no custody-rule divergence was added (the data is
// not bound to the link, so the custody rules do not apply to it).
func requireOnlyLinkHashFailure(t *testing.T, r *ResultV2, wantBroken int) {
	t.Helper()
	if r.OK {
		t.Fatal("tampered Type-C link verified OK")
	}
	if got := chainBrokenCount(r); got != wantBroken {
		t.Fatalf("ErrChainBroken divergences = %d, want %d: %v", got, wantBroken, divergenceStrings(r))
	}
	if len(r.Divergences) != wantBroken {
		t.Fatalf("unexpected extra divergences: %v", divergenceStrings(r))
	}
	v := r.V2Verdict
	if v == nil || v.ChainPolicyValid {
		t.Fatal("ChainPolicyValid = true for a link whose hash does not recompute")
	}
	if !v.ProofValid || !v.DisclosureValid || !v.CommitmentsValid || !v.SignatureValid {
		t.Fatalf("a link-hash failure changed another verdict bool: %+v", *v)
	}
	if r.Custody.Assurance != BrokerAssuranceNotVerified {
		t.Fatalf("custody assurance = %s, want not_verified", r.Custody.Assurance)
	}
}

// TestTypeCLinkHash_HonestChainVerifies is the control: the honest bundle,
// whose custody link is the regenerated parity link, verifies with no
// chain divergence and shows the v3 record's no_marker level.
func TestTypeCLinkHash_HonestChainVerifies(t *testing.T) {
	r := verifyTypeCWithLinkMutation(t, nil)
	if !r.OK {
		t.Fatalf("honest Type-C bundle rejected: %v", divergenceStrings(r))
	}
	if r.Custody.Assurance != BrokerAssuranceNoMarker {
		t.Fatalf("custody assurance = %s, want no_marker", r.Custody.Assurance)
	}
}

// TestTypeCLinkHash_TamperedCustodyDataDiverges is the R2 case: the
// custody data changes after the chain was written and the stored hash
// does not. It must be a divergence, not a silent not_verified.
func TestTypeCLinkHash_TamperedCustodyDataDiverges(t *testing.T) {
	r := verifyTypeCWithLinkMutation(t, func(b *BundleV2) {
		tail := &b.Chain[len(b.Chain)-1]
		tail.Data = []byte(strings.Replace(string(tail.Data), "TOTAL_SATS: 0", "TOTAL_SATS: 1", 1))
	})
	requireOnlyLinkHashFailure(t, r, 1)
	if !strings.Contains(r.Divergences[0].Msg, "chain[0] (custody): recomputed hash") {
		t.Fatalf("divergence does not name the custody link: %q", r.Divergences[0].Msg)
	}
}

// TestTypeCLinkHash_TamperedToRuleFailingDataDiverges replaces the custody
// data with a blob that fails the custody rules, keeping the old hash. The
// failure is the link hash. The custody rules are not applied to data that
// is not bound to the link, so there is no ErrCustodyRecordInvalid.
func TestTypeCLinkHash_TamperedToRuleFailingDataDiverges(t *testing.T) {
	r := verifyTypeCWithLinkMutation(t, func(b *BundleV2) {
		b.Chain[len(b.Chain)-1].Data = []byte("{}")
	})
	requireOnlyLinkHashFailure(t, r, 1)
}

// TestTypeCLinkHash_StrippedDataIsRefused removes the custody data. The
// disclosure matrix refuses a Type-C link with no data, so the bundle fails
// with ErrDisclosureInconsistent. The link-hash check skips the link rather
// than report the same fault twice.
func TestTypeCLinkHash_StrippedDataIsRefused(t *testing.T) {
	r := verifyTypeCWithLinkMutation(t, func(b *BundleV2) {
		b.Chain[len(b.Chain)-1].Data = nil
	})
	if r.OK {
		t.Fatal("Type-C bundle with stripped link data verified OK")
	}
	if len(r.Divergences) != 1 || !errors.Is(r.Divergences[0].Err, ErrDisclosureInconsistent) {
		t.Fatalf("divergences = %v, want one ErrDisclosureInconsistent", divergenceStrings(r))
	}
	if r.Custody.Assurance != BrokerAssuranceNotVerified {
		t.Fatalf("custody assurance = %s, want not_verified", r.Custody.Assurance)
	}
}

// TestTypeCLinkHash_TamperedHashDiverges changes the stored hash and keeps
// the data.
func TestTypeCLinkHash_TamperedHashDiverges(t *testing.T) {
	r := verifyTypeCWithLinkMutation(t, func(b *BundleV2) {
		tail := &b.Chain[len(b.Chain)-1]
		h := append([]byte(nil), tail.Hash...)
		h[0] ^= 0xff
		tail.Hash = h
	})
	requireOnlyLinkHashFailure(t, r, 1)
}

// TestTypeCLinkHash_EarlierLinkIsChecked puts an honest structured_bundle
// link before the custody link, then changes only that earlier link's data.
// prev_hash continuity still holds, so only the recompute catches it.
func TestTypeCLinkHash_EarlierLinkIsChecked(t *testing.T) {
	// prependHonestLink makes a two-link honest chain:
	// structured_bundle (genesis) -> custody.
	prependHonestLink := func(b *BundleV2) {
		ts := "2026-06-09T00:00:00.000000Z"
		first := ComputeChainHash("", "structured bundle", ts)
		custody := b.Chain[len(b.Chain)-1]
		custody.PrevHash = first[:]
		h := ComputeChainHash(hex.EncodeToString(first[:]), string(custody.Data), custody.Timestamp)
		custody.Hash = h[:]
		b.Chain = []ChainLinkV2{
			{ProofType: "structured_bundle", Hash: first[:], Data: []byte("structured bundle"), Timestamp: ts},
			custody,
		}
	}

	honest := verifyTypeCWithLinkMutation(t, prependHonestLink)
	if !honest.OK {
		t.Fatalf("honest two-link Type-C chain rejected: %v", divergenceStrings(honest))
	}

	r := verifyTypeCWithLinkMutation(t, func(b *BundleV2) {
		prependHonestLink(b)
		b.Chain[0].Data = []byte("structured bundle, edited")
	})
	if r.OK || chainBrokenCount(r) != 1 || !strings.Contains(r.Divergences[0].Msg, "chain[0] (structured_bundle)") {
		t.Fatalf("tampered earlier link: OK = %v, divergences = %v", r.OK, divergenceStrings(r))
	}
	// The custody tail still recomputes, but the bundle failed, so no
	// broker claim is shown.
	if r.Custody.Assurance != BrokerAssuranceNotVerified {
		t.Fatalf("custody assurance = %s, want not_verified (bundle failed)", r.Custody.Assurance)
	}
}

// TestTypeCLinkHash_TypeDIsNotRecomputed pins that a Type-D bundle gets no
// link-hash divergence. A Type-D link carries no data, so its hash cannot
// be recomputed. (Since R2b the fixture's link hash is the chain hash of a
// Type-D custody blob, but the bundle does not carry that blob.) This test
// does not isolate the Disclosure == "C" gate:
// the empty-data skip alone would also pass it.
func TestTypeCLinkHash_TypeDIsNotRecomputed(t *testing.T) {
	r := VerifyV2(loadParityEnvelopeStripped(t, "parity-v2-typed.cbor"), WithAcceptingVerifierForTests())
	if got := chainBrokenCount(r); got != 0 {
		t.Fatalf("Type-D bundle got %d ErrChainBroken divergences: %v", got, divergenceStrings(r))
	}
}

// TestTypeCLinkHash_AdjacencyAnchorStillRecomputes pins that the recompute
// runs whatever mode the bundle declares. A Type-C bundle that declares
// adjacency_anchor is refused for the mode itself (R2b), and a tampered
// link in it must still add its own link-hash divergence, so a declared
// mode cannot switch the recompute off.
func TestTypeCLinkHash_AdjacencyAnchorStillRecomputes(t *testing.T) {
	r := verifyTypeCWithLinkMutation(t, func(b *BundleV2) {
		b.ChainPolicyMode = "adjacency_anchor"
		tail := &b.Chain[len(b.Chain)-1]
		tail.Data = []byte(strings.Replace(string(tail.Data), "TOTAL_SATS: 0", "TOTAL_SATS: 1", 1))
	})
	if r.OK || chainBrokenCount(r) != 2 {
		t.Fatalf("want a mode refusal and a link-hash divergence, got OK=%v %v", r.OK, divergenceStrings(r))
	}
	if !strings.Contains(strings.Join(divergenceStrings(r), "|"), "chain[0] (custody): recomputed hash") {
		t.Fatalf("link-hash divergence missing: %v", divergenceStrings(r))
	}
}

// TestTypeCLinkHash_OddWidthPrevHashDiverges gives the genesis custody link
// a prev_hash that is not 32 bytes. ComputeChainHash ignores such a value,
// so the link would otherwise still recompute.
func TestTypeCLinkHash_OddWidthPrevHashDiverges(t *testing.T) {
	r := verifyTypeCWithLinkMutation(t, func(b *BundleV2) {
		b.Chain[0].PrevHash = []byte{0x01, 0x02, 0x03}
	})
	requireOnlyLinkHashFailure(t, r, 1)
	if !strings.Contains(r.Divergences[0].Msg, "prev_hash length 3") {
		t.Fatalf("divergence does not name the prev_hash width: %q", r.Divergences[0].Msg)
	}
}
