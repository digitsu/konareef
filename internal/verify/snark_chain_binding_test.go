// Copyright 2026 Jerry David Chan, Konareef.ai
// SPDX-License-Identifier: Apache-2.0

// snark_chain_binding_test.go — regression tests for R2b (reef-core#74).
//
// The v2 chain policy used to follow the mode the bundle declared, the
// Type-D adjacency_anchor branch did not check adjacency, and the
// bsv_txids anchors were not read. These tests pin:
//
//   - the disclosure tag selects the chain rule, and a declared mode
//     that disagrees is refused (checkChainPolicy);
//   - Type D gets the PRD 3 § 7.2 adjacency rule;
//   - a link txid that disagrees with its bsv_txids entry, or a
//     bsv_txids key with no chain link, is refused (checkChainAnchors);
//   - a chain that starts mid-chain is valid and reported as truncated
//     (owner decision D2);
//   - a fully re-hashed chain without a chain-head anchor is still not
//     detected; the anchor tests in anchor_test.go cover it (D1,
//     reef-core#76).
package verify

import (
	"encoding/hex"
	"errors"
	"strings"
	"testing"

	"github.com/fxamacker/cbor/v2"
)

// verifyTypeDParityWithMutation loads the Type-D parity fixture without
// its attestation envelope, applies mutate, and verifies it with the
// accepting SNARK stub. The fixture's signature is synthetic, so the
// whole bundle never verifies; callers check the chain-policy verdict.
//
// Inputs: t; mutate, which edits the decoded bundle (nil for none).
// Output: the verification result.
func verifyTypeDParityWithMutation(t *testing.T, mutate func(b *BundleV2)) *ResultV2 {
	t.Helper()
	b, err := decodeBundleV2(loadParityEnvelopeStripped(t, "parity-v2-typed.cbor"))
	if err != nil {
		t.Fatalf("decode Type-D parity: %v", err)
	}
	if mutate != nil {
		mutate(b)
	}
	enc, err := cbor.CoreDetEncOptions().EncMode()
	if err != nil {
		t.Fatalf("enc mode: %v", err)
	}
	out, err := enc.Marshal(b)
	if err != nil {
		t.Fatalf("re-encode: %v", err)
	}
	return VerifyV2(out, WithAcceptingVerifierForTests())
}

// requireOnlyChainPolicyFailure asserts that r failed on the chain policy
// and on nothing else, with exactly one ErrChainBroken divergence whose
// message contains want.
func requireOnlyChainPolicyFailure(t *testing.T, r *ResultV2, want string) {
	t.Helper()
	if r.OK {
		t.Fatal("bundle verified OK; want a chain-policy refusal")
	}
	if len(r.Divergences) != 1 || !errors.Is(r.Divergences[0].Err, ErrChainBroken) {
		t.Fatalf("want exactly one ErrChainBroken divergence, got %v", divergenceStrings(r))
	}
	if !strings.Contains(r.Divergences[0].Msg, want) {
		t.Fatalf("divergence %q does not contain %q", r.Divergences[0].Msg, want)
	}
	v := r.V2Verdict
	if v == nil || v.ChainPolicyValid {
		t.Fatal("ChainPolicyValid = true on a chain-policy refusal")
	}
	if !v.ProofValid || !v.DisclosureValid || !v.CommitmentsValid || !v.SignatureValid {
		t.Fatalf("a chain-policy refusal changed another verdict bool: %+v", *v)
	}
}

// TestR2b_GenuineTypeCBundlePasses is the Type-C control: the honest
// bundle verifies under full_hash_chain, with no declared mode and with
// the matching declared mode.
func TestR2b_GenuineTypeCBundlePasses(t *testing.T) {
	for _, declared := range []string{"", "full_hash_chain"} {
		r := verifyTypeCWithLinkMutation(t, func(b *BundleV2) { b.ChainPolicyMode = declared })
		if !r.OK {
			t.Fatalf("declared=%q: honest Type-C bundle rejected: %v", declared, divergenceStrings(r))
		}
		if r.V2Verdict.ChainPolicyMode != "full_hash_chain" {
			t.Fatalf("declared=%q: chain mode = %q, want full_hash_chain", declared, r.V2Verdict.ChainPolicyMode)
		}
	}
}

// TestR2b_GenuineTypeDChainPasses is the Type-D control: the parity
// fixture's chain passes under adjacency_anchor, the mode PRD 3 § 7.2
// requires, with no declared mode and with the matching declared mode.
func TestR2b_GenuineTypeDChainPasses(t *testing.T) {
	for _, declared := range []string{"", "adjacency_anchor"} {
		r := verifyTypeDParityWithMutation(t, func(b *BundleV2) { b.ChainPolicyMode = declared })
		if !r.V2Verdict.ChainPolicyValid || chainBrokenCount(r) != 0 {
			t.Fatalf("declared=%q: Type-D chain refused: %v", declared, divergenceStrings(r))
		}
		if r.V2Verdict.ChainPolicyMode != "adjacency_anchor" {
			t.Fatalf("declared=%q: chain mode = %q, want adjacency_anchor", declared, r.V2Verdict.ChainPolicyMode)
		}
	}
}

// TestR2b_TypeCDowngradeIsRefused declares adjacency_anchor on an honest
// Type-C bundle. PRD 3 § 7.3 requires the full hash chain for Type C, so
// the weaker declared mode is refused.
func TestR2b_TypeCDowngradeIsRefused(t *testing.T) {
	r := verifyTypeCWithLinkMutation(t, func(b *BundleV2) { b.ChainPolicyMode = "adjacency_anchor" })
	requireOnlyChainPolicyFailure(t, r, `requires "full_hash_chain"`)
	if r.V2Verdict.ChainPolicyMode != "full_hash_chain" {
		t.Fatalf("reported chain mode = %q, want the required full_hash_chain", r.V2Verdict.ChainPolicyMode)
	}
}

// TestR2b_TypeDFullHashChainClaimIsRefused declares full_hash_chain on a
// Type-D bundle. Type D carries no link data, so it cannot show a full
// hash chain, and the claim is refused.
func TestR2b_TypeDFullHashChainClaimIsRefused(t *testing.T) {
	r := verifyTypeDParityWithMutation(t, func(b *BundleV2) { b.ChainPolicyMode = "full_hash_chain" })
	if r.V2Verdict.ChainPolicyValid || chainBrokenCount(r) != 1 {
		t.Fatalf("Type-D full_hash_chain claim not refused: %v", divergenceStrings(r))
	}
	if !strings.Contains(strings.Join(divergenceStrings(r), "|"), `requires "adjacency_anchor"`) {
		t.Fatalf("divergence does not name the required mode: %v", divergenceStrings(r))
	}
	if r.V2Verdict.ChainPolicyMode != "adjacency_anchor" {
		t.Fatalf("reported chain mode = %q, want the required adjacency_anchor", r.V2Verdict.ChainPolicyMode)
	}
}

// TestR2b_UnknownDisclosureChainPolicyFails pins that a bundle with an
// unknown disclosure tag never shows a passed chain policy, whatever mode
// it declares. The disclosure matrix reports the fault itself.
func TestR2b_UnknownDisclosureChainPolicyFails(t *testing.T) {
	for _, declared := range []string{"", "full_hash_chain", "adjacency_anchor"} {
		r := verifyTypeCWithLinkMutation(t, func(b *BundleV2) {
			b.Disclosure = "X"
			b.ChainPolicyMode = declared
		})
		if r.OK || r.V2Verdict.ChainPolicyValid {
			t.Fatalf("declared=%q: unknown disclosure passed the chain policy: OK=%v %v",
				declared, r.OK, divergenceStrings(r))
		}
	}
}

// TestR2b_UnknownModeIsRefused declares a mode that PRD 3 does not name.
func TestR2b_UnknownModeIsRefused(t *testing.T) {
	r := verifyTypeCWithLinkMutation(t, func(b *BundleV2) { b.ChainPolicyMode = "none" })
	requireOnlyChainPolicyFailure(t, r, `chain_policy_mode="none"`)
}

// TestR2b_TypeDBrokenAdjacencyIsRefused gives a Type-D bundle, declaring
// adjacency_anchor, a two-link chain whose custody link does not point at
// its predecessor. Before R2b the adjacency_anchor branch did not check
// adjacency, so this passed. PRD 3 § 7.2 rule 1 refuses it.
func TestR2b_TypeDBrokenAdjacencyIsRefused(t *testing.T) {
	prepend := func(b *BundleV2, linked bool) {
		first := ChainLinkV2{
			ProofType: "structured_bundle",
			Hash:      make([]byte, 32),
			Scrubbed:  true,
			Timestamp: "2026-06-09T00:00:00.000000Z",
		}
		first.Hash[0] = 0x51
		custody := b.Chain[len(b.Chain)-1]
		custody.PrevHash = make([]byte, 32)
		if linked {
			copy(custody.PrevHash, first.Hash)
		}
		b.ChainPolicyMode = "adjacency_anchor"
		b.Chain = []ChainLinkV2{first, custody}
	}

	honest := verifyTypeDParityWithMutation(t, func(b *BundleV2) { prepend(b, true) })
	if !honest.V2Verdict.ChainPolicyValid {
		t.Fatalf("linked two-link Type-D chain refused: %v", divergenceStrings(honest))
	}

	r := verifyTypeDParityWithMutation(t, func(b *BundleV2) { prepend(b, false) })
	if r.V2Verdict.ChainPolicyValid || chainBrokenCount(r) != 1 {
		t.Fatalf("broken Type-D adjacency not refused: %v", divergenceStrings(r))
	}
	if !strings.Contains(strings.Join(divergenceStrings(r), "|"), "chain[1].prev_hash != chain[0].hash") {
		t.Fatalf("divergence does not name the broken link: %v", divergenceStrings(r))
	}
}

// TestR2b_TxidCrossReference covers PRD 3 § 8.4. A link txid that matches
// its bsv_txids entry passes. A mismatched txid, or a bsv_txids key that
// names no chain link, is refused.
func TestR2b_TxidCrossReference(t *testing.T) {
	txA := strings.Repeat("a", 64)
	txB := strings.Repeat("b", 64)
	anchor := func(linkTxid, mapTxid string, orphan bool) func(b *BundleV2) {
		return func(b *BundleV2) {
			tail := &b.Chain[len(b.Chain)-1]
			tail.Txid = linkTxid
			b.BsvTxids = map[string]string{hex.EncodeToString(tail.Hash): mapTxid}
			if orphan {
				b.BsvTxids[strings.Repeat("0", 64)] = txA
			}
		}
	}

	if r := verifyTypeCWithLinkMutation(t, anchor(txA, txA, false)); !r.OK {
		t.Fatalf("matching txid rejected: %v", divergenceStrings(r))
	}
	// A bsv_txids entry with no link txid is allowed: the link field is optional.
	if r := verifyTypeCWithLinkMutation(t, anchor("", txA, false)); !r.OK {
		t.Fatalf("bsv_txids entry without link txid rejected: %v", divergenceStrings(r))
	}

	wrong := verifyTypeCWithLinkMutation(t, anchor(txA, txB, false))
	requireOnlyChainPolicyFailure(t, wrong, "txid")

	orphan := verifyTypeCWithLinkMutation(t, anchor(txA, txA, true))
	requireOnlyChainPolicyFailure(t, orphan, "references no chain link")

	// PRD 3 § 8.4 keys are lowercase hex; an uppercase key matches no link.
	upper := verifyTypeCWithLinkMutation(t, func(b *BundleV2) {
		tail := &b.Chain[len(b.Chain)-1]
		b.BsvTxids = map[string]string{strings.ToUpper(hex.EncodeToString(tail.Hash)): txA}
	})
	requireOnlyChainPolicyFailure(t, upper, "lowercase hex")
}

// TestR2b_TxidCheckedOnEveryLinkWithARepeatedHash gives two Type-D links
// the same hash. The bsv_txids entry must be checked against both, not
// only the last one.
func TestR2b_TxidCheckedOnEveryLinkWithARepeatedHash(t *testing.T) {
	txA := strings.Repeat("a", 64)
	txB := strings.Repeat("b", 64)
	r := verifyTypeDParityWithMutation(t, func(b *BundleV2) {
		custody := b.Chain[len(b.Chain)-1]
		first := custody
		first.PrevHash = nil
		first.Txid = txB
		custody.PrevHash = append([]byte(nil), first.Hash...)
		custody.Txid = txA
		b.Chain = []ChainLinkV2{first, custody}
		b.BsvTxids = map[string]string{hex.EncodeToString(custody.Hash): txA}
	})
	if r.V2Verdict.ChainPolicyValid {
		t.Fatalf("earlier link's mismatched txid not checked: %v", divergenceStrings(r))
	}
	if !strings.Contains(strings.Join(divergenceStrings(r), "|"), "txid") {
		t.Fatalf("no txid divergence: %v", divergenceStrings(r))
	}
}

// The fully re-hashed chain is covered by the chain-head anchor tests
// (anchor_test.go, reef-core#76): TestAnchor_AbsentKeepsResidual (no
// anchor: still verifies, head not anchored),
// TestAnchor_RehashedChainWithOriginalAnchorRefused and
// TestAnchor_RehashedChainWithForgedAnchorNotAnchored.

// TestR2b_TruncatedChainIsReported covers the PRD 3 § 8.1 amendment (R2b
// D2): a chain whose first link has a prev_hash starts mid-chain. It is
// valid, and the verdict reports it as truncated. A chain that starts at
// its genesis link is not truncated.
func TestR2b_TruncatedChainIsReported(t *testing.T) {
	genesis := verifyTypeCWithLinkMutation(t, nil)
	if !genesis.OK || genesis.V2Verdict.ChainTruncated || genesis.V2Verdict.ChainHeadAnchored {
		t.Fatalf("genesis chain: OK=%v truncated=%v anchored=%v %v", genesis.OK,
			genesis.V2Verdict.ChainTruncated, genesis.V2Verdict.ChainHeadAnchored, divergenceStrings(genesis))
	}

	// Type C: the custody link points at a predecessor the bundle does not
	// carry, and its hash is recomputed over that prev_hash.
	missing := make([]byte, 32)
	missing[0] = 0x77
	typeC := verifyTypeCWithLinkMutation(t, func(b *BundleV2) {
		tail := &b.Chain[len(b.Chain)-1]
		tail.PrevHash = missing
		h := ComputeChainHash(hex.EncodeToString(missing), string(tail.Data), tail.Timestamp)
		tail.Hash = h[:]
	})
	if !typeC.OK || !typeC.V2Verdict.ChainTruncated {
		t.Fatalf("truncated Type-C chain: OK=%v truncated=%v %v", typeC.OK, typeC.V2Verdict.ChainTruncated,
			divergenceStrings(typeC))
	}

	// Type D: same shape, adjacency rule.
	typeD := verifyTypeDParityWithMutation(t, func(b *BundleV2) { b.Chain[0].PrevHash = missing })
	if !typeD.V2Verdict.ChainPolicyValid || !typeD.V2Verdict.ChainTruncated || chainBrokenCount(typeD) != 0 {
		t.Fatalf("truncated Type-D chain: valid=%v truncated=%v %v", typeD.V2Verdict.ChainPolicyValid,
			typeD.V2Verdict.ChainTruncated, divergenceStrings(typeD))
	}
}
