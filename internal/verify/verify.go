// Copyright 2026 Jerry David Chan, Konareef.ai
// SPDX-License-Identifier: Apache-2.0

// verify.go — the offline bundle verifier (P0.2's heart).
//
// Verify runs the four cryptographic re-checks the assessment §P0.2
// mandates, in order, and collects human-readable divergence
// messages for any that fail. The check set is closed (no
// extension points) by design — the bundle's wire contract is the
// only thing that needs to stay stable across implementations.
//
//   1. Chain-link verification. For each commitment, recompute
//      SHA-256(prev_hash || data || timestamp) and compare against
//      the stored hash. A single failure here invalidates the whole
//      chain — but the verifier still walks every link so a CLI
//      caller can see every break, not just the first.
//
//   2. Snapshot Merkle root rebuild. If the chain contains an
//      `openbrain_snapshot` commitment, rebuild a Merkle tree from
//      snapshot_leaves[].content_hash and compare to the stored
//      `openbrain_snapshot_root`.
//
//   3. Access membership. Every memory access whose `source` is
//      `"snapshot"` must have its content_hash present in the
//      snapshot leaves. Captures don't go through this check —
//      they're recorded against the capture root, not the snapshot.
//
//   4. Access-log hash. ComputeAccessLogHash(every access's content
//      hash) must equal the custody commitment's recorded
//      `openbrain_access_log_hash`.

package verify

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"

	"github.com/digitsu/konareef/internal/identity"
)

// Result is the verifier's structured output. OK is true iff every
// applicable check passed; ChainLength is the number of commitments
// walked; Divergences enumerates the specific failures (one human-
// readable line per check that diverged). The set of divergences is
// always exhaustive — the verifier never short-circuits on the
// first failure.
//
// AttestationStatus classifies how the bundle's publisher attestation
// envelope was treated (WI-P0-007). A green OK from `legacy_unsigned`
// is fundamentally different from a green OK from `attested`; a CLI
// can surface the distinction so users don't read every pass as
// cryptographic proof:
//
//   - "legacy_unsigned" — no attestation fields were present; this
//     is a pre-P0.3 bundle and the publisher signature was not
//     checked. Default mode passes; strict mode rejects.
//   - "attested"        — all six attestation fields were present
//     and the signature + hash checks ran successfully.
//   - "incomplete"      — some attestation fields were present but
//     not all. Both default and strict mode reject this; it is
//     neither legacy nor fully verifiable.
type Result struct {
	OK                bool
	ChainLength       int
	Divergences       []string
	AttestationStatus string
}

// Verify runs the full re-check pipeline on b and returns the
// aggregated result. The bundle is read but not mutated. Verify
// performs no network I/O and depends on no DB.
//
// Pipeline ordering matters: structural checks run first so the
// cryptographic checks below them never have to ask "is the field
// I want even here?" — a malformed or topologically broken bundle
// is rejected at the structure phase. This is the WI-P0-001
// fail-closed guarantee: a verifier that returns OK because the
// crypto checks had no target is a verifier that lies, so the
// crypto phase only runs once structure is sound.
//
// Default mode is back-compat with legacy v0 (unsigned) bundles —
// when the publisher-attestation envelope is absent, that check is
// skipped. Use VerifyStrict for the strict mode that requires
// attestation.
func Verify(b *Bundle) *Result {
	return verifyWith(b, false)
}

// VerifyStrict is Verify with `--strict` semantics (WI-P0-002):
// the publisher attestation envelope MUST be present and every
// signed field MUST be populated. A legacy unsigned bundle is
// rejected.
func VerifyStrict(b *Bundle) *Result {
	return verifyWith(b, true)
}

func verifyWith(b *Bundle, strict bool) *Result {
	r := &Result{OK: true, ChainLength: len(b.Chain)}

	// Phase 0 — structure.
	checkStructure(b, r)
	if !r.OK {
		return r
	}

	checkChainHashes(b, r)
	checkSnapshotMerkleRoot(b, r)
	checkAccessMembership(b, r)
	checkAccessLogHash(b, r)
	checkPublisherAttestation(b, r, strict)

	return r
}

// ── Phase 0 — structural fail-closed (WI-P0-001) ─────────────────
//
// The pre-WI verifier inherited from P0.2 short-circuited on any
// missing optional-looking field and reported OK=true. That's the
// classic "verifier that lies" bug: a bundle whose chain has been
// stripped of its custody commitment still verified, because the
// access-log-hash check returned early when the custody link was
// absent.
//
// checkStructure rejects every shape that a verifiable bundle MUST
// NOT have. It is intentionally noisy — each divergence names the
// offending position — so a caller can fix the producer.
func checkStructure(b *Bundle, r *Result) {
	if len(b.Chain) == 0 {
		r.diverge("chain is empty; a verifiable bundle requires structured_bundle → openbrain_snapshot → custody")
		return
	}

	// Exactly-one-of-each for the three required commitment types.
	// Other types (capture_commitment) may appear at most once
	// between the snapshot and custody; counted but not required.
	counts := map[string]int{}
	for _, link := range b.Chain {
		counts[link.ProofType]++
	}
	for _, required := range []string{"structured_bundle", "openbrain_snapshot", "custody"} {
		switch counts[required] {
		case 0:
			r.diverge("chain is missing a %s commitment", required)
		case 1:
			// good
		default:
			r.diverge("chain has %d %s commitments; exactly one is required", counts[required], required)
		}
	}

	// Genesis MUST be a structured_bundle with no prev_hash.
	if b.Chain[0].ProofType != "structured_bundle" {
		r.diverge("chain[0] proof_type = %q; must be structured_bundle (the genesis link)", b.Chain[0].ProofType)
	}
	if b.Chain[0].PrevHash != nil {
		r.diverge("chain[0] (%s): genesis must have prev_hash = null, got %q",
			b.Chain[0].ProofType, *b.Chain[0].PrevHash)
	}

	// Tail MUST be the custody commitment.
	tail := b.Chain[len(b.Chain)-1]
	if tail.ProofType != "custody" {
		r.diverge("chain tail proof_type = %q; must be custody", tail.ProofType)
	}

	// Linkage: each non-genesis link's prev_hash MUST equal the
	// previous link's hash. Walks in array order — the chain is
	// stored oldest-first by `ReefCore.Proofs.Bundle.pack/2`.
	for i := 1; i < len(b.Chain); i++ {
		link := b.Chain[i]
		if link.PrevHash == nil {
			r.diverge("chain[%d] (%s): prev_hash is null; only the genesis link may have a null prev_hash",
				i, link.ProofType)
			continue
		}
		if *link.PrevHash != b.Chain[i-1].Hash {
			r.diverge(
				"chain[%d] (%s): prev_hash %s does not match chain[%d].hash %s",
				i, link.ProofType, *link.PrevHash, i-1, b.Chain[i-1].Hash,
			)
		}
	}

	// Required body fields per commitment type. These were
	// previously nullable-skipped by the crypto-phase checks.
	if snap := findLink(b, "openbrain_snapshot"); snap != nil && snap.OpenbrainSnapshotRoot == nil {
		r.diverge("openbrain_snapshot commitment: openbrain_snapshot_root is null; required for Merkle verification")
	}
	if custody := findLink(b, "custody"); custody != nil && custody.OpenbrainAccessLogHash == nil {
		r.diverge("custody commitment: openbrain_access_log_hash is null; required for access-log verification")
	}

	// Snapshot-source accesses with no leaf set: nothing can ever
	// satisfy the membership check, so the bundle is internally
	// contradictory.
	if len(b.SnapshotLeaves) == 0 {
		for i, acc := range b.Accesses {
			if acc.Source == "snapshot" {
				r.diverge("accesses[%d]: snapshot-source access but snapshot_leaves is empty", i)
			}
		}
	}
}

// ── Step 1 — chain hashes ─────────────────────────────────────────

func checkChainHashes(b *Bundle, r *Result) {
	for i, link := range b.Chain {
		prevHex := ""
		if link.PrevHash != nil {
			prevHex = *link.PrevHash
		}
		got := ComputeChainHash(prevHex, link.Data, link.Timestamp)

		want, ok := decodeHash32(link.Hash)
		if !ok {
			r.diverge("chain[%d] (%s): hash field is not a 32-byte hex string", i, link.ProofType)
			continue
		}
		if got != want {
			r.diverge(
				"chain[%d] (%s): recomputed hash %s != stored %s",
				i, link.ProofType,
				hex.EncodeToString(got[:]), hex.EncodeToString(want[:]),
			)
		}
	}
}

// ── Step 2 — snapshot Merkle root ─────────────────────────────────

func checkSnapshotMerkleRoot(b *Bundle, r *Result) {
	link := findLink(b, "openbrain_snapshot")
	if link == nil || link.OpenbrainSnapshotRoot == nil {
		return
	}

	leaves := make([][]byte, 0, len(b.SnapshotLeaves))
	for _, lf := range b.SnapshotLeaves {
		bs, err := hex.DecodeString(lf.ContentHash)
		if err != nil || len(bs) != 32 {
			r.diverge("snapshot_leaves[%d]: content_hash is not a 32-byte hex string", lf.LeafIndex)
			return
		}
		leaves = append(leaves, bs)
	}

	got := BuildMerkleRoot(leaves)
	want, ok := decodeHash32(*link.OpenbrainSnapshotRoot)
	if !ok {
		r.diverge("openbrain_snapshot.openbrain_snapshot_root: not a 32-byte hex string")
		return
	}
	if got != want {
		r.diverge(
			"snapshot Merkle root: rebuilt %s != chain claim %s",
			hex.EncodeToString(got[:]), hex.EncodeToString(want[:]),
		)
	}
}

// ── Step 3 — access membership ────────────────────────────────────

func checkAccessMembership(b *Bundle, r *Result) {
	if len(b.SnapshotLeaves) == 0 {
		return
	}
	leafSet := make(map[string]bool, len(b.SnapshotLeaves))
	for _, lf := range b.SnapshotLeaves {
		leafSet[lf.ContentHash] = true
	}
	for i, acc := range b.Accesses {
		if acc.Source != "snapshot" {
			continue
		}
		if !leafSet[acc.ContentHash] {
			r.diverge(
				"accesses[%d]: snapshot-source content_hash %s is not in the snapshot leaves",
				i, acc.ContentHash,
			)
		}
	}
}

// ── Step 4 — access-log hash ──────────────────────────────────────

func checkAccessLogHash(b *Bundle, r *Result) {
	link := findLink(b, "custody")
	if link == nil || link.OpenbrainAccessLogHash == nil {
		return
	}

	hashes := make([][]byte, 0, len(b.Accesses))
	for i, acc := range b.Accesses {
		bs, err := hex.DecodeString(acc.ContentHash)
		if err != nil || len(bs) != 32 {
			r.diverge("accesses[%d]: content_hash is not a 32-byte hex string", i)
			return
		}
		hashes = append(hashes, bs)
	}

	got := ComputeAccessLogHash(hashes)
	want, ok := decodeHash32(*link.OpenbrainAccessLogHash)
	if !ok {
		r.diverge("custody.openbrain_access_log_hash: not a 32-byte hex string")
		return
	}
	if got != want {
		r.diverge(
			"access log hash: recomputed %s != custody claim %s",
			hex.EncodeToString(got[:]), hex.EncodeToString(want[:]),
		)
	}
}

// ── Phase 5 — publisher attestation (WI-P0-002) ──────────────────
//
// Re-checks the publisher's signature on the manifest entirely
// offline: every byte needed (pod_hash, signature, pubkey, manifest)
// rides on the bundle envelope. Two cryptographic invariants:
//
//  1. SHA-256(manifest) == pod_hash. Confirms the bytes the
//     bundle carries are the bytes that produced the claimed hash.
//  2. publisher_signature is a valid secp256k1 DER ECDSA signature
//     of the manifest bytes under publisher_pubkey.
//
// In default (non-strict) mode, a bundle without ANY attestation
// fields is a legacy v0 bundle and the check passes silently. A
// bundle with SOME but not all signed fields is checked as far as
// possible — for example, pod_hash + signature + pubkey alone
// still let the verifier confirm "this hash was signed by this
// key", even though it can't recompute the hash from the manifest.
//
// In strict mode, every signed field MUST be present; partial
// attestations are rejected.
func checkPublisherAttestation(b *Bundle, r *Result, strict bool) {
	present := attestationFieldsPresent(b)

	// Classify the bundle. Strict mode tightens "legacy_unsigned"
	// into a divergence; default mode tolerates it for back-compat
	// with v0 bundles.
	switch {
	case !present.any:
		r.AttestationStatus = "legacy_unsigned"
		if strict {
			r.diverge("publisher attestation envelope is absent; --strict requires it")
		}
		return

	case !present.all:
		// WI-P0-007: partial attestation is neither legacy nor
		// fully verifiable. Reject in BOTH modes, name the missing
		// fields so the producer can fix the bundle.
		r.AttestationStatus = "incomplete"
		r.diverge(
			"publisher attestation is incomplete (missing: %s); a bundle that supplies any attestation field must supply all six",
			present.missingNames(b),
		)
		return

	default:
		r.AttestationStatus = "attested"
	}

	// Hash check: only possible when both manifest + pod_hash are
	// present. In default mode, a missing manifest just skips this
	// step (the signature check below still runs against pod_hash).
	if b.Manifest != nil && b.PodHash != nil {
		manifestBytes, err := base64.StdEncoding.DecodeString(*b.Manifest)
		if err != nil {
			r.diverge("publisher manifest: not valid base64: %v", err)
			return
		}
		got := sha256.Sum256(manifestBytes)
		wantHex := *b.PodHash
		gotHex := hex.EncodeToString(got[:])
		if gotHex != wantHex {
			r.diverge(
				"publisher manifest: SHA-256(manifest) = %s != pod_hash = %s",
				gotHex, wantHex,
			)
			return
		}
	}

	// Signature check: needs pod_hash, signature, pubkey. The
	// digest signed is SHA-256(manifest) — which is pod_hash. We
	// don't re-derive it from manifest here; we just verify the
	// signature over the bytes the manifest produces, by passing
	// the manifest to identity.Verify (which itself takes SHA-256
	// internally). When manifest is absent in default mode, fall
	// back to verifying the signature over the raw pod_hash bytes,
	// which is what the publisher signed.
	if b.PodHash == nil || b.PublisherSignature == nil || b.PublisherPubkey == nil {
		return
	}
	sig, err := base64.StdEncoding.DecodeString(*b.PublisherSignature)
	if err != nil {
		r.diverge("publisher_signature: not valid base64: %v", err)
		return
	}
	pubBytes, err := base64.StdEncoding.DecodeString(*b.PublisherPubkey)
	if err != nil {
		r.diverge("publisher_pubkey: not valid base64: %v", err)
		return
	}
	pubKeyHex := hex.EncodeToString(pubBytes)

	// The signature check needs the pre-image (manifest bytes),
	// because identity.Sign / identity.Verify take SHA-256
	// internally. Without manifest we cannot recompute the same
	// digest the publisher signed — default mode skips this step
	// silently (the hash check above also short-circuited), and
	// strict mode already rejected upstream via the all-present
	// gate. Partial-attestation handling is intentional: a buyer
	// without the manifest at least gets the structural chain
	// rechecked; a verifier mistakenly reporting OK in this
	// degraded case would be the wrong call.
	if b.Manifest == nil {
		return
	}
	manifestBytes, err := base64.StdEncoding.DecodeString(*b.Manifest)
	if err != nil {
		r.diverge("publisher manifest: not valid base64: %v", err)
		return
	}
	ok, err := identity.Verify(pubKeyHex, manifestBytes, sig)
	if err != nil {
		r.diverge("publisher signature: %v", err)
		return
	}
	if !ok {
		r.diverge("publisher signature did not verify under publisher_pubkey")
	}
}

type attestationPresence struct {
	any bool
	all bool
}

func attestationFieldsPresent(b *Bundle) attestationPresence {
	var setCount int
	for _, f := range attestationFields(b) {
		if f.value != nil && *f.value != "" {
			setCount++
		}
	}
	return attestationPresence{
		any: setCount > 0,
		all: setCount == len(attestationFields(b)),
	}
}

// missingNames returns a human-readable comma-separated list of
// attestation field names that are absent on b. Used in the
// "incomplete attestation" divergence so the producer sees which
// fields to add.
func (p attestationPresence) missingNames(b *Bundle) string {
	var names []string
	for _, f := range attestationFields(b) {
		if f.value == nil || *f.value == "" {
			names = append(names, f.name)
		}
	}
	if len(names) == 0 {
		return "(none)"
	}
	out := names[0]
	for _, n := range names[1:] {
		out += ", " + n
	}
	return out
}

type attestationField struct {
	name  string
	value *string
}

func attestationFields(b *Bundle) []attestationField {
	return []attestationField{
		{"pod_hash", b.PodHash},
		{"pod_version", b.PodVersion},
		{"publisher_id", b.PublisherID},
		{"publisher_signature", b.PublisherSignature},
		{"publisher_pubkey", b.PublisherPubkey},
		{"manifest", b.Manifest},
	}
}

// ── helpers ──────────────────────────────────────────────────────

// diverge records a divergence and clears OK. The format helpers
// keep call sites readable.
func (r *Result) diverge(format string, args ...any) {
	r.OK = false
	r.Divergences = append(r.Divergences, fmt.Sprintf(format, args...))
}

func findLink(b *Bundle, proofType string) *ChainLink {
	for i, link := range b.Chain {
		if link.ProofType == proofType {
			return &b.Chain[i]
		}
	}
	return nil
}

func decodeHash32(hex32 string) ([32]byte, bool) {
	bs, err := hex.DecodeString(hex32)
	if err != nil || len(bs) != 32 {
		return [32]byte{}, false
	}
	var out [32]byte
	copy(out[:], bs)
	return out, true
}
