package verify

import (
	"encoding/hex"
	"strings"
	"testing"
)

// buildValidBundle constructs a fully self-consistent bundle: chain
// hashes link correctly, snapshot_leaves rebuild to the chain's
// openbrain_snapshot_root, snapshot-source accesses are members of
// the leaf set, and ComputeAccessLogHash(accesses) matches the
// custody proof's openbrain_access_log_hash. Verify on this bundle
// MUST return OK with no divergences; every other Verify test
// tampers one field and checks for the right complaint.
func buildValidBundle() *Bundle {
	leaves := [][]byte{
		bytesOfLen(32, 0x10),
		bytesOfLen(32, 0x20),
		bytesOfLen(32, 0x30),
	}
	snapshotRoot := BuildMerkleRoot(leaves)
	snapshotRootHex := hex.EncodeToString(snapshotRoot[:])

	accesses := []Access{
		{TaskID: "t1", ThoughtID: 1, ContentHash: hex.EncodeToString(leaves[0]),
			Source: "snapshot", AccessedAt: "2026-05-23T15:00:00.000000Z"},
		{TaskID: "t1", ThoughtID: 2, ContentHash: hex.EncodeToString(leaves[1]),
			Source: "snapshot", AccessedAt: "2026-05-23T15:01:00.000000Z"},
	}
	accessLogHash := ComputeAccessLogHash([][]byte{leaves[0], leaves[1]})
	accessLogHex := hex.EncodeToString(accessLogHash[:])

	link0Data := "STRUCTURED_BUNDLE: v1\nBUNDLE_HASH: sha256:00\n"
	link0TS := "2026-05-23T14:00:00.000000Z"
	link0 := ComputeChainHash("", link0Data, link0TS)
	link0Hex := hex.EncodeToString(link0[:])

	link1Data := "OPENBRAIN_SNAPSHOT: v1\nROOT: sha256:abcd\n"
	link1TS := "2026-05-23T14:01:00.000000Z"
	link1 := ComputeChainHash(link0Hex, link1Data, link1TS)
	link1Hex := hex.EncodeToString(link1[:])

	link2Data := "CUSTODY_PROOF: v3\nACCESS_LOG_HASH: sha256:xxx\n"
	link2TS := "2026-05-23T14:02:00.000000Z"
	link2 := ComputeChainHash(link1Hex, link2Data, link2TS)
	link2Hex := hex.EncodeToString(link2[:])

	taskID := "t1"
	leafs := make([]SnapshotLeaf, len(leaves))
	for i, leaf := range leaves {
		leafs[i] = SnapshotLeaf{LeafIndex: i, ContentHash: hex.EncodeToString(leaf), ThoughtID: i + 1}
	}

	return &Bundle{
		Version: BundleVersion,
		Chain: []ChainLink{
			{ProofType: "structured_bundle", Hash: link0Hex, Data: link0Data, Timestamp: link0TS},
			{ProofType: "openbrain_snapshot", Hash: link1Hex, PrevHash: &link0Hex,
				Data: link1Data, Timestamp: link1TS, OpenbrainSnapshotRoot: &snapshotRootHex},
			{ProofType: "custody", Hash: link2Hex, PrevHash: &link1Hex,
				Data: link2Data, Timestamp: link2TS, TaskID: &taskID,
				OpenbrainAccessLogHash: &accessLogHex},
		},
		SnapshotLeaves: leafs,
		Accesses:       accesses,
	}
}

func TestVerifyValidBundle(t *testing.T) {
	b := buildValidBundle()
	r := Verify(b)
	if !r.OK {
		t.Errorf("Verify rejected a valid bundle:\n%s", strings.Join(r.Divergences, "\n  "))
	}
	if r.ChainLength != 3 {
		t.Errorf("ChainLength = %d, want 3", r.ChainLength)
	}
}

func TestVerifyDetectsTamperedChainData(t *testing.T) {
	b := buildValidBundle()
	b.Chain[2].Data = b.Chain[2].Data + "\nINJECTED: yes\n"
	r := Verify(b)
	if r.OK {
		t.Errorf("Verify accepted a bundle with tampered chain data")
	}
	if !containsAny(r.Divergences, "chain") {
		t.Errorf("expected a chain-related divergence, got: %v", r.Divergences)
	}
}

func TestVerifyDetectsTamperedSnapshotLeaves(t *testing.T) {
	b := buildValidBundle()
	// Mutate leaf 0's content hash → root rebuild no longer matches
	b.SnapshotLeaves[0].ContentHash = hex.EncodeToString(bytesOfLen(32, 0xff))
	r := Verify(b)
	if r.OK {
		t.Errorf("Verify accepted a bundle with tampered snapshot leaves")
	}
	if !containsAny(r.Divergences, "snapshot") {
		t.Errorf("expected a snapshot-related divergence, got: %v", r.Divergences)
	}
}

func TestVerifyDetectsAccessNotInSnapshot(t *testing.T) {
	b := buildValidBundle()
	// Inject a snapshot-source access whose content_hash isn't in the leaves.
	b.Accesses = append(b.Accesses, Access{
		TaskID: "t1", ThoughtID: 99,
		ContentHash: hex.EncodeToString(bytesOfLen(32, 0xab)),
		Source:      "snapshot",
		AccessedAt:  "2026-05-23T15:02:00.000000Z",
	})
	r := Verify(b)
	if r.OK {
		t.Errorf("Verify accepted a bundle with an off-snapshot access")
	}
	if !containsAny(r.Divergences, "accesses") {
		t.Errorf("expected an access-membership divergence, got: %v", r.Divergences)
	}
}

func TestVerifyDetectsAccessLogHashMismatch(t *testing.T) {
	b := buildValidBundle()
	// Drop one of the accesses → the cached access_log_hash in the
	// custody proof no longer matches what the verifier recomputes.
	b.Accesses = b.Accesses[:1]
	// Re-add it to leaf set if it was the missing one — but ah, the
	// remaining access's content_hash is in the leaves so membership
	// is fine; only the log-hash check should fail.
	r := Verify(b)
	if r.OK {
		t.Errorf("Verify accepted a bundle whose access set no longer hashes to the recorded log hash")
	}
	if !containsAny(r.Divergences, "access log hash") {
		t.Errorf("expected an access-log-hash divergence, got: %v", r.Divergences)
	}
}

// ── WI-P0-001: structural fail-closed checks ─────────────────────
//
// A bundle that is structurally incomplete (no chain, missing
// required commitment types, broken prev_hash linkage, etc.) MUST
// fail, not silently pass because the cryptographic checks happened
// to have no target. These tests pin every structural failure mode.

// Empty chain is no longer a vacuous-success ("nothing to check");
// it is a hard reject. A bundle without commitments cannot prove
// anything, so reporting OK=true was actively misleading.
func TestVerifyRejectsEmptyChain(t *testing.T) {
	b := &Bundle{Version: BundleVersion}
	r := Verify(b)
	if r.OK {
		t.Errorf("Verify accepted an empty-chain bundle")
	}
	if !containsAny(r.Divergences, "empty") {
		t.Errorf("expected an empty-chain divergence, got: %v", r.Divergences)
	}
}

func TestVerifyRejectsChainMissingStructuredBundle(t *testing.T) {
	b := buildValidBundle()
	// drop the genesis link
	b.Chain = b.Chain[1:]
	r := Verify(b)
	if r.OK {
		t.Errorf("Verify accepted a chain missing structured_bundle")
	}
	if !containsAny(r.Divergences, "structured_bundle") {
		t.Errorf("expected a structured_bundle divergence, got: %v", r.Divergences)
	}
}

func TestVerifyRejectsChainMissingSnapshot(t *testing.T) {
	b := buildValidBundle()
	// remove the openbrain_snapshot link
	b.Chain = []ChainLink{b.Chain[0], b.Chain[2]}
	r := Verify(b)
	if r.OK {
		t.Errorf("Verify accepted a chain missing openbrain_snapshot")
	}
	if !containsAny(r.Divergences, "openbrain_snapshot") {
		t.Errorf("expected an openbrain_snapshot divergence, got: %v", r.Divergences)
	}
}

func TestVerifyRejectsChainMissingCustody(t *testing.T) {
	b := buildValidBundle()
	b.Chain = b.Chain[:2]
	r := Verify(b)
	if r.OK {
		t.Errorf("Verify accepted a chain missing custody")
	}
	if !containsAny(r.Divergences, "custody") {
		t.Errorf("expected a custody divergence, got: %v", r.Divergences)
	}
}

func TestVerifyRejectsCustodyNotAtTail(t *testing.T) {
	b := buildValidBundle()
	// swap custody (index 2) with snapshot (index 1)
	b.Chain[1], b.Chain[2] = b.Chain[2], b.Chain[1]
	r := Verify(b)
	if r.OK {
		t.Errorf("Verify accepted a chain with custody not at the tail")
	}
}

func TestVerifyRejectsBrokenPrevHashLinkage(t *testing.T) {
	b := buildValidBundle()
	bogus := "00" + strings.Repeat("ff", 31)
	b.Chain[2].PrevHash = &bogus
	r := Verify(b)
	if r.OK {
		t.Errorf("Verify accepted a chain with a wrong prev_hash pointer")
	}
	if !containsAny(r.Divergences, "prev_hash") {
		t.Errorf("expected a prev_hash divergence, got: %v", r.Divergences)
	}
}

func TestVerifyRejectsGenesisWithNonNilPrevHash(t *testing.T) {
	b := buildValidBundle()
	notNil := strings.Repeat("aa", 32)
	b.Chain[0].PrevHash = &notNil
	r := Verify(b)
	if r.OK {
		t.Errorf("Verify accepted a chain whose genesis has a non-nil prev_hash")
	}
}

func TestVerifyRejectsDuplicateStructuredBundle(t *testing.T) {
	b := buildValidBundle()
	// append a second structured_bundle — uniqueness is required
	b.Chain = append(b.Chain, ChainLink{
		ProofType: "structured_bundle", Hash: b.Chain[0].Hash,
		Data: b.Chain[0].Data, Timestamp: b.Chain[0].Timestamp,
	})
	r := Verify(b)
	if r.OK {
		t.Errorf("Verify accepted a chain with two structured_bundle commitments")
	}
}

func TestVerifyRejectsSnapshotSourceAccessesWithoutLeaves(t *testing.T) {
	b := buildValidBundle()
	b.SnapshotLeaves = nil
	// b.Accesses still has source: "snapshot" entries
	r := Verify(b)
	if r.OK {
		t.Errorf("Verify accepted snapshot-source accesses against an empty leaf set")
	}
}

func TestVerifyRejectsSnapshotWithoutRoot(t *testing.T) {
	b := buildValidBundle()
	b.Chain[1].OpenbrainSnapshotRoot = nil
	r := Verify(b)
	if r.OK {
		t.Errorf("Verify accepted an openbrain_snapshot commitment with nil root")
	}
}

func TestVerifyRejectsCustodyWithoutAccessLogHash(t *testing.T) {
	b := buildValidBundle()
	b.Chain[2].OpenbrainAccessLogHash = nil
	r := Verify(b)
	if r.OK {
		t.Errorf("Verify accepted a custody commitment with nil openbrain_access_log_hash")
	}
}

func containsAny(divs []string, needle string) bool {
	for _, d := range divs {
		if strings.Contains(strings.ToLower(d), strings.ToLower(needle)) {
			return true
		}
	}
	return false
}
