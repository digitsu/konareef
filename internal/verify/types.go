// Package verify implements the offline `konareef verify` workflow
// (P0.2): parse a konareef-bundle/v1 JSON document and re-check the
// chain integrity, snapshot Merkle root, access membership, and
// access-log hash without any reef-core dependency.
//
// All primitives in this package mirror reef-core's Elixir
// implementations bit-exactly:
//
//   - ComputeChainHash  ↔  ReefCore.Proofs.Hash.compute/3
//   - BuildMerkleRoot   ↔  ReefCore.Proofs.MerkleTree.build/1
//   - AccessLogHash     ↔  ReefCore.Proofs.compute_access_log_hash/1
//
// A divergence on any of those primitives breaks every verifier in
// the field, so the unit tests treat them as the spec's wire
// contract — not an implementation detail.

package verify

// Bundle is the parsed konareef-bundle/v1 JSON document.
//
// The shape mirrors ReefCore.Proofs.Bundle.pack/2's output exactly:
// binary fields ride as hex strings, datetimes as ISO-8601 strings,
// `prev_hash` is nullable for the genesis commitment.
//
// WI-P0-002: the publisher-attestation envelope fields below are
// all nullable. A legacy unsigned (v0) bundle has every one nil;
// a fully signed bundle has all six populated and the verifier
// re-checks SHA-256(manifest) == pod_hash AND that
// publisher_signature is a valid secp256k1-DER ECDSA signature of
// pod_hash under publisher_pubkey.
//
//   - Verifiable: explicit flag mirroring the envelope's verifiable
//     bool. nil → assume true (legacy). false → the bundle is the
//     sanitized display variant and chain-hash check will fail by
//     design; callers shouldn't treat that as a tamper signal.
type Bundle struct {
	Version        string            `json:"version"`
	Verifiable     *bool             `json:"verifiable"`
	Chain          []ChainLink       `json:"chain"`
	Snapshot       *Snapshot         `json:"snapshot"`
	SnapshotLeaves []SnapshotLeaf    `json:"snapshot_leaves"`
	Accesses       []Access          `json:"accesses"`
	BsvTxids       map[string]string `json:"bsv_txids"`

	// Publisher attestation envelope (WI-P0-002). All nullable; a
	// legacy unsigned bundle leaves every field unset.
	PodHash            *string `json:"pod_hash"`
	PodVersion         *string `json:"pod_version"`
	PublisherID        *string `json:"publisher_id"`
	PublisherSignature *string `json:"publisher_signature"`
	PublisherPubkey    *string `json:"publisher_pubkey"`
	Manifest           *string `json:"manifest"`

	// P1.3 — disclosure policy ("C" or "D") asserted by
	// `konareef verify --disclosure-policy`. Sourced from v2 bundles
	// (PRD 3 § 9); empty on v1 bundles. AssertDisclosurePolicy uses
	// this field for the optional verify-side equality check.
	Disclosure string `json:"disclosure,omitempty"`
}

// ChainLink is one commitment in the per-task proof chain. Binary
// fields are hex-encoded; nullable fields use Go's pointer-to-string
// so the verifier can distinguish "missing" from "empty string".
type ChainLink struct {
	ProofType              string   `json:"proof_type"`
	Hash                   string   `json:"hash"`
	PrevHash               *string  `json:"prev_hash"`
	Data                   string   `json:"data"`
	Timestamp              string   `json:"timestamp"`
	Txid                   *string  `json:"txid"`
	AgentID                string   `json:"agent_id"`
	TaskID                 *string  `json:"task_id"`
	TaskHash               *string  `json:"task_hash"`
	ResultHash             *string  `json:"result_hash"`
	StructuredBundleHash   *string  `json:"structured_bundle_hash"`
	OpenbrainSnapshotRoot  *string  `json:"openbrain_snapshot_root"`
	OpenbrainCaptureRoot   *string  `json:"openbrain_capture_root"`
	OpenbrainAccessLogHash *string  `json:"openbrain_access_log_hash"`
	AccessedCount          *int     `json:"accessed_count"`
	Iterations             *int     `json:"iterations"`
	DurationSecs           *int     `json:"duration_secs"`
	ToolsUsed              []string `json:"tools_used"`
	TotalSats              *int     `json:"total_sats"`
}

// Snapshot is the MemorySnapshot row the chain references.
type Snapshot struct {
	ID         string `json:"id"`
	Root       string `json:"root"`
	EntryCount int    `json:"entry_count"`
	TakenAt    string `json:"taken_at"`
	PodID      string `json:"pod_id"`
	AgentID    string `json:"agent_id"`
}

// SnapshotLeaf is one leaf in the Merkle tree the verifier rebuilds.
type SnapshotLeaf struct {
	LeafIndex   int    `json:"leaf_index"`
	ContentHash string `json:"content_hash"`
	ThoughtID   int    `json:"thought_id"`
}

// Access is one MemoryAccess record for the task — what the pod
// read from memory while running.
type Access struct {
	TaskID      string `json:"task_id"`
	ThoughtID   int    `json:"thought_id"`
	ContentHash string `json:"content_hash"`
	Source      string `json:"source"` // "snapshot" | "capture"
	AccessedAt  string `json:"accessed_at"`
}
