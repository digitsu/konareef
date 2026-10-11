// Copyright 2026 Jerry David Chan, Konareef.ai
// SPDX-License-Identifier: Apache-2.0

// internal/tlog/tlog.go — public surface for PRD 1 § 5.4 T_log
// reconstruction. The record_bytes encoding here is normative across
// every konareef verifier; treat it as wire-format spec.
//
// Hash construction (post Lever-1, PRD 1 § 5.4): the tool-log Merkle
// tree is built over Poseidon-over-Pallas-Fq, NOT SHA-256. Each leaf is
// poseidon.LeafHash(poseidon.RecordToField(record_bytes)); internal
// nodes use poseidon.InternalHash; the count is bound by the 0x03
// length element. All hashing delegates to internal/poseidon (the
// drift-gated, neptune-parity primitive); this package owns only the
// record_bytes encoding and the call_index ordering.
package tlog

import (
	"crypto/sha256"
	"encoding/binary"
	"sort"
	"time"

	"github.com/digitsu/konareef/internal/poseidon"
)

// Row is a single proof_tool_calls-equivalent row, matching the
// writer-side schema in reef-core's `proof_tool_calls` table (P1.1).
// CallIndex is the SOLE sort key for T_log leaf order (PRD 4 § 4.1.4);
// TS is for audit/debugging only and is not used to order leaves.
type Row struct {
	// ToolID is the UTF-8 NFC tool identifier. Length is bound by
	// LEB128(len(tool_id_utf8)) at the start of record_bytes.
	ToolID string

	// ArgsHash is the 32-byte SHA-256 of the canonical tool-call
	// argument bytes. Canonicalization is the runtime's responsibility;
	// PRD 1 only binds the hash.
	ArgsHash [32]byte

	// ResultHash is the 32-byte SHA-256 of the canonical tool-call
	// result bytes. Canonicalization is the runtime's responsibility;
	// PRD 1 only binds the hash.
	ResultHash [32]byte

	// TS is the wall-clock timestamp of the call. Encoded as u64
	// big-endian microseconds since the Unix epoch (UTC). PRD 1 § 5.4
	// SHOULD be monotone non-decreasing within a single T_log, but the
	// helper does not enforce monotonicity (PRD 4 § 4.1.4 makes that
	// the writer's responsibility).
	TS time.Time

	// CallIndex is the writer-assigned ordering key. Rows are sorted by
	// CallIndex ASC before leaves are hashed; it is NOT part of the
	// leaf preimage. PRD 4 § 4.1.4 makes (proof_id, call_index) the
	// uniqueness constraint.
	CallIndex uint32

	// Sats is the satoshis paid for this tool call (0 for unpaid/local
	// tools, e.g. `bash`). Encoded big-endian as the trailing 8 bytes of
	// record_bytes (PRD 1 § 5.4 amended 2026-07-05). The circuit binds
	// Σ(sats) ≤ c; the writer is responsible for that invariant.
	Sats uint64
}

// RecordBytes returns the canonical PRD 1 § 5.4 per-record encoding
// (amended 2026-07-05 — decision `2026-07-05-konareef-digest-tool-ids`),
// byte-identical to paygate-zk's konareef_circuit troot_sha::encode_record:
//
//	record_bytes = 0x20                            // ULEB128(32), constant under the digest shape
//	            || tool_id_digest (32 B)           // SHA-256(tool_id_utf8)
//	            || args_hash (32 B)
//	            || result_hash (32 B)
//	            || ts (8 B big-endian u64, microseconds since Unix epoch)
//	            || sats (8 B big-endian u64)
//
// Every record is a FIXED 113 bytes: the variable-length name form is
// superseded (it committed the raw name and had no sats). CallIndex is
// intentionally not part of record_bytes — it is the out-of-band sort key
// (PRD 4 § 4.1.4).
func RecordBytes(r Row) []byte {
	digest := sha256.Sum256([]byte(r.ToolID))
	tsUs := uint64(r.TS.UnixMicro()) //nolint:gosec // Unix microseconds fit in u64 until year 586524

	out := make([]byte, 0, 113)
	out = append(out, 0x20) // ULEB128(32) — constant single byte under the digest shape
	out = append(out, digest[:]...)
	out = append(out, r.ArgsHash[:]...)
	out = append(out, r.ResultHash[:]...)
	var tsBytes [8]byte
	binary.BigEndian.PutUint64(tsBytes[:], tsUs)
	out = append(out, tsBytes[:]...)
	var satsBytes [8]byte
	binary.BigEndian.PutUint64(satsBytes[:], r.Sats)
	out = append(out, satsBytes[:]...)
	return out
}

// LeafHash returns the PRD 1 § 5.4 Poseidon leaf hash for a single Row:
// poseidon.LeafHash(poseidon.RecordToField(RecordBytes(r))). It returns
// an error if the record exceeds the pinned circuit cap (fail-closed:
// such a record could not have been proven).
func LeafHash(r Row) ([32]byte, error) {
	rf, err := poseidon.Default().RecordToField(RecordBytes(r))
	if err != nil {
		return [32]byte{}, err
	}
	return poseidon.Default().LeafHash(rf)
}

// TRootFromRows reconstructs PRD 1 § 5.4's Poseidon t_root from an
// unordered set of Rows:
//
//  1. Sort by Row.CallIndex ASC (PRD 4 § 4.1.4 — the sole sort key).
//  2. Build record_bytes for each row.
//  3. t_root = poseidon.TRoot(records) — the Z-padded balanced Poseidon
//     tree of leaf_hash(record_to_field(record)) leaves, bound by the
//     0x03 length element.
//
// It does not mutate the input slice (sort happens on an internal copy)
// and returns an error if the log exceeds the pinned record/count caps.
func TRootFromRows(rows []Row) ([32]byte, error) {
	work := make([]Row, len(rows))
	copy(work, rows)
	sort.SliceStable(work, func(i, j int) bool {
		return work[i].CallIndex < work[j].CallIndex
	})

	records := make([][]byte, len(work))
	for i, r := range work {
		records[i] = RecordBytes(r)
	}
	return poseidon.Default().TRoot(records)
}
