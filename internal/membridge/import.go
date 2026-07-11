// Copyright 2026 Jerry David Chan, Konareef.ai
// SPDX-License-Identifier: Apache-2.0

// internal/membridge/import.go — PRD 4 §B.5 snapshot import + audit trail.
//
// Procedure (ordered):
//  1. Enumerate MemorySnapshotLeaf records by leaf_index ASC.
//  2. Derive (index, value_hash) per B.1 for each leaf.
//  3. Assemble the depth-20 sparse Merkle tree.
//  4. Read off the root → r_init.
//  5. Verify r_init == manifest.r_init; mismatch → ErrRInitMismatch.
//  6. Any structural failure → ErrSnapshotImportFailed.
package membridge

import (
	"bytes"
	"errors"
	"sort"
)

// MemorySnapshotLeaf is one row from the Phase-0 MemorySnapshot.
type MemorySnapshotLeaf struct {
	LeafIndex   uint64 // PRD 4 §B.5 step-1 sort key
	ThoughtID   uint64
	ContentHash []byte // 32 bytes
}

// AuditTrailEntry is one row of the §B.5 ordered audit record. Salt is
// the runtime's responsibility to keep alongside (Type-C: bundled;
// Type-D: out-of-band confidential).
type AuditTrailEntry struct {
	ThoughtID   uint64
	LogicalKey  []byte
	Index       uint32
	ValueHash   [32]byte
	ContentHash []byte
}

// ImportSnapshot performs §B.5 steps 1-5.
//
// Returns the computed r_init and the audit trail in leaf_index ASC
// order. On r_init mismatch the trail is still returned so callers can
// diagnose; the error fully unwraps to ErrRInitMismatch.
func ImportSnapshot(podSalt []byte, leaves []MemorySnapshotLeaf, manifestRInit []byte) ([32]byte, []AuditTrailEntry, error) {
	var zero [32]byte
	if len(podSalt) != 32 {
		return zero, nil, ErrCellSaltLen
	}
	if len(manifestRInit) != 32 {
		return zero, nil, ErrSnapshotImportFailed
	}
	if err := EnforceHardCap(len(leaves)); err != nil {
		return zero, nil, err
	}
	sorted := make([]MemorySnapshotLeaf, len(leaves))
	copy(sorted, leaves)
	sort.Slice(sorted, func(i, j int) bool {
		return sorted[i].LeafIndex < sorted[j].LeafIndex
	})

	cells := make(map[uint32][32]byte, len(sorted))
	trail := make([]AuditTrailEntry, 0, len(sorted))
	seenIdx := make(map[uint32]uint64, len(sorted))
	for _, leaf := range sorted {
		if len(leaf.ContentHash) != 32 {
			return zero, nil, ErrSnapshotImportFailed
		}
		lk, err := LogicalKey(podSalt, leaf.ThoughtID)
		if err != nil {
			if errors.Is(err, ErrCellSaltLen) {
				return zero, nil, err
			}
			return zero, nil, ErrSnapshotImportFailed
		}
		idx, err := CellIndex(podSalt, leaf.ThoughtID)
		if err != nil {
			return zero, nil, ErrSnapshotImportFailed
		}
		if prevTID, taken := seenIdx[idx]; taken && prevTID != leaf.ThoughtID {
			return zero, nil, ErrCellIndexCollision
		}
		seenIdx[idx] = leaf.ThoughtID
		vh, err := ValueHash(podSalt, leaf.ThoughtID, leaf.ContentHash)
		if err != nil {
			return zero, nil, ErrSnapshotImportFailed
		}
		cells[idx] = vh
		trail = append(trail, AuditTrailEntry{
			ThoughtID:   leaf.ThoughtID,
			LogicalKey:  lk,
			Index:       idx,
			ValueHash:   vh,
			ContentHash: append([]byte(nil), leaf.ContentHash...),
		})
	}

	root, err := SparseRoot(cells)
	if err != nil {
		// Defensive: CellIndex always returns idx < 2^D so the tree
		// rejection path is unreachable through this codepath. Convert
		// to ErrSnapshotImportFailed to keep the import error vocabulary.
		return zero, trail, ErrSnapshotImportFailed
	}
	if !bytes.Equal(root[:], manifestRInit) {
		return root, trail, ErrRInitMismatch
	}
	return root, trail, nil
}
