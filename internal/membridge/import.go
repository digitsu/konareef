// Copyright 2026 Jerry David Chan, Konareef.ai
// SPDX-License-Identifier: Apache-2.0

// internal/membridge/import.go — PRD 4 §B.5 snapshot import + audit trail.
//
// Procedure (ordered):
//  1. Enumerate MemorySnapshotLeaf records by leaf_index ASC.
//  2. Derive (index, value_hash) per B.1 for each leaf (Poseidon value
//     hash after the 2026-06-10 swap; RInitV1).
//  3. Assemble the depth-20 Poseidon sparse Merkle tree.
//  4. Read off the root → r_init.
//  5. Verify r_init == manifest.r_init; mismatch → ErrRInitMismatch.
//  6. Any structural failure → ErrSnapshotImportFailed.
package membridge

import (
	"bytes"
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

// ImportSnapshot performs §B.5 steps 1-5 under the konareef-rinit/v1
// derivation (Poseidon tree; RInitV1).
//
// Inputs: the 32-byte podSalt, the snapshot leaves (any order; each
// ThoughtID is the cell identifier) and the 32-byte r_init the manifest
// committed.
//
// Output: the computed r_init and the audit trail in leaf_index ASC
// order. On r_init mismatch the root and trail are still returned so
// callers can diagnose, and the error unwraps to ErrRInitMismatch. Every
// RInitV1 refusal passes through unchanged (ErrCellSaltLen,
// ErrCellCapExceeded, ErrCellDuplicateID, ErrCellIndexCollision,
// ErrValueHashZero, ErrSnapshotImportFailed); a manifestRInit that is not
// 32 bytes is ErrSnapshotImportFailed.
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
	sort.SliceStable(sorted, func(i, j int) bool {
		return sorted[i].LeafIndex < sorted[j].LeafIndex
	})

	cells := make([]Cell, 0, len(sorted))
	for _, leaf := range sorted {
		cells = append(cells, Cell{CellID: leaf.ThoughtID, ContentHash: leaf.ContentHash})
	}
	root, derived, err := RInitV1(podSalt, cells)
	if err != nil {
		return zero, nil, err
	}
	byID := make(map[uint64]DerivedCell, len(derived))
	for _, d := range derived {
		byID[d.CellID] = d
	}

	trail := make([]AuditTrailEntry, 0, len(sorted))
	for _, leaf := range sorted {
		lk, err := LogicalKey(podSalt, leaf.ThoughtID)
		if err != nil {
			return zero, nil, err
		}
		d := byID[leaf.ThoughtID]
		trail = append(trail, AuditTrailEntry{
			ThoughtID:   leaf.ThoughtID,
			LogicalKey:  lk,
			Index:       d.Index,
			ValueHash:   d.ValueHash,
			ContentHash: append([]byte(nil), leaf.ContentHash...),
		})
	}
	if !bytes.Equal(root[:], manifestRInit) {
		return root, trail, ErrRInitMismatch
	}
	return root, trail, nil
}

// CheckRInitV1 is the salt holder's root check for resolved cells
// (konareef-rinit/v1 spec §6.2, §8 "root check").
//
// Inputs: the 32-byte podSalt, the cells reef-core exported for the run
// (or the publisher resolved), and the r_init the manifest committed.
//
// Output: the per-cell derivation (ascending CellID) when RInitV1 over
// the cells equals committed; otherwise ErrRInitMismatch, or the RInitV1
// refusal. On any error the caller MUST NOT build a witness or submit a
// proof. The error carries no salt, no content hash and no root.
func CheckRInitV1(podSalt []byte, cells []Cell, committed [32]byte) ([]DerivedCell, error) {
	root, derived, err := RInitV1(podSalt, cells)
	if err != nil {
		return nil, err
	}
	if root != committed {
		return nil, ErrRInitMismatch
	}
	return derived, nil
}
