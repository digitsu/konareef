// Copyright 2026 Jerry David Chan, Konareef.ai
// SPDX-License-Identifier: Apache-2.0

// internal/membridge/rinit.go — the konareef-rinit/v1 r_init derivation
// (docs/reference/konareef-memory-root-v1-spec.md §5).
//
// For a 32-byte pod_salt and the resolved cells (cell_id, content_hash):
//
//	for each cell, ascending cell_id:
//	  index      = CellIndex(pod_salt, cell_id)              SHA-256, PRD 4 §3.2.5
//	  value_hash = ValueHash(pod_salt, cell_id, content_hash) Poseidon, PRD 1 §5.5
//	r_init = SparseRoot({index → value_hash})                 Poseidon, depth 20
//
// The empty cell set gives E20 regardless of the salt (R-M10). The
// derivation sorts by cell_id before it checks duplicates and
// collisions, so both the root and the refusal it reports are
// independent of input order (R-M7).
package membridge

import "sort"

// Cell is one resolved memory cell: a stable identifier and the 32-byte
// SHA-256 digest of the exact bytes loaded for it. For Open Brain cells
// the identifier is a thought_id; for [[context.memory]] sources it is
// SourceCellID (bit 63 set, so the two namespaces never meet).
type Cell struct {
	CellID      uint64
	ContentHash []byte
}

// DerivedCell is the per-cell output of RInitV1: the tree address and the
// Poseidon value hash that enter the root.
type DerivedCell struct {
	CellID    uint64
	Index     uint32
	ValueHash [32]byte
}

// RInitV1 computes the konareef-rinit/v1 root over cells under podSalt.
//
// Inputs: a 32-byte podSalt and the resolved cells in any order.
//
// Output: the 32-byte little-endian Poseidon root, the per-cell
// derivation in ascending CellID order, or the first refusal:
// ErrCellSaltLen, ErrCellCapExceeded (more than HardCapK cells),
// ErrSnapshotImportFailed (content hash not 32 bytes), ErrCellDuplicateID
// (two cells with one CellID), ErrCellIndexCollision (two CellIDs with
// one index; no relocation, R-M8) or ErrValueHashZero (a populated cell
// whose value hash is the empty sentinel).
//
// The salt never appears in an error: every refusal is a bare sentinel.
func RInitV1(podSalt []byte, cells []Cell) ([32]byte, []DerivedCell, error) {
	var zero [32]byte
	if len(podSalt) != 32 {
		return zero, nil, ErrCellSaltLen
	}
	if err := EnforceHardCap(len(cells)); err != nil {
		return zero, nil, err
	}
	sorted := append([]Cell(nil), cells...)
	sort.SliceStable(sorted, func(i, j int) bool { return sorted[i].CellID < sorted[j].CellID })

	byIndex := make(map[uint32][32]byte, len(sorted))
	derived := make([]DerivedCell, 0, len(sorted))
	for i, c := range sorted {
		if len(c.ContentHash) != 32 {
			return zero, nil, ErrSnapshotImportFailed
		}
		if i > 0 && sorted[i-1].CellID == c.CellID {
			return zero, nil, ErrCellDuplicateID
		}
		idx, err := CellIndex(podSalt, c.CellID)
		if err != nil {
			return zero, nil, err
		}
		// Distinct CellIDs reach here (duplicates refused above), so any
		// taken index is a collision between two different cells.
		if _, taken := byIndex[idx]; taken {
			return zero, nil, ErrCellIndexCollision
		}
		vh, err := ValueHash(podSalt, c.CellID, c.ContentHash)
		if err != nil {
			return zero, nil, err
		}
		if vh == EmptyValueHash {
			return zero, nil, ErrValueHashZero
		}
		byIndex[idx] = vh
		derived = append(derived, DerivedCell{CellID: c.CellID, Index: idx, ValueHash: vh})
	}
	root, err := SparseRoot(byIndex)
	if err != nil {
		return zero, nil, err
	}
	return root, derived, nil
}
