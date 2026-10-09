// Copyright 2026 Jerry David Chan, Konareef.ai
// SPDX-License-Identifier: Apache-2.0

// internal/membridge/sparse_merkle.go — PRD 1 §5.5 depth-20 sparse tree,
// Poseidon-over-Pallas after the 2026-06-10 hash swap.
//
// Construction: bottom-up, only populated subtrees are computed
// explicitly; empty siblings reuse EmptyRoots[k]. Node hash is the
// Poseidon arity-2 InternalHash(L, R); leaf hash is LeafHash(value_hash).
// Authentication path is leaf→root ordered with LSB-first direction (bit
// j of index at level j). This is the same tree the pod-step circuit
// authenticates against z[Z_R_MEM] (paygate-zk gadgets/memory_poseidon.rs).
//
// Fail-closed validation (Hermes review on MR !7): callers MUST supply
// indices < 2^D. Out-of-range indices return ErrSparseIndexOutOfRange.
// Masking belongs only at the normative CellIndex derivation boundary
// (PRD 4 §3.2.5 specifies `& 0x0FFFFF` happens at index derivation, not
// inside the tree). Two callers differing only in bits >= 20 would
// otherwise collide silently.
package membridge

import (
	"fmt"

	"github.com/digitsu/konareef/internal/poseidon"
)

// internalHash computes the PRD 1 §5.5 Poseidon node hash over [L, R].
// Inputs are canonical field elements (every leaf, node and empty root
// is); a non-canonical input returns an error wrapping
// ErrSnapshotImportFailed.
func internalHash(left, right [32]byte) ([32]byte, error) {
	h, err := poseidon.Default().InternalHash(left, right)
	if err != nil {
		return [32]byte{}, fmt.Errorf("node hash: %v: %w", err, ErrSnapshotImportFailed)
	}
	return h, nil
}

// validateCellKeys returns ErrSparseIndexOutOfRange if any key in cells
// is >= 2^D. The fail-closed gate runs before any hashing so an
// out-of-range key cannot influence the computed root.
func validateCellKeys(cells map[uint32][32]byte) error {
	for idx := range cells {
		if idx >= 1<<D {
			return ErrSparseIndexOutOfRange
		}
	}
	return nil
}

// buildLevels hashes the populated cells into per-level node maps.
//
// Input: value hashes keyed by index (already range-checked). Output:
// levels[0] holds the leaf hashes, levels[k] the populated nodes at
// height k, and levels[D] holds at most the root at key 0. Absent keys
// stand for the empty subtree EmptyRoots[k].
func buildLevels(cells map[uint32][32]byte) ([D + 1]map[uint32][32]byte, error) {
	var levels [D + 1]map[uint32][32]byte
	levels[0] = make(map[uint32][32]byte, len(cells))
	for idx, vh := range cells {
		lh, err := LeafHash(vh)
		if err != nil {
			return levels, err
		}
		levels[0][idx] = lh
	}
	for k := 0; k < D; k++ {
		next := make(map[uint32][32]byte, len(levels[k]))
		for idx := range levels[k] {
			parent := idx >> 1
			if _, done := next[parent]; done {
				continue
			}
			left, hasLeft := levels[k][parent<<1]
			right, hasRight := levels[k][parent<<1|1]
			if !hasLeft {
				left = EmptyRoots[k]
			}
			if !hasRight {
				right = EmptyRoots[k]
			}
			h, err := internalHash(left, right)
			if err != nil {
				return levels, err
			}
			next[parent] = h
		}
		levels[k+1] = next
	}
	return levels, nil
}

// SparseRoot computes the depth-20 Poseidon sparse Merkle root for the
// set of (index, value_hash) pairs in cells.
//
// Input: value hashes keyed by index. Output: the 32-byte little-endian
// root; nil or empty cells return EmptyRoots[20] (E20). Any index >= 2^D
// is rejected fail-closed with ErrSparseIndexOutOfRange — callers MUST
// mask at the CellIndex derivation boundary, not rely on the tree to
// mask. A non-canonical value hash returns an error wrapping
// ErrSnapshotImportFailed.
func SparseRoot(cells map[uint32][32]byte) ([32]byte, error) {
	if err := validateCellKeys(cells); err != nil {
		return [32]byte{}, err
	}
	if len(cells) == 0 {
		return EmptyRoots[D], nil
	}
	levels, err := buildLevels(cells)
	if err != nil {
		return [32]byte{}, err
	}
	root, ok := levels[D][0]
	if !ok {
		return EmptyRoots[D], nil
	}
	return root, nil
}

// BuildAuthPath returns the 20 sibling hashes (leaf→root order) needed
// to authenticate the leaf at index against the root of cells.
//
// Inputs: value hashes keyed by index, and the index to authenticate
// (populated or empty). Output: always length D; siblings at empty
// subtrees use the corresponding EmptyRoots[k]. Out-of-range index or
// leaf-map key returns ErrSparseIndexOutOfRange; a non-canonical value
// hash returns an error wrapping ErrSnapshotImportFailed.
func BuildAuthPath(cells map[uint32][32]byte, index uint32) ([D][32]byte, error) {
	var path [D][32]byte
	if index >= 1<<D {
		return path, ErrSparseIndexOutOfRange
	}
	if err := validateCellKeys(cells); err != nil {
		return path, err
	}
	levels, err := buildLevels(cells)
	if err != nil {
		return path, err
	}
	// Walk leaf→root pulling siblings.
	cur := index
	for k := 0; k < D; k++ {
		sib, ok := levels[k][cur^1]
		if !ok {
			sib = EmptyRoots[k]
		}
		path[k] = sib
		cur >>= 1
	}
	return path, nil
}

// VerifyAuthPath recomputes the root by walking leafHash up to the root
// using LSB-first direction bits from index.
//
// Inputs: the index (< 2^D), the leaf hash at that index (EmptyRoots[0]
// for an empty slot) and its D siblings. Output: the recomputed root, or
// ErrSparseIndexOutOfRange for an index >= 2^D, or an error wrapping
// ErrSnapshotImportFailed when a sibling is not a canonical field
// element. Callers compare the result with the expected root.
func VerifyAuthPath(index uint32, leafHash [32]byte, path [D][32]byte) ([32]byte, error) {
	if index >= 1<<D {
		return [32]byte{}, ErrSparseIndexOutOfRange
	}
	cur := leafHash
	for k := 0; k < D; k++ {
		var err error
		if (index>>uint(k))&1 == 0 {
			cur, err = internalHash(cur, path[k])
		} else {
			cur, err = internalHash(path[k], cur)
		}
		if err != nil {
			return [32]byte{}, err
		}
	}
	return cur, nil
}
