// internal/membridge/sparse_merkle.go — PRD 1 §5.5 depth-20 sparse tree.
//
// Construction: bottom-up, only populated subtrees are computed
// explicitly; empty siblings reuse EmptyRoots[k]. Authentication path
// is leaf→root ordered with LSB-first direction (bit j of index at
// level j).
//
// Fail-closed validation (Hermes review on MR !7): callers MUST supply
// indices < 2^D. Out-of-range indices return ErrSparseIndexOutOfRange.
// Masking belongs only at the normative CellIndex derivation boundary
// (PRD 4 §3.2.5 specifies `& 0x0FFFFF` happens at index derivation, not
// inside the tree). Two callers differing only in bits >= 20 would
// otherwise collide silently.
package membridge

import "crypto/sha256"

// internalHash computes SHA-256(NODE_TAG || L || R) per PRD 1 §5.5.
func internalHash(left, right [32]byte) [32]byte {
	h := sha256.New()
	h.Write([]byte{NODE_TAG})
	h.Write(left[:])
	h.Write(right[:])
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
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

// SparseRoot computes the depth-20 sparse Merkle root for the set of
// (index, value_hash) pairs in cells. nil or empty cells returns
// EmptyRoots[20]. Any index >= 2^D is rejected fail-closed with
// ErrSparseIndexOutOfRange — callers MUST mask at the CellIndex
// derivation boundary, not rely on the tree to mask.
func SparseRoot(cells map[uint32][32]byte) ([32]byte, error) {
	if err := validateCellKeys(cells); err != nil {
		return [32]byte{}, err
	}
	if len(cells) == 0 {
		return EmptyRoots[D], nil
	}
	// Level 0: leaf hashes for each populated cell, keyed by index.
	level := make(map[uint32][32]byte, len(cells))
	for idx, vh := range cells {
		level[idx] = LeafHash(vh)
	}
	for k := 0; k < D; k++ {
		next := make(map[uint32][32]byte, len(level))
		seen := make(map[uint32]bool, len(level))
		for idx := range level {
			parent := idx >> 1
			if seen[parent] {
				continue
			}
			seen[parent] = true
			leftIdx := parent << 1
			rightIdx := leftIdx | 1
			left, hasLeft := level[leftIdx]
			right, hasRight := level[rightIdx]
			if !hasLeft {
				left = EmptyRoots[k]
			}
			if !hasRight {
				right = EmptyRoots[k]
			}
			next[parent] = internalHash(left, right)
		}
		level = next
	}
	root, ok := level[0]
	if !ok {
		return EmptyRoots[D], nil
	}
	return root, nil
}

// BuildAuthPath returns the 20 sibling hashes (leaf→root order) needed
// to authenticate the leaf at index against the root of cells. The
// returned slice always has length D; siblings at empty subtrees use
// the corresponding EmptyRoots[k]. Out-of-range index or leaf-map key
// returns ErrSparseIndexOutOfRange.
func BuildAuthPath(cells map[uint32][32]byte, index uint32) ([D][32]byte, error) {
	var path [D][32]byte
	if index >= 1<<D {
		return path, ErrSparseIndexOutOfRange
	}
	if err := validateCellKeys(cells); err != nil {
		return path, err
	}
	// Build full per-level node table, same as SparseRoot but kept
	// at each level so we can read siblings.
	levels := make([]map[uint32][32]byte, D+1)
	levels[0] = make(map[uint32][32]byte, len(cells))
	for idx, vh := range cells {
		levels[0][idx] = LeafHash(vh)
	}
	for k := 0; k < D; k++ {
		next := make(map[uint32][32]byte, len(levels[k]))
		seen := make(map[uint32]bool, len(levels[k]))
		for idx := range levels[k] {
			parent := idx >> 1
			if seen[parent] {
				continue
			}
			seen[parent] = true
			leftIdx := parent << 1
			rightIdx := leftIdx | 1
			left, hasLeft := levels[k][leftIdx]
			right, hasRight := levels[k][rightIdx]
			if !hasLeft {
				left = EmptyRoots[k]
			}
			if !hasRight {
				right = EmptyRoots[k]
			}
			next[parent] = internalHash(left, right)
		}
		levels[k+1] = next
	}
	// Walk leaf→root pulling siblings.
	cur := index
	for k := 0; k < D; k++ {
		siblingIdx := cur ^ 1
		sib, ok := levels[k][siblingIdx]
		if !ok {
			sib = EmptyRoots[k]
		}
		path[k] = sib
		cur >>= 1
	}
	return path, nil
}

// VerifyAuthPath recomputes the root by walking leafHash up to the root
// using LSB-first direction bits from index. Indices >= 2^D produce
// undefined output; callers MUST validate range upstream (the normative
// CellIndex boundary).
func VerifyAuthPath(index uint32, leafHash [32]byte, path [D][32]byte) [32]byte {
	cur := leafHash
	for k := 0; k < D; k++ {
		bit := (index >> uint(k)) & 1
		if bit == 0 {
			cur = internalHash(cur, path[k])
		} else {
			cur = internalHash(path[k], cur)
		}
	}
	return cur
}
