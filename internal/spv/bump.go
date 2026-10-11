// Copyright 2026 Jerry David Chan, Konareef.ai
// SPDX-License-Identifier: Apache-2.0

// bump.go — BRC-74 BSV Unified Merkle Path (BUMP) parsing and merkle
// root computation.
//
// Wire form: VarInt block height; one byte tree height; then, for each
// level from the leaves up, a VarInt leaf count and that many leaves.
// A leaf is a VarInt offset, a flags byte, and (unless the flags say
// "duplicate") a 32-byte hash in internal byte order.

package spv

// BUMP leaf flags (BRC-74).
const (
	// LeafData marks a hash that is a sibling, not a subject txid.
	LeafData byte = 0x00
	// LeafDuplicate marks a leaf with no hash: it equals its sibling.
	LeafDuplicate byte = 0x01
	// LeafTxID marks a subject txid at level 0.
	LeafTxID byte = 0x02
)

// maxTreeHeight bounds the tree height. 64 levels cover any block.
const maxTreeHeight = 64

// Leaf is one node of a BUMP level.
type Leaf struct {
	// Offset is the node's index within its level.
	Offset uint64
	// Flags is LeafData, LeafDuplicate or LeafTxID.
	Flags byte
	// Hash is the node hash in internal order; zero for a duplicate.
	Hash [32]byte
}

// BUMP is a parsed merkle path.
type BUMP struct {
	// BlockHeight is the height of the block the path proves.
	BlockHeight uint64
	// Levels holds the leaves of each level, level 0 first.
	Levels [][]Leaf
	// index maps, per level, an offset to its position in Levels (built
	// by the parser so lookups are O(1) on large paths).
	index []map[uint64]int
}

// ParseBUMP parses one BUMP that fills all of raw.
// Input: raw, the serialized BUMP.
// Output: the BUMP, or an error wrapping ErrMalformed.
func ParseBUMP(raw []byte) (*BUMP, error) {
	r := &reader{buf: raw}
	b, err := readBUMP(r)
	if err != nil {
		return nil, err
	}
	if r.remaining() != 0 {
		return nil, malformed("%d trailing bytes after the BUMP", r.remaining())
	}
	return b, nil
}

// readBUMP reads one BUMP from r. Level 0 must not be empty; a level
// above 0 may be empty, because a trimmed compound path (BRC-74) leaves
// out every node that its two children at the level below give.
// Input: r, positioned at the start of a BUMP.
// Output: the BUMP, or an error wrapping ErrMalformed.
func readBUMP(r *reader) (*BUMP, error) {
	height, err := r.varInt("bump block height")
	if err != nil {
		return nil, err
	}
	treeHeight, err := r.byte1("bump tree height")
	if err != nil {
		return nil, err
	}
	if treeHeight == 0 || treeHeight > maxTreeHeight {
		return nil, malformed("bump tree height %d out of range", treeHeight)
	}
	b := &BUMP{BlockHeight: height, Levels: make([][]Leaf, treeHeight), index: make([]map[uint64]int, treeHeight)}
	for level := 0; level < int(treeHeight); level++ {
		// Smallest leaf: 1 offset byte + 1 flags byte.
		n, err := r.count("bump leaf", 2)
		if err != nil {
			return nil, err
		}
		// Level 0 must hold at least one leaf: the transactions the path
		// proves. A level above 0 may be empty: a trimmed compound path
		// leaves out every node of a level that its children give, and
		// findOrCompute computes such nodes.
		if n == 0 && level == 0 {
			return nil, malformed("bump level 0 has no leaves")
		}
		seen := make(map[uint64]int, n)
		leaves := make([]Leaf, 0, n)
		for i := 0; i < n; i++ {
			off, err := r.varInt("bump leaf offset")
			if err != nil {
				return nil, err
			}
			if _, dup := seen[off]; dup {
				return nil, malformed("bump level %d repeats offset %d", level, off)
			}
			seen[off] = i
			flags, err := r.byte1("bump leaf flags")
			if err != nil {
				return nil, err
			}
			leaf := Leaf{Offset: off, Flags: flags}
			switch flags {
			case LeafDuplicate:
			case LeafData, LeafTxID:
				if flags == LeafTxID && level != 0 {
					return nil, malformed("bump txid flag above level 0")
				}
				if leaf.Hash, err = r.hash32("bump leaf hash"); err != nil {
					return nil, err
				}
			default:
				return nil, malformed("bump leaf flags 0x%02x unknown", flags)
			}
			leaves = append(leaves, leaf)
		}
		b.Levels[level] = leaves
		b.index[level] = seen
	}
	return b, nil
}

// find returns the leaf at offset in level, if present.
func (b *BUMP) find(level int, offset uint64) (Leaf, bool) {
	if level < len(b.index) && b.index[level] != nil {
		i, ok := b.index[level][offset]
		if !ok {
			return Leaf{}, false
		}
		return b.Levels[level][i], true
	}
	for _, l := range b.Levels[level] {
		if l.Offset == offset {
			return l, true
		}
	}
	return Leaf{}, false
}

// findOrCompute returns the node at offset in level. A compound BUMP
// (one path for several transactions) may leave out a node that its two
// children at the level below give; a trimmed compound path can leave
// out all nodes of a level, so the level is empty. Such a node is
// computed here, as the BRC-74 reference implementations do: parent =
// sha256d(left || right), and a right child flagged duplicate equals the
// left child. When the left child is absent or flagged duplicate, or the
// right child is absent, the node cannot be computed. The recursion
// depth is bounded by the tree height.
// Input: level and offset of the node.
// Output: the node and true, or false when it cannot be found or
// computed.
func (b *BUMP) findOrCompute(level int, offset uint64) (Leaf, bool) {
	if l, ok := b.find(level, offset); ok {
		return l, true
	}
	if level == 0 {
		return Leaf{}, false
	}
	left, ok := b.findOrCompute(level-1, offset*2)
	if !ok || left.Flags == LeafDuplicate {
		return Leaf{}, false
	}
	right, ok := b.findOrCompute(level-1, offset*2+1)
	if !ok {
		return Leaf{}, false
	}
	rightHash := right.Hash
	if right.Flags == LeafDuplicate {
		rightHash = left.Hash
	}
	var buf [64]byte
	copy(buf[:32], left.Hash[:])
	copy(buf[32:], rightHash[:])
	return Leaf{Offset: offset, Flags: LeafData, Hash: DoubleSHA256(buf[:])}, true
}

// HasTxID reports whether level 0 holds txid (internal order) as a
// hash leaf.
// Input: txid. Output: true when present.
func (b *BUMP) HasTxID(txid [32]byte) bool {
	_, ok := b.leafFor(txid)
	return ok
}

// leafFor finds the level-0 hash leaf equal to txid.
func (b *BUMP) leafFor(txid [32]byte) (Leaf, bool) {
	for _, l := range b.Levels[0] {
		if l.Flags != LeafDuplicate && l.Hash == txid {
			return l, true
		}
	}
	return Leaf{}, false
}

// ComputeRoot computes the merkle root that the path gives for txid.
// Input: txid in internal order.
// Output: the root in internal order (the byte order of a block
// header's merkle-root field), or an error wrapping ErrMalformed when
// txid is not a level-0 leaf or a needed sibling is missing.
func (b *BUMP) ComputeRoot(txid [32]byte) ([32]byte, error) {
	leaf, ok := b.leafFor(txid)
	if !ok {
		return [32]byte{}, malformed("txid is not a level-0 leaf of the bump")
	}
	// A block with a single transaction: the root is the txid.
	if len(b.Levels) == 1 && len(b.Levels[0]) == 1 {
		return txid, nil
	}
	working := txid
	index := leaf.Offset
	for level := range b.Levels {
		sib, ok := b.findOrCompute(level, index^1)
		if !ok {
			return [32]byte{}, malformed("bump level %d lacks the sibling at offset %d", level, index^1)
		}
		sibling := sib.Hash
		if sib.Flags == LeafDuplicate {
			sibling = working
		}
		var buf [64]byte
		if index&1 == 1 {
			copy(buf[:32], sibling[:])
			copy(buf[32:], working[:])
		} else {
			copy(buf[:32], working[:])
			copy(buf[32:], sibling[:])
		}
		working = DoubleSHA256(buf[:])
		index >>= 1
	}
	if index != 0 {
		return [32]byte{}, malformed("bump offset exceeds its tree height")
	}
	return working, nil
}
