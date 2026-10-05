// Copyright 2026 Jerry David Chan, Konareef.ai
// SPDX-License-Identifier: Apache-2.0

// internal/membridge/leaftable.go — the salt-free memory leaf table of a
// memory-bearing publish (konareef-rinit/v1 spec §6.4, MEM-SEAM option
// A1, reef-core#79).
//
// The publisher computes r_init with the lineage salt (§5). The salt-
// dependent part of that work is the per-cell (index, value_hash). The
// leaf table records it next to the salt-free (cell_id, content_hash), so
// a proving path that does not hold the salt can still build the memory
// witness lane. The publisher signs the table; the signature binds each
// cell_id and content_hash to its index and value hash, which the root
// alone does not do (the root binds only index → value_hash).
//
// Canonical bytes (signed as SHA-256(bytes), and sent as is):
//
//	"konareef-mem-leaves/v1"               22 bytes
//	pod_hash                               32 bytes
//	r_init                                 32 bytes, LE Fq
//	be_u32(n)                               4 bytes, 1 ≤ n ≤ HardCapK
//	n × ( be_u64(cell_id)                   8 bytes, bit 63 set, strictly ascending
//	    ‖ content_hash                     32 bytes
//	    ‖ be_u32(index)                     4 bytes, < 2^20, unique
//	    ‖ value_hash )                     32 bytes, LE Fq, not zero
//
// The table holds no salt and no content. Without the salt, a value hash
// does not let a reader test a guess of the content. It is still served
// only to the proving path, never in a public bundle (spec §6.4).
package membridge

import (
	"bytes"
	"encoding/binary"
	"math/big"
	"sort"
)

// LeafTableDomain is the domain string that starts every leaf table. It
// separates a signed table from a signed manifest (which starts with a
// "#!konareef-toml" magic line or TOML text) under the same publisher key.
var LeafTableDomain = []byte("konareef-mem-leaves/v1")

// Sizes of the fixed parts of the canonical bytes.
const (
	leafTableHeaderLen = 22 + 32 + 32 + 4
	leafEntryLen       = 8 + 32 + 4 + 32
)

// fqModulus is the Pallas Fq modulus. A canonical field element is a
// little-endian integer below it (MEM-01 §2).
var fqModulus, _ = new(big.Int).SetString("40000000000000000000000000000000224698fc0994a8dd8c46eb2100000001", 16)

// canonicalFq reports whether le is a canonical LE field element.
func canonicalFq(le [32]byte) bool {
	var be [32]byte
	for i := range le {
		be[31-i] = le[i]
	}
	return new(big.Int).SetBytes(be[:]).Cmp(fqModulus) < 0
}

// ErrLeafTableInvalid means the table bytes are malformed or break a rule
// of the canonical form. ErrLeafTableMismatch means a well-formed table
// does not match the manifest it is paired with (another pod_hash, or
// another cell list). Neither carries table content.
var (
	ErrLeafTableInvalid  = &MembridgeError{CodeStr: "MEMORY_LEAF_TABLE_INVALID"}
	ErrLeafTableMismatch = &MembridgeError{CodeStr: "MEMORY_LEAF_TABLE_MISMATCH"}
)

// Leaf is one row of a leaf table: the salt-free cell and the salted
// tree position and value hash the publisher derived for it.
type Leaf struct {
	CellID      uint64
	ContentHash [32]byte
	Index       uint32
	ValueHash   [32]byte
}

// LeafTable is the parsed leaf table of one published version.
type LeafTable struct {
	PodHash [32]byte
	RInit   [32]byte
	Leaves  []Leaf
}

// NewLeafTable builds the table a memory-bearing publish signs.
//
// Inputs: the pod_hash of the signed manifest, the r_init RInitV1
// returned, the cells it was given and the derivation it returned.
// Output: the table, rows in ascending cell_id, or ErrLeafTableInvalid
// when the cells and the derivation do not describe the same set, or the
// result breaks a rule of the canonical form.
func NewLeafTable(podHash, rInit [32]byte, cells []Cell, derived []DerivedCell) (*LeafTable, error) {
	if len(cells) != len(derived) {
		return nil, ErrLeafTableInvalid
	}
	content := make(map[uint64][]byte, len(cells))
	for _, c := range cells {
		if len(c.ContentHash) != 32 {
			return nil, ErrLeafTableInvalid
		}
		content[c.CellID] = c.ContentHash
	}
	t := &LeafTable{PodHash: podHash, RInit: rInit, Leaves: make([]Leaf, 0, len(derived))}
	for _, d := range derived {
		ch, ok := content[d.CellID]
		if !ok {
			return nil, ErrLeafTableInvalid
		}
		l := Leaf{CellID: d.CellID, Index: d.Index, ValueHash: d.ValueHash}
		copy(l.ContentHash[:], ch)
		t.Leaves = append(t.Leaves, l)
	}
	sort.Slice(t.Leaves, func(i, j int) bool { return t.Leaves[i].CellID < t.Leaves[j].CellID })
	if err := t.validate(); err != nil {
		return nil, err
	}
	return t, nil
}

// Bytes returns the canonical bytes of t (see the file comment). They are
// what the publisher signs and what travels on the wire.
func (t *LeafTable) Bytes() []byte {
	out := make([]byte, 0, leafTableHeaderLen+leafEntryLen*len(t.Leaves))
	out = append(out, LeafTableDomain...)
	out = append(out, t.PodHash[:]...)
	out = append(out, t.RInit[:]...)
	out = binary.BigEndian.AppendUint32(out, uint32(len(t.Leaves)))
	for _, l := range t.Leaves {
		out = binary.BigEndian.AppendUint64(out, l.CellID)
		out = append(out, l.ContentHash[:]...)
		out = binary.BigEndian.AppendUint32(out, l.Index)
		out = append(out, l.ValueHash[:]...)
	}
	return out
}

// ParseLeafTable parses canonical leaf-table bytes.
//
// Input: the bytes. Output: the table, or ErrLeafTableInvalid for a wrong
// domain, a length that is not exactly header + n entries, n outside
// 1..HardCapK, a cell_id without bit 63 or out of ascending order, an
// index ≥ 2^20 or used twice, a zero value hash, or an r_init or value
// hash that is not a canonical field element. It does not check the root
// or the signature; see CheckRoot and the caller. reef-core's
// MemoryLeafTable.parse applies the same rules.
func ParseLeafTable(b []byte) (*LeafTable, error) {
	if len(b) < leafTableHeaderLen || !bytes.Equal(b[:len(LeafTableDomain)], LeafTableDomain) {
		return nil, ErrLeafTableInvalid
	}
	p := b[len(LeafTableDomain):]
	t := &LeafTable{}
	copy(t.PodHash[:], p[0:32])
	copy(t.RInit[:], p[32:64])
	n := binary.BigEndian.Uint32(p[64:68])
	p = p[68:]
	if n == 0 || n > HardCapK || uint64(len(p)) != uint64(n)*leafEntryLen {
		return nil, ErrLeafTableInvalid
	}
	t.Leaves = make([]Leaf, n)
	for i := range t.Leaves {
		e := p[i*leafEntryLen : (i+1)*leafEntryLen]
		l := &t.Leaves[i]
		l.CellID = binary.BigEndian.Uint64(e[0:8])
		copy(l.ContentHash[:], e[8:40])
		l.Index = binary.BigEndian.Uint32(e[40:44])
		copy(l.ValueHash[:], e[44:76])
	}
	if err := t.validate(); err != nil {
		return nil, err
	}
	return t, nil
}

// validate checks the per-row and set rules of the canonical form.
func (t *LeafTable) validate() error {
	if len(t.Leaves) == 0 || len(t.Leaves) > HardCapK || !canonicalFq(t.RInit) {
		return ErrLeafTableInvalid
	}
	indices := make(map[uint32]bool, len(t.Leaves))
	for i, l := range t.Leaves {
		if l.CellID&sourceCellIDHighBit == 0 {
			return ErrLeafTableInvalid
		}
		if i > 0 && t.Leaves[i-1].CellID >= l.CellID {
			return ErrLeafTableInvalid
		}
		if l.Index >= 1<<D || indices[l.Index] {
			return ErrLeafTableInvalid
		}
		if l.ValueHash == EmptyValueHash || !canonicalFq(l.ValueHash) {
			return ErrLeafTableInvalid
		}
		indices[l.Index] = true
	}
	return nil
}

// ValueHashes returns the table's index → value_hash map, the form the
// feeder's memory lane is built from.
func (t *LeafTable) ValueHashes() map[uint32][32]byte {
	out := make(map[uint32][32]byte, len(t.Leaves))
	for _, l := range t.Leaves {
		out[l.Index] = l.ValueHash
	}
	return out
}

// Cells returns the table's (cell_id, content_hash) list in ascending
// cell_id.
func (t *LeafTable) Cells() []Cell {
	out := make([]Cell, len(t.Leaves))
	for i, l := range t.Leaves {
		out[i] = Cell{CellID: l.CellID, ContentHash: append([]byte(nil), l.ContentHash[:]...)}
	}
	return out
}

// CheckRoot recomputes the sparse root over the table's leaves.
//
// Output: nil when it equals t.RInit; ErrRInitMismatch when it does not;
// an error wrapping ErrSnapshotImportFailed for a non-canonical value
// hash. No salt is used: this is the salt-free half of the root check.
func (t *LeafTable) CheckRoot() error {
	root, err := SparseRoot(t.ValueHashes())
	if err != nil {
		return err
	}
	if root != t.RInit {
		return ErrRInitMismatch
	}
	return nil
}

// SameCells reports whether a and b hold exactly the same (cell_id,
// content_hash) pairs, ignoring order. A duplicate cell_id in either list
// makes them unequal.
func SameCells(a, b []Cell) bool {
	if len(a) != len(b) {
		return false
	}
	sa, sb := sortedCells(a), sortedCells(b)
	for i := range sa {
		if sa[i].CellID != sb[i].CellID || !bytes.Equal(sa[i].ContentHash, sb[i].ContentHash) {
			return false
		}
		if i > 0 && sa[i-1].CellID == sa[i].CellID {
			return false
		}
	}
	return true
}

// sortedCells returns a copy of cells in ascending cell_id.
func sortedCells(cells []Cell) []Cell {
	out := append([]Cell(nil), cells...)
	sort.SliceStable(out, func(i, j int) bool { return out[i].CellID < out[j].CellID })
	return out
}
