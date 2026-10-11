// Copyright 2026 Jerry David Chan, Konareef.ai
// SPDX-License-Identifier: Apache-2.0

// internal/membridge/leaftable_v2.go — the konareef-rinit/v2 memory leaf
// table (docs/reference/konareef-rinit-v2-spec.md §3, R-M19 v2).
//
// A memory-bearing --zk publish signs this table with the publisher key
// that signs the manifest (DER ECDSA over SHA-256 of the bytes). Canonical
// bytes:
//
//	"konareef-mem-leaves/v2"                     22 bytes
//	pod_hash                                     32 bytes
//	r_init                                       32 bytes, LE Fq
//	be_u32(n)                                     4 bytes, 1 ≤ n ≤ HardCapK
//	n × ( be_u64(cell_id)                         8 bytes, bit 63 set, strictly ascending
//	    ‖ content_hash                           32 bytes
//	    ‖ key_tag                                32 bytes
//	    ‖ be_u32(index)                           4 bytes, < 2^20, unique
//	    ‖ value_hash )                           32 bytes, LE Fq, not zero
//
// Unlike v1, every row is checkable with no salt: the index and the value
// hash derive from key_tag (CheckRows), and the root from the rows
// (CheckRoot). The signature still binds each cell_id to its key_tag,
// because key_tag is not derivable without the salt.
//
// The checks are split by layer. ParseLeafTableV2 applies only the
// structural rules, which are also all that reef-core applies (spec §3).
// CheckRows and CheckRoot are the feeder's run-time steps d and e (§4).
package membridge

import (
	"bytes"
	"encoding/binary"
)

// LeafTableDomainV2 is the domain string that starts every v2 leaf table.
// It has the same length as the v1 LeafTableDomain, so a v1 table fails
// the v2 domain check, not a length check.
var LeafTableDomainV2 = []byte("konareef-mem-leaves/v2")

// Sizes of the fixed parts of the v2 canonical bytes.
const (
	leafTableV2HeaderLen = 22 + 32 + 32 + 4     // 90
	leafEntryV2Len       = 8 + 32 + 32 + 4 + 32 // 108
)

// LeafV2 is one row of a v2 leaf table.
type LeafV2 struct {
	CellID      uint64
	ContentHash [32]byte
	KeyTag      [32]byte
	Index       uint32
	ValueHash   [32]byte
}

// LeafTableV2 is the parsed v2 leaf table of one published version.
type LeafTableV2 struct {
	PodHash [32]byte
	RInit   [32]byte
	Leaves  []LeafV2
}

// NewLeafTableV2 builds the table a memory-bearing publish signs.
//
// Inputs: the pod_hash of the signed manifest, the r_init RInitV2 returned
// and the derivation it returned. Output: the table, rows in ascending
// cell_id, or ErrLeafTableInvalid when the result breaks a structural or
// row rule (which an honest RInitV2 output never does).
func NewLeafTableV2(podHash, rInit [32]byte, derived []DerivedCellV2) (*LeafTableV2, error) {
	sorted := append([]DerivedCellV2(nil), derived...)
	sortCellsV2(sorted)
	t := &LeafTableV2{PodHash: podHash, RInit: rInit, Leaves: make([]LeafV2, len(sorted))}
	for i, d := range sorted {
		t.Leaves[i] = LeafV2{CellID: d.CellID, ContentHash: d.ContentHash, KeyTag: d.KeyTag, Index: d.Index, ValueHash: d.ValueHash}
	}
	if err := t.validateStructure(); err != nil {
		return nil, err
	}
	if err := t.CheckRows(); err != nil {
		return nil, err
	}
	return t, nil
}

// Bytes returns the canonical bytes of t (see the file comment). They are
// what the publisher signs and what travels on the wire.
func (t *LeafTableV2) Bytes() []byte {
	out := make([]byte, 0, leafTableV2HeaderLen+leafEntryV2Len*len(t.Leaves))
	out = append(out, LeafTableDomainV2...)
	out = append(out, t.PodHash[:]...)
	out = append(out, t.RInit[:]...)
	out = binary.BigEndian.AppendUint32(out, uint32(len(t.Leaves)))
	for _, l := range t.Leaves {
		out = binary.BigEndian.AppendUint64(out, l.CellID)
		out = append(out, l.ContentHash[:]...)
		out = append(out, l.KeyTag[:]...)
		out = binary.BigEndian.AppendUint32(out, l.Index)
		out = append(out, l.ValueHash[:]...)
	}
	return out
}

// ParseLeafTableV2 parses canonical v2 leaf-table bytes and applies the
// spec §3 structural rules only.
//
// Input: the bytes. Output: the table, or ErrLeafTableInvalid for a domain
// other than LeafTableDomainV2 (a v1 table included), a length that is not
// exactly header + n rows, n outside 1..HardCapK, a cell_id without bit 63
// or out of strictly ascending order, an index ≥ 2^20 or used twice, a
// zero value hash, or an r_init or value hash that is not a canonical
// field element. It does not check the signature, the row rules or the
// root: see the caller, CheckRows and CheckRoot. reef-core applies the
// same structural rules and no others.
func ParseLeafTableV2(b []byte) (*LeafTableV2, error) {
	if len(b) < leafTableV2HeaderLen || !bytes.Equal(b[:len(LeafTableDomainV2)], LeafTableDomainV2) {
		return nil, ErrLeafTableInvalid
	}
	p := b[len(LeafTableDomainV2):]
	t := &LeafTableV2{}
	copy(t.PodHash[:], p[0:32])
	copy(t.RInit[:], p[32:64])
	n := binary.BigEndian.Uint32(p[64:68])
	p = p[68:]
	if n == 0 || n > HardCapK || uint64(len(p)) != uint64(n)*leafEntryV2Len {
		return nil, ErrLeafTableInvalid
	}
	t.Leaves = make([]LeafV2, n)
	for i := range t.Leaves {
		e := p[i*leafEntryV2Len : (i+1)*leafEntryV2Len]
		l := &t.Leaves[i]
		l.CellID = binary.BigEndian.Uint64(e[0:8])
		copy(l.ContentHash[:], e[8:40])
		copy(l.KeyTag[:], e[40:72])
		l.Index = binary.BigEndian.Uint32(e[72:76])
		copy(l.ValueHash[:], e[76:108])
	}
	if err := t.validateStructure(); err != nil {
		return nil, err
	}
	return t, nil
}

// validateStructure checks the spec §3 structural rules.
func (t *LeafTableV2) validateStructure() error {
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

// CheckRows applies the spec §3 row rules (feeder step d): for every row,
// index = CellIndexV2(key_tag) and value_hash = ValueHashV2(key_tag,
// content_hash).
//
// Output: nil, or ErrLeafTableInvalid for the first row that breaks a
// rule. No salt is used.
func (t *LeafTableV2) CheckRows() error {
	for _, l := range t.Leaves {
		if l.Index != CellIndexV2(l.KeyTag) {
			return ErrLeafTableInvalid
		}
		vh, err := ValueHashV2(l.KeyTag, l.ContentHash)
		if err != nil || vh != l.ValueHash {
			return ErrLeafTableInvalid
		}
	}
	return nil
}

// CheckRoot recomputes the sparse root over the table's rows (feeder step
// e).
//
// Output: nil when it equals t.RInit; ErrRInitMismatch when it does not;
// an error wrapping ErrSnapshotImportFailed for a non-canonical value
// hash. No salt is used.
func (t *LeafTableV2) CheckRoot() error {
	root, err := SparseRoot(t.ValueHashes())
	if err != nil {
		return err
	}
	if root != t.RInit {
		return ErrRInitMismatch
	}
	return nil
}

// ValueHashes returns the table's index → value_hash map, the form the
// feeder builds the authentication path from.
func (t *LeafTableV2) ValueHashes() map[uint32][32]byte {
	out := make(map[uint32][32]byte, len(t.Leaves))
	for _, l := range t.Leaves {
		out[l.Index] = l.ValueHash
	}
	return out
}

// Cells returns the table's (cell_id, content_hash) list in ascending
// cell_id.
func (t *LeafTableV2) Cells() []Cell {
	out := make([]Cell, len(t.Leaves))
	for i, l := range t.Leaves {
		out[i] = Cell{CellID: l.CellID, ContentHash: append([]byte(nil), l.ContentHash[:]...)}
	}
	return out
}

// Leaf returns the row of cellID.
//
// Input: a cell_id. Output: the row and true, or a zero row and false when
// the table has no such row.
func (t *LeafTableV2) Leaf(cellID uint64) (LeafV2, bool) {
	for _, l := range t.Leaves {
		if l.CellID == cellID {
			return l, true
		}
	}
	return LeafV2{}, false
}
