// Copyright 2026 Jerry David Chan, Konareef.ai
// SPDX-License-Identifier: Apache-2.0

// internal/membridge/rinit_v2.go — the konareef-rinit/v2 derivation, the
// touched-cell rule and the read-lane relation
// (docs/reference/konareef-rinit-v2-spec.md §2, §5, §6; CL-4-live,
// reef-core#84, owner decisions T-A, W-A, O1-b, O1-b.ii).
//
// For a 32-byte pod_salt and the resolved cells (cell_id, content_hash):
//
//	for each cell, ascending cell_id:
//	  logical_key = LogicalKey(pod_salt, cell_id)                 v1 §5, unchanged
//	  key_tag     = SHA-256("konareef-mem-ktag/v1" ‖ logical_key)
//	  payload     = 0x23 ‖ key_tag ‖ content_hash                 65 bytes
//	  value_hash  = Poseidon_arity4(chunks(payload))              PRD 1 §5.5
//	  index       = be_u32(SHA-256("konareef-mem-idx/v2" ‖ key_tag)[0:4]) & 0x0FFFFF
//	r_init = SparseRoot({index → value_hash})
//
// The payload and the index depend on the salt only through key_tag, a
// one-way per-cell value. So a party that holds key_tag (the leaf table v2,
// the PS-1 lane) can recompute the index and the value hash with no salt.
// The salt stays with the publisher (R-M14).
package membridge

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"sort"

	"github.com/digitsu/konareef/internal/poseidon"
)

// DTAG_CELL_V2 is the konareef-rinit/v2 payload domain tag. It is
// byte-disjoint from DTAG_KEY, DTAG_CELL, DTAG_PROV, LEAF_TAG, NODE_TAG and
// the T_log tags.
const DTAG_CELL_V2 byte = 0x23

// PayloadV2Len is the length of a konareef-rinit/v2 payload:
// 1 tag byte, 32 key_tag bytes and 32 content_hash bytes.
const PayloadV2Len = 1 + 32 + 32

// KeyTagDomain is the 20 ASCII bytes prefixed to logical_key before
// SHA-256 to derive key_tag. No length prefix and no terminator.
var KeyTagDomain = []byte("konareef-mem-ktag/v1")

// IndexDomainSepV2 is the 19 ASCII bytes prefixed to key_tag before
// SHA-256 to derive the v2 cell index (O1-b.ii). It differs from the v1
// IndexDomainSep, so a v1 and a v2 index never share a preimage.
var IndexDomainSepV2 = []byte("konareef-mem-idx/v2")

// Refusal codes added by konareef-rinit/v2 (spec §9). The feeder, PS-1 and
// the circuit use the same strings.
var (
	ErrMemoryTouchedCellInvalid  = &MembridgeError{CodeStr: "MEMORY_TOUCHED_CELL_INVALID"}
	ErrMemoryTouchedCellMismatch = &MembridgeError{CodeStr: "MEMORY_TOUCHED_CELL_MISMATCH"}
	ErrMemoryPayloadMismatch     = &MembridgeError{CodeStr: "MEMORY_PAYLOAD_MISMATCH"}
	ErrMemoryIndexMismatch       = &MembridgeError{CodeStr: "MEMORY_INDEX_MISMATCH"}
	ErrMemoryEmptySlotRead       = &MembridgeError{CodeStr: "MEMORY_EMPTY_SLOT_READ"}
	ErrMemoryWriteRefused        = &MembridgeError{CodeStr: "MEMORY_WRITE_REFUSED"}
)

// KeyTag derives the per-cell key_tag of (podSalt, cellID).
//
// Inputs: a 32-byte podSalt and the cell identifier. Output: the 32-byte
// SHA-256 tag, or ErrCellSaltLen. The salt never appears in an error.
func KeyTag(podSalt []byte, cellID uint64) ([32]byte, error) {
	lk, err := LogicalKey(podSalt, cellID)
	if err != nil {
		return [32]byte{}, err
	}
	h := sha256.New()
	h.Write(KeyTagDomain)
	h.Write(lk)
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out, nil
}

// CellIndexV2 derives the 20-bit tree address of a cell from its key_tag.
//
// Input: the key_tag. Output: be_u32(SHA-256(IndexDomainSepV2 ‖ keyTag)[0:4])
// masked to 20 bits. No salt is needed.
func CellIndexV2(keyTag [32]byte) uint32 {
	h := sha256.New()
	h.Write(IndexDomainSepV2)
	h.Write(keyTag[:])
	return binary.BigEndian.Uint32(h.Sum(nil)[0:4]) & 0x0FFFFF
}

// CanonicalCellPayloadV2 builds the 65-byte payload 0x23 ‖ keyTag ‖
// contentHash.
//
// Inputs: the key_tag and the 32-byte content hash. Output: the payload.
func CanonicalCellPayloadV2(keyTag, contentHash [32]byte) []byte {
	out := make([]byte, 0, PayloadV2Len)
	out = append(out, DTAG_CELL_V2)
	out = append(out, keyTag[:]...)
	return append(out, contentHash[:]...)
}

// ValueHashV2 returns the PRD 1 §5.5 Poseidon value hash of the v2
// payload of (keyTag, contentHash).
//
// Inputs: the key_tag and the content hash. Output: the 32-byte
// little-endian field element, or an error wrapping
// ErrSnapshotImportFailed (unreachable for a 65-byte payload).
func ValueHashV2(keyTag, contentHash [32]byte) ([32]byte, error) {
	vh, err := poseidon.Default().ValueHash(CanonicalCellPayloadV2(keyTag, contentHash))
	if err != nil {
		return [32]byte{}, fmt.Errorf("value_hash: %v: %w", err, ErrSnapshotImportFailed)
	}
	return vh, nil
}

// DerivedCellV2 is the per-cell output of RInitV2: the salt-free cell, the
// key_tag the salt holder derived for it, and the tree address and value
// hash that enter the root. It holds no salt.
type DerivedCellV2 struct {
	CellID      uint64
	ContentHash [32]byte
	KeyTag      [32]byte
	Index       uint32
	ValueHash   [32]byte
}

// RInitV2 computes the konareef-rinit/v2 root over cells under podSalt.
//
// Inputs: a 32-byte podSalt and the resolved cells in any order. Output:
// the 32-byte little-endian Poseidon root, the per-cell derivation in
// ascending CellID order, or the first refusal (R-M21, cells processed in
// ascending cell_id): ErrCellSaltLen, ErrCellCapExceeded,
// ErrSnapshotImportFailed (content hash not 32 bytes), ErrCellDuplicateID,
// ErrCellIndexCollision (two cell_ids with one v2 index; no relocation) or
// ErrValueHashZero. The empty cell set gives E20 regardless of the salt.
//
// The salt never appears in an error: every refusal is a bare sentinel.
func RInitV2(podSalt []byte, cells []Cell) ([32]byte, []DerivedCellV2, error) {
	var zero [32]byte
	if len(podSalt) != 32 {
		return zero, nil, ErrCellSaltLen
	}
	if err := EnforceHardCap(len(cells)); err != nil {
		return zero, nil, err
	}
	sorted := sortedCells(cells)
	byIndex := make(map[uint32][32]byte, len(sorted))
	derived := make([]DerivedCellV2, 0, len(sorted))
	for i, c := range sorted {
		if len(c.ContentHash) != 32 {
			return zero, nil, ErrSnapshotImportFailed
		}
		if i > 0 && sorted[i-1].CellID == c.CellID {
			return zero, nil, ErrCellDuplicateID
		}
		kt, err := KeyTag(podSalt, c.CellID)
		if err != nil {
			return zero, nil, err
		}
		idx := CellIndexV2(kt)
		if _, taken := byIndex[idx]; taken {
			return zero, nil, ErrCellIndexCollision
		}
		var ch [32]byte
		copy(ch[:], c.ContentHash)
		vh, err := ValueHashV2(kt, ch)
		if err != nil {
			return zero, nil, err
		}
		if vh == EmptyValueHash {
			return zero, nil, ErrValueHashZero
		}
		byIndex[idx] = vh
		derived = append(derived, DerivedCellV2{CellID: c.CellID, ContentHash: ch, KeyTag: kt, Index: idx, ValueHash: vh})
	}
	root, err := SparseRoot(byIndex)
	if err != nil {
		return zero, nil, err
	}
	return root, derived, nil
}

// TouchedCellID applies the touched-cell rule R-M23 (T-A): the touched
// cell of a memory-bearing run is the committed cell with the lowest
// cell_id, in unsigned 64-bit order. Declaration order does not matter.
//
// Input: the committed cells. Output: the lowest cell_id, or
// ErrMemoryTouchedCellInvalid for an empty list (a memory-free run has no
// touched cell).
func TouchedCellID(cells []Cell) (uint64, error) {
	if len(cells) == 0 {
		return 0, ErrMemoryTouchedCellInvalid
	}
	lowest := cells[0].CellID
	for _, c := range cells[1:] {
		if c.CellID < lowest {
			lowest = c.CellID
		}
	}
	return lowest, nil
}

// ReadLane is the salt-free part of a v2 PS-1 memory lane (spec R-M26):
// the root, the touched cell's index, value hash, key_tag and content
// hash, and its LSB-first authentication path.
type ReadLane struct {
	RInit       [32]byte
	Index       uint32
	ValueHashIn [32]byte
	Siblings    [D][32]byte
	KeyTag      [32]byte
	ContentHash [32]byte
}

// CheckReadLane applies the PS-1 checks (spec R-M27) and the
// konareef-pod-step-v1.2 read relation (R-M28, W-A) to a lane.
//
// Inputs: the lane, the payload_in the step proves over (PS-1 builds it as
// CanonicalCellPayloadV2(lane.KeyTag, lane.ContentHash); a test can pass a
// forged one), and the value the step writes back. Output: nil, or the
// first refusal in spec order: ErrMemoryEmptySlotRead (value_hash_in = 0),
// ErrMemoryPayloadMismatch (payload_in is not 65 bytes starting 0x23, is
// not built from the lane's key_tag and content_hash, or does not hash to
// value_hash_in), ErrMemoryIndexMismatch (index ≠ CellIndexV2(key_tag), or
// the path does not authenticate to r_init) or ErrMemoryWriteRefused
// (valueHashOut ≠ value_hash_in).
//
// It holds no leaf table, as PS-1 holds none: it proves that some
// committed cell is read, not which one (spec §6 residual). The feeder
// enforces the R-M23 choice separately.
func CheckReadLane(l ReadLane, payloadIn []byte, valueHashOut [32]byte) error {
	if l.ValueHashIn == EmptyValueHash {
		return ErrMemoryEmptySlotRead
	}
	if len(payloadIn) != PayloadV2Len || payloadIn[0] != DTAG_CELL_V2 ||
		!bytes.Equal(payloadIn, CanonicalCellPayloadV2(l.KeyTag, l.ContentHash)) {
		return ErrMemoryPayloadMismatch
	}
	vh, err := ValueHashV2(l.KeyTag, l.ContentHash)
	if err != nil || vh != l.ValueHashIn {
		return ErrMemoryPayloadMismatch
	}
	if l.Index != CellIndexV2(l.KeyTag) {
		return ErrMemoryIndexMismatch
	}
	leaf, err := LeafHash(l.ValueHashIn)
	if err != nil {
		return ErrMemoryPayloadMismatch
	}
	root, err := VerifyAuthPath(l.Index, leaf, l.Siblings)
	if err != nil || root != l.RInit {
		return ErrMemoryIndexMismatch
	}
	if valueHashOut != l.ValueHashIn {
		return ErrMemoryWriteRefused
	}
	return nil
}

// sortCellsV2 sorts derived cells in ascending cell_id, in place.
func sortCellsV2(cells []DerivedCellV2) {
	sort.Slice(cells, func(i, j int) bool { return cells[i].CellID < cells[j].CellID })
}
