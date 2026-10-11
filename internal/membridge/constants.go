// Copyright 2026 Jerry David Chan, Konareef.ai
// SPDX-License-Identifier: Apache-2.0

// internal/membridge/constants.go
package membridge

import "github.com/digitsu/konareef/internal/poseidon"

// Domain-tag constants. DTAG_KEY/DTAG_CELL/DTAG_PROV are Part-B only
// (PRD 4 §3.2.1 + §3.7.1). LEAF_TAG/NODE_TAG mirror the PRD 1 §5.5 tag
// values the conformance-vector file still lists in its `constants`
// block. Since the 2026-06-10 PRD 4 hash swap the tree no longer
// prefixes SHA-256 input with them: leaf and node hashing are Poseidon
// (internal/poseidon), whose domain separation lives in the pinned
// parameter artifact. All five stay byte-disjoint from the PRD 1 §5.4
// T_log tags (0x00, 0x01, 0x03).
const (
	DTAG_KEY  byte = 0x20 // logical-key domain separator
	DTAG_CELL byte = 0x21 // canonical-cell-payload domain separator
	DTAG_PROV byte = 0x22 // provisional-id domain separator (B.6.1)
	LEAF_TAG  byte = 0x10 // PRD 1 §5.5 leaf tag value (vector constant)
	NODE_TAG  byte = 0x11 // PRD 1 §5.5 node tag value (vector constant)
)

// IndexDomainSep is the literal 19 ASCII bytes prefixed to logical_key
// before SHA-256 to derive the cell index (PRD 4 §3.2.5). No null
// terminator, no length prefix — raw bytes only. The index is the one
// part of the derivation that stays SHA-256 after the hash swap.
var IndexDomainSep = []byte("konareef-mem-idx/v1")

// EmptyValueHash is the reserved sentinel for an unpopulated cell
// (PRD 1 §5.5): the field element zero. A populated cell whose Poseidon
// value hash is zero is refused (ErrValueHashZero).
var EmptyValueHash = [32]byte{}

// D is the fixed sparse Merkle tree depth per PRD 1 §5.5.
const D = 20

// HardCapK is the v1 per-pod cell cap (PRD 4 §3.4.1). Fail-closed.
const HardCapK = 500

// RMax is the genesis salt-resample bound (PRD 4 §3.4.2).
const RMax = 8

// EmptyRoots is the PRD 1 §5.5 Poseidon empty-subtree root table:
//
//	EmptyRoots[0] = Poseidon LeafHash(0)
//	EmptyRoots[k] = Poseidon InternalHash(EmptyRoots[k-1], EmptyRoots[k-1])
//
// EmptyRoots[20] is E20 = c5a959b0…d727, the root of the all-empty
// depth-20 tree and the konareef-rinit/v1 memory-free r_init (R-M10).
// Before the D6 migration (konareef-rinit/v1 spec §13) this table held
// the pre-swap SHA-256 roots, whose EmptyRoots[20] (0f2106fa…7790) is
// not a canonical field element.
var EmptyRoots = func() [D + 1][32]byte {
	var out [D + 1][32]byte
	copy(out[:], poseidon.Default().EmptyRoots())
	return out
}()
