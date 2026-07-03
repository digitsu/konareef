// internal/membridge/constants.go
package membridge

import "crypto/sha256"

// Domain-tag constants. DTAG_KEY/DTAG_CELL/DTAG_PROV are Part-B only
// (PRD 4 §3.2.1 + §3.7.1). LEAF_TAG/NODE_TAG are PRD 1 §5.5 tree tags.
// All five are byte-disjoint from PRD 1 §5.4 T_log tags (0x00, 0x01, 0x03).
const (
	DTAG_KEY  byte = 0x20 // logical-key domain separator
	DTAG_CELL byte = 0x21 // canonical-cell-payload domain separator
	DTAG_PROV byte = 0x22 // provisional-id domain separator (B.6.1)
	LEAF_TAG  byte = 0x10 // PRD 1 §5.5 leaf hashing tag
	NODE_TAG  byte = 0x11 // PRD 1 §5.5 internal-node hashing tag
)

// IndexDomainSep is the literal 19 ASCII bytes prefixed to logical_key
// before SHA-256 to derive the cell index (PRD 4 §3.2.5). No null
// terminator, no length prefix — raw bytes only.
var IndexDomainSep = []byte("konareef-mem-idx/v1")

// EmptyValueHash is the reserved sentinel for an unpopulated cell
// (PRD 1 §5.5). Distinct from SHA-256 of any well-formed payload.
var EmptyValueHash = [32]byte{}

// D is the fixed sparse Merkle tree depth per PRD 1 §5.5.
const D = 20

// HardCapK is the v1 per-pod cell cap (PRD 4 §3.4.1). Fail-closed.
const HardCapK = 500

// RMax is the genesis salt-resample bound (PRD 4 §3.4.2).
const RMax = 8

// EmptyRoots is the precomputed PRD 1 §5.5 empty-subtree root table.
// EmptyRoots[0] = SHA-256(LEAF_TAG || 0x00*32)
// EmptyRoots[k] = SHA-256(NODE_TAG || EmptyRoots[k-1] || EmptyRoots[k-1])
// EmptyRoots[20] is the root of the all-empty depth-20 tree.
var EmptyRoots = func() [21][32]byte {
	var out [21][32]byte
	h := sha256.New()
	h.Write([]byte{LEAF_TAG})
	h.Write(EmptyValueHash[:])
	copy(out[0][:], h.Sum(nil))
	for k := 1; k <= D; k++ {
		h.Reset()
		h.Write([]byte{NODE_TAG})
		h.Write(out[k-1][:])
		h.Write(out[k-1][:])
		copy(out[k][:], h.Sum(nil))
	}
	return out
}()
