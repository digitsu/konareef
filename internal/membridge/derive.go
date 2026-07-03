// internal/membridge/derive.go — PRD 4 §3.2 (B.1) byte-exact derivation.
//
// Chain:
//
//	logical_key = DTAG_KEY || ULEB128(32) || pod_salt
//	            || ULEB128(len(tid_bytes)) || tid_bytes
//	index       = be_u32(SHA-256(IndexDomainSep || logical_key)[0:4]) & 0x0FFFFF
//	payload     = DTAG_CELL || ULEB128(len(logical_key)) || logical_key
//	            || content_hash   (32 bytes, no length prefix)
//	value_hash  = SHA-256(payload)
//	leaf_hash   = SHA-256(LEAF_TAG || value_hash)
package membridge

import (
	"crypto/sha256"
	"encoding/binary"
)

// LogicalKey constructs the canonical logical-key byte string for
// (podSalt, thoughtID). podSalt MUST be exactly 32 bytes; otherwise
// ErrCellSaltLen is returned and no other field is computed.
func LogicalKey(podSalt []byte, thoughtID uint64) ([]byte, error) {
	if len(podSalt) != 32 {
		return nil, ErrCellSaltLen
	}
	tid := EncodeThoughtID(thoughtID)
	saltLenLEB := EncodeThoughtID(uint64(len(podSalt)))
	tidLenLEB := EncodeThoughtID(uint64(len(tid)))
	out := make([]byte, 0, 1+len(saltLenLEB)+len(podSalt)+len(tidLenLEB)+len(tid))
	out = append(out, DTAG_KEY)
	out = append(out, saltLenLEB...) // ULEB128(32) == 0x20
	out = append(out, podSalt...)
	out = append(out, tidLenLEB...)
	out = append(out, tid...)
	return out, nil
}

// CellIndex computes the 20-bit Merkle address per §3.2.5.
func CellIndex(podSalt []byte, thoughtID uint64) (uint32, error) {
	lk, err := LogicalKey(podSalt, thoughtID)
	if err != nil {
		return 0, err
	}
	h := sha256.New()
	h.Write(IndexDomainSep)
	h.Write(lk)
	sum := h.Sum(nil)
	raw := binary.BigEndian.Uint32(sum[0:4])
	return raw & 0x0FFFFF, nil
}

// CanonicalCellPayload constructs the §3.2.6 payload. contentHash MUST
// be exactly 32 bytes.
func CanonicalCellPayload(podSalt []byte, thoughtID uint64, contentHash []byte) ([]byte, error) {
	if len(contentHash) != 32 {
		return nil, ErrSnapshotImportFailed
	}
	lk, err := LogicalKey(podSalt, thoughtID)
	if err != nil {
		return nil, err
	}
	lkLenLEB := EncodeThoughtID(uint64(len(lk)))
	out := make([]byte, 0, 1+len(lkLenLEB)+len(lk)+32)
	out = append(out, DTAG_CELL)
	out = append(out, lkLenLEB...)
	out = append(out, lk...)
	out = append(out, contentHash...)
	return out, nil
}

// ValueHash returns SHA-256(canonical_cell_payload).
func ValueHash(podSalt []byte, thoughtID uint64, contentHash []byte) ([32]byte, error) {
	var zero [32]byte
	// Surface salt-length errors before content-hash errors so callers
	// see the higher-priority fail-closed code per PRD 4 §3.2.2.
	if len(podSalt) != 32 {
		return zero, ErrCellSaltLen
	}
	payload, err := CanonicalCellPayload(podSalt, thoughtID, contentHash)
	if err != nil {
		return zero, err
	}
	return sha256.Sum256(payload), nil
}

// LeafHash returns SHA-256(LEAF_TAG || valueHash) per PRD 1 §5.5.
func LeafHash(valueHash [32]byte) [32]byte {
	h := sha256.New()
	h.Write([]byte{LEAF_TAG})
	h.Write(valueHash[:])
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}
