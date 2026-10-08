// Copyright 2026 Jerry David Chan, Konareef.ai
// SPDX-License-Identifier: Apache-2.0

// internal/membridge/derive.go — PRD 4 §3.2 (B.1) byte-exact derivation,
// after the 2026-06-10 hash swap (PRD 4 §3.2.6/§3.2.7, PRD 1 §5.5).
//
// Chain:
//
//	logical_key = DTAG_KEY || ULEB128(32) || pod_salt
//	            || ULEB128(len(tid_bytes)) || tid_bytes
//	index       = be_u32(SHA-256(IndexDomainSep || logical_key)[0:4]) & 0x0FFFFF
//	payload     = DTAG_CELL || ULEB128(len(logical_key)) || logical_key
//	            || content_hash   (32 bytes, no length prefix)
//	value_hash  = Poseidon_arity4(payload chunks)       (PRD 1 §5.5 sponge)
//	leaf_hash   = Poseidon_arity2(value_hash, 0)        (PRD 1 §5.5 leaf)
//
// Only the index stays SHA-256. value_hash and leaf_hash are canonical
// Pallas Fq elements (32 bytes, little-endian), so the tree root is a
// field element with no reduction step (konareef-rinit/v1 spec §0).
package membridge

import (
	"crypto/sha256"
	"encoding/binary"
	"fmt"

	"github.com/digitsu/konareef/internal/poseidon"
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

// ValueHash returns the PRD 1 §5.5 Poseidon value hash of the §3.2.6
// canonical cell payload for (podSalt, thoughtID, contentHash).
//
// Inputs: a 32-byte podSalt, the cell identifier and a 32-byte
// contentHash. Output: the 32-byte little-endian field element, or
// ErrCellSaltLen (salt first, per PRD 4 §3.2.2), or
// ErrSnapshotImportFailed (content hash length, or a payload over the
// 93-byte sponge cap, which a minimal-LEB128 u64 identifier cannot reach).
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
	vh, err := poseidon.Default().ValueHash(payload)
	if err != nil {
		return zero, fmt.Errorf("value_hash: %v: %w", err, ErrSnapshotImportFailed)
	}
	return vh, nil
}

// LeafHash returns the PRD 1 §5.5 Poseidon leaf hash over [valueHash, 0].
//
// Input: a 32-byte little-endian value hash. Output: the leaf hash, or an
// error wrapping ErrSnapshotImportFailed when valueHash is not a
// canonical field element (every ValueHash output is canonical).
func LeafHash(valueHash [32]byte) ([32]byte, error) {
	lh, err := poseidon.Default().LeafHash(valueHash)
	if err != nil {
		return [32]byte{}, fmt.Errorf("leaf_hash: %v: %w", err, ErrSnapshotImportFailed)
	}
	return lh, nil
}
