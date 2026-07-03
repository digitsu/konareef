// internal/membridge/provisional.go — PRD 4 §B.6.1 (WI-5) normative.
//
// provisional_id = be_u64(SHA-256(
//
//	DTAG_PROV || content_hash || be_u64(task_id) || be_u32(ordinal)
//
// )[0:8])
//
// Reconciliation is byte-exact equality against the eventual
// persistent thought_id; mismatch fails closed.
package membridge

import (
	"crypto/sha256"
	"encoding/binary"
	"fmt"
)

// ProvisionalID computes the deterministic capture-time provisional
// thought_id per §B.6.1. contentHash MUST be exactly 32 bytes.
func ProvisionalID(contentHash []byte, taskID uint64, ordinal uint32) (uint64, error) {
	if len(contentHash) != 32 {
		return 0, fmt.Errorf("provisional id: content_hash len=%d, want 32: %w",
			len(contentHash), ErrSnapshotImportFailed)
	}
	preimage := make([]byte, 0, 1+32+8+4)
	preimage = append(preimage, DTAG_PROV)
	preimage = append(preimage, contentHash...)
	var b8 [8]byte
	binary.BigEndian.PutUint64(b8[:], taskID)
	preimage = append(preimage, b8[:]...)
	var b4 [4]byte
	binary.BigEndian.PutUint32(b4[:], ordinal)
	preimage = append(preimage, b4[:]...)
	sum := sha256.Sum256(preimage)
	return binary.BigEndian.Uint64(sum[0:8]), nil
}

// ReconcileProvisional asserts the persistent thought_id matches the
// provisional id byte-for-byte. Mismatch is the §B.6.1 fail-closed gate.
func ReconcileProvisional(provisional, persistent uint64) error {
	if provisional != persistent {
		return ErrProvisionalIDMismatch
	}
	return nil
}
