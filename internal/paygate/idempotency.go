// internal/paygate/idempotency.go — PRD 2 § 6.5 errata-locked preimage.
//
// preimage     = ULEB128(len(circuit_id_bytes)) ‖ circuit_id_bytes
//
//	‖ be_u64(step_index)             (8 bytes, fixed)
//	‖ h_p                            (32 bytes, fixed)
//
// Idempotency-Key = hex_lower( SHA-256(preimage) )
//
// circuit_id_bytes is the UTF-8 NFC bytes of the circuit_id tstr.
// Per the PRD P1.8 normative-encoding rationale, ULEB128 length prefix
// + fixed-width big-endian step_index removes all delimiter ambiguity
// the upstream PRD 2 § 6.5 erratum (2026-06-06) flagged.
package paygate

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"

	"golang.org/x/text/unicode/norm"
)

// encodeULEB128 returns the minimal-length unsigned LEB128 encoding of n.
func encodeULEB128(n uint64) []byte {
	if n == 0 {
		return []byte{0}
	}
	var out []byte
	for n > 0 {
		b := byte(n & 0x7f)
		n >>= 7
		if n != 0 {
			b |= 0x80
		}
		out = append(out, b)
	}
	return out
}

// IdempotencyPreimage returns the byte-exact preimage from PRD 2 § 6.5
// errata. circuitID is NFC-normalised internally before the byte
// sequence is computed, so canonically-equivalent Unicode forms
// (composed vs decomposed) always produce the same preimage and the
// same idempotency key. Callers SHOULD pass NFC-normalised circuit IDs
// already, but the function is defensive: an upstream component that
// forgets to normalise cannot produce a divergent key and double-bill.
func IdempotencyPreimage(circuitID string, stepIndex uint64, hP [32]byte) []byte {
	cid := norm.NFC.Bytes([]byte(circuitID))
	lenPrefix := encodeULEB128(uint64(len(cid)))
	var stepBytes [8]byte
	binary.BigEndian.PutUint64(stepBytes[:], stepIndex)
	out := make([]byte, 0, len(lenPrefix)+len(cid)+8+32)
	out = append(out, lenPrefix...)
	out = append(out, cid...)
	out = append(out, stepBytes[:]...)
	out = append(out, hP[:]...)
	return out
}

// IdempotencyKey returns hex_lower(SHA-256(preimage)) — 64 lowercase hex
// ASCII characters, suitable for the `Idempotency-Key` request header.
func IdempotencyKey(circuitID string, stepIndex uint64, hP [32]byte) string {
	preimage := IdempotencyPreimage(circuitID, stepIndex, hP)
	sum := sha256.Sum256(preimage)
	return hex.EncodeToString(sum[:])
}
