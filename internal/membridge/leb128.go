// Copyright 2026 Jerry David Chan, Konareef.ai
// SPDX-License-Identifier: Apache-2.0

// internal/membridge/leb128.go — minimal unsigned LEB128 (PRD 4 §3.2.3).
//
// EncodeThoughtID emits the minimal encoding for any uint64. The runtime
// owns the integer value at derivation time so the output is always valid.
//
// ParseThoughtIDBytes consumes externally-supplied bytes (snapshots,
// conformance vectors, on-wire messages, audit trails) and rejects
// non-minimal encodings per the WI-6 normative separation. The encoder
// path is tautological; the parser path is the real validation surface.
package membridge

import "bytes"

// EncodeThoughtID emits the minimal unsigned LEB128 encoding of n.
func EncodeThoughtID(n uint64) []byte {
	if n == 0 {
		return []byte{0x00}
	}
	out := make([]byte, 0, 10)
	for n != 0 {
		b := byte(n & 0x7f)
		n >>= 7
		if n != 0 {
			b |= 0x80
		}
		out = append(out, b)
	}
	return out
}

// ParseThoughtIDBytes decodes b as standard minimal unsigned LEB128 per
// PRD 4 §3.2.3.
//
// Minimality rule (post-Hermes-review correction): the parser performs
// a standard LSB-first ULEB128 decode and then re-encodes the decoded
// value via EncodeThoughtID. Input bytes are minimal iff they equal the
// canonical encoding. This is the textbook ULEB128 minimality check.
//
// This rule correctly accepts encodings such as 0x80 0x80 0x01
// (canonical minimal encoding of 16384, well within the v1 thought_id
// range of 2^21-1 = 2097151) and correctly rejects encodings such as
// 0x80 0x00 (non-minimal 0; canonical minimal encoding of 0 is 0x00).
//
// The earlier interior-0x80 rejection rule was incorrect: it would
// fail-closed on legitimate 16384 thought_ids. See paygate-zk issue #1
// for the upstream conformance-vector text mismatch.
//
// Rejects with ErrLeb128NonMinimal when:
//   - b is empty,
//   - b is truncated (final byte still has the continuation bit set),
//   - trailing bytes follow the terminator,
//   - the decoded value's canonical encoding differs from the input,
//   - decode would consume more than 10 bytes (64-bit overflow guard).
func ParseThoughtIDBytes(b []byte) (uint64, error) {
	if len(b) == 0 {
		return 0, ErrLeb128NonMinimal
	}
	var value uint64
	var shift uint
	for i, c := range b {
		if i >= 10 {
			return 0, ErrLeb128NonMinimal
		}
		value |= uint64(c&0x7f) << shift
		if c&0x80 == 0 {
			// Reject any unconsumed trailing bytes.
			if i != len(b)-1 {
				return 0, ErrLeb128NonMinimal
			}
			// Standard minimality check: encode-and-compare. The input is
			// minimal iff it equals the canonical encoding of the decoded
			// value. This catches 0x80 0x00 (non-minimal 0) and accepts
			// 0x80 0x80 0x01 (canonical minimal encoding of 16384).
			canonical := EncodeThoughtID(value)
			if !bytes.Equal(canonical, b) {
				return 0, ErrLeb128NonMinimal
			}
			return value, nil
		}
		shift += 7
	}
	// Loop fell through with continuation bit still set on last byte.
	return 0, ErrLeb128NonMinimal
}
