// Copyright 2026 Jerry David Chan, Konareef.ai
// SPDX-License-Identifier: Apache-2.0

// internal/tlog/leb128.go — private minimal unsigned LEB128 encoder.
//
// PRD 1 § 5.4 requires minimal LEB128 encoding for two fields:
// `len(tool_id_utf8)` inside each leaf record, and `|T_log|` inside the
// length-binding wrapper. PRD 1 § 5.2 cites RFC 7049 § 1.3.2 for the
// primitive.
//
// This encoder is deliberately duplicated rather than imported from
// internal/membridge (which exposes `EncodeThoughtID` + a parser). The
// two packages are sibling Phase-1 work; spec coupling between PRD 1
// § 5.4 (T_log) and PRD 4 § 3.2.3 (memory bridge) is incidental, the
// encoder is 12 LOC, and both packages anchor their outputs to upstream
// conformance vectors so divergence would fail loudly. A future
// consolidation MAY promote both to `internal/leb128/` once the two
// packages have settled — see the optional Task 4 in this plan.
//
// T_log only needs the producer side. There is no `Parse` in this file
// because the tlog package never decodes externally supplied LEB128
// bytes (internal/membridge does, for snapshot import).

package tlog

// encodeULEB128 emits the minimal unsigned LEB128 encoding of n.
//
// The "minimal" property is guaranteed by the loop structure: bytes
// are emitted only while n is nonzero, so no trailing zero septet can
// appear after a terminator. For n == 0 the loop emits a single 0x00
// terminator (the unique minimal encoding of zero).
func encodeULEB128(n uint64) []byte {
	if n == 0 {
		return []byte{0x00}
	}
	out := make([]byte, 0, 10) // ceil(64 / 7) = 10
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
