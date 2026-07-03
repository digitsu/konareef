// der_gate.go — strict-DER + low-S parser for secp256k1 ECDSA signatures.
//
// Mirrors reef-core's `ReefCore.PublishedPods.DerGate` byte for byte
// against the shared P1.4 conformance vectors at
// `testdata/der_gate/vectors.json`. Both sides MUST report the same
// outcome on the same bytes — wire-format identity is the load-bearing
// property of P1.4.
//
// Enforces the four PRD rules:
//
//  1. Outer SEQUENCE tag (0x30) with minimal definite-length encoding
//     (short form for ≤127 body bytes; one-byte long-form 0x81 only
//     when body ≥128 bytes). All 0x82+ long-forms reject — a
//     secp256k1 ECDSA SEQUENCE never exceeds 255 body bytes.
//  2. Two INTEGERs (r, s) minimally encoded: no superfluous leading
//     0x00 (a leading 0x00 is permitted only when the next byte has
//     its high bit set, to keep the signed INTEGER positive).
//  3. No trailing bytes after the outer SEQUENCE.
//  4. s ≤ n/2 where n is the secp256k1 curve order. konareef rejects
//     high-S — never normalises — so the wire form a third party
//     observed is the same form the verifier checked.
//
// Surface:
//
//   - ErrDerGateReject — sentinel returned by every rule violation.
//   - ParseStrict(der) — (r, s, err); r, s are positive *big.Int on
//     accept, nil on reject.
package identity

import (
	"errors"
	"math/big"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
)

// ErrDerGateReject is returned for any signature that fails strict-DER
// or low-S. Callers MUST surface this verbatim — no normalisation,
// no fallback, no lenient retry. The reef-core Elixir side reports
// the structurally-identical `{:error, :der_gate_reject}` on the
// same bytes.
var ErrDerGateReject = errors.New("der_gate_reject")

// halfN is n/2 where n is the secp256k1 curve order. A signature is
// "low-S" iff its s ≤ halfN. Cached at package load so the hot path
// avoids a re-shift on every call.
var halfN = new(big.Int).Rsh(secp256k1.S256().N, 1)

// curveN is the secp256k1 curve order n. Used for r,s ∈ [1, n-1] range
// enforcement in ClassifyStrictError.
var curveN = secp256k1.S256().N

// ParseStrict validates the DER-encoded signature against the P1.4
// rules and returns r, s as positive *big.Int on success. Any rule
// violation yields (nil, nil, ErrDerGateReject).
//
// The two-return-value-plus-error shape matches the rest of the
// `identity` package; callers compose it with the existing ECDSA
// verify primitives without translation.
func ParseStrict(der []byte) (*big.Int, *big.Int, error) {
	// Outer SEQUENCE tag.
	if len(der) < 2 || der[0] != 0x30 {
		return nil, nil, ErrDerGateReject
	}
	body, rest, ok := readDefiniteLength(der[1:])
	if !ok || len(rest) != 0 {
		return nil, nil, ErrDerGateReject
	}

	r, body, ok := readInteger(body)
	if !ok {
		return nil, nil, ErrDerGateReject
	}
	s, body, ok := readInteger(body)
	if !ok || len(body) != 0 {
		return nil, nil, ErrDerGateReject
	}

	if r.Sign() <= 0 || s.Sign() <= 0 {
		return nil, nil, ErrDerGateReject
	}
	// r,s ∈ [1, n-1] range gate (PRD rule: r,s < n). A strict-DER, low-S
	// signature with r >= n (or s >= n) is still out-of-range and MUST be
	// rejected here — not just classified on the error path. ClassifyStrictError
	// reports rs_out_of_range for these once ParseStrict rejects.
	if r.Cmp(curveN) >= 0 || s.Cmp(curveN) >= 0 {
		return nil, nil, ErrDerGateReject
	}
	if s.Cmp(halfN) > 0 {
		return nil, nil, ErrDerGateReject
	}
	return r, s, nil
}

// ClassifyStrictError returns a granular reason string for a DER byte slice
// that is known to have failed ParseStrict. It attempts a permissive integer
// extraction to distinguish the three normative failure reasons:
//
//   - "high_s"          — strict-DER structure OK but s > n/2.
//   - "rs_out_of_range" — r or s is zero, negative, or ≥ n (structural parse
//     succeeded but range violated).
//   - "strict_der_invalid" — DER structure itself is malformed.
//
// This function is used by Check 4 (PRD 1 §4 / PRD 3 §11.2) to emit
// granular divergence reasons without requiring ParseStrict to grow a
// richer error type. Called only on the error path.
func ClassifyStrictError(der []byte) string {
	// Attempt a permissive parse: minimal structure only (tag + length), no
	// strict-encoding checks. If this fails the bytes are structurally broken.
	if len(der) < 2 || der[0] != 0x30 {
		return "strict_der_invalid"
	}
	body, rest, ok := readDefiniteLength(der[1:])
	if !ok || len(rest) != 0 {
		return "strict_der_invalid"
	}
	r, body, ok := readInteger(body)
	if !ok {
		return "strict_der_invalid"
	}
	s, body, ok := readInteger(body)
	if !ok || len(body) != 0 {
		return "strict_der_invalid"
	}
	// Structure parsed. Classify by value range.
	if r.Sign() <= 0 || s.Sign() <= 0 || r.Cmp(curveN) >= 0 || s.Cmp(curveN) >= 0 {
		return "rs_out_of_range"
	}
	if s.Cmp(halfN) > 0 {
		return "high_s"
	}
	// Structurally valid and values in range — failure must be a strict-DER
	// encoding violation (e.g. non-minimal length, superfluous leading zero).
	return "strict_der_invalid"
}

// readDefiniteLength parses a DER definite-length encoding and returns
// (body, rest, ok). Enforces minimal length encoding: short form when
// ≤127, one-byte long form 0x81 only when body ≥128. Any other long
// form (0x82+) is rejected — a secp256k1 ECDSA SEQUENCE never exceeds
// 255 body bytes, so 0x82+ is always strictly non-minimal here.
func readDefiniteLength(in []byte) ([]byte, []byte, bool) {
	if len(in) == 0 {
		return nil, nil, false
	}
	first := in[0]
	switch {
	case first < 0x80:
		n := int(first)
		if len(in) < 1+n {
			return nil, nil, false
		}
		return in[1 : 1+n], in[1+n:], true
	case first == 0x81:
		if len(in) < 2 {
			return nil, nil, false
		}
		n := int(in[1])
		if n < 0x80 {
			// Not minimal — short form would have sufficed.
			return nil, nil, false
		}
		if len(in) < 2+n {
			return nil, nil, false
		}
		return in[2 : 2+n], in[2+n:], true
	default:
		return nil, nil, false
	}
}

// readInteger parses a DER INTEGER (0x02 tag + length + body) from in
// and returns (value, rest, ok). Enforces minimal-INTEGER encoding:
//
//   - body MUST be at least one byte;
//   - high bit of first byte MUST be unset (r,s are positive unsigned);
//   - first byte 0x00 only permitted when the next byte has its high
//     bit set (otherwise the leading zero is superfluous).
func readInteger(in []byte) (*big.Int, []byte, bool) {
	if len(in) < 2 || in[0] != 0x02 {
		return nil, nil, false
	}
	body, rest, ok := readDefiniteLength(in[1:])
	if !ok || len(body) == 0 {
		return nil, nil, false
	}
	if body[0] >= 0x80 {
		return nil, nil, false
	}
	if body[0] == 0x00 {
		if len(body) == 1 || body[1] < 0x80 {
			return nil, nil, false
		}
	}
	return new(big.Int).SetBytes(body), rest, true
}
