// Package verify — RFC 8949 § 4.2 deterministic-CBOR canonicality
// validator (Round-1 B3 fix).
//
// The fxamacker/cbor v2 library exposes options for duplicate-key
// rejection, indefinite-length rejection, and tag rejection, but does
// NOT enforce the two remaining "core deterministic" rules from
// RFC 8949 § 4.2.1:
//
//  1. integers, lengths, and simple values MUST use the shortest form
//     encoding (no leading-zero promotion such as 0x18 0x17 for the
//     value 23, which fits in the major-type+5-bit head).
//
//  2. map keys MUST be sorted by length-first then lexicographic byte
//     order of their canonical CBOR encoding (RFC 8949 § 4.2.1, bullet
//     3 — the deterministic-encoding rule used by the konareef Bundle
//     v2 wire contract: shorter encoded keys MUST sort before longer
//     ones, and equal-length keys are compared bytewise).
//
// validateCanonicalCBOR walks the raw CBOR byte stream once and rejects
// any non-canonical input with ErrMalformedCBOR (the wire-stable code
// for malformed/non-canonical bundles per PRD 3 § 12.3; the taxonomy
// does not carve out a separate ErrBundleNonCanonical so we wrap the
// closest stable code with a divergence message naming the rule).
package verify

import (
	"bytes"
	"encoding/binary"
	"fmt"
)

// validateCanonicalCBOR walks `input` as a single CBOR data item and
// asserts every nested integer/length is encoded in shortest form and
// every map's keys are in canonical lexicographic order. On the first
// violation it returns an ErrMalformedCBOR wrap describing the rule
// that failed.
//
// The walker is informational-only: it does NOT mutate `input` and it
// does NOT decode into typed Go values. It exists solely to plug the
// canonicality holes the upstream library leaves open.
func validateCanonicalCBOR(input []byte) error {
	n, err := walkCanonical(input, 0)
	if err != nil {
		return err
	}
	if n != len(input) {
		return fmt.Errorf("%w: trailing bytes after canonical walk (consumed=%d, total=%d)",
			ErrMalformedCBOR, n, len(input))
	}
	return nil
}

// walkCanonical advances through one CBOR item starting at offset `off`
// in `input` and returns the next offset after the item. Any
// non-canonical encoding causes an ErrMalformedCBOR-wrapped error.
func walkCanonical(input []byte, off int) (int, error) {
	if off >= len(input) {
		return off, fmt.Errorf("%w: truncated CBOR item at offset %d", ErrMalformedCBOR, off)
	}
	ib := input[off]
	majorType := ib >> 5
	ai := ib & 0x1F

	// Indefinite-length items (ai == 31, major types 2/3/4/5/7-break) are
	// rejected by the library-level IndefLengthForbidden option; we keep
	// a defence-in-depth guard so the canonicality walker fails closed
	// rather than silently accepting an unknown encoding.
	if ai == 31 {
		return off, fmt.Errorf("%w: indefinite-length item at offset %d", ErrMalformedCBOR, off)
	}

	// Decode argument and consume the head bytes.
	arg, headLen, err := readArg(input, off, ai)
	if err != nil {
		return off, err
	}
	next := off + headLen

	switch majorType {
	case 0, 1: // unsigned int / negative int — no payload, no children.
		return next, nil
	case 2, 3: // byte string / text string — fixed-length payload.
		end := next + int(arg)
		if end > len(input) || end < next {
			return off, fmt.Errorf("%w: %s payload runs past buffer (offset %d)",
				ErrMalformedCBOR, majorName(majorType), off)
		}
		return end, nil
	case 4: // array — `arg` children.
		cur := next
		for i := uint64(0); i < arg; i++ {
			n, err := walkCanonical(input, cur)
			if err != nil {
				return off, err
			}
			cur = n
		}
		return cur, nil
	case 5: // map — `arg` key/value pairs.
		cur := next
		var prevKey []byte
		for i := uint64(0); i < arg; i++ {
			keyStart := cur
			keyEnd, err := walkCanonical(input, cur)
			if err != nil {
				return off, err
			}
			keyBytes := input[keyStart:keyEnd]
			if prevKey != nil {
				// RFC 8949 § 4.2.1 bullet 3 (deterministic encoding):
				// length-first then lexicographic byte order on the
				// canonical-encoded keys. Pure bytewise comparison would
				// accept mixed-encoding cases (e.g. a 1-byte tstr key
				// `0x60` AFTER a 2-byte uint key `0x18 0x18`) that the
				// length-first rule rejects.
				if compareKeysCanonical(prevKey, keyBytes) >= 0 {
					return off, fmt.Errorf("%w: map keys not in canonical (length-first then lexicographic) order at offset %d",
						ErrMalformedCBOR, keyStart)
				}
			}
			prevKey = keyBytes
			valEnd, err := walkCanonical(input, keyEnd)
			if err != nil {
				return off, err
			}
			cur = valEnd
		}
		return cur, nil
	case 6: // tag — payload is one tagged item.
		// Tags are independently rejected by TagsForbidden; defence-in-
		// depth: refuse to descend into a tag here.
		return off, fmt.Errorf("%w: CBOR tag at offset %d (tags forbidden)", ErrMalformedCBOR, off)
	case 7: // floats / simple values / break.
		// Major type 7 leaves payload encoding to readArg (which already
		// enforced shortest form for simple-value heads ai 24).
		return next, nil
	}
	return off, fmt.Errorf("%w: unknown CBOR major type %d at offset %d", ErrMalformedCBOR, majorType, off)
}

// readArg decodes the argument that follows an initial byte and returns
// (argument value, total head length including the initial byte). It
// enforces the RFC 8949 § 4.2.1 shortest-form rule: a value encoded with
// a 1/2/4/8-byte trailing argument MUST not have fit in a smaller form.
//
// For major type 7 the only "argument" we touch is the simple-value /
// half-float discriminator at ai 24 — we reject the redundant encoding
// of simple values 0..23 in ai 24's one-byte form (must have used ai
// 0..23 directly).
func readArg(input []byte, off int, ai byte) (uint64, int, error) {
	switch {
	case ai < 24:
		return uint64(ai), 1, nil
	case ai == 24:
		if off+1 >= len(input) {
			return 0, 0, fmt.Errorf("%w: truncated 1-byte argument at offset %d", ErrMalformedCBOR, off)
		}
		v := uint64(input[off+1])
		if v < 24 {
			return 0, 0, fmt.Errorf("%w: non-shortest 1-byte argument (value %d encodable in head) at offset %d",
				ErrMalformedCBOR, v, off)
		}
		return v, 2, nil
	case ai == 25:
		if off+2 >= len(input) {
			return 0, 0, fmt.Errorf("%w: truncated 2-byte argument at offset %d", ErrMalformedCBOR, off)
		}
		// Float16 (major type 7, ai 25) is allowed at this width even
		// for "small" values; only integer/length majors invoke the
		// shortest-form rule on the 2-byte path.
		major := input[off] >> 5
		v := uint64(binary.BigEndian.Uint16(input[off+1 : off+3]))
		if major != 7 && v <= 0xFF {
			return 0, 0, fmt.Errorf("%w: non-shortest 2-byte argument (value %d fits in 1 byte) at offset %d",
				ErrMalformedCBOR, v, off)
		}
		return v, 3, nil
	case ai == 26:
		if off+4 >= len(input) {
			return 0, 0, fmt.Errorf("%w: truncated 4-byte argument at offset %d", ErrMalformedCBOR, off)
		}
		major := input[off] >> 5
		v := uint64(binary.BigEndian.Uint32(input[off+1 : off+5]))
		if major != 7 && v <= 0xFFFF {
			return 0, 0, fmt.Errorf("%w: non-shortest 4-byte argument (value %d fits in 2 bytes) at offset %d",
				ErrMalformedCBOR, v, off)
		}
		return v, 5, nil
	case ai == 27:
		if off+8 >= len(input) {
			return 0, 0, fmt.Errorf("%w: truncated 8-byte argument at offset %d", ErrMalformedCBOR, off)
		}
		major := input[off] >> 5
		v := binary.BigEndian.Uint64(input[off+1 : off+9])
		if major != 7 && v <= 0xFFFFFFFF {
			return 0, 0, fmt.Errorf("%w: non-shortest 8-byte argument (value %d fits in 4 bytes) at offset %d",
				ErrMalformedCBOR, v, off)
		}
		return v, 9, nil
	case ai >= 28 && ai <= 30:
		return 0, 0, fmt.Errorf("%w: reserved additional info %d at offset %d", ErrMalformedCBOR, ai, off)
	}
	// ai == 31 handled by caller (indefinite-length rejection).
	return 0, 0, fmt.Errorf("%w: unexpected additional info %d at offset %d", ErrMalformedCBOR, ai, off)
}

// compareKeysCanonical orders two canonical-encoded CBOR map keys per
// RFC 8949 § 4.2.1 deterministic encoding rules: shorter encoded keys
// sort first; equal-length keys are compared bytewise (memcmp).
// Returns a negative number if a < b, zero if equal, positive if a > b.
//
// Hermes MR !19 round-2 blocker fix — the previous implementation used
// `bytes.Compare` alone, which is bytewise-only and accepts mixed-length
// orderings (e.g. `{ uint(24): 0, "": 0 }` encoded as
// `0xA2 0x18 0x18 0x00 0x60 0x00`) that length-first canonical order
// rejects.
func compareKeysCanonical(a, b []byte) int {
	if len(a) != len(b) {
		return len(a) - len(b)
	}
	return bytes.Compare(a, b)
}

func majorName(mt byte) string {
	switch mt {
	case 0:
		return "uint"
	case 1:
		return "negint"
	case 2:
		return "bstr"
	case 3:
		return "tstr"
	case 4:
		return "array"
	case 5:
		return "map"
	case 6:
		return "tag"
	case 7:
		return "simple/float"
	}
	return "unknown"
}
