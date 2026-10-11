// Copyright 2026 Jerry David Chan, Konareef.ai
// SPDX-License-Identifier: Apache-2.0

// round2_blockers_test.go — Hermes MR !19 round-2 blocker regressions.
//
// Round-2 B1: Deterministic-CBOR map-key ordering MUST use the
// length-first then lexicographic-byte rule from RFC 8949 § 4.2.1
// deterministic encoding (the Bundle v2 wire contract). The previous
// implementation used pure bytewise comparison via `bytes.Compare`,
// which accepts mixed-length cases that strict length-first canonical
// order rejects.
//
// These tests are intentionally laser-focused on the comparator and
// exercise `validateCanonicalCBOR` directly with hand-crafted byte
// streams, so the regressions cannot be masked by surrounding bundle
// validation (e.g. v2 schema gates that would reject these toy maps
// for unrelated reasons).

package verify

import (
	"errors"
	"testing"
)

// TestB1Round2_HermesRepro_MixedLengthOutOfOrderRejected asserts the
// exact Hermes repro vector — a map `{ uint(24): 0, "": 0 }` encoded as
// 0xA2 0x18 0x18 0x00 0x60 0x00 — is now rejected.
//
// Under pure bytewise comparison the key encodings sort as
//
//	[0x18 0x18]  (uint 24, 2 bytes)   first byte 0x18
//	[0x60]       (empty tstr, 1 byte) first byte 0x60
//
// so 0x18 < 0x60 and the previous walker accepted the map. Under
// length-first canonical ordering the 1-byte key MUST come first; the
// encoded order shown above is therefore non-canonical and MUST be
// rejected with ErrMalformedCBOR.
func TestB1Round2_HermesRepro_MixedLengthOutOfOrderRejected(t *testing.T) {
	bs := []byte{
		0xA2,       // map(2)
		0x18, 0x18, // key 1: uint, ai 24, value 24
		0x00, // val 1: uint 0
		0x60, // key 2: tstr length 0 (empty string)
		0x00, // val 2: uint 0
	}
	err := validateCanonicalCBOR(bs)
	if !errors.Is(err, ErrMalformedCBOR) {
		t.Fatalf("Hermes repro `{ uint(24): 0, \"\": 0 }` accepted under non-canonical key order; err=%v", err)
	}
}

// TestB1Round2_MixedLengthCanonicalAccepted asserts the mirror-image
// canonical encoding of the same two keys — the shorter empty-string
// key first, then the longer uint(24) key — passes the walker.
//
// Encoding: 0xA2 0x60 0x00 0x18 0x18 0x00
//
//	key 1: tstr length 0  (1 byte total — 0x60)
//	val 1: uint 0
//	key 2: uint, ai 24, value 24  (2 bytes total — 0x18 0x18)
//	val 2: uint 0
//
// This is the canonical order: the 1-byte key sorts before the 2-byte
// key. The walker MUST accept it.
func TestB1Round2_MixedLengthCanonicalAccepted(t *testing.T) {
	bs := []byte{
		0xA2,       // map(2)
		0x60,       // key 1: tstr length 0 (1-byte encoding)
		0x00,       // val 1: uint 0
		0x18, 0x18, // key 2: uint, ai 24, value 24 (2-byte encoding)
		0x00, // val 2: uint 0
	}
	if err := validateCanonicalCBOR(bs); err != nil {
		t.Fatalf("canonical length-first order rejected: %v", err)
	}
}

// TestB1Round2_SameLengthLexOrderAccepted is a regression sanity test:
// two equal-length keys in ascending bytewise order MUST still be
// accepted. Uses single-byte tstr keys "a" and "b" — both encode as 2
// bytes (0x61 0x61, 0x61 0x62) so the length tiebreak does not fire and
// the bytewise comparator decides.
func TestB1Round2_SameLengthLexOrderAccepted(t *testing.T) {
	bs := []byte{
		0xA2,      // map(2)
		0x61, 'a', // key 1: tstr "a"
		0x00,      // val 1: uint 0
		0x61, 'b', // key 2: tstr "b"
		0x00, // val 2: uint 0
	}
	if err := validateCanonicalCBOR(bs); err != nil {
		t.Fatalf("same-length keys in lex order rejected: %v", err)
	}
}

// TestB1Round2_SameLengthOutOfLexOrderRejected asserts two equal-length
// keys in descending bytewise order are rejected. Uses tstr keys "b"
// then "a" — both 2-byte encodings (0x61 0x62, 0x61 0x61). Length-first
// is a tie so the bytewise tiebreak fires; the comparator MUST report
// the inversion and the walker MUST surface ErrMalformedCBOR.
func TestB1Round2_SameLengthOutOfLexOrderRejected(t *testing.T) {
	bs := []byte{
		0xA2,      // map(2)
		0x61, 'b', // key 1: tstr "b"
		0x00,      // val 1: uint 0
		0x61, 'a', // key 2: tstr "a"
		0x00, // val 2: uint 0
	}
	err := validateCanonicalCBOR(bs)
	if !errors.Is(err, ErrMalformedCBOR) {
		t.Fatalf("same-length keys out of lex order accepted; err=%v", err)
	}
}

// TestB1Round2_CompareKeysCanonicalUnit pins the comparator's three
// branches directly so any future refactor that flips a sign or drops
// the length tiebreak gets caught at the unit boundary, not buried in
// a CBOR walker integration test.
func TestB1Round2_CompareKeysCanonicalUnit(t *testing.T) {
	cases := []struct {
		name string
		a, b []byte
		want int // sign: -1 for <, 0 for ==, 1 for >
	}{
		{"shorter first", []byte{0x60}, []byte{0x18, 0x18}, -1},
		{"longer last", []byte{0x18, 0x18}, []byte{0x60}, 1},
		{"equal-length lex less", []byte{0x61, 0x61}, []byte{0x61, 0x62}, -1},
		{"equal-length lex greater", []byte{0x61, 0x62}, []byte{0x61, 0x61}, 1},
		{"equal bytes", []byte{0x61, 0x61}, []byte{0x61, 0x61}, 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := compareKeysCanonical(tc.a, tc.b)
			gotSign := 0
			switch {
			case got < 0:
				gotSign = -1
			case got > 0:
				gotSign = 1
			}
			if gotSign != tc.want {
				t.Errorf("compareKeysCanonical(%x, %x) sign = %d; want %d (raw=%d)",
					tc.a, tc.b, gotSign, tc.want, got)
			}
		})
	}
}
