// Copyright 2026 Jerry David Chan, Konareef.ai
// SPDX-License-Identifier: Apache-2.0

// internal/membridge/leb128_test.go
package membridge

import (
	"bytes"
	"errors"
	"testing"
)

func TestEncodeThoughtID(t *testing.T) {
	cases := []struct {
		in   uint64
		want []byte
	}{
		{0, []byte{0x00}},
		{1, []byte{0x01}},
		{127, []byte{0x7f}},
		{128, []byte{0x80, 0x01}},
		{255, []byte{0xff, 0x01}},
		{300, []byte{0xac, 0x02}},
		{2097151, []byte{0xff, 0xff, 0x7f}},
	}
	for _, c := range cases {
		got := EncodeThoughtID(c.in)
		if !bytes.Equal(got, c.want) {
			t.Errorf("EncodeThoughtID(%d) = %x, want %x", c.in, got, c.want)
		}
	}
}

func TestParseThoughtIDBytes_Minimal(t *testing.T) {
	cases := []struct {
		in   []byte
		want uint64
	}{
		{[]byte{0x00}, 0},
		{[]byte{0x7f}, 127},
		{[]byte{0x80, 0x01}, 128},
		{[]byte{0xff, 0xff, 0x7f}, 2097151},
	}
	for _, c := range cases {
		got, err := ParseThoughtIDBytes(c.in)
		if err != nil {
			t.Errorf("ParseThoughtIDBytes(%x) err = %v", c.in, err)
			continue
		}
		if got != c.want {
			t.Errorf("ParseThoughtIDBytes(%x) = %d, want %d", c.in, got, c.want)
		}
	}
}

// TestParseThoughtIDBytes_StandardMinimalEncoding16384 codifies the
// post-Hermes-review correction: bytes 0x80 0x80 0x01 are the canonical
// minimal ULEB128 encoding of 16384, well within the v1 thought_id
// range (2^21-1 = 2097151). The standard rule MUST accept it. See
// paygate-zk issue #1 for the upstream conformance-vector text fix.
func TestParseThoughtIDBytes_StandardMinimalEncoding16384(t *testing.T) {
	got, err := ParseThoughtIDBytes([]byte{0x80, 0x80, 0x01})
	if err != nil {
		t.Fatalf("ParseThoughtIDBytes(0x80 0x80 0x01) err = %v, want nil (16384 is the canonical minimal encoding)", err)
	}
	if got != 16384 {
		t.Fatalf("ParseThoughtIDBytes(0x80 0x80 0x01) = %d, want 16384", got)
	}
}

// TestParseThoughtIDBytes_NonMinimalZeroRejects covers a true
// non-minimal encoding: 0x80 0x00 decodes to 0 but the canonical
// minimal encoding of 0 is the single byte 0x00.
func TestParseThoughtIDBytes_NonMinimalZeroRejects(t *testing.T) {
	_, err := ParseThoughtIDBytes([]byte{0x80, 0x00})
	if !errors.Is(err, ErrLeb128NonMinimal) {
		t.Fatalf("err = %v, want ErrLeb128NonMinimal", err)
	}
}

// TestParseThoughtIDBytes_Truncated rejects an input that ends mid-encoding
// (last byte still has the continuation bit set).
func TestParseThoughtIDBytes_Truncated(t *testing.T) {
	_, err := ParseThoughtIDBytes([]byte{0x80})
	if !errors.Is(err, ErrLeb128NonMinimal) {
		t.Fatalf("err = %v, want ErrLeb128NonMinimal (truncated treated as malformed)", err)
	}
}

// TestParseThoughtIDBytes_Empty rejects zero-length input.
func TestParseThoughtIDBytes_Empty(t *testing.T) {
	_, err := ParseThoughtIDBytes(nil)
	if !errors.Is(err, ErrLeb128NonMinimal) {
		t.Fatalf("err = %v, want ErrLeb128NonMinimal", err)
	}
}

// TestLeb128ExternalParserReject codifies the WI-6 normative parser
// rule: external bytes feed ParseThoughtIDBytes, not EncodeThoughtID,
// and truly non-minimal external input MUST surface ErrLeb128NonMinimal.
// Encoder round-trip tests are tautological and not the contract here.
//
// Note: 0x80 0x80 0x01 is the standard minimal encoding of 16384 and
// MUST be accepted — see TestParseThoughtIDBytes_StandardMinimalEncoding16384.
func TestLeb128ExternalParserReject(t *testing.T) {
	for _, in := range [][]byte{
		{0x80, 0x00}, // 0, non-minimal (trailing zero septet)
		{0xff, 0xff, 0xff, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80}, // overlong
	} {
		_, err := ParseThoughtIDBytes(in)
		if !errors.Is(err, ErrLeb128NonMinimal) {
			t.Errorf("ParseThoughtIDBytes(%x) err = %v, want ErrLeb128NonMinimal", in, err)
		}
	}
}
