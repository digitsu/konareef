// Copyright 2026 Jerry David Chan, Konareef.ai
// SPDX-License-Identifier: Apache-2.0

// reader.go — a bounds-checked byte reader with Bitcoin-style
// variable-length integers (VarInt). Every parser in this package reads
// through it, so a truncated input always ends in ErrMalformed and never
// in a panic.

package spv

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
)

// ErrMalformed wraps every structural parse failure in this package.
var ErrMalformed = errors.New("spv: malformed input")

// reader walks a byte slice. It never reads past the end.
type reader struct {
	buf []byte
	off int
}

// malformed returns an error wrapping ErrMalformed with a context message.
func malformed(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrMalformed, fmt.Sprintf(format, args...))
}

// remaining reports how many unread bytes are left.
func (r *reader) remaining() int { return len(r.buf) - r.off }

// bytes returns the next n bytes, or an error when fewer are left.
func (r *reader) bytes(n int, what string) ([]byte, error) {
	if n < 0 || r.remaining() < n {
		return nil, malformed("truncated %s: need %d bytes, have %d", what, n, r.remaining())
	}
	out := r.buf[r.off : r.off+n]
	r.off += n
	return out, nil
}

// byte1 reads one byte.
func (r *reader) byte1(what string) (byte, error) {
	b, err := r.bytes(1, what)
	if err != nil {
		return 0, err
	}
	return b[0], nil
}

// uint32LE reads a little-endian uint32.
func (r *reader) uint32LE(what string) (uint32, error) {
	b, err := r.bytes(4, what)
	if err != nil {
		return 0, err
	}
	return binary.LittleEndian.Uint32(b), nil
}

// hash32 reads a 32-byte hash as is (no byte reversal).
func (r *reader) hash32(what string) ([32]byte, error) {
	var h [32]byte
	b, err := r.bytes(32, what)
	if err != nil {
		return h, err
	}
	copy(h[:], b)
	return h, nil
}

// varInt reads a Bitcoin VarInt and refuses a non-minimal encoding, so
// every value has exactly one byte form.
func (r *reader) varInt(what string) (uint64, error) {
	first, err := r.byte1(what)
	if err != nil {
		return 0, err
	}
	switch first {
	case 0xfd:
		b, err := r.bytes(2, what)
		if err != nil {
			return 0, err
		}
		v := uint64(binary.LittleEndian.Uint16(b))
		if v < 0xfd {
			return 0, malformed("non-minimal varint for %s", what)
		}
		return v, nil
	case 0xfe:
		b, err := r.bytes(4, what)
		if err != nil {
			return 0, err
		}
		v := uint64(binary.LittleEndian.Uint32(b))
		if v <= 0xffff {
			return 0, malformed("non-minimal varint for %s", what)
		}
		return v, nil
	case 0xff:
		b, err := r.bytes(8, what)
		if err != nil {
			return 0, err
		}
		v := binary.LittleEndian.Uint64(b)
		if v <= 0xffffffff {
			return 0, malformed("non-minimal varint for %s", what)
		}
		return v, nil
	default:
		return uint64(first), nil
	}
}

// count reads a VarInt used as an element count and bounds it by the
// bytes left (each element takes at least minSize bytes), so a hostile
// count cannot drive a huge allocation.
func (r *reader) count(what string, minSize int) (int, error) {
	n, err := r.varInt(what)
	if err != nil {
		return 0, err
	}
	if minSize < 1 {
		minSize = 1
	}
	if n > uint64(r.remaining()/minSize) {
		return 0, malformed("%s count %d exceeds the remaining input", what, n)
	}
	return int(n), nil
}

// AppendVarInt appends the minimal Bitcoin VarInt encoding of v to dst.
// Input: dst, v. Output: the extended slice.
func AppendVarInt(dst []byte, v uint64) []byte {
	switch {
	case v < 0xfd:
		return append(dst, byte(v))
	case v <= 0xffff:
		return binary.LittleEndian.AppendUint16(append(dst, 0xfd), uint16(v))
	case v <= 0xffffffff:
		return binary.LittleEndian.AppendUint32(append(dst, 0xfe), uint32(v))
	default:
		return binary.LittleEndian.AppendUint64(append(dst, 0xff), v)
	}
}

// DoubleSHA256 returns SHA-256(SHA-256(b)) in internal byte order.
// Input: b. Output: the 32-byte digest.
func DoubleSHA256(b []byte) [32]byte {
	first := sha256.Sum256(b)
	return sha256.Sum256(first[:])
}

// Reverse32 returns h with its bytes reversed (internal ↔ display order).
// Input: h. Output: the reversed copy.
func Reverse32(h [32]byte) [32]byte {
	var out [32]byte
	for i := range h {
		out[i] = h[31-i]
	}
	return out
}
