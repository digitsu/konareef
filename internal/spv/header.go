// Copyright 2026 Jerry David Chan, Konareef.ai
// SPDX-License-Identifier: Apache-2.0

// header.go — 80-byte block headers and the proof-of-work check.
//
// A header source is trusted to return the best-chain header. CheckWork
// reduces that trust: a forged header must carry real proof of work at
// or above a difficulty floor, which costs about as much as mining a
// real block at that difficulty.

package spv

import (
	"encoding/binary"
	"errors"
	"math/big"
	"time"
)

// HeaderSize is the size of a serialized block header.
const HeaderSize = 80

// ErrInsufficientWork is returned when a header fails the proof-of-work
// check or the difficulty floor.
var ErrInsufficientWork = errors.New("spv: header proof of work below the floor")

// Header is a parsed block header.
type Header struct {
	// Raw is the 80 header bytes.
	Raw [HeaderSize]byte
	// Version is the block version.
	Version uint32
	// PrevBlock is the previous block hash, internal order.
	PrevBlock [32]byte
	// MerkleRoot is the merkle root, internal order.
	MerkleRoot [32]byte
	// Time is the block timestamp (seconds since the Unix epoch).
	Time uint32
	// Bits is the compact difficulty target.
	Bits uint32
	// Nonce is the proof-of-work nonce.
	Nonce uint32
}

// diff1Target is the difficulty-1 target, 0xFFFF × 2^208.
var diff1Target = new(big.Int).Lsh(big.NewInt(0xFFFF), 208)

// DefaultMinDifficulty is the difficulty floor a mainnet header must
// meet. BSV mainnet difficulty in 2026 is several tens of billions, so a
// floor of 1e9 accepts every real header with a wide margin, while a
// forged header still costs about 4.3e18 hashes.
const DefaultMinDifficulty = 1_000_000_000

// DefaultMaxTarget is the largest target (lowest difficulty) accepted by
// default: diff1Target / DefaultMinDifficulty.
var DefaultMaxTarget = new(big.Int).Div(diff1Target, big.NewInt(DefaultMinDifficulty))

// ParseHeader parses exactly 80 bytes.
// Input: raw. Output: the header, or an error wrapping ErrMalformed.
func ParseHeader(raw []byte) (*Header, error) {
	if len(raw) != HeaderSize {
		return nil, malformed("header is %d bytes, want %d", len(raw), HeaderSize)
	}
	h := &Header{}
	copy(h.Raw[:], raw)
	h.Version = binary.LittleEndian.Uint32(raw[0:4])
	copy(h.PrevBlock[:], raw[4:36])
	copy(h.MerkleRoot[:], raw[36:68])
	h.Time = binary.LittleEndian.Uint32(raw[68:72])
	h.Bits = binary.LittleEndian.Uint32(raw[72:76])
	h.Nonce = binary.LittleEndian.Uint32(raw[76:80])
	return h, nil
}

// Hash returns the block hash in internal order.
func (h *Header) Hash() [32]byte { return DoubleSHA256(h.Raw[:]) }

// Timestamp returns the header time as a time.Time (UTC).
func (h *Header) Timestamp() time.Time { return time.Unix(int64(h.Time), 0).UTC() }

// CompactToTarget expands a compact difficulty target.
// Input: bits. Output: the target, or nil when bits encode a negative
// or zero target.
func CompactToTarget(bits uint32) *big.Int {
	exponent := bits >> 24
	mantissa := int64(bits & 0x007fffff)
	if bits&0x00800000 != 0 || mantissa == 0 {
		return nil
	}
	t := big.NewInt(mantissa)
	if exponent <= 3 {
		t.Rsh(t, uint(8*(3-exponent)))
	} else {
		t.Lsh(t, uint(8*(exponent-3)))
	}
	if t.Sign() <= 0 {
		return nil
	}
	return t
}

// CheckWork checks that the header's own target is at or below
// maxTarget and that the header hash meets that target.
// Input: maxTarget (nil means DefaultMaxTarget).
// Output: nil, or an error wrapping ErrInsufficientWork.
func (h *Header) CheckWork(maxTarget *big.Int) error {
	if maxTarget == nil {
		maxTarget = DefaultMaxTarget
	}
	target := CompactToTarget(h.Bits)
	if target == nil {
		return ErrInsufficientWork
	}
	if target.Cmp(maxTarget) > 0 {
		return ErrInsufficientWork
	}
	hash := h.Hash()
	be := Reverse32(hash)
	if new(big.Int).SetBytes(be[:]).Cmp(target) > 0 {
		return ErrInsufficientWork
	}
	return nil
}
