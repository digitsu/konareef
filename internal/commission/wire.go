// Copyright 2026 Jerry David Chan, Konareef.ai
// SPDX-License-Identifier: Apache-2.0

// wire.go — the v1 wire envelope of the admission contract
// (docs/design/commission-admission-contract.md §5.2) and the request
// constants the CLI sends to reef-core (§5.3).
//
// The wire envelope is a deterministic CBOR map with four integer keys:
//
//	{1: 1, 2: <canonical bytes>, 3: <33-byte compressed key>, 4: <DER signature>}
//
// The canonical bytes ride as an opaque byte string, so the bytes the buyer
// signed are the bytes the server hashes. EncodeWireV1 is the only
// producer, and it takes a Commission, never a Proposal: a proposal that
// was never signed has no path to wire bytes (§5.2). The encoder is kept in
// byte parity with the admission_v1 vectors by wire_parity_test.go.

package commission

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/digitsu/konareef/internal/identity"
)

// The request constants of the admission contract.
const (
	// AdmissionContractV1 is the "contract" value of a commissioned-run
	// request and of a revocation (§5.3, §7.5).
	AdmissionContractV1 = "konareef-commission-admission/v1"
	// AssuranceModeLimitedV1 is the only assurance mode v1 defines (§10).
	// The client names it; the server never picks a mode.
	AssuranceModeLimitedV1 = "memory_free_limited/v1"
	// WireVersionV1 is the value of wire key 1.
	WireVersionV1 = 1
)

// Signature length bounds of wire key 4 (§5.6): a DER ECDSA signature.
const (
	minWireSigBytes = 8
	maxWireSigBytes = 72
)

// ErrWireEncode means a commission cannot be put on the wire: its
// signature, its semantics or its size would make the server refuse it.
var ErrWireEncode = errors.New("commission cannot be encoded as a v1 wire envelope")

// EncodeWireV1 returns the v1 wire bytes of a signed commission.
//
// Input: a commission, normally from loadAndVerifyCommission. Output: the
// wire bytes, or an error wrapping ErrWireEncode.
//
// It checks again what the server checks, and refuses rather than encoding
// a commission the server must refuse:
//   - the signature verifies over SHA-256 of the canonical bytes;
//   - ValidateSignable passes (every dimension stated, a pinned binding,
//     the §5.6 limits);
//   - the public key is a 33-byte compressed key;
//   - the signature is strict DER of 8–72 bytes;
//   - the whole envelope is at most MaxWireBytes.
func EncodeWireV1(c Commission) ([]byte, error) {
	if err := c.Verify(); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrWireEncode, err)
	}
	if err := ValidateSignable(c.proposal); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrWireEncode, err)
	}
	canonical, err := c.proposal.Canonical()
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrWireEncode, err)
	}
	pub, err := hex.DecodeString(c.PubKeyHex)
	if err != nil || len(pub) != 33 || (pub[0] != 0x02 && pub[0] != 0x03) {
		return nil, fmt.Errorf("%w: public key is not a 33-byte compressed secp256k1 key", ErrWireEncode)
	}
	if len(c.Sig) < minWireSigBytes || len(c.Sig) > maxWireSigBytes {
		return nil, fmt.Errorf("%w: signature is %d bytes, want %d to %d", ErrWireEncode, len(c.Sig), minWireSigBytes, maxWireSigBytes)
	}
	// Verify applies this gate only while identity.StrictDerGateEnabled is
	// set; the server applies it always (Q4), so the encoder does too.
	if _, _, err := identity.ParseStrict(c.Sig); err != nil {
		return nil, fmt.Errorf("%w: signature is not strict low-S DER: %w", ErrWireEncode, err)
	}

	out := wireHead(5, 4)
	out = append(out, wireHead(0, 1)...)
	out = append(out, wireHead(0, WireVersionV1)...)
	out = append(out, wireHead(0, 2)...)
	out = append(out, wireBstr(canonical)...)
	out = append(out, wireHead(0, 3)...)
	out = append(out, wireBstr(pub)...)
	out = append(out, wireHead(0, 4)...)
	out = append(out, wireBstr(c.Sig)...)
	if len(out) > MaxWireBytes {
		return nil, fmt.Errorf("%w: %w: wire envelope is %d bytes, the limit is %d", ErrWireEncode, ErrOverAdmissionLimit, len(out), MaxWireBytes)
	}
	return out, nil
}

// HCommissionHex returns h_commission, SHA-256 of the canonical bytes, as
// lowercase hex: the identifier the server uses in receipts and logs.
//
// Input: a commission. Output: 64 hex characters, or the canonical
// encoding error.
func (c Commission) HCommissionHex() (string, error) {
	canonical, err := c.proposal.Canonical()
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(canonical)
	return hex.EncodeToString(sum[:]), nil
}

// wireHead encodes a CBOR head of the given major type in its shortest
// form (the §5.4 rule 2 the server enforces).
//
// Inputs: the major type (0–7) and the argument. Output: 1–9 bytes.
func wireHead(major byte, n uint64) []byte {
	m := major << 5
	switch {
	case n < 24:
		return []byte{m | byte(n)}
	case n <= 0xff:
		return []byte{m | 24, byte(n)}
	case n <= 0xffff:
		return []byte{m | 25, byte(n >> 8), byte(n)}
	case n <= 0xffffffff:
		return []byte{m | 26, byte(n >> 24), byte(n >> 16), byte(n >> 8), byte(n)}
	}
	return []byte{m | 27, byte(n >> 56), byte(n >> 48), byte(n >> 40), byte(n >> 32), byte(n >> 24), byte(n >> 16), byte(n >> 8), byte(n)}
}

// wireBstr encodes a definite-length CBOR byte string.
//
// Input: the bytes. Output: the head followed by the bytes.
func wireBstr(b []byte) []byte { return append(wireHead(2, uint64(len(b))), b...) }
