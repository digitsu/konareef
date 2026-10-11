// Copyright 2026 Jerry David Chan, Konareef.ai
// SPDX-License-Identifier: Apache-2.0

// brc42.go — BRC-42 child public key derivation.
//
// For a recipient public key R, a sender private key s and an invoice
// number, BRC-42 defines the child public key
//
//	child = R + HMAC-SHA256(key = compressed(R × s), msg = invoice) × G
//
// A BRC-100 wallet that signs with counterparty "anyone" uses s = 1 (the
// "anyone" private key) and R = its identity key, so anyone who knows
// the identity key can compute the key it signs with
// (DeriveAnyonePublicKey). The invoice number is
// "<security level>-<protocol name>-<key id>" (BRC-43).

package spv

import (
	"crypto/hmac"
	"crypto/sha256"
	"errors"
	"fmt"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
)

// ErrBadKey is returned for an unusable public key or derivation.
var ErrBadKey = errors.New("spv: bad key")

// anyonePrivateKey is the BRC-100 "anyone" private key, the scalar 1.
var anyonePrivateKey = [32]byte{31: 1}

// InvoiceNumber builds a BRC-43 invoice number.
// Inputs: security level, protocol name, key id. Output: the string.
func InvoiceNumber(level int, protocol, keyID string) string {
	return fmt.Sprintf("%d-%s-%s", level, protocol, keyID)
}

// parseCompressed parses a 33-byte compressed secp256k1 public key.
func parseCompressed(pub []byte) (*secp256k1.PublicKey, error) {
	if len(pub) != 33 {
		return nil, fmt.Errorf("%w: public key must be 33-byte compressed secp256k1", ErrBadKey)
	}
	key, err := secp256k1.ParsePubKey(pub)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrBadKey, err)
	}
	return key, nil
}

// ChildTweak returns the BRC-42 tweak HMAC-SHA256(compressed(R × s),
// invoice).
// Inputs: recipient R (33-byte compressed); sender private key s
// (32 bytes big-endian, non-zero, below n); invoice.
// Output: the 32-byte HMAC, or ErrBadKey.
func ChildTweak(recipient []byte, sender [32]byte, invoice string) ([32]byte, error) {
	var out [32]byte
	pub, err := parseCompressed(recipient)
	if err != nil {
		return out, err
	}
	var s secp256k1.ModNScalar
	if overflow := s.SetBytes(&sender); overflow != 0 || s.IsZero() {
		return out, fmt.Errorf("%w: sender private key out of range", ErrBadKey)
	}
	var p, shared secp256k1.JacobianPoint
	pub.AsJacobian(&p)
	secp256k1.ScalarMultNonConst(&s, &p, &shared)
	shared.ToAffine()
	secret := secp256k1.NewPublicKey(&shared.X, &shared.Y).SerializeCompressed()
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(invoice))
	copy(out[:], mac.Sum(nil))
	return out, nil
}

// DeriveChildPublicKey returns the BRC-42 child public key
// R + ChildTweak(R, s, invoice) × G.
// Inputs: recipient R; sender private key s; invoice.
// Output: the 33-byte compressed child key, or ErrBadKey.
func DeriveChildPublicKey(recipient []byte, sender [32]byte, invoice string) ([]byte, error) {
	tweak, err := ChildTweak(recipient, sender, invoice)
	if err != nil {
		return nil, err
	}
	pub, _ := parseCompressed(recipient)
	var k secp256k1.ModNScalar
	k.SetBytes(&tweak)
	if k.IsZero() {
		return nil, fmt.Errorf("%w: zero tweak", ErrBadKey)
	}
	var tG, r, sum secp256k1.JacobianPoint
	secp256k1.ScalarBaseMultNonConst(&k, &tG)
	pub.AsJacobian(&r)
	secp256k1.AddNonConst(&r, &tG, &sum)
	if (sum.X.IsZero() && sum.Y.IsZero()) || sum.Z.IsZero() {
		return nil, fmt.Errorf("%w: derived point at infinity", ErrBadKey)
	}
	sum.ToAffine()
	return secp256k1.NewPublicKey(&sum.X, &sum.Y).SerializeCompressed(), nil
}

// AnyoneTweak is ChildTweak with the "anyone" sender key (1): the HMAC
// key is the compressed identity key itself.
// Inputs: identity (33-byte compressed); invoice. Output: the tweak.
func AnyoneTweak(identity []byte, invoice string) ([32]byte, error) {
	return ChildTweak(identity, anyonePrivateKey, invoice)
}

// DeriveAnyonePublicKey returns the key a BRC-100 wallet with this
// identity key signs with for counterparty "anyone".
// Inputs: identity (33-byte compressed); invoice (see InvoiceNumber).
// Output: the 33-byte compressed child key, or ErrBadKey.
func DeriveAnyonePublicKey(identity []byte, invoice string) ([]byte, error) {
	return DeriveChildPublicKey(identity, anyonePrivateKey, invoice)
}
