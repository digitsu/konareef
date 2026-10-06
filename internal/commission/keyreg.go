// Copyright 2026 Jerry David Chan, Konareef.ai
// SPDX-License-Identifier: Apache-2.0

// keyreg.go — the buyer key registration message
// (docs/design/commission-admission-contract.md §6.1).
//
// reef-core admits a commission only when its signer key is registered to
// the authenticated account. A key is registered with proof of possession:
// the key signs SHA-256 of this message, once, with strict low-S DER:
//
//	"konareef-commission-key-registration/v1\n" || user_id || "\n" ||
//	pubkey_hex || "\n" || challenge_hex
//
// user_id is the lowercase canonical UUID of the account, pubkey_hex is 66
// lowercase hex characters, and challenge_hex is the 64 lowercase hex
// characters the server issued to this session. The prefix separates this
// signature from a commission signature (canonical bytes start with 0xa6)
// and a publish signature (manifests start with "#!"). The bytes match
// reef-core ReefCore.Commission.Keys.registration_message/3.

package commission

import (
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
)

// KeyRegistrationPrefix is the domain-separation prefix of the message.
const KeyRegistrationPrefix = "konareef-commission-key-registration/v1\n"

// ErrKeyRegistrationInput means an input to KeyRegistrationMessage is not
// in the form the server signs over.
var ErrKeyRegistrationInput = errors.New("invalid key registration input")

// KeyRegistrationMessage returns the exact bytes a registration signature
// covers.
//
// Inputs: the account id (a canonical UUID; upper-case hex is lowered, as
// the server lowers it), the compressed public key as hex, and the server
// challenge as hex. Output: the UTF-8 message, or an error wrapping
// ErrKeyRegistrationInput. The caller signs it with identity.Sign, which
// hashes it once with SHA-256.
func KeyRegistrationMessage(userID, pubKeyHex, challengeHex string) ([]byte, error) {
	userID = strings.ToLower(userID)
	if !isCanonicalUUID(userID) {
		return nil, fmt.Errorf("%w: account id %q is not a canonical UUID", ErrKeyRegistrationInput, userID)
	}
	if !isLowerHex(pubKeyHex, 33) || (pubKeyHex[:2] != "02" && pubKeyHex[:2] != "03") {
		return nil, fmt.Errorf("%w: public key must be 66 lowercase hex characters of a compressed key", ErrKeyRegistrationInput)
	}
	if !isLowerHex(challengeHex, 32) {
		return nil, fmt.Errorf("%w: challenge must be 64 lowercase hex characters", ErrKeyRegistrationInput)
	}
	return []byte(KeyRegistrationPrefix + userID + "\n" + pubKeyHex + "\n" + challengeHex), nil
}

// IsCanonicalUserID reports whether s is an account id in the exact form
// the registration message signs: a lowercase 8-4-4-4-12 hex UUID.
//
// Input: the candidate id. Output: true only for that exact form; upper
// case, whitespace and any other byte make it false.
func IsCanonicalUserID(s string) bool { return isCanonicalUUID(s) }

// isLowerHex reports whether s is exactly n bytes as lowercase hex.
func isLowerHex(s string, n int) bool {
	if len(s) != 2*n || strings.ToLower(s) != s {
		return false
	}
	_, err := hex.DecodeString(s)
	return err == nil
}

// isCanonicalUUID reports whether s is a lowercase 8-4-4-4-12 hex UUID.
func isCanonicalUUID(s string) bool {
	parts := strings.Split(s, "-")
	if len(parts) != 5 {
		return false
	}
	for i, n := range []int{4, 2, 2, 2, 6} {
		if !isLowerHex(parts[i], n) {
			return false
		}
	}
	return true
}
