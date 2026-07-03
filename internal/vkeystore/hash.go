package vkeystore

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
)

// Sha256Hex returns the lowercase-hex SHA-256 of body. This is the canonical
// pin form used in the discovery manifest and on-chain anchor.
func Sha256Hex(body []byte) string {
	sum := sha256.Sum256(body)
	return hex.EncodeToString(sum[:])
}

// VerifyPin compares the SHA-256 of body against the caller-supplied want pin.
// Case-insensitive (both sides are lowered before compare). Returns
// ErrCircuitPinMismatch when the hashes differ. Returns a plain error when
// want is not a 64-char hex string.
func VerifyPin(want string, body []byte) error {
	want = strings.ToLower(strings.TrimSpace(want))
	if len(want) != 64 {
		return fmt.Errorf("vkeystore: pin %q is not 64 hex chars", want)
	}
	if _, err := hex.DecodeString(want); err != nil {
		return fmt.Errorf("vkeystore: pin %q is not valid hex: %w", want, err)
	}
	got := Sha256Hex(body)
	if want != got {
		return fmt.Errorf("%w: want=%s got=%s", ErrCircuitPinMismatch, want, got)
	}
	return nil
}
