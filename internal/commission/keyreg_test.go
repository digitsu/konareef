// Copyright 2026 Jerry David Chan, Konareef.ai
// SPDX-License-Identifier: Apache-2.0

package commission

import (
	"crypto/sha256"
	"errors"
	"strings"
	"testing"

	"github.com/digitsu/konareef/internal/identity"
)

// TestKeyRegistrationMessage pins the §6.1 encoding (the same shape
// reef-core's keys_test asserts), checks that a signature over it verifies
// the way the server verifies it (one SHA-256, strict low-S DER), and
// checks each refused input.
func TestKeyRegistrationMessage(t *testing.T) {
	_, id := testKey("buyer-a", "account-1", "active")
	user := "0F1E2D3C-4B5A-4978-8695-A4B3C2D1E0F9"
	challenge := strings.Repeat("ab", 32)

	msg, err := KeyRegistrationMessage(user, id.PublicKeyHex, challenge)
	if err != nil {
		t.Fatal(err)
	}
	want := "konareef-commission-key-registration/v1\n" + strings.ToLower(user) + "\n" + id.PublicKeyHex + "\n" + challenge
	if string(msg) != want {
		t.Fatalf("message = %q, want %q", msg, want)
	}

	sig, err := id.Sign(msg)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(msg)
	if ok, err := identity.VerifyDigest(id.PublicKeyHex, digest[:], sig); !ok || err != nil {
		t.Fatalf("signature does not verify over SHA-256(message): %v", err)
	}
	if _, _, err := identity.ParseStrict(sig); err != nil {
		t.Fatalf("signature is not strict DER: %v", err)
	}

	for name, args := range map[string][3]string{
		"not a uuid":          {"account-1", id.PublicKeyHex, challenge},
		"uuid without dash":   {strings.ReplaceAll(user, "-", ""), id.PublicKeyHex, challenge},
		"uppercase key":       {user, strings.ToUpper(id.PublicKeyHex), challenge},
		"uncompressed key":    {user, "04" + id.PublicKeyHex[2:], challenge},
		"short challenge":     {user, id.PublicKeyHex, challenge[:62]},
		"uppercase challenge": {user, id.PublicKeyHex, strings.ToUpper(challenge)},
	} {
		if _, err := KeyRegistrationMessage(args[0], args[1], args[2]); !errors.Is(err, ErrKeyRegistrationInput) {
			t.Errorf("%s: err = %v, want ErrKeyRegistrationInput", name, err)
		}
	}
}
