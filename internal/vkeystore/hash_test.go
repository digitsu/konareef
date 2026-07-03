package vkeystore_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/digitsu/konareef/internal/vkeystore"
)

func TestSha256HexLowercaseDeterministic(t *testing.T) {
	got := vkeystore.Sha256Hex([]byte("konareef"))
	if len(got) != 64 {
		t.Fatalf("Sha256Hex must return 64 hex chars; got %d", len(got))
	}
	if got != strings.ToLower(got) {
		t.Fatalf("Sha256Hex must be lowercase; got %q", got)
	}
}

func TestVerifyPinAcceptsExactMatch(t *testing.T) {
	body := []byte{0x42, 0x42, 0x42}
	pin := vkeystore.Sha256Hex(body)
	if err := vkeystore.VerifyPin(pin, body); err != nil {
		t.Fatalf("VerifyPin(matching pin) returned %v", err)
	}
}

func TestVerifyPinRejectsCaseSensitive(t *testing.T) {
	body := []byte{0x42}
	pin := vkeystore.Sha256Hex(body)
	upper := strings.ToUpper(pin)
	if err := vkeystore.VerifyPin(upper, body); err != nil {
		t.Fatalf("VerifyPin must normalise case before compare; got %v", err)
	}
}

func TestVerifyPinReturnsPinMismatchOnDiff(t *testing.T) {
	body := []byte{0x42}
	wrongPin := strings.Repeat("a", 64)
	err := vkeystore.VerifyPin(wrongPin, body)
	if !errors.Is(err, vkeystore.ErrCircuitPinMismatch) {
		t.Fatalf("VerifyPin(mismatch) returned %v; want ErrCircuitPinMismatch", err)
	}
}

func TestVerifyPinRejectsMalformedPin(t *testing.T) {
	body := []byte{0x42}
	err := vkeystore.VerifyPin("not-hex", body)
	if err == nil {
		t.Fatal("VerifyPin must reject non-hex pin")
	}
}
