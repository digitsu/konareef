package identity

import (
	"encoding/hex"
	"strings"
	"testing"
)

func TestGenerate(t *testing.T) {
	id, err := Generate("alice")
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if id.Handle != "alice" {
		t.Errorf("Handle = %q, want %q", id.Handle, "alice")
	}
	if id.Version != "konareef-identity/v1" {
		t.Errorf("Version = %q, want %q", id.Version, "konareef-identity/v1")
	}
	if id.Scheme != "secp256k1-ecdsa-der" {
		t.Errorf("Scheme = %q, want %q", id.Scheme, "secp256k1-ecdsa-der")
	}
	if len(id.PublicKeyHex) != 66 {
		t.Errorf("PublicKeyHex length = %d, want 66 (compressed secp256k1 = 33 bytes hex)", len(id.PublicKeyHex))
	}
	if len(id.PrivateKeyHex) != 64 {
		t.Errorf("PrivateKeyHex length = %d, want 64 (32 bytes hex)", len(id.PrivateKeyHex))
	}
	if _, err := hex.DecodeString(id.PublicKeyHex); err != nil {
		t.Errorf("PublicKeyHex is not valid hex: %v", err)
	}
	if _, err := hex.DecodeString(id.PrivateKeyHex); err != nil {
		t.Errorf("PrivateKeyHex is not valid hex: %v", err)
	}
	if !strings.HasPrefix(id.PublicKeyHex, "02") && !strings.HasPrefix(id.PublicKeyHex, "03") {
		t.Errorf("PublicKeyHex prefix %q is not a compressed secp256k1 marker (02/03)", id.PublicKeyHex[:2])
	}
	if id.CreatedAt.IsZero() {
		t.Errorf("CreatedAt is zero")
	}
}

func TestGenerateUnique(t *testing.T) {
	a, err := Generate("alice")
	if err != nil {
		t.Fatalf("Generate (a): %v", err)
	}
	b, err := Generate("alice")
	if err != nil {
		t.Fatalf("Generate (b): %v", err)
	}
	if a.PrivateKeyHex == b.PrivateKeyHex {
		t.Errorf("two Generate calls produced identical private keys — keygen is not random")
	}
}
