package feeder

import (
	"bytes"
	"testing"
)

const (
	fixtureHex = "404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f"
	fixtureB64 = "QEFCQ0RFRkdISUpLTE1OT1BRUlNUVVZXWFlaW1xdXl8="
	taskID     = "2f8a9c14-6b3d-4e57-9a01-7c5d3e8f0b26"
	expected   = "eb01df6b118a3d056984d955d9c956a40ffebb50b886484b75f0514884375413"

	// mixedCaseTaskID is taskID above with letter case swapped throughout.
	// Its expected MAC was computed independently (Python hmac/hashlib, not
	// this package), over the mixed-case bytes exactly as written. If a
	// regression folds case before hashing (e.g. strings.ToLower(taskID)),
	// mixedCaseTaskID.lower() == taskID, so the regressed output would
	// silently equal `expected` above instead of `expectedMixedCase` —
	// this fixture exists to catch exactly that.
	mixedCaseTaskID   = "2F8a9C14-6B3d-4E57-9A01-7c5D3E8f0B26"
	expectedMixedCase = "e22e3a54727099e0d69b11cc06d788d64bcea5e3b1f88d52ada7628279bbe07e"

	// nonASCIITaskID contains multi-byte UTF-8 runes (accented Latin letters
	// and an emoji outside the BMP). Its expected MAC was computed
	// independently (Python hmac/hashlib) over the raw UTF-8 bytes of this
	// exact literal, with no Unicode normalization applied. A regression
	// that normalizes (e.g. NFC/NFD) or otherwise re-encodes the task_id
	// before hashing would change the byte sequence fed to HMAC and produce
	// a different digest than expectedNonASCII.
	nonASCIITaskID   = "tâche-café-🚀-2f8a9c14"
	expectedNonASCII = "051693844edde9779061e71f4fbe6e04bbcf12a5d3ac5d77426f690959851713"

	// rawSecretFallback is exactly 32 bytes, contains no character valid in
	// hex (0-9a-f) or standard base64 (A-Za-z0-9+/), so it fails to decode
	// under either encoding and must fall through to the raw-bytes branch
	// of DecodeSecret32 unchanged.
	rawSecretFallback = "not-hex-not-base64-raw-secret!!!"
)

func TestMintIngestToken_NormativeVector(t *testing.T) {
	secret, err := DecodeSecret32(fixtureHex)
	if err != nil {
		t.Fatalf("DecodeSecret32: %v", err)
	}
	if got := MintIngestToken(secret, taskID); got != expected {
		t.Fatalf("token mismatch:\n got %s\nwant %s", got, expected)
	}
}

func TestDecodeSecret32_HexAndBase64Agree(t *testing.T) {
	h, err := DecodeSecret32(fixtureHex)
	if err != nil {
		t.Fatalf("hex: %v", err)
	}
	b, err := DecodeSecret32(fixtureB64)
	if err != nil {
		t.Fatalf("base64: %v", err)
	}
	if !bytes.Equal(h, b) {
		t.Fatal("hex and base64 forms decoded to different bytes")
	}
}

func TestDecodeSecret32_RejectsWrongLength(t *testing.T) {
	if _, err := DecodeSecret32("too-short"); err == nil {
		t.Fatal("expected an error for a non-32-byte secret")
	}
}

// TestDecodeSecret32_RawBytesFallback exercises the third decode branch
// directly: rawSecretFallback decodes cleanly under neither hex nor
// base64, so DecodeSecret32 must fall through to treating it as the
// literal 32 raw bytes of the string, unchanged.
func TestDecodeSecret32_RawBytesFallback(t *testing.T) {
	if len(rawSecretFallback) != 32 {
		t.Fatalf("fixture is not 32 bytes: got %d", len(rawSecretFallback))
	}
	got, err := DecodeSecret32(rawSecretFallback)
	if err != nil {
		t.Fatalf("DecodeSecret32: %v", err)
	}
	if !bytes.Equal(got, []byte(rawSecretFallback)) {
		t.Fatalf("raw-bytes fallback mismatch:\n got %x\nwant %x", got, []byte(rawSecretFallback))
	}
}

// TestMintIngestToken_MixedCaseNotFolded guards against a regression that
// lowercases (or otherwise case-folds) task_id before hashing. taskID and
// mixedCaseTaskID differ only in letter case, so a case-folding regression
// would make MintIngestToken(secret, mixedCaseTaskID) equal `expected`
// (the normative vector's answer) instead of `expectedMixedCase`.
func TestMintIngestToken_MixedCaseNotFolded(t *testing.T) {
	secret, err := DecodeSecret32(fixtureHex)
	if err != nil {
		t.Fatalf("DecodeSecret32: %v", err)
	}
	if got := MintIngestToken(secret, mixedCaseTaskID); got != expectedMixedCase {
		t.Fatalf("token mismatch:\n got  %s\nwant %s", got, expectedMixedCase)
	}
}

// TestMintIngestToken_NonASCIINotNormalized guards against a regression
// that applies Unicode normalization (or any other re-encoding) to task_id
// before hashing. The expected digest was computed independently, over the
// exact UTF-8 bytes of the literal below, with no normalization applied.
func TestMintIngestToken_NonASCIINotNormalized(t *testing.T) {
	secret, err := DecodeSecret32(fixtureHex)
	if err != nil {
		t.Fatalf("DecodeSecret32: %v", err)
	}
	if got := MintIngestToken(secret, nonASCIITaskID); got != expectedNonASCII {
		t.Fatalf("token mismatch:\n got  %s\nwant %s", got, expectedNonASCII)
	}
}
