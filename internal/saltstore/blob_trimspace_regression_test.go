// Copyright 2026 Jerry David Chan, Konareef.ai
// SPDX-License-Identifier: Apache-2.0

// internal/saltstore/blob_trimspace_regression_test.go — regression
// coverage for a decrypt failure discovered via probabilistic fuzzing
// (CI pipelines 460 and 464): ImportBlob used to run an unconditional
// bytes.TrimSpace(blob) before touching the wire format. The blob is
// BINARY, and its final 16 bytes are the AES-GCM authentication tag —
// uniformly random bytes with no framing. Whenever the tag's last byte
// happened to be an ASCII whitespace character (' ', '\t', '\n', '\v',
// '\f', '\r' — 6 of 256 possible byte values, ≈2.3% of exports),
// TrimSpace silently dropped it, corrupting the tag and causing GCM
// authentication to fail on a correct-passphrase roundtrip
// (ERR_SALT_BLOB_DECRYPT). At scale this made roughly 1 in 43 real
// binary salt-backup blobs unrecoverable.
//
// TestImportBlobBinaryBlobEndingInWhitespaceByte pins a hand-selected,
// deterministic (entries, passphrase, KDF params, createdAt, kdfSalt,
// nonce) tuple whose sealed blob is known to end in a whitespace byte,
// and asserts ImportBlob still recovers it. The nonce below was found by
// deriving the Argon2id key once for this fixture and then brute-forcing
// candidate nonces with cheap GCM seals until the final tag byte landed
// on 0x20 (space); see the file history / PR description for the search
// method. The fixture is intentionally hardcoded rather than
// re-searched at test time so this test is fully deterministic in CI.
//
// TestImportBlobArmoredBlobToleratesSurroundingWhitespace covers the
// behavior the old unconditional TrimSpace legitimately served: an
// armored (base64, PEM-style) blob padded with leading/trailing
// whitespace or newlines — e.g. from copy-paste or a text editor — must
// still import cleanly. The fix scopes whitespace trimming to armor
// detection only, so this must keep passing.
package saltstore

import (
	"bytes"
	"testing"
)

func TestImportBlobBinaryBlobEndingInWhitespaceByte(t *testing.T) {
	entries := []Entry{
		{
			LineageID: [16]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16},
			Salt:      blobTestSalt(0xAA),
		},
	}
	passphrase := []byte("correct horse battery staple")
	params := TestKDFParams
	createdAt := uint64(1717977600)

	kdfSalt := make([]byte, kdfSaltLen)
	for i := range kdfSalt {
		kdfSalt[i] = byte(i + 1)
	}
	// Hand-picked so the sealed blob's final byte (the last byte of the
	// GCM tag) is 0x20 (space) — found by fixing the Argon2id key for
	// this exact fixture and brute-forcing nonces with direct GCM seals
	// (bypassing the KDF per attempt) until the tag ended in whitespace.
	nonce := []byte{0x04, 0xe6, 0xd2, 0x6c, 0x70, 0x3e, 0xa7, 0x39, 0xe8, 0x79, 0xa9, 0x3f}

	blob, err := SealBlobDeterministic(entries, passphrase, params, createdAt, kdfSalt, nonce)
	if err != nil {
		t.Fatalf("SealBlobDeterministic: %v", err)
	}
	last := blob[len(blob)-1]
	if !isASCIIWhitespace(last) {
		t.Fatalf("fixture rotted: blob no longer ends in whitespace (got 0x%02x) — the nonce must be re-derived", last)
	}
	if !bytes.Equal(bytes.TrimSpace(blob), blob[:len(blob)-1]) {
		t.Fatalf("fixture invariant broken: bytes.TrimSpace must strip exactly the final byte")
	}

	got, err := ImportBlob(blob, passphrase)
	if err != nil {
		t.Fatalf("ImportBlob: %v (blob's final byte is whitespace 0x%02x — this is the TrimSpace regression)", err, last)
	}
	if len(got) != len(entries) {
		t.Fatalf("got %d entries, want %d", len(got), len(entries))
	}
	for i := range entries {
		if got[i] != entries[i] {
			t.Errorf("entry[%d] mismatch: got %+v, want %+v", i, got[i], entries[i])
		}
	}
}

func TestImportBlobArmoredBlobToleratesSurroundingWhitespace(t *testing.T) {
	entries := []Entry{{LineageID: [16]byte{9}, Salt: blobTestSalt(0x11)}}
	passphrase := []byte("armor-whitespace-pw")
	params := TestKDFParams

	raw, err := ExportBlobWithParams(entries, passphrase, params, 1717977600)
	if err != nil {
		t.Fatalf("ExportBlobWithParams: %v", err)
	}
	armored := ArmorBlob(raw)
	padded := append([]byte("\r\n  \t\n"), armored...)
	padded = append(padded, []byte("\n\n   \r\n")...)

	got, err := ImportBlob(padded, passphrase)
	if err != nil {
		t.Fatalf("ImportBlob(armored, whitespace-padded): %v", err)
	}
	if len(got) != len(entries) || got[0] != entries[0] {
		t.Fatalf("got %+v, want %+v", got, entries)
	}
}

func isASCIIWhitespace(b byte) bool {
	switch b {
	case ' ', '\t', '\n', '\v', '\f', '\r':
		return true
	default:
		return false
	}
}
