// internal/saltstore/blob_test.go — round-trip + reject paths for the
// versioned export blob. Exercises Argon2id key derivation, AES-256-GCM
// seal/open, header parse, and tampered-byte rejection.
package saltstore

import (
	"errors"
	"testing"
)

func TestBlobRoundTrip(t *testing.T) {
	entries := []Entry{
		{LineageID: [16]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16},
			Salt: blobTestSalt(0xAA)},
		{LineageID: [16]byte{0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0},
			Salt: blobTestSalt(0x55)},
	}
	passphrase := []byte("hunter2-correct-horse-battery-staple")
	params := KDFParams{Iterations: 2, MemoryKiB: 16384, Parallelism: 1}
	blob, err := ExportBlobWithParams(entries, passphrase, params, 1717977600)
	if err != nil {
		t.Fatalf("ExportBlobWithParams: %v", err)
	}
	if len(blob) < 9+12+16+12+16 {
		t.Fatalf("blob too short: %d bytes", len(blob))
	}

	got, err := ImportBlob(blob, passphrase)
	if err != nil {
		t.Fatalf("ImportBlob: %v", err)
	}
	if len(got) != len(entries) {
		t.Fatalf("got %d entries, want %d", len(got), len(entries))
	}
	for i := range entries {
		if got[i] != entries[i] {
			t.Errorf("entry[%d] mismatch", i)
		}
	}
}

func TestBlobWrongPassphraseRejects(t *testing.T) {
	entries := []Entry{{LineageID: [16]byte{1}, Salt: blobTestSalt(7)}}
	params := KDFParams{Iterations: 2, MemoryKiB: 16384, Parallelism: 1}
	blob, err := ExportBlobWithParams(entries, []byte("right"), params, 0)
	if err != nil {
		t.Fatalf("export: %v", err)
	}
	_, err = ImportBlob(blob, []byte("wrong"))
	if !errors.Is(err, ErrSaltBlobDecrypt) {
		t.Fatalf("err = %v, want ErrSaltBlobDecrypt", err)
	}
}

func TestBlobTamperedRejects(t *testing.T) {
	entries := []Entry{{LineageID: [16]byte{1}, Salt: blobTestSalt(7)}}
	params := KDFParams{Iterations: 2, MemoryKiB: 16384, Parallelism: 1}
	blob, err := ExportBlobWithParams(entries, []byte("pw"), params, 0)
	if err != nil {
		t.Fatalf("export: %v", err)
	}
	// Flip a ciphertext byte (just past the header at offset 49+1).
	blob[49+1] ^= 0xFF
	_, err = ImportBlob(blob, []byte("pw"))
	if !errors.Is(err, ErrSaltBlobDecrypt) {
		t.Fatalf("err = %v, want ErrSaltBlobDecrypt", err)
	}
}

func TestBlobBadMagicMalformed(t *testing.T) {
	bad := append([]byte("WRONGMAG"), 0x01)
	bad = append(bad, make([]byte, 100)...)
	_, err := ImportBlob(bad, []byte("pw"))
	if !errors.Is(err, ErrSaltBlobMalformed) {
		t.Fatalf("err = %v, want ErrSaltBlobMalformed", err)
	}
}

func TestBlobUnsupportedVersion(t *testing.T) {
	bad := append([]byte("KRSALT01"), 0xFF) // version 0xFF
	bad = append(bad, make([]byte, 100)...)
	_, err := ImportBlob(bad, []byte("pw"))
	if !errors.Is(err, ErrSaltBlobUnsupportedVersion) {
		t.Fatalf("err = %v, want ErrSaltBlobUnsupportedVersion", err)
	}
}

func blobTestSalt(b byte) [32]byte {
	var s [32]byte
	for i := range s {
		s[i] = b
	}
	return s
}

// TestValidateKDFParams covers each documented bound. The helper is the
// only line of defence against a hostile blob requesting multi-GiB
// memory or pathological iteration counts; cover both the boundary and
// the rejection path so a future bound change is loud.
func TestValidateKDFParams(t *testing.T) {
	cases := []struct {
		name        string
		iterations  uint32
		memoryKiB   uint32
		parallelism uint32
		wantOK      bool
	}{
		{"production defaults", 4, 131072, 1, true},
		{"test defaults", 2, 16384, 1, true},
		{"min boundary", 1, 1024, 1, true},
		{"max boundary", 16, 1048576, 16, true},
		{"zero iterations", 0, 16384, 1, false},
		{"excessive iterations", 17, 16384, 1, false},
		{"huge iterations", 100, 16384, 1, false},
		{"zero memory", 4, 0, 1, false},
		{"sub-MiB memory", 4, 1023, 1, false},
		{"excessive memory (>1 GiB)", 4, 1048577, 1, false},
		{"max uint32 memory", 4, ^uint32(0), 1, false},
		{"zero parallelism", 4, 16384, 0, false},
		{"excessive parallelism", 4, 16384, 17, false},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateKDFParams(tc.iterations, tc.memoryKiB, tc.parallelism)
			if tc.wantOK {
				if err != nil {
					t.Fatalf("err = %v, want nil", err)
				}
				return
			}
			if !errors.Is(err, ErrSaltBlobKDFParamsInvalid) {
				t.Fatalf("err = %v, want ErrSaltBlobKDFParamsInvalid", err)
			}
		})
	}
}

// TestImportBlobRejectsHostileKDFParams ensures the validation gate runs
// inside ImportBlob BEFORE Argon2 executes. We craft a header with a
// pathological memoryKiB value and verify the error surfaces without the
// caller paying the multi-GiB allocation cost.
func TestImportBlobRejectsHostileKDFParams(t *testing.T) {
	// Build a well-formed blob, then rewrite its KDF-params field to a
	// hostile value. The validation gate must fire before argon2.IDKey
	// is invoked, so this test never allocates the demanded memory.
	entries := []Entry{{LineageID: [16]byte{1}, Salt: blobTestSalt(7)}}
	params := KDFParams{Iterations: 2, MemoryKiB: 16384, Parallelism: 1}
	blob, err := ExportBlobWithParams(entries, []byte("pw"), params, 0)
	if err != nil {
		t.Fatalf("export: %v", err)
	}
	// Header layout: magic(8) | version(1) | iterations u32LE @9
	// | memoryKiB u32LE @13 | parallelism u32LE @17 …
	cases := []struct {
		name        string
		patchOffset int
		patchValue  uint32
	}{
		{"hostile memoryKiB", 13, ^uint32(0)}, // ~4 GiB demand
		{"zero iterations", 9, 0},
		{"excessive iterations", 9, 1000},
		{"zero parallelism", 17, 0},
		{"excessive parallelism", 17, 64},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			tampered := make([]byte, len(blob))
			copy(tampered, blob)
			tampered[tc.patchOffset+0] = byte(tc.patchValue)
			tampered[tc.patchOffset+1] = byte(tc.patchValue >> 8)
			tampered[tc.patchOffset+2] = byte(tc.patchValue >> 16)
			tampered[tc.patchOffset+3] = byte(tc.patchValue >> 24)
			_, err := ImportBlob(tampered, []byte("pw"))
			if !errors.Is(err, ErrSaltBlobKDFParamsInvalid) {
				t.Fatalf("err = %v, want ErrSaltBlobKDFParamsInvalid", err)
			}
		})
	}
}
