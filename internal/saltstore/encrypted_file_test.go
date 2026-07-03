// internal/saltstore/encrypted_file_test.go — passphrase-protected
// file backend: round-trip, wrong-passphrase, and persistence across
// fresh backend instances.
package saltstore

import (
	"errors"
	"path/filepath"
	"testing"
)

func TestEncryptedFileBackendRoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "salts.enc")
	b := NewEncryptedFileBackendForTest(path, []byte("test-passphrase"))
	if err := b.Available(); err != nil {
		t.Fatalf("Available: %v", err)
	}
	lid := [16]byte{1}
	salt := blobTestSalt(0x42)
	if err := b.Put(lid, salt); err != nil {
		t.Fatalf("Put: %v", err)
	}
	got, err := b.Get(lid)
	if err != nil || got != salt {
		t.Fatalf("Get: got=%x err=%v", got, err)
	}
}

func TestEncryptedFileBackendWrongPassphrase(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "salts.enc")
	b1 := NewEncryptedFileBackendForTest(path, []byte("right"))
	if err := b1.Put([16]byte{1}, blobTestSalt(0x11)); err != nil {
		t.Fatalf("Put: %v", err)
	}
	b2 := NewEncryptedFileBackendForTest(path, []byte("wrong"))
	_, err := b2.Get([16]byte{1})
	if !errors.Is(err, ErrSaltBlobDecrypt) {
		t.Fatalf("err = %v, want ErrSaltBlobDecrypt", err)
	}
}

func TestEncryptedFileBackendMultiLineagePersistence(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "salts.enc")
	b1 := NewEncryptedFileBackendForTest(path, []byte("pw"))
	lids := [][16]byte{{1}, {2}, {3}}
	for i, lid := range lids {
		if err := b1.Put(lid, blobTestSalt(byte(i+1))); err != nil {
			t.Fatalf("Put[%d]: %v", i, err)
		}
	}
	b2 := NewEncryptedFileBackendForTest(path, []byte("pw"))
	list, err := b2.List()
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(list) != len(lids) {
		t.Errorf("List len = %d, want %d", len(list), len(lids))
	}
}
