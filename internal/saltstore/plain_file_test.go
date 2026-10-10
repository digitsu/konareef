// Copyright 2026 Jerry David Chan, Konareef.ai
// SPDX-License-Identifier: Apache-2.0

// internal/saltstore/plain_file_test.go — exercises the plain-file
// backend's hardened controls on a real tempdir filesystem: 0600 file
// perms, ErrSaltAlreadyExists on duplicate Put, symlink rejection, list
// enumeration, and the CACHEDIR.TAG backup-exclusion marker.
package saltstore

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestPlainFileBackendRoundTrip(t *testing.T) {
	root := t.TempDir()
	b := NewPlainFileBackend(&StoragePaths{PlainFileRoot: root})
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
	path := filepath.Join(root, "typed", "01000000000000000000000000000000", "salt.bin")
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Errorf("perms = %v, want 0600", info.Mode().Perm())
	}
	if err := b.Delete(lid); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if _, err := b.Get(lid); !errors.Is(err, ErrSaltNotFound) {
		t.Fatalf("post-Delete Get err = %v, want ErrSaltNotFound", err)
	}
}

func TestPlainFileBackendPutAlreadyExists(t *testing.T) {
	root := t.TempDir()
	b := NewPlainFileBackend(&StoragePaths{PlainFileRoot: root})
	lid := [16]byte{2}
	salt := blobTestSalt(0x33)
	if err := b.Put(lid, salt); err != nil {
		t.Fatalf("first Put: %v", err)
	}
	if err := b.Put(lid, salt); !errors.Is(err, ErrSaltAlreadyExists) {
		t.Fatalf("second Put err = %v, want ErrSaltAlreadyExists", err)
	}
}

func TestPlainFileBackendSymlinkRejected(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink semantics differ on windows; backend itself unsupported there")
	}
	root := t.TempDir()
	lid := [16]byte{3}
	dir := filepath.Join(root, "typed", "03000000000000000000000000000000")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	decoy, err := os.CreateTemp(t.TempDir(), "decoy")
	if err != nil {
		t.Fatal(err)
	}
	decoy.Close()
	link := filepath.Join(dir, "salt.bin")
	if err := os.Symlink(decoy.Name(), link); err != nil {
		t.Fatal(err)
	}
	b := NewPlainFileBackend(&StoragePaths{PlainFileRoot: root})
	err = b.Put(lid, blobTestSalt(0x77))
	// O_NOFOLLOW on Put should refuse rather than write through the
	// symlink. We accept either ErrSaltBackendIO (O_NOFOLLOW surfaced as
	// IO error) or ErrSaltAlreadyExists (some platforms surface EEXIST
	// on the symlink itself). The contract that MUST hold: the decoy
	// remains zero bytes after the call.
	if !errors.Is(err, ErrSaltBackendIO) && !errors.Is(err, ErrSaltAlreadyExists) {
		t.Fatalf("Put on symlink path err = %v, want ErrSaltBackendIO or ErrSaltAlreadyExists", err)
	}
	info, err := os.Stat(decoy.Name())
	if err != nil {
		t.Fatal(err)
	}
	if info.Size() != 0 {
		t.Errorf("decoy was modified (size=%d)", info.Size())
	}
}

func TestPlainFileBackendList(t *testing.T) {
	root := t.TempDir()
	b := NewPlainFileBackend(&StoragePaths{PlainFileRoot: root})
	lids := [][16]byte{{1}, {2}, {3}}
	for _, lid := range lids {
		if err := b.Put(lid, blobTestSalt(0x10)); err != nil {
			t.Fatalf("Put: %v", err)
		}
	}
	got, err := b.List()
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(got) != len(lids) {
		t.Errorf("List len = %d, want %d", len(got), len(lids))
	}
}

func TestPlainFileBackendBackupExclusionMarker(t *testing.T) {
	root := t.TempDir()
	b := NewPlainFileBackend(&StoragePaths{PlainFileRoot: root})
	if err := b.Put([16]byte{1}, blobTestSalt(0x55)); err != nil {
		t.Fatal(err)
	}
	marker := filepath.Join(root, "typed", "CACHEDIR.TAG")
	data, err := os.ReadFile(marker)
	if err != nil {
		t.Fatalf("CACHEDIR.TAG missing: %v", err)
	}
	if string(data[:43]) != "Signature: 8a477f597d28d172789f06886806bc55" {
		t.Errorf("CACHEDIR.TAG signature mismatch")
	}
	info, err := fs.Stat(os.DirFS(root), "typed")
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o700 {
		t.Errorf("typed/ perms = %v, want 0700", info.Mode().Perm())
	}
}
