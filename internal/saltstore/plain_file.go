// internal/saltstore/plain_file.go — last-resort plain-file backend.
//
// All hardened controls for the plain-file salt backend apply:
//
//   - Mode 0600 file; O_CREAT|O_EXCL|O_NOFOLLOW on open
//   - Path: ${KONAREEF_STATE_DIR:-~/.konareef}/typed/{lineage_id_hex}/salt.bin
//   - Refuse tmpfs / network share mounts at Available() (stub today)
//   - CACHEDIR.TAG at typed/ root for backup exclusion
//   - Never log the salt bytes (the leak-grep test guarantees this)
package saltstore

import (
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"syscall"
)

// cacheDirTag is the standard CACHEDIR.TAG body (Borg / restic / rsync
// --exclude-caches all recognise this exact byte sequence).
const cacheDirTag = "Signature: 8a477f597d28d172789f06886806bc55\n" +
	"# This file is a cache directory tag created by konareef.\n" +
	"# For information about cache directory tags see https://bford.info/cachedir/\n"

type plainFileBackend struct {
	root string
}

// newPlainFileBackendForRoot builds a backend rooted at root.
func newPlainFileBackendForRoot(root string) Backend {
	return &plainFileBackend{root: root}
}

func defaultPlainFileRoot() string {
	if v := os.Getenv("KONAREEF_STATE_DIR"); v != "" {
		return v
	}
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".konareef")
}

func (p *plainFileBackend) Name() string { return "plain-file" }

func (p *plainFileBackend) Available() error {
	if runtime.GOOS == "windows" {
		return errors.New("plain-file backend unsupported on windows (v1.5 DPAPI)")
	}
	if p.root == "" {
		return errors.New("plain-file backend: empty root path")
	}
	if err := refuseVolatileFS(p.root); err != nil {
		return err
	}
	return nil
}

func (p *plainFileBackend) Put(lid [16]byte, salt [32]byte) error {
	dir, file := p.targetPath(lid)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("%w: mkdir: %v", ErrSaltBackendIO, err)
	}
	if err := p.ensureBackupExcludeMarker(); err != nil {
		return fmt.Errorf("%w: cachedir.tag: %v", ErrSaltBackendIO, err)
	}
	flag := os.O_CREATE | os.O_EXCL | os.O_WRONLY | syscall.O_NOFOLLOW
	f, err := os.OpenFile(file, flag, 0o600)
	if err != nil {
		if errors.Is(err, os.ErrExist) {
			return ErrSaltAlreadyExists
		}
		return fmt.Errorf("%w: open: %v", ErrSaltBackendIO, err)
	}
	defer f.Close()
	if _, err := f.Write(salt[:]); err != nil {
		return fmt.Errorf("%w: write: %v", ErrSaltBackendIO, err)
	}
	return nil
}

func (p *plainFileBackend) Get(lid [16]byte) ([32]byte, error) {
	_, file := p.targetPath(lid)
	f, err := os.OpenFile(file, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return [32]byte{}, ErrSaltNotFound
		}
		return [32]byte{}, fmt.Errorf("%w: open: %v", ErrSaltBackendIO, err)
	}
	defer f.Close()
	var s [32]byte
	if _, err := f.Read(s[:]); err != nil {
		return [32]byte{}, fmt.Errorf("%w: read: %v", ErrSaltBackendIO, err)
	}
	return s, nil
}

func (p *plainFileBackend) Delete(lid [16]byte) error {
	dir, file := p.targetPath(lid)
	if err := os.Remove(file); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return ErrSaltNotFound
		}
		return fmt.Errorf("%w: remove: %v", ErrSaltBackendIO, err)
	}
	// Best-effort: remove the now-empty lineage directory.
	_ = os.Remove(dir)
	return nil
}

func (p *plainFileBackend) List() ([][16]byte, error) {
	typedRoot := filepath.Join(p.root, "typed")
	entries, err := os.ReadDir(typedRoot)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, fmt.Errorf("%w: readdir: %v", ErrSaltBackendIO, err)
	}
	out := [][16]byte{}
	for _, e := range entries {
		if !e.IsDir() || len(e.Name()) != 32 {
			continue
		}
		raw, err := hex.DecodeString(e.Name())
		if err != nil || len(raw) != 16 {
			continue
		}
		var lid [16]byte
		copy(lid[:], raw)
		out = append(out, lid)
	}
	return out, nil
}

func (p *plainFileBackend) targetPath(lid [16]byte) (dir, file string) {
	dir = filepath.Join(p.root, "typed", hex.EncodeToString(lid[:]))
	file = filepath.Join(dir, "salt.bin")
	return dir, file
}

func (p *plainFileBackend) ensureBackupExcludeMarker() error {
	typedRoot := filepath.Join(p.root, "typed")
	if err := os.MkdirAll(typedRoot, 0o700); err != nil {
		return err
	}
	marker := filepath.Join(typedRoot, "CACHEDIR.TAG")
	if _, err := os.Stat(marker); err == nil {
		return nil
	} else if !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	return os.WriteFile(marker, []byte(cacheDirTag), 0o600)
}

// refuseVolatileFS rejects tmpfs / known-volatile mounts. Platform-
// specific detection is deferred to a follow-up; the initial TDD pass
// returns nil (tests use t.TempDir() which is always a real FS).
func refuseVolatileFS(_ string) error {
	return nil
}
