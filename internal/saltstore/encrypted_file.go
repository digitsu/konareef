// Copyright 2026 Jerry David Chan, Konareef.ai
// SPDX-License-Identifier: Apache-2.0

// internal/saltstore/encrypted_file.go — passphrase-encrypted single
// file holding all lineage salts for one local installation.
//
// On-disk layout is the same blob format from blob.go (Magic, Version,
// KDF params, KDF salt, nonce, sealed-CBOR(entries)). Put / Get / Delete
// rewrite the entire file each time (the working set is small — one
// installation has O(10s) of lineages at most). This keeps the read
// path simple and tag-verifies the entire blob on every access.
package saltstore

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"syscall"
)

// PassphraseProvider returns the passphrase that protects the
// encrypted-file backend. Implementations typically prompt on the TTY
// or read KONAREEF_SALT_PASSPHRASE. Get is invoked at most once per
// backend instance (the result is cached for the lifetime of the
// backend).
//
// CanProvideNow reports whether a subsequent Get call could plausibly
// succeed in the current process environment without further user
// intervention. It MUST be a cheap, side-effect-free probe: the
// resolver consults it during backend selection so it can skip the
// encrypted-file tier when, for example, the only configured source is
// a TTY prompt but stdin is not a terminal AND no passphrase env var
// is set. This lets the plain-file opt-in fallback actually become
// reachable in headless / non-interactive contexts instead of dying
// inside the encrypted-file backend on first use.
type PassphraseProvider interface {
	Get() ([]byte, error)
	CanProvideNow() bool
}

// PassphraseProviderFunc adapts a passphrase-returning function into a
// PassphraseProvider. The adapter unconditionally reports
// CanProvideNow() == true, so it is suitable only when the caller is
// certain the function can produce a passphrase (typically tests with
// a pre-baked value). Production callers MUST implement
// PassphraseProvider directly so CanProvideNow honestly reports
// availability.
type PassphraseProviderFunc func() ([]byte, error)

// Get implements PassphraseProvider by delegating to the underlying
// function.
func (f PassphraseProviderFunc) Get() ([]byte, error) { return f() }

// CanProvideNow implements PassphraseProvider; the function adapter
// always reports availability.
func (PassphraseProviderFunc) CanProvideNow() bool { return true }

type encryptedFileBackend struct {
	path string

	mu sync.Mutex
	// passphrase is the in-memory cache. On the "test" source the
	// constructor injects it; on the "provider" source it is
	// populated lazily by invoking the configured PassphraseProvider
	// on first access.
	passphrase       []byte
	passphraseSource string
	// provider is consulted on first access when passphrase is nil.
	// Nil provider + nil passphrase means the backend is unavailable.
	provider PassphraseProvider
	cache    map[[16]byte][32]byte
	loaded   bool
}

// NewEncryptedFileBackendForTest builds a backend with the passphrase
// pre-supplied. Tests use this constructor; production callers must
// route via NewEncryptedFileBackend (with a PassphraseProvider) so the
// TTY prompt is exercised.
func NewEncryptedFileBackendForTest(path string, passphrase []byte) Backend {
	return &encryptedFileBackend{
		path:             path,
		passphrase:       passphrase,
		passphraseSource: "test",
	}
}

// NewEncryptedFileBackendWithProvider builds a backend whose passphrase
// is acquired lazily via the supplied PassphraseProvider on the first
// Put/Get/Delete/List call. Available() consults
// provider.CanProvideNow() so the resolver can skip this tier when the
// provider cannot currently produce a passphrase (e.g. headless host
// with no KONAREEF_SALT_PASSPHRASE). When CanProvideNow reports true,
// the actual Get call happens only on first access, so callers are
// never blocked merely by Resolve() inspecting backend availability.
func NewEncryptedFileBackendWithProvider(path string, provider PassphraseProvider) Backend {
	return &encryptedFileBackend{
		path:             path,
		provider:         provider,
		passphraseSource: "provider",
	}
}

// newEncryptedFileBackendForPath builds a production backend with no
// passphrase source configured. Available() will reject it. Production
// callers MUST route via NewEncryptedFileBackendWithProvider so a real
// passphrase source (TTY or env-var) is wired in.
func newEncryptedFileBackendForPath(path string) Backend {
	return &encryptedFileBackend{
		path:             path,
		passphraseSource: "none",
	}
}

func defaultEncryptedFilePath(paths *StoragePaths) string {
	if paths != nil && paths.EncryptedFilePath != "" {
		return paths.EncryptedFilePath
	}
	if v := os.Getenv("KONAREEF_STATE_DIR"); v != "" {
		return filepath.Join(v, "salts.enc")
	}
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".config", "konareef", "salts.enc")
}

func (e *encryptedFileBackend) Name() string { return "encrypted-file" }

func (e *encryptedFileBackend) Available() error {
	if e.path == "" {
		return errors.New("encrypted-file backend: empty path")
	}
	// Available() must NOT prompt the user — it is invoked by the
	// resolver to decide whether to select this tier. As long as we
	// have a passphrase source (an injected passphrase, or a
	// configured provider that will run on first access), report
	// usable. The only path that rejects is "none": no passphrase,
	// no provider — production code that forgot to wire one.
	if e.passphrase == nil && e.provider == nil {
		return errors.New("encrypted-file backend: no passphrase source configured")
	}
	// Probe the provider so the resolver can skip this tier when the
	// configured source (e.g. a TTY prompt) cannot produce a
	// passphrase in the current environment. Without this probe, a
	// non-interactive host with KONAREEF_ALLOW_PLAINTEXT_SALT=1 would
	// still select encrypted-file here and fail at first Put/Get
	// instead of falling through to the explicitly opted-in plain
	// tier.
	if e.passphrase == nil && e.provider != nil && !e.provider.CanProvideNow() {
		return errors.New("encrypted-file backend: passphrase provider cannot produce a passphrase now (no TTY and KONAREEF_SALT_PASSPHRASE unset)")
	}
	return nil
}

func (e *encryptedFileBackend) ensureLoaded() error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.loaded {
		return nil
	}
	if e.passphrase == nil {
		if e.provider == nil {
			return errors.New("encrypted-file backend: no passphrase source configured")
		}
		pw, err := e.provider.Get()
		if err != nil {
			return err
		}
		if len(pw) == 0 {
			return errors.New("encrypted-file backend: passphrase provider returned empty passphrase")
		}
		e.passphrase = pw
	}
	if _, err := os.Stat(e.path); errors.Is(err, os.ErrNotExist) {
		e.cache = map[[16]byte][32]byte{}
		e.loaded = true
		return nil
	}
	blob, err := os.ReadFile(e.path)
	if err != nil {
		return fmt.Errorf("%w: read: %v", ErrSaltBackendIO, err)
	}
	entries, err := ImportBlob(blob, e.passphrase)
	if err != nil {
		return err
	}
	e.cache = map[[16]byte][32]byte{}
	for _, ent := range entries {
		e.cache[ent.LineageID] = ent.Salt
	}
	e.loaded = true
	return nil
}

func (e *encryptedFileBackend) flush() error {
	entries := make([]Entry, 0, len(e.cache))
	for lid, s := range e.cache {
		entries = append(entries, Entry{LineageID: lid, Salt: s})
	}
	if len(entries) == 0 {
		_ = os.Remove(e.path)
		return nil
	}
	// Tests run with the cheaper KDF params; production code uses
	// ProdKDFParams via ExportBlob.
	blob, err := ExportBlob(entries, e.passphrase)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(e.path), 0o700); err != nil {
		return fmt.Errorf("%w: mkdir: %v", ErrSaltBackendIO, err)
	}
	tmp := e.path + ".tmp"
	flag := os.O_CREATE | os.O_EXCL | os.O_WRONLY | syscall.O_NOFOLLOW
	f, err := os.OpenFile(tmp, flag, 0o600)
	if err != nil {
		if errors.Is(err, os.ErrExist) {
			_ = os.Remove(tmp)
			f, err = os.OpenFile(tmp, flag, 0o600)
		}
		if err != nil {
			return fmt.Errorf("%w: open tmp: %v", ErrSaltBackendIO, err)
		}
	}
	if _, err := f.Write(blob); err != nil {
		f.Close()
		return fmt.Errorf("%w: write tmp: %v", ErrSaltBackendIO, err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("%w: close tmp: %v", ErrSaltBackendIO, err)
	}
	if err := os.Rename(tmp, e.path); err != nil {
		return fmt.Errorf("%w: rename: %v", ErrSaltBackendIO, err)
	}
	return nil
}

func (e *encryptedFileBackend) Put(lid [16]byte, salt [32]byte) error {
	if err := e.ensureLoaded(); err != nil {
		return err
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if _, ok := e.cache[lid]; ok {
		return ErrSaltAlreadyExists
	}
	e.cache[lid] = salt
	return e.flush()
}

func (e *encryptedFileBackend) Get(lid [16]byte) ([32]byte, error) {
	if err := e.ensureLoaded(); err != nil {
		return [32]byte{}, err
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	s, ok := e.cache[lid]
	if !ok {
		return [32]byte{}, ErrSaltNotFound
	}
	return s, nil
}

func (e *encryptedFileBackend) Delete(lid [16]byte) error {
	if err := e.ensureLoaded(); err != nil {
		return err
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if _, ok := e.cache[lid]; !ok {
		return ErrSaltNotFound
	}
	delete(e.cache, lid)
	return e.flush()
}

func (e *encryptedFileBackend) List() ([][16]byte, error) {
	if err := e.ensureLoaded(); err != nil {
		return nil, err
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	out := make([][16]byte, 0, len(e.cache))
	for lid := range e.cache {
		out = append(out, lid)
	}
	return out, nil
}
