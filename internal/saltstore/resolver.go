// Copyright 2026 Jerry David Chan, Konareef.ai
// SPDX-License-Identifier: Apache-2.0

// internal/saltstore/resolver.go — backend selection per PRD
// §"Resolver". Tries backends in preference order (Keychain →
// EncryptedFile → PlainFile), logging each skip and returning the
// first whose Available() is nil.
package saltstore

import "log"

// ResolveOpts configures path overrides for non-default installation
// layouts (integration tests, custom KONAREEF_STATE_DIR) and the
// passphrase source for the encrypted-file tier.
type ResolveOpts struct {
	// Paths overrides default OS-determined storage directories.
	// Nil uses the platform defaults.
	Paths *StoragePaths

	// EncryptedFilePassphrase, when non-nil, is injected directly
	// into the encrypted-file backend. Tests and automation paths
	// that already hold the passphrase use this field.
	EncryptedFilePassphrase []byte

	// EncryptedFilePassphraseProvider, when non-nil and
	// EncryptedFilePassphrase is unset, is invoked lazily on first
	// salt access. Production callers wire the TTY prompt /
	// KONAREEF_SALT_PASSPHRASE reader here. Required for the
	// encrypted-file tier to be selectable in production.
	EncryptedFilePassphraseProvider PassphraseProvider

	// PlainFileOptIn must be set true for the resolver to consider
	// the plain-file backend. The CLI sets it from
	// KONAREEF_ALLOW_PLAINTEXT_SALT=1 — without explicit opt-in we
	// refuse to silently write salts to disk in cleartext.
	PlainFileOptIn bool

	// DisableKeychain, when true, drops the keychain backend from the
	// candidate list. Hermetic CLI test subprocesses set this so the
	// resolver never reaches macOS Keychain (which can pop a UI prompt
	// and block the test). The konareef CLI wires it from
	// KONAREEF_DISABLE_KEYCHAIN_BACKEND=1. Off by default so production
	// keeps the keychain as the preferred tier.
	DisableKeychain bool
}

// Resolve tries backends in preference order: KeychainBackend →
// EncryptedFileBackend → PlainFileBackend. It skips each backend
// whose Available() returns a non-nil error, logging the reason via
// log.Printf. It returns the first available backend.
//
// SECURITY: the plain-file tier is included ONLY when
// opts.PlainFileOptIn is true. Hosts without a usable keychain and
// without an encrypted-file passphrase source fail closed with
// ErrSaltStorageUnavailable rather than silently writing salts in
// cleartext. Callers (today, the konareef CLI) opt in explicitly via
// KONAREEF_ALLOW_PLAINTEXT_SALT=1 after a deliberate user decision.
//
// Returns ErrSaltStorageUnavailable if no backend is usable.
func Resolve(opts ResolveOpts) (Backend, error) {
	var candidates []Backend
	if !opts.DisableKeychain {
		candidates = append(candidates, NewKeychainBackend())
	}
	candidates = append(candidates, newEncryptedFileBackendFromOpts(opts))
	if opts.PlainFileOptIn {
		candidates = append(candidates, NewPlainFileBackend(opts.Paths))
	}
	return resolveFrom(candidates)
}

// newEncryptedFileBackendFromOpts wires the encrypted-file backend
// from ResolveOpts: a pre-supplied passphrase takes precedence over a
// provider; absence of both yields an unusable backend (Available()
// returns an error and the resolver skips it).
func newEncryptedFileBackendFromOpts(opts ResolveOpts) Backend {
	path := defaultEncryptedFilePath(opts.Paths)
	if opts.EncryptedFilePassphrase != nil {
		return NewEncryptedFileBackendForTest(path, opts.EncryptedFilePassphrase)
	}
	if opts.EncryptedFilePassphraseProvider != nil {
		return NewEncryptedFileBackendWithProvider(path, opts.EncryptedFilePassphraseProvider)
	}
	return NewEncryptedFileBackend(opts.Paths)
}

// resolveFrom is the testable core: tests inject a synthetic candidate
// list so the decision table can be exercised without touching real
// OS APIs.
func resolveFrom(candidates []Backend) (Backend, error) {
	for _, b := range candidates {
		if err := b.Available(); err != nil {
			log.Printf("saltstore: skipping backend %s: %v", b.Name(), err)
			continue
		}
		log.Printf("saltstore: using backend %s", b.Name())
		return b, nil
	}
	return nil, ErrSaltStorageUnavailable
}
