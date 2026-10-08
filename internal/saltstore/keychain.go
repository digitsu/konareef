// Copyright 2026 Jerry David Chan, Konareef.ai
// SPDX-License-Identifier: Apache-2.0

// internal/saltstore/keychain.go — OS keyring backend.
//
// service name = "konareef-pod-salt"
// account      = lineage_id hex (32 chars, lowercase)
// secret value = salt bytes hex (64 chars, lowercase)
//
// Unit tests use MockBackend; this backend's real OS-API coverage is
// the integration_test.go suite (build tag "integration") which runs
// on the darwin CI runner against macOS Keychain and on the linux CI
// runner against gnome-keyring-daemon-provided Secret Service.
package saltstore

import (
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/zalando/go-keyring"
)

const keychainService = "konareef-pod-salt"

type keychainBackend struct{}

func newKeychainBackend() Backend { return &keychainBackend{} }

func (k *keychainBackend) Name() string { return "keychain" }

func (k *keychainBackend) Available() error {
	// Probe: try to Get a sentinel non-existent account. ErrNotFound
	// is the "service responding, just no entry" signal we want; any
	// other error means the keyring daemon is unreachable.
	_, err := keyring.Get(keychainService, "_probe_availability")
	if err == nil || errors.Is(err, keyring.ErrNotFound) {
		return nil
	}
	return fmt.Errorf("keyring unavailable: %w", err)
}

func (k *keychainBackend) Put(lid [16]byte, salt [32]byte) error {
	account := hex.EncodeToString(lid[:])
	if existing, err := keyring.Get(keychainService, account); err == nil && existing != "" {
		return ErrSaltAlreadyExists
	} else if err != nil && !errors.Is(err, keyring.ErrNotFound) {
		return fmt.Errorf("%w: get probe: %v", ErrSaltBackendIO, err)
	}
	if err := keyring.Set(keychainService, account, hex.EncodeToString(salt[:])); err != nil {
		return fmt.Errorf("%w: set: %v", ErrSaltBackendIO, err)
	}
	return nil
}

func (k *keychainBackend) Get(lid [16]byte) ([32]byte, error) {
	account := hex.EncodeToString(lid[:])
	val, err := keyring.Get(keychainService, account)
	if err != nil {
		if errors.Is(err, keyring.ErrNotFound) {
			return [32]byte{}, ErrSaltNotFound
		}
		return [32]byte{}, fmt.Errorf("%w: get: %v", ErrSaltBackendIO, err)
	}
	raw, err := hex.DecodeString(val)
	if err != nil || len(raw) != 32 {
		return [32]byte{}, fmt.Errorf("%w: bad-hex secret: %v", ErrSaltBackendIO, err)
	}
	var s [32]byte
	copy(s[:], raw)
	return s, nil
}

func (k *keychainBackend) Delete(lid [16]byte) error {
	account := hex.EncodeToString(lid[:])
	if err := keyring.Delete(keychainService, account); err != nil {
		if errors.Is(err, keyring.ErrNotFound) {
			return ErrSaltNotFound
		}
		return fmt.Errorf("%w: delete: %v", ErrSaltBackendIO, err)
	}
	return nil
}

// List is best-effort on keychain backends — go-keyring does not expose
// enumeration on all platforms. We surface a clear sentinel rather than
// silently returning an empty list, so `konareef salt status` can
// degrade visibly. The encrypted-file and plain-file backends DO
// support List(); a publisher using keychain alone is told to use
// either of those backends or to maintain their own lineage_id list
// via the pod manifests.
func (k *keychainBackend) List() ([][16]byte, error) {
	return nil, fmt.Errorf("%w: keychain List() unsupported on this platform; use `konareef salt status` against a manifest-driven backend",
		ErrSaltBackendIO)
}
