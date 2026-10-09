// Copyright 2026 Jerry David Chan, Konareef.ai
// SPDX-License-Identifier: Apache-2.0

//go:build integration

// internal/saltstore/integration_test.go — exercises the real OS
// keyring (not mocked). Build tag "integration" so it's excluded from
// the standard go test ./... sweep.
//
// CI prerequisites:
//
//	darwin runner (GitHub macos-latest): nothing extra; macOS Keychain
//	is available out of the box. The first Set() call may prompt for
//	keychain access — the CI runner should pre-unlock the login
//	keychain via `security unlock-keychain -p '' login.keychain` before
//	this test runs.
//
//	linux runner: spin up gnome-keyring-daemon + dbus session BEFORE
//	`go test -tags integration` runs. Sample workflow recipe:
//
//	  sudo apt-get install -y gnome-keyring libsecret-1-0 dbus-x11
//	  dbus-run-session -- bash -c '
//	    printf "test-passphrase\n" |
//	      gnome-keyring-daemon --unlock --components=secrets &
//	    printf "test-passphrase\n" |
//	      gnome-keyring-daemon --start --components=secrets
//	    go test -tags integration -v ./internal/saltstore/...
//	  '
package saltstore

import (
	"crypto/rand"
	"testing"
)

func TestKeychainBackendIntegration(t *testing.T) {
	b := NewKeychainBackend()
	if err := b.Available(); err != nil {
		t.Skipf("keyring unavailable on this runner: %v", err)
	}
	var lid [16]byte
	if _, err := rand.Read(lid[:]); err != nil {
		t.Fatal(err)
	}
	var salt [32]byte
	if _, err := rand.Read(salt[:]); err != nil {
		t.Fatal(err)
	}
	// Cleanup at the end so a re-run doesn't trip ErrSaltAlreadyExists.
	t.Cleanup(func() { _ = b.Delete(lid) })

	if err := b.Put(lid, salt); err != nil {
		t.Fatalf("Put: %v", err)
	}
	got, err := b.Get(lid)
	if err != nil || got != salt {
		t.Fatalf("Get: got=%x err=%v", got, err)
	}
}

func TestKeychainBackendIntegrationAlreadyExists(t *testing.T) {
	b := NewKeychainBackend()
	if err := b.Available(); err != nil {
		t.Skipf("keyring unavailable: %v", err)
	}
	var lid [16]byte
	if _, err := rand.Read(lid[:]); err != nil {
		t.Fatal(err)
	}
	var salt [32]byte
	if _, err := rand.Read(salt[:]); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = b.Delete(lid) })
	if err := b.Put(lid, salt); err != nil {
		t.Fatal(err)
	}
	if err := b.Put(lid, salt); err == nil {
		t.Error("second Put should have returned ErrSaltAlreadyExists")
	}
}
