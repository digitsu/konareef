// Copyright 2026 Jerry David Chan, Konareef.ai
// SPDX-License-Identifier: Apache-2.0

// storage.go — persistence of the publisher identity file.
//
// Path returns the canonical location (`<home>/.konareef/identity.json`).
// Save writes the file atomically with mode 0600 inside a 0700 parent
// directory. Load reads it back, refusing any file whose permissions
// have drifted looser than 0600 — the private key is a credential and
// a careless `chmod` must be treated as fatal, not silently honored.

package identity

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

const (
	dirName      = ".konareef"
	fileName     = "identity.json"
	requiredMode = os.FileMode(0o600)
	dirMode      = os.FileMode(0o700)
)

// Path returns the canonical identity-file path under home:
// `<home>/.konareef/identity.json`. The CLI passes os.UserHomeDir();
// tests pass t.TempDir().
func Path(home string) string {
	return filepath.Join(home, dirName, fileName)
}

// Save writes id to <home>/.konareef/identity.json with mode 0600.
// The parent directory is created (mode 0700) on first save.
//
// The write is atomic: id is serialized to a sibling temp file (with
// the target permission bits already set), then renamed onto the final
// path. A crash mid-write therefore never leaves a half-written
// identity, and a successful Save never widens the file's permissions.
func (id *Identity) Save(home string) error {
	dir := filepath.Join(home, dirName)
	if err := os.MkdirAll(dir, dirMode); err != nil {
		return fmt.Errorf("create identity directory: %w", err)
	}
	body, err := json.MarshalIndent(id, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal identity: %w", err)
	}
	body = append(body, '\n')

	tmp, err := os.CreateTemp(dir, ".identity-*.json.tmp")
	if err != nil {
		return fmt.Errorf("create temp identity: %w", err)
	}
	tmpName := tmp.Name()
	renamed := false
	defer func() {
		if !renamed {
			_ = os.Remove(tmpName)
		}
	}()

	if err := os.Chmod(tmpName, requiredMode); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("chmod temp identity: %w", err)
	}
	if _, err := tmp.Write(body); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("write temp identity: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close temp identity: %w", err)
	}
	if err := os.Rename(tmpName, Path(home)); err != nil {
		return fmt.Errorf("rename temp identity: %w", err)
	}
	renamed = true
	return nil
}

// Load reads the identity file at Path(home). It returns an error
// rather than the parsed Identity in three cases:
//
//   - the file does not exist (run `konareef pod identity create` first);
//   - the file's permissions are anything other than exactly 0600;
//   - the file's contents are not valid Identity JSON.
//
// The permission check is strict: a 0644 file is refused, not honored,
// because the private key inside it is a credential and a careless
// chmod is the most likely silent compromise vector.
func Load(home string) (*Identity, error) {
	path := Path(home)
	fi, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("stat identity file: %w", err)
	}
	if perm := fi.Mode().Perm(); perm != requiredMode {
		return nil, fmt.Errorf(
			"identity file %s has mode %o; expected %o — restore with `chmod 600 %s`",
			path, perm, requiredMode, path,
		)
	}
	body, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read identity file: %w", err)
	}
	var id Identity
	if err := json.Unmarshal(body, &id); err != nil {
		return nil, fmt.Errorf("parse identity file: %w", err)
	}
	return &id, nil
}
