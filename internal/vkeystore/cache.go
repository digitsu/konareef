package vkeystore

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// CACHEDIR.TAG body recognised by borg/restic/rsync --exclude-caches.
const cacheDirTag = "Signature: 8a477f597d28d172789f06886806bc55\n" +
	"# This file is a cache directory tag created by konareef.\n" +
	"# For information about cache directory tags see https://bford.info/cachedir/\n"

// LocalCache persists resolved vkeys under
// ${KONAREEF_STATE_DIR:-~/.konareef}/vkeys/{circuit_id}/{vkey_sha256}/.
type LocalCache struct {
	rootDir string // .../vkeys
}

// NewLocalCache initialises the cache directory tree and writes CACHEDIR.TAG
// on first use.
func NewLocalCache() (*LocalCache, error) {
	base, err := stateDir()
	if err != nil {
		return nil, err
	}
	root := filepath.Join(base, "vkeys")
	if err := os.MkdirAll(root, 0o700); err != nil {
		return nil, fmt.Errorf("vkeystore: mkdir cache: %w", err)
	}
	tag := filepath.Join(root, "CACHEDIR.TAG")
	if _, err := os.Stat(tag); errors.Is(err, os.ErrNotExist) {
		if err := os.WriteFile(tag, []byte(cacheDirTag), 0o600); err != nil {
			return nil, fmt.Errorf("vkeystore: write CACHEDIR.TAG: %w", err)
		}
	}
	return &LocalCache{rootDir: root}, nil
}

// Lookup returns the cached Vkey for (circuitID, vkeySha256) or nil if absent.
// Returns ErrCircuitIDInvalid / ErrVkeySha256Invalid when the inputs would
// be unsafe to interpolate into a filesystem path (path traversal /
// separator / non-hex / wrong-length). Returns ErrCircuitPinMismatch when
// the on-disk vkey.bin no longer hashes to its pin (tampering / partial
// write). Returns ErrVkeyCorrupt when meta.json is malformed or vkey.bin
// is missing.
func (c *LocalCache) Lookup(circuitID, vkeySha256 string) (*Vkey, error) {
	if err := ValidateCircuitID(circuitID); err != nil {
		return nil, err
	}
	if err := ValidateVkeySha256(vkeySha256); err != nil {
		return nil, err
	}
	dir := filepath.Join(c.rootDir, circuitID, vkeySha256)
	binPath := filepath.Join(dir, "vkey.bin")
	metaPath := filepath.Join(dir, "meta.json")
	body, err := os.ReadFile(binPath)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("vkeystore: read vkey.bin: %w", err)
	}
	if err := VerifyPin(vkeySha256, body); err != nil {
		return nil, err
	}
	metaBytes, err := os.ReadFile(metaPath)
	if err != nil {
		return nil, fmt.Errorf("%w: meta.json: %v", ErrVkeyCorrupt, err)
	}
	var meta struct {
		CircuitID  string `json:"circuit_id"`
		VkeySha256 string `json:"vkey_sha256"`
		Source     string `json:"source"`
		ResolvedAt string `json:"resolved_at"`
	}
	if err := json.Unmarshal(metaBytes, &meta); err != nil {
		return nil, fmt.Errorf("%w: meta.json parse: %v", ErrVkeyCorrupt, err)
	}
	resolvedAt, err := time.Parse(time.RFC3339Nano, meta.ResolvedAt)
	if err != nil {
		return nil, fmt.Errorf("%w: meta.json resolved_at: %v", ErrVkeyCorrupt, err)
	}
	return &Vkey{
		CircuitID:  circuitID,
		VkeySha256: vkeySha256,
		Bytes:      body,
		Source:     SourceCache,
		ResolvedAt: resolvedAt,
	}, nil
}

// Store writes (circuitID, vkeySha256, body) and a meta.json record. The
// caller is responsible for having pin-verified body before calling Store;
// Store double-checks defensively. Both identifier inputs are validated
// (ErrCircuitIDInvalid / ErrVkeySha256Invalid) before any filesystem
// interpolation to defeat path traversal / cache poisoning.
func (c *LocalCache) Store(circuitID, vkeySha256 string, body []byte, src Source) error {
	if err := ValidateCircuitID(circuitID); err != nil {
		return err
	}
	if err := ValidateVkeySha256(vkeySha256); err != nil {
		return err
	}
	if err := VerifyPin(vkeySha256, body); err != nil {
		return err
	}
	dir := filepath.Join(c.rootDir, circuitID, vkeySha256)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("vkeystore: mkdir entry: %w", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "vkey.bin"), body, 0o600); err != nil {
		return fmt.Errorf("vkeystore: write vkey.bin: %w", err)
	}
	meta := map[string]string{
		"circuit_id":  circuitID,
		"vkey_sha256": vkeySha256,
		"source":      string(src),
		"resolved_at": time.Now().UTC().Format(time.RFC3339Nano),
	}
	out, err := json.MarshalIndent(meta, "", "  ")
	if err != nil {
		return fmt.Errorf("vkeystore: marshal meta: %w", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "meta.json"), out, 0o600); err != nil {
		return fmt.Errorf("vkeystore: write meta.json: %w", err)
	}
	return nil
}

// HasAnyPinFor reports whether the cache contains at least one entry
// for circuitID (under any vkey_sha256 directory). Used by the P1.8
// pin-check state machine to detect State C divergence (a different
// pin for the same circuit_id is cached).
//
// Identifier validation mirrors Lookup/Store; an invalid circuitID
// returns false (the caller cannot have stored anything under it).
func (c *LocalCache) HasAnyPinFor(circuitID string) bool {
	if err := ValidateCircuitID(circuitID); err != nil {
		return false
	}
	entries, err := os.ReadDir(filepath.Join(c.rootDir, circuitID))
	if err != nil {
		return false
	}
	for _, e := range entries {
		if e.IsDir() {
			return true
		}
	}
	return false
}

// Has reports whether the cache contains an entry at
// circuitID/vkeySha256 (directory exists with a vkey.bin file). Used
// by the P1.8 pin-check state machine to distinguish State B (cache
// hit, pins match) from State A (cache miss) without invoking the
// full Lookup (which would also do pin verification).
//
// Invalid identifiers return false.
func (c *LocalCache) Has(circuitID, vkeySha256 string) bool {
	if err := ValidateCircuitID(circuitID); err != nil {
		return false
	}
	if err := ValidateVkeySha256(vkeySha256); err != nil {
		return false
	}
	binPath := filepath.Join(c.rootDir, circuitID, vkeySha256, "vkey.bin")
	if _, err := os.Stat(binPath); err != nil {
		return false
	}
	return true
}

// stateDir resolves ${KONAREEF_STATE_DIR} or ~/.konareef. Mirrors the P1.7.1
// saltstore pattern so both subsystems share one on-disk root.
func stateDir() (string, error) {
	if v := os.Getenv("KONAREEF_STATE_DIR"); v != "" {
		return v, nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("vkeystore: resolve home: %w", err)
	}
	return filepath.Join(home, ".konareef"), nil
}
