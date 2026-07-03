// Package install: idempotency.go — implements CheckInstalled, the
// pre-Verify gate that decides whether a fetched pod should be
// re-installed, treated as already installed (same hash), or refused
// as a conflict (different hash) against the local cache.
//
// CheckInstalled is read-only against the cache; it never mutates
// disk. Callers are responsible for acting on the returned Status
// (typically: print "already installed" + exit 0 on AlreadyInstalled,
// wrap ErrInstallHashMismatch on Conflict, fall through to Verify +
// Cache on NotInstalled).
//
// A returned error is reserved for "I could not decide" — e.g.
// corrupt or partially-written meta.json. Corrupt meta is fail-loud
// (not silently treated as not-installed) because a partial write
// from a previous crash is exactly the case StatusConflict exists to
// prevent silently overwriting.
package install

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// Status is the verdict CheckInstalled returns for a fetched pod
// against the local cache.
type Status int

const (
	// StatusNotInstalled — no cache entry for this handle/pod/version.
	// Caller should proceed with Verify + Cache as normal.
	StatusNotInstalled Status = iota
	// StatusAlreadyInstalled — cache entry exists and its pod_hash
	// matches the fetched manifest. Caller should print
	// "already installed" and exit 0; skip Verify + Cache.
	StatusAlreadyInstalled
	// StatusConflict — cache entry exists at this version but its
	// pod_hash differs from the fetched manifest. Caller MUST refuse
	// (do not overwrite) and surface ErrInstallHashMismatch.
	StatusConflict
)

// String renders a Status for log lines and error messages.
func (s Status) String() string {
	switch s {
	case StatusNotInstalled:
		return "not-installed"
	case StatusAlreadyInstalled:
		return "already-installed"
	case StatusConflict:
		return "conflict"
	default:
		return fmt.Sprintf("Status(%d)", int(s))
	}
}

// metaShape mirrors the on-disk meta.json layout produced by Cache.
// Kept in sync with the map literal in install.go's Cache function.
type metaShape struct {
	Handle             string `json:"handle"`
	PodName            string `json:"pod_name"`
	PodVersion         string `json:"pod_version"`
	PodHash            string `json:"pod_hash"`
	PublisherPubkeyHex string `json:"publisher_pubkey_hex"`
}

// CheckInstalled inspects
// `<home>/.konareef/installed/<handle>/<podName>/<version>/meta.json`
// and reports whether a fetched pod with hash `fetchedHash` should be
// re-installed, treated as already installed, or rejected as a
// conflict.
//
// Returns:
//   - (StatusNotInstalled, nil) when the version directory or
//     meta.json is absent — happy path for first install of this
//     version.
//   - (StatusAlreadyInstalled, nil) when the local pod_hash equals
//     fetchedHash — idempotent re-install.
//   - (StatusConflict, nil) when the local pod_hash exists and
//     differs from fetchedHash — caller MUST refuse.
//   - (StatusNotInstalled, non-nil error) only when meta.json is
//     present but cannot be parsed (corrupt JSON, missing pod_hash
//     field, malformed hex, wrong byte length). Status is always
//     StatusNotInstalled on error paths so callers cannot accidentally
//     act on an indeterminate verdict.
func CheckInstalled(home, handle, podName, version string, fetchedHash [32]byte) (Status, error) {
	metaPath := filepath.Join(home, ".konareef", "installed", handle, podName, version, "meta.json")
	raw, err := os.ReadFile(metaPath)
	if errors.Is(err, os.ErrNotExist) {
		return StatusNotInstalled, nil
	}
	if err != nil {
		return StatusNotInstalled, fmt.Errorf("read meta.json at %s: %w", metaPath, err)
	}
	var m metaShape
	if err := json.Unmarshal(raw, &m); err != nil {
		return StatusNotInstalled, fmt.Errorf("parse meta.json at %s: %w", metaPath, err)
	}
	if m.PodHash == "" {
		return StatusNotInstalled, fmt.Errorf("meta.json at %s is missing pod_hash", metaPath)
	}
	haveBytes, err := hex.DecodeString(m.PodHash)
	if err != nil {
		return StatusNotInstalled, fmt.Errorf("meta.json at %s has malformed pod_hash hex: %w", metaPath, err)
	}
	if len(haveBytes) != 32 {
		return StatusNotInstalled, fmt.Errorf("meta.json at %s pod_hash is %d bytes; SHA-256 is exactly 32", metaPath, len(haveBytes))
	}
	var have [32]byte
	copy(have[:], haveBytes)
	if have == fetchedHash {
		return StatusAlreadyInstalled, nil
	}
	return StatusConflict, nil
}
