// Copyright 2026 Jerry David Chan, Konareef.ai
// SPDX-License-Identifier: Apache-2.0

// Package install: meta.go — read back the `meta.json` that Cache
// writes into an install-cache version directory.
//
// Cache is the only writer of that file and metaShape (idempotency.go)
// is its on-disk shape; this file exposes the read side to packages
// outside install — today `internal/run`, which must know a pod's
// publication mode and its locally verified pod_hash before deciding
// how to spawn it. Keeping the decode here rather than in the consumer
// means the cache format has exactly one definition.

package install

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

// CachedMeta is the subset of an install cache's meta.json that
// callers outside this package act on.
//
// PodHash is the 64-char lowercase hex SHA-256 of the canonical
// manifest, as re-derived and signature-checked locally by Verify at
// install time — not a value taken on a server's word.
//
// Visibility is "closed" for a closed pod and EMPTY for an open one:
// Cache writes the key only for closed pods, so absence is the
// open-pod default both on the wire and on disk. Callers must treat an
// empty Visibility as open rather than as "unknown".
type CachedMeta struct {
	PodHash    string
	Visibility string
}

// IsClosed reports whether the cached pod is a closed pod — HEAD-only
// on disk, with no content/ dir to spawn from. A nil receiver (no
// meta.json at all, i.e. an unsigned/legacy install) is open.
func (m *CachedMeta) IsClosed() bool {
	return m != nil && m.Visibility == visibilityClosed
}

// LoadCachedMeta reads
// `<home>/.konareef/installed/<handle>/<podName>/<version>/meta.json`
// and returns its decoded CachedMeta.
//
// A missing meta.json is reported as an error wrapping os.ErrNotExist,
// which callers are expected to check with errors.Is and treat as the
// legacy/unsigned open-pod install (that path predates meta.json and
// must keep working). Every other failure — unreadable file, malformed
// JSON — is fatal: meta.json is what a closed pod's spawn dispatches
// on, so a corrupt one must fail loud rather than silently fall back to
// a path that assumes local content exists.
func LoadCachedMeta(home, handle, podName, version string) (*CachedMeta, error) {
	metaPath := filepath.Join(home, ".konareef", "installed", handle, podName, version, "meta.json")
	raw, err := os.ReadFile(metaPath)
	if err != nil {
		return nil, fmt.Errorf("read meta.json at %s: %w", metaPath, err)
	}
	var m metaShape
	if err := json.Unmarshal(raw, &m); err != nil {
		return nil, fmt.Errorf("parse meta.json at %s: %w", metaPath, err)
	}
	return &CachedMeta{PodHash: m.PodHash, Visibility: m.Visibility}, nil
}
