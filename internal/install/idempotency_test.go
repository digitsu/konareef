// Copyright 2026 Jerry David Chan, Konareef.ai
// SPDX-License-Identifier: Apache-2.0

// Package install: idempotency_test.go — CheckInstalled exercises
// the four observable verdicts: dir missing, hash match, hash
// conflict, and corrupt meta.json (fail-loud).
package install

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// writeMeta writes a meta.json under
// <home>/.konareef/installed/<handle>/<pod>/<version>/ with the
// given pod_hash hex. Helper for the conflict/match cases.
func writeMeta(t *testing.T, home, handle, pod, version, podHashHex string) {
	t.Helper()
	dir := filepath.Join(home, ".konareef", "installed", handle, pod, version)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	body, _ := json.Marshal(map[string]string{
		"handle":               handle,
		"pod_name":             pod,
		"pod_version":          version,
		"pod_hash":             podHashHex,
		"publisher_pubkey_hex": "027d31884f6f895b6b5f4a249296150d648bbda4d57c4424bb2676f7671c63ff5d",
	})
	if err := os.WriteFile(filepath.Join(dir, "meta.json"), body, 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
}

func TestCheckInstalledMissingDir(t *testing.T) {
	home := t.TempDir()
	hash := sha256.Sum256([]byte("anything"))
	status, err := CheckInstalled(home, "alice", "research-bot", "1.0.0", hash)
	if err != nil {
		t.Fatalf("CheckInstalled: %v", err)
	}
	if status != StatusNotInstalled {
		t.Errorf("status = %v, want StatusNotInstalled", status)
	}
}

func TestCheckInstalledSameHash(t *testing.T) {
	home := t.TempDir()
	hash := sha256.Sum256([]byte("manifest-bytes"))
	writeMeta(t, home, "alice", "research-bot", "1.0.0", hex.EncodeToString(hash[:]))

	status, err := CheckInstalled(home, "alice", "research-bot", "1.0.0", hash)
	if err != nil {
		t.Fatalf("CheckInstalled: %v", err)
	}
	if status != StatusAlreadyInstalled {
		t.Errorf("status = %v, want StatusAlreadyInstalled", status)
	}
}

func TestCheckInstalledDifferentHash(t *testing.T) {
	home := t.TempDir()
	localHash := sha256.Sum256([]byte("manifest-bytes-v1"))
	remoteHash := sha256.Sum256([]byte("manifest-bytes-v2"))
	writeMeta(t, home, "alice", "research-bot", "1.0.0", hex.EncodeToString(localHash[:]))

	status, err := CheckInstalled(home, "alice", "research-bot", "1.0.0", remoteHash)
	if err != nil {
		t.Fatalf("CheckInstalled: %v", err)
	}
	if status != StatusConflict {
		t.Errorf("status = %v, want StatusConflict", status)
	}
}

func TestCheckInstalledMalformedMeta(t *testing.T) {
	home := t.TempDir()
	dir := filepath.Join(home, ".konareef", "installed", "alice", "research-bot", "1.0.0")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	// Truncated JSON — parse fails.
	if err := os.WriteFile(filepath.Join(dir, "meta.json"), []byte(`{"pod_hash":"a`), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	hash := sha256.Sum256([]byte("anything"))
	status, err := CheckInstalled(home, "alice", "research-bot", "1.0.0", hash)
	if err == nil {
		t.Fatalf("CheckInstalled accepted corrupt meta.json; status=%v", status)
	}
}
