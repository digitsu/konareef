// internal/publish/publish_salt_leak_test.go — B2 acceptance test.
//
// Architectural argument: the genesis salt is persisted under
// ${KONAREEF_STATE_DIR:-~/.konareef}/typed/{lineage_id_hex}/salt.bin
// (or in the OS keyring) — a path OUTSIDE every pod worktree. The
// `konareef pod publish` path operates on the pod worktree only and
// therefore cannot include the salt.
//
// This test makes the claim falsifiable: it runs a fresh pod.Init →
// genesis-salt Put (via a tempdir KONAREEF_STATE_DIR), then runs
// publish.Prepare against the worktree, and greps both the canonical
// manifest bytes and every file under the worktree for the literal
// 32-byte salt. Zero hits is required; any hit means the publish
// boundary leaks the salt.
package publish_test

import (
	"bytes"
	cryptorand "crypto/rand"
	"os"
	"path/filepath"
	"testing"

	"github.com/digitsu/konareef/internal/identity"
	"github.com/digitsu/konareef/internal/pod"
	"github.com/digitsu/konareef/internal/publish"
	"github.com/digitsu/konareef/internal/saltstore"
)

func TestPublish_DoesNotLeakGenesisSalt(t *testing.T) {
	stateDir := t.TempDir()
	t.Setenv("KONAREEF_STATE_DIR", stateDir)

	// Scaffold a brand-new pod and persist the genesis salt under the
	// resolved backend. We do this directly (rather than via
	// runPodInitCore in main.go) to avoid a cross-package cycle; the
	// behaviour mirrors what `konareef pod init` does.
	podDir := filepath.Join(t.TempDir(), "leak-grep-fixture")
	if _, err := pod.Init(pod.InitOptions{Name: "leak-grep-fixture", Dir: podDir}); err != nil {
		t.Fatalf("pod.Init: %v", err)
	}
	spec, err := pod.ParseFile(filepath.Join(podDir, "pod.toml"))
	if err != nil {
		t.Fatalf("ParseFile: %v", err)
	}
	lid, err := saltstore.LineageIDFromManifest(&spec)
	if err != nil {
		t.Fatalf("LineageIDFromManifest: %v", err)
	}
	var salt [32]byte
	if _, err := cryptorand.Read(salt[:]); err != nil {
		t.Fatal(err)
	}
	// Inject the passphrase via ResolveOpts so the encrypted-file backend
	// is unconditionally available. CI has no OS keyring (no dbus) and no
	// TTY, and the production encrypted-file backend wires no env-reading
	// passphrase provider, so a bare Resolve({}) returns
	// ErrSaltStorageUnavailable there. The leak-grep below is
	// backend-independent (the salt is stored outside the pod worktree
	// regardless of tier).
	backend, err := saltstore.Resolve(saltstore.ResolveOpts{
		EncryptedFilePassphrase: []byte("ci-test-passphrase"),
	})
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if err := backend.Put(lid, salt); err != nil {
		t.Fatalf("backend.Put: %v", err)
	}
	t.Cleanup(func() { _ = backend.Delete(lid) })

	// publish.Prepare requires a publisher identity but does not
	// touch the salt or the resolved backend.
	id, err := identity.Generate("leak-grep-publisher")
	if err != nil {
		t.Fatalf("identity.Generate: %v", err)
	}
	prepared, err := publish.Prepare(podDir, id)
	if err != nil {
		t.Fatalf("publish.Prepare: %v", err)
	}

	// (1) The canonical bytes that go on the wire MUST NOT contain
	// the raw 32-byte salt.
	if bytes.Contains(prepared.CanonicalBytes, salt[:]) {
		t.Errorf("LEAK: raw 32-byte salt found in publish canonical bytes")
	}

	// (2) Defense in depth: every file that ended up in the pod
	// worktree. If a future refactor moves the salt path INTO the
	// worktree, this catches the regression at the earliest possible
	// point.
	err = filepath.Walk(podDir, func(p string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return nil
		}
		body, err := os.ReadFile(p)
		if err != nil {
			return nil
		}
		if bytes.Contains(body, salt[:]) {
			t.Errorf("LEAK: raw 32-byte salt found in worktree file %s", p)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("Walk: %v", err)
	}
}
