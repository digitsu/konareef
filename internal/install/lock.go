// Copyright 2026 Jerry David Chan, Konareef.ai
// SPDX-License-Identifier: Apache-2.0

// Package install: lock.go — per-pod advisory locking around the
// install pipeline.
//
// Concurrent `konareef install <same-handle>/<same-pod>` invocations
// would otherwise race on the cache directory and on
// known_publishers.json. AcquireLock serializes them at a per-pod
// granularity (parallel installs of *different* handles or pods do
// not block each other).
//
// The lock primitive is platform-specific (see lock_unix.go,
// lock_windows.go). This file defines the cross-platform surface:
// AcquireLock returns a *Lock; the caller MUST Release it (typically
// via defer).
package install

import (
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// Lock represents a held per-pod advisory lock. Acquired via
// AcquireLock; released via Release (or via the kernel on FD close,
// on unix). Release is idempotent and safe on a nil receiver.
type Lock struct {
	file *os.File
}

// AcquireLock takes an exclusive advisory lock on
// `<home>/.konareef/installed/<handle>/<podName>/.lock`. If another
// process holds the lock, AcquireLock polls every 250 ms until the
// timeout elapses, at which point it returns ErrLocalLocked.
//
// The pod-scoped lock directory (`<handle>/<podName>/`) is created
// if absent; the version subdirectory is NOT created here (that
// remains Cache's responsibility).
//
// On windows, this is a no-op + one-time stderr warning; the
// returned Lock can still be Release'd safely.
func AcquireLock(home, handle, podName string, timeout time.Duration) (*Lock, error) {
	podDir := filepath.Join(home, ".konareef", "installed", handle, podName)
	if err := os.MkdirAll(podDir, 0o755); err != nil {
		return nil, fmt.Errorf("create pod dir for lock: %w", err)
	}
	lockPath := filepath.Join(podDir, ".lock")
	f, err := os.OpenFile(lockPath, os.O_RDWR|os.O_CREATE, 0o644)
	if err != nil {
		return nil, fmt.Errorf("open lock file %s: %w", lockPath, err)
	}
	if err := acquireFlock(f, timeout); err != nil {
		_ = f.Close()
		return nil, err
	}
	return &Lock{file: f}, nil
}

// Release releases the advisory lock and closes the lock file. Safe
// to call on a nil receiver, and idempotent (a second call is a
// no-op).
func (l *Lock) Release() error {
	if l == nil || l.file == nil {
		return nil
	}
	releaseFlock(l.file)
	err := l.file.Close()
	l.file = nil
	return err
}
