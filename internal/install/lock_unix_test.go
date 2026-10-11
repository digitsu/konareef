// Copyright 2026 Jerry David Chan, Konareef.ai
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

// Package install: lock_unix_test.go — flock semantics on unix.
// Two distinct file descriptors on the same lock path mutually
// exclude via BSD flock(2) / POSIX flock semantics, so we can
// simulate two callers within one process by opening two FDs.
package install

import (
	"errors"
	"testing"
	"time"
)

func TestLockAcquireReleaseRoundTrip(t *testing.T) {
	home := t.TempDir()
	lock, err := AcquireLock(home, "alice", "research-bot", time.Second)
	if err != nil {
		t.Fatalf("AcquireLock: %v", err)
	}
	if err := lock.Release(); err != nil {
		t.Errorf("Release: %v", err)
	}
	// Second acquire should succeed immediately.
	lock2, err := AcquireLock(home, "alice", "research-bot", time.Second)
	if err != nil {
		t.Fatalf("second AcquireLock: %v", err)
	}
	_ = lock2.Release()
}

func TestLockBlocksSecondCaller(t *testing.T) {
	home := t.TempDir()
	lock, err := AcquireLock(home, "alice", "research-bot", time.Second)
	if err != nil {
		t.Fatalf("AcquireLock: %v", err)
	}
	defer lock.Release()

	// Second caller with a tight timeout should give up with ErrLocalLocked.
	start := time.Now()
	_, err = AcquireLock(home, "alice", "research-bot", 400*time.Millisecond)
	elapsed := time.Since(start)
	if !errors.Is(err, ErrLocalLocked) {
		t.Fatalf("expected ErrLocalLocked, got %v", err)
	}
	if elapsed < 400*time.Millisecond {
		t.Errorf("second AcquireLock returned too fast: %v", elapsed)
	}
}

func TestLockReleasedAfterCallerExits(t *testing.T) {
	home := t.TempDir()
	lock, err := AcquireLock(home, "alice", "research-bot", time.Second)
	if err != nil {
		t.Fatalf("AcquireLock: %v", err)
	}
	if err := lock.Release(); err != nil {
		t.Fatalf("Release: %v", err)
	}
	// Second caller should NOT see ErrLocalLocked.
	lock2, err := AcquireLock(home, "alice", "research-bot", 100*time.Millisecond)
	if err != nil {
		t.Fatalf("second AcquireLock after release: %v", err)
	}
	_ = lock2.Release()
}
