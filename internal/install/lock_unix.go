// Copyright 2026 Jerry David Chan, Konareef.ai
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

// Package install: lock_unix.go — POSIX/BSD flock implementation of
// the per-pod advisory lock. Kernel releases the lock on FD close,
// so a kill -9'd install does not strand the next attempt.
package install

import (
	"errors"
	"fmt"
	"os"
	"syscall"
	"time"
)

// acquireFlock takes an exclusive non-blocking advisory lock on f,
// polling every 250 ms until timeout expires. Returns ErrLocalLocked
// if the lock could not be acquired within timeout.
func acquireFlock(f *os.File, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for {
		err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
		if err == nil {
			return nil
		}
		if !errors.Is(err, syscall.EWOULDBLOCK) {
			return fmt.Errorf("flock: %w", err)
		}
		if !time.Now().Before(deadline) {
			return ErrLocalLocked
		}
		time.Sleep(250 * time.Millisecond)
	}
}

// releaseFlock releases the advisory lock on f. The kernel also
// releases on FD close, so errors here are intentionally ignored —
// Close in Release will tidy up regardless.
func releaseFlock(f *os.File) {
	_ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
}
