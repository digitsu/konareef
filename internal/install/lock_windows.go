//go:build windows

// Package install: lock_windows.go — no-op fallback for the per-pod
// advisory lock. A real LockFileEx-based implementation is deferred
// to a follow-up slice; this file keeps the install path functional
// on windows and emits a one-time stderr warning so the regression
// is visible.
package install

import (
	"fmt"
	"os"
	"sync"
	"time"
)

var windowsLockWarnOnce sync.Once

// acquireFlock on windows is a no-op + one-time stderr warning. The
// timeout is intentionally ignored.
func acquireFlock(_ *os.File, _ time.Duration) error {
	windowsLockWarnOnce.Do(func() {
		fmt.Fprintln(os.Stderr,
			"warning: concurrent-install lock unsupported on windows; concurrent installs may race")
	})
	return nil
}

// releaseFlock on windows is a no-op.
func releaseFlock(_ *os.File) {}
