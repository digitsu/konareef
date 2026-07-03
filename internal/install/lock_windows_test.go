//go:build windows

package install

import (
	"testing"
	"time"
)

// On windows the lock is a no-op + warning; we just confirm
// AcquireLock succeeds and Release does not panic. Mutual exclusion
// is not exercised — there is none, by current design.
func TestLockNoOpOnWindows(t *testing.T) {
	home := t.TempDir()
	lock, err := AcquireLock(home, "alice", "research-bot", time.Second)
	if err != nil {
		t.Fatalf("AcquireLock: %v", err)
	}
	if err := lock.Release(); err != nil {
		t.Errorf("Release: %v", err)
	}
}
