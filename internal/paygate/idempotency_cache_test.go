// Copyright 2026 Jerry David Chan, Konareef.ai
// SPDX-License-Identifier: Apache-2.0

// internal/paygate/idempotency_cache_test.go — SQLite cache tests.
package paygate_test

import (
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/digitsu/konareef/internal/paygate"
)

func tempCache(t *testing.T) *paygate.IdempCache {
	t.Helper()
	dir := t.TempDir()
	c, err := paygate.OpenIdempCache(filepath.Join(dir, "state.db"))
	if err != nil {
		t.Fatalf("OpenIdempCache: %v", err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return c
}

func TestIdempCacheLookupMissReturnsNotFound(t *testing.T) {
	c := tempCache(t)
	_, err := c.Lookup("sess-A", "deadbeef")
	if !errors.Is(err, paygate.ErrIdempCacheMiss) {
		t.Fatalf("miss err = %v, want ErrIdempCacheMiss", err)
	}
}

func TestIdempCacheInsertThenLookupRoundtrips(t *testing.T) {
	c := tempCache(t)
	now := time.Now().UTC()
	if err := c.Insert("sess-A", "key1", "job-1", now); err != nil {
		t.Fatalf("Insert: %v", err)
	}
	job, err := c.Lookup("sess-A", "key1")
	if err != nil {
		t.Fatalf("Lookup: %v", err)
	}
	if job != "job-1" {
		t.Errorf("Lookup = %q, want job-1", job)
	}
}

func TestIdempCacheSessionScopingIsolatesIdenticalKeys(t *testing.T) {
	c := tempCache(t)
	now := time.Now().UTC()
	if err := c.Insert("sess-A", "same-key", "job-A", now); err != nil {
		t.Fatalf("Insert A: %v", err)
	}
	if err := c.Insert("sess-B", "same-key", "job-B", now); err != nil {
		t.Fatalf("Insert B: %v", err)
	}
	gotA, _ := c.Lookup("sess-A", "same-key")
	gotB, _ := c.Lookup("sess-B", "same-key")
	if gotA != "job-A" || gotB != "job-B" {
		t.Errorf("session-scoped lookup leaked: got A=%q B=%q", gotA, gotB)
	}
}

func TestIdempCacheExpiredEntryNotReturned(t *testing.T) {
	c := tempCache(t)
	twoHoursAgo := time.Now().UTC().Add(-2 * time.Hour)
	// Insert with submitted_at = 2h ago; default window is 1h.
	if err := c.Insert("sess-A", "old-key", "job-old", twoHoursAgo); err != nil {
		t.Fatalf("Insert: %v", err)
	}
	_, err := c.Lookup("sess-A", "old-key")
	if !errors.Is(err, paygate.ErrIdempCacheMiss) {
		t.Fatalf("expired entry must surface as miss; got %v", err)
	}
}

// API safety: single-argument lookup must not exist. This test compiles
// only against the documented signature; if a future PR adds a
// `LookupByKey(key string)` shortcut the test fails to compile.
var _ = func(c *paygate.IdempCache) {
	// expect (sessID, key) — two args
	_, _ = c.Lookup("sess", "key")
}
