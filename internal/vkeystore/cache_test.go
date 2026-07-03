package vkeystore_test

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/digitsu/konareef/internal/vkeystore"
)

func withTempStateDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	t.Setenv("KONAREEF_STATE_DIR", dir)
	return dir
}

func TestLocalCacheLookupMissReturnsNil(t *testing.T) {
	withTempStateDir(t)
	c, err := vkeystore.NewLocalCache()
	if err != nil {
		t.Fatalf("NewLocalCache: %v", err)
	}
	v, err := c.Lookup("circuit-a", strings.Repeat("0", 64))
	if err != nil {
		t.Fatalf("Lookup on empty cache returned error: %v", err)
	}
	if v != nil {
		t.Fatalf("Lookup on empty cache returned Vkey: %+v", v)
	}
}

func TestLocalCacheStoreThenLookupRoundtrips(t *testing.T) {
	withTempStateDir(t)
	c, err := vkeystore.NewLocalCache()
	if err != nil {
		t.Fatalf("NewLocalCache: %v", err)
	}
	body := []byte("vkey-bytes-go-here")
	pin := vkeystore.Sha256Hex(body)
	if err := c.Store("circuit-a", pin, body, vkeystore.SourceWellKnown); err != nil {
		t.Fatalf("Store: %v", err)
	}
	got, err := c.Lookup("circuit-a", pin)
	if err != nil {
		t.Fatalf("Lookup after Store: %v", err)
	}
	if got == nil {
		t.Fatal("Lookup after Store returned nil")
	}
	if string(got.Bytes) != string(body) {
		t.Errorf("Bytes round-trip failed: got %q want %q", got.Bytes, body)
	}
	if got.Source != vkeystore.SourceCache {
		t.Errorf("Source on lookup = %q, want %q", got.Source, vkeystore.SourceCache)
	}
	if got.VkeySha256 != pin {
		t.Errorf("VkeySha256 round-trip = %q, want %q", got.VkeySha256, pin)
	}
}

func TestLocalCacheTwoVkeysSameCircuitCoexist(t *testing.T) {
	withTempStateDir(t)
	c, _ := vkeystore.NewLocalCache()
	bodyA := []byte("vkey-A")
	bodyB := []byte("vkey-B")
	pinA := vkeystore.Sha256Hex(bodyA)
	pinB := vkeystore.Sha256Hex(bodyB)
	if err := c.Store("circuit-x", pinA, bodyA, vkeystore.SourceWellKnown); err != nil {
		t.Fatalf("Store A: %v", err)
	}
	if err := c.Store("circuit-x", pinB, bodyB, vkeystore.SourceWellKnown); err != nil {
		t.Fatalf("Store B: %v", err)
	}
	gotA, _ := c.Lookup("circuit-x", pinA)
	gotB, _ := c.Lookup("circuit-x", pinB)
	if gotA == nil || string(gotA.Bytes) != "vkey-A" {
		t.Errorf("Lookup A: got %+v", gotA)
	}
	if gotB == nil || string(gotB.Bytes) != "vkey-B" {
		t.Errorf("Lookup B: got %+v", gotB)
	}
}

func TestLocalCacheRejectsPinMismatchOnRead(t *testing.T) {
	dir := withTempStateDir(t)
	c, _ := vkeystore.NewLocalCache()
	body := []byte("vkey-good")
	pin := vkeystore.Sha256Hex(body)
	if err := c.Store("circuit-tamper", pin, body, vkeystore.SourceWellKnown); err != nil {
		t.Fatalf("Store: %v", err)
	}
	// Tamper with vkey.bin on disk so SHA-256 no longer matches the pin
	// in the directory name.
	tampered := filepath.Join(dir, "vkeys", "circuit-tamper", pin, "vkey.bin")
	if err := os.WriteFile(tampered, []byte("EVIL"), 0o600); err != nil {
		t.Fatalf("tamper: %v", err)
	}
	_, err := c.Lookup("circuit-tamper", pin)
	if !errors.Is(err, vkeystore.ErrCircuitPinMismatch) {
		t.Fatalf("tampered cache must surface pin mismatch; got %v", err)
	}
}

func TestLocalCacheCorruptMetaJSONReturnsVkeyCorrupt(t *testing.T) {
	dir := withTempStateDir(t)
	c, _ := vkeystore.NewLocalCache()
	body := []byte("vkey")
	pin := vkeystore.Sha256Hex(body)
	_ = c.Store("circuit-y", pin, body, vkeystore.SourceWellKnown)
	bad := filepath.Join(dir, "vkeys", "circuit-y", pin, "meta.json")
	_ = os.WriteFile(bad, []byte("{not-json"), 0o600)
	_, err := c.Lookup("circuit-y", pin)
	if !errors.Is(err, vkeystore.ErrVkeyCorrupt) {
		t.Fatalf("corrupt meta.json must surface ErrVkeyCorrupt; got %v", err)
	}
}

func TestLocalCacheResolvedAtPersisted(t *testing.T) {
	withTempStateDir(t)
	c, _ := vkeystore.NewLocalCache()
	body := []byte("vkey")
	pin := vkeystore.Sha256Hex(body)
	before := time.Now()
	_ = c.Store("circuit-z", pin, body, vkeystore.SourceWellKnown)
	got, err := c.Lookup("circuit-z", pin)
	if err != nil || got == nil {
		t.Fatalf("Lookup: %v / %+v", err, got)
	}
	if got.ResolvedAt.Before(before.Add(-time.Second)) {
		t.Errorf("ResolvedAt = %v; expected >= %v", got.ResolvedAt, before)
	}
}

func TestLocalCacheCachedirTagWrittenOnInit(t *testing.T) {
	dir := withTempStateDir(t)
	_, err := vkeystore.NewLocalCache()
	if err != nil {
		t.Fatalf("NewLocalCache: %v", err)
	}
	tag := filepath.Join(dir, "vkeys", "CACHEDIR.TAG")
	data, err := os.ReadFile(tag)
	if err != nil {
		t.Fatalf("CACHEDIR.TAG missing: %v", err)
	}
	if got := string(data); got[:44] != "Signature: 8a477f597d28d172789f06886806bc55\n" {
		t.Errorf("CACHEDIR.TAG signature wrong: %q", got)
	}
}

func TestLocalCacheMetaJSONShape(t *testing.T) {
	dir := withTempStateDir(t)
	c, _ := vkeystore.NewLocalCache()
	body := []byte("vkey")
	pin := vkeystore.Sha256Hex(body)
	_ = c.Store("circ", pin, body, vkeystore.SourceAnchor)
	metaPath := filepath.Join(dir, "vkeys", "circ", pin, "meta.json")
	raw, err := os.ReadFile(metaPath)
	if err != nil {
		t.Fatalf("read meta: %v", err)
	}
	var got struct {
		CircuitID  string `json:"circuit_id"`
		VkeySha256 string `json:"vkey_sha256"`
		Source     string `json:"source"`
		ResolvedAt string `json:"resolved_at"`
	}
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatalf("unmarshal meta: %v\nraw=%s", err, raw)
	}
	if got.CircuitID != "circ" || got.VkeySha256 != pin || got.Source != "on-chain-anchor" {
		t.Errorf("meta shape wrong: %+v", got)
	}
	if got.ResolvedAt == "" {
		t.Error("meta.resolved_at missing")
	}
}

func TestLocalCacheRejectsTraversalCircuitID(t *testing.T) {
	withTempStateDir(t)
	c, _ := vkeystore.NewLocalCache()
	body := []byte("vkey")
	pin := vkeystore.Sha256Hex(body)
	// Each of these MUST be rejected by LocalCache.Store / Lookup BEFORE
	// any filepath.Join touches them, otherwise an attacker who controls
	// manifest/bundle data can write outside the cache root or read
	// arbitrary files.
	bad := []string{
		"../../../etc/passwd",
		"foo/bar",
		`..\..\windows\system32`,
		"",
		".",
		"..",
		"foo\x00bar",
	}
	for _, id := range bad {
		if err := c.Store(id, pin, body, vkeystore.SourceWellKnown); !errors.Is(err, vkeystore.ErrCircuitIDInvalid) {
			t.Errorf("Store(circuitID=%q) = %v; want ErrCircuitIDInvalid", id, err)
		}
		if _, err := c.Lookup(id, pin); !errors.Is(err, vkeystore.ErrCircuitIDInvalid) {
			t.Errorf("Lookup(circuitID=%q) = %v; want ErrCircuitIDInvalid", id, err)
		}
	}
}

func TestLocalCacheRejectsInvalidPin(t *testing.T) {
	withTempStateDir(t)
	c, _ := vkeystore.NewLocalCache()
	body := []byte("vkey")
	bad := []string{
		"",                      // empty
		"deadbeef",              // short
		strings.Repeat("A", 64), // uppercase
		strings.Repeat("g", 64), // non-hex
		"../../../etc/passwd",
	}
	for _, pin := range bad {
		if err := c.Store("circ", pin, body, vkeystore.SourceWellKnown); !errors.Is(err, vkeystore.ErrVkeySha256Invalid) {
			t.Errorf("Store(pin=%q) = %v; want ErrVkeySha256Invalid", pin, err)
		}
		if _, err := c.Lookup("circ", pin); !errors.Is(err, vkeystore.ErrVkeySha256Invalid) {
			t.Errorf("Lookup(pin=%q) = %v; want ErrVkeySha256Invalid", pin, err)
		}
	}
}

func TestLocalCacheTraversalCannotEscapeRoot(t *testing.T) {
	dir := withTempStateDir(t)
	c, _ := vkeystore.NewLocalCache()
	// Even though Store is supposed to reject, confirm no `foo/bar` path
	// got written under the cache root or its parent.
	body := []byte("vkey")
	pin := vkeystore.Sha256Hex(body)
	_ = c.Store("foo/bar", pin, body, vkeystore.SourceWellKnown)
	// The cache root parent must not have grown a sibling.
	entries, _ := os.ReadDir(dir)
	for _, e := range entries {
		if e.Name() != "vkeys" {
			t.Errorf("traversal write produced sibling entry under state dir: %q", e.Name())
		}
	}
}
