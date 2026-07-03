package install

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// ── Fingerprint ─────────────────────────────────────────────────

func TestFingerprintFormat(t *testing.T) {
	// 33-byte compressed-secp256k1 pubkey, all zeros for predictability
	pubBytes := make([]byte, 33)
	pubBytes[0] = 0x02
	pubHex := hex.EncodeToString(pubBytes)

	digest := sha256.Sum256(pubBytes)
	want := fmt.Sprintf("%02x%02x:%02x%02x:%02x%02x",
		digest[0], digest[1], digest[2], digest[3], digest[4], digest[5])

	got, err := Fingerprint(pubHex)
	if err != nil {
		t.Fatalf("Fingerprint: %v", err)
	}
	if got != want {
		t.Errorf("Fingerprint = %q, want %q", got, want)
	}
}

func TestFingerprintRejectsBadHex(t *testing.T) {
	if _, err := Fingerprint("not-hex"); err == nil {
		t.Errorf("Fingerprint accepted non-hex input")
	}
}

// ── KnownPublishers I/O ─────────────────────────────────────────

func TestLoadKnownPublishersMissingFileReturnsEmpty(t *testing.T) {
	home := t.TempDir()
	k, err := LoadKnownPublishers(home)
	if err != nil {
		t.Fatalf("LoadKnownPublishers: %v", err)
	}
	if k == nil || len(k.Publishers) != 0 {
		t.Errorf("expected empty struct, got %+v", k)
	}
	if k.Version != KnownPublishersVersion {
		t.Errorf("Version = %q, want %q", k.Version, KnownPublishersVersion)
	}
}

func TestSaveAndLoadRoundTrip(t *testing.T) {
	home := t.TempDir()
	now := time.Now().UTC().Round(time.Microsecond)
	k := &KnownPublishers{
		Version:    KnownPublishersVersion,
		Publishers: map[string]*PublisherRecord{},
	}
	k.Record("alice", "02"+strings.Repeat("aa", 32), now)
	if err := k.Save(home); err != nil {
		t.Fatalf("Save: %v", err)
	}
	got, err := LoadKnownPublishers(home)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	rec := got.Get("alice")
	if rec == nil {
		t.Fatalf("alice not found after round-trip")
	}
	if rec.PubkeyHex != k.Publishers["alice"].PubkeyHex {
		t.Errorf("pubkey hex round-trip mismatch")
	}
}

func TestSaveSetsMode0644(t *testing.T) {
	home := t.TempDir()
	k := emptyKnownPublishers()
	if err := k.Save(home); err != nil {
		t.Fatalf("Save: %v", err)
	}
	fi, err := os.Stat(KnownPublishersPath(home))
	if err != nil {
		t.Fatalf("Stat: %v", err)
	}
	if perm := fi.Mode().Perm(); perm != 0o644 {
		t.Errorf("known_publishers.json perms = %o, want 0644", perm)
	}
}

// ── Match ───────────────────────────────────────────────────────

func TestMatchNewPublisher(t *testing.T) {
	k := emptyKnownPublishers()
	m := k.Match("alice", "02"+strings.Repeat("aa", 32))
	if m.Status != TrustNew {
		t.Errorf("Match on unknown handle = %v, want TrustNew", m.Status)
	}
	if m.Known != nil {
		t.Errorf("TrustNew result should have nil Known record")
	}
}

func TestMatchKnownGood(t *testing.T) {
	k := emptyKnownPublishers()
	pub := "02" + strings.Repeat("aa", 32)
	k.Record("alice", pub, time.Now().UTC())
	m := k.Match("alice", pub)
	if m.Status != TrustOK {
		t.Errorf("Match on known matching pubkey = %v, want TrustOK", m.Status)
	}
	if m.Known == nil {
		t.Errorf("TrustOK result must include the known record")
	}
}

func TestMatchKeyChange(t *testing.T) {
	k := emptyKnownPublishers()
	pubOld := "02" + strings.Repeat("aa", 32)
	pubNew := "03" + strings.Repeat("bb", 32)
	k.Record("alice", pubOld, time.Now().UTC())
	m := k.Match("alice", pubNew)
	if m.Status != TrustChange {
		t.Errorf("Match on key-change = %v, want TrustChange", m.Status)
	}
	if m.Known == nil || m.Known.PubkeyHex != pubOld {
		t.Errorf("TrustChange result must surface the old known record")
	}
}

// ── Record ──────────────────────────────────────────────────────

func TestRecordNewPublisher(t *testing.T) {
	k := emptyKnownPublishers()
	pub := "02" + strings.Repeat("aa", 32)
	now := time.Now().UTC()
	k.Record("alice", pub, now)
	rec := k.Get("alice")
	if rec == nil {
		t.Fatalf("alice not recorded")
	}
	if rec.PubkeyHex != pub {
		t.Errorf("pubkey not stored")
	}
	if !rec.FirstSeenAt.Equal(now) {
		t.Errorf("first_seen_at not set: %v", rec.FirstSeenAt)
	}
	if !rec.LastVerifiedAt.Equal(now) {
		t.Errorf("last_verified_at not set: %v", rec.LastVerifiedAt)
	}
	if len(rec.KeyHistory) != 1 {
		t.Errorf("key_history should have 1 entry, got %d", len(rec.KeyHistory))
	}
	if rec.Fingerprint == "" {
		t.Errorf("fingerprint not populated")
	}
}

func TestRecordRotation(t *testing.T) {
	k := emptyKnownPublishers()
	pubOld := "02" + strings.Repeat("aa", 32)
	pubNew := "03" + strings.Repeat("bb", 32)
	t0 := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	t1 := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)

	k.Record("alice", pubOld, t0)
	k.Record("alice", pubNew, t1)

	rec := k.Get("alice")
	if rec.PubkeyHex != pubNew {
		t.Errorf("current pubkey should be the new one")
	}
	if !rec.FirstSeenAt.Equal(t0) {
		t.Errorf("first_seen_at should NOT change on rotation; got %v", rec.FirstSeenAt)
	}
	if len(rec.KeyHistory) != 2 {
		t.Fatalf("key_history should have 2 entries, got %d", len(rec.KeyHistory))
	}
	old := rec.KeyHistory[0]
	if old.PubkeyHex != pubOld {
		t.Errorf("history[0] should be the old key")
	}
	if old.ActiveTo == nil || !old.ActiveTo.Equal(t1) {
		t.Errorf("history[0].active_to should be the rotation time")
	}
	if old.RotatedTo == nil || *old.RotatedTo != pubNew {
		t.Errorf("history[0].rotated_to should point at the new key")
	}
}

func TestRecordSameKeyIsIdempotent(t *testing.T) {
	k := emptyKnownPublishers()
	pub := "02" + strings.Repeat("aa", 32)
	t0 := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	t1 := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)
	k.Record("alice", pub, t0)
	k.Record("alice", pub, t1)
	rec := k.Get("alice")
	if len(rec.KeyHistory) != 1 {
		t.Errorf("re-recording the same key should not grow history; got %d", len(rec.KeyHistory))
	}
	if !rec.LastVerifiedAt.Equal(t1) {
		t.Errorf("last_verified_at should refresh on re-Record")
	}
}

// ── helpers ────────────────────────────────────────────────────

func emptyKnownPublishers() *KnownPublishers {
	return &KnownPublishers{
		Version:    KnownPublishersVersion,
		Publishers: map[string]*PublisherRecord{},
	}
}

func TestSaveWritesValidJSON(t *testing.T) {
	home := t.TempDir()
	k := emptyKnownPublishers()
	k.Record("alice", "02"+strings.Repeat("aa", 32), time.Now().UTC())
	if err := k.Save(home); err != nil {
		t.Fatalf("Save: %v", err)
	}
	body, err := os.ReadFile(filepath.Join(home, ".konareef", "known_publishers.json"))
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	var raw map[string]any
	if err := json.Unmarshal(body, &raw); err != nil {
		t.Fatalf("output is not valid JSON: %v", err)
	}
	if raw["version"] != KnownPublishersVersion {
		t.Errorf("version field missing or wrong: %v", raw["version"])
	}
}
