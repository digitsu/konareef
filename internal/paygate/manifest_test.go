// internal/paygate/manifest_test.go — discovery manifest tests.
package paygate_test

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/digitsu/konareef/internal/paygate"
)

func loadManifest(t *testing.T, name string) *paygate.Manifest {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", "manifest", name))
	if err != nil {
		t.Fatalf("read %s: %v", name, err)
	}
	m, err := paygate.ParseManifest(raw)
	if err != nil {
		t.Fatalf("ParseManifest: %v", err)
	}
	return m
}

func TestManifestParseActive(t *testing.T) {
	m := loadManifest(t, "active.json")
	if m.Service != "paygate-zk" {
		t.Errorf("service = %q", m.Service)
	}
	c, ok := m.Circuits["konareef-pod-step-v1"]
	if !ok {
		t.Fatal("konareef-pod-step-v1 missing")
	}
	if c.VkeySha256 != "0101010101010101010101010101010101010101010101010101010101010101" {
		t.Errorf("vkey_sha256 = %q", c.VkeySha256)
	}
	if c.Pricing["nova-fold"].RetailUSD != 0.001 {
		t.Errorf("nova-fold retail = %v", c.Pricing["nova-fold"].RetailUSD)
	}
}

func TestManifestActiveScheduleNotStaleWhenEffectiveAfterNil(t *testing.T) {
	m := loadManifest(t, "active.json")
	if m.IsScheduleStale(time.Now()) {
		t.Errorf("active manifest must not report stale schedule")
	}
}

func TestManifestStaleSchedule(t *testing.T) {
	m := loadManifest(t, "stale.json")
	now := time.Date(2026, 6, 6, 0, 0, 0, 0, time.UTC)
	if !m.IsScheduleStale(now) {
		t.Errorf("manifest with schedule_effective_after=2026-01-01 must report stale at now=%v", now)
	}
}

func TestManifestActiveScheduleReturnsPricingRow(t *testing.T) {
	m := loadManifest(t, "active.json")
	sched, err := m.ActiveSchedule("konareef-pod-step-v1", "nova-fold")
	if err != nil {
		t.Fatalf("ActiveSchedule: %v", err)
	}
	if sched.RetailUSD != 0.001 {
		t.Errorf("ActiveSchedule retail = %v", sched.RetailUSD)
	}
}
