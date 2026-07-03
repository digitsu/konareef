// internal/paygate/manifest_cache_test.go — refresh cadence tests.
package paygate_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/digitsu/konareef/internal/paygate"
)

func TestManifestCacheRefreshesPastCadence(t *testing.T) {
	raw, _ := os.ReadFile(filepath.Join("testdata", "manifest", "active.json"))
	var calls int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/.well-known/x402-info" {
			calls++
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write(raw)
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()

	mc := &paygate.ManifestCache{
		BaseURL: srv.URL,
		HTTP:    srv.Client(),
		Cadence: 50 * time.Millisecond,
	}
	if _, err := mc.Get(context.Background()); err != nil {
		t.Fatalf("first Get: %v", err)
	}
	// The first Get with cadence=50ms (below 60s floor → 60s) will fetch once;
	// subsequent calls within 60s should be cache hits.
	if calls != 1 {
		t.Errorf("first Get: calls=%d, want 1", calls)
	}

	// Immediate second call must NOT refetch (still within cadence).
	if _, err := mc.Get(context.Background()); err != nil {
		t.Fatalf("second Get: %v", err)
	}
	if calls != 1 {
		t.Errorf("within-cadence Get: calls=%d, want 1", calls)
	}

	// Refresh() forces an unconditional refetch — proves the refresh path works.
	if _, err := mc.Refresh(context.Background()); err != nil {
		t.Fatalf("third Refresh: %v", err)
	}
	if calls != 2 {
		t.Errorf("Refresh forced: calls=%d, want 2", calls)
	}
}

func TestManifestCacheCadenceHardFloor(t *testing.T) {
	mc := &paygate.ManifestCache{Cadence: 30 * time.Second} // below 60s floor
	if got := mc.EffectiveCadence(); got != 60*time.Second {
		t.Errorf("EffectiveCadence = %v, want 60s (hard floor)", got)
	}
}

func TestManifestCacheCadenceSoftCeiling(t *testing.T) {
	mc := &paygate.ManifestCache{Cadence: 2 * time.Hour} // above 1h ceiling
	if got := mc.EffectiveCadence(); got != time.Hour {
		t.Errorf("EffectiveCadence = %v, want 1h (soft ceiling)", got)
	}
}
