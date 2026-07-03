// internal/paygate/m5_circuit_pin_mismatch_test.go — M-5 pin mismatch halt.
package paygate_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/digitsu/konareef/internal/paygate"
	"github.com/digitsu/konareef/internal/paygate/stubserver"
	"github.com/digitsu/konareef/internal/vkeystore"
)

// M-5: present manifest with mismatched vkey_sha256 → runtime halts
// before any submission and surfaces ErrCircuitPinMismatch.
func TestM5CircuitPinMismatchHalt(t *testing.T) {
	// 1. Pre-seed cache with the CORRECT vkey under the correct pin.
	t.Setenv("KONAREEF_STATE_DIR", t.TempDir())
	cache, err := vkeystore.NewLocalCache()
	if err != nil {
		t.Fatal(err)
	}
	body, err := os.ReadFile(filepath.Join("testdata", "vkey", "fixture.bin"))
	if err != nil {
		t.Fatal(err)
	}
	correctPin := paygate.Sha256HexFor(body)
	if err := cache.Store("konareef-pod-step-v1", correctPin, body, vkeystore.SourceWellKnown); err != nil {
		t.Fatal(err)
	}

	// 2. Spin up a vkey-server that serves the same body if asked.
	vkSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/vkey") {
			_, _ = w.Write(body)
			return
		}
		http.NotFound(w, r)
	}))
	defer vkSrv.Close()
	tier1 := vkeystore.NewTier1HTTPSBackend(vkSrv.Client())
	tier1.BaseURLOverride = vkSrv.URL
	resolver := &vkeystore.Resolver{Cache: cache, Tier1: tier1}

	// 3. Stub PayGate advertises a MISMATCHED pin.
	mismatchedPin := "ff" + correctPin[2:]
	s := stubserver.New(stubserver.Options{
		ManifestProfile:     "active",
		PinMismatchManifest: mismatchedPin,
	})
	defer s.Close()

	// M-5 explicitly overrides the default noopPinChecker with a real
	// *paygate.PinChecker so we exercise the State C halt path.
	realPin := &paygate.PinChecker{Resolver: resolver, Domain: "example.test"}
	c := newSmokeClient(t, s, smokeOpts{PinChecker: realPin})
	c.Resolver = resolver

	_, err = c.Open(context.Background(), paygate.OpenSessionInput{CircuitID: "konareef-pod-step-v1", DisclosurePolicy: paygate.DisclosureTypeC})
	if !errors.Is(err, paygate.ErrCircuitPinMismatch) {
		t.Fatalf("M-5: Open err = %v, want ErrCircuitPinMismatch", err)
	}
	if s.BEEFSubmits() != 0 {
		t.Errorf("M-5: BEEF submits = %d, want 0 (halt before any submission)", s.BEEFSubmits())
	}
}
