// Copyright 2026 Jerry David Chan, Konareef.ai
// SPDX-License-Identifier: Apache-2.0

// internal/paygate/pin_check_test.go — State A/B/C state machine tests.
package paygate_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/digitsu/konareef/internal/paygate"
	"github.com/digitsu/konareef/internal/vkeystore"
)

// pinHarness wires a vkeystore.Resolver against an httptest.Server +
// state-dir tempdir, then exposes PinCheck for table-driven testing.
type pinHarness struct {
	resolver *vkeystore.Resolver
	domain   string
}

func newPinHarness(t *testing.T, vkeyBody []byte) *pinHarness {
	t.Helper()
	t.Setenv("KONAREEF_STATE_DIR", t.TempDir())
	cache, err := vkeystore.NewLocalCache()
	if err != nil {
		t.Fatalf("NewLocalCache: %v", err)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/.well-known/circuits/konareef-pod-step-v1/vkey" {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write(vkeyBody)
	}))
	t.Cleanup(srv.Close)
	tier1 := vkeystore.NewTier1HTTPSBackend(srv.Client())
	tier1.BaseURLOverride = srv.URL
	resolver := &vkeystore.Resolver{Cache: cache, Tier1: tier1}
	// Use a synthetic publisher domain that passes ValidatePublisherDomain;
	// the actual fetch goes through BaseURLOverride so the domain string is
	// not used for transport.
	return &pinHarness{resolver: resolver, domain: "example.test"}
}

func loadFixtureVkey(t *testing.T) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", "vkey", "fixture.bin"))
	if err != nil {
		t.Fatalf("read fixture vkey: %v", err)
	}
	return b
}

func TestPinCheckStateANoCacheResolveSucceeds(t *testing.T) {
	body := loadFixtureVkey(t)
	hp := paygate.Sha256HexFor(body)
	h := newPinHarness(t, body)
	pc := &paygate.PinChecker{Resolver: h.resolver, Domain: h.domain}
	state, err := pc.Check(context.Background(), "konareef-pod-step-v1", hp)
	if err != nil {
		t.Fatalf("State A check: %v", err)
	}
	if state != paygate.PinStateA {
		t.Errorf("first call must report State A; got %v", state)
	}
}

func TestPinCheckStateBCachedHashMatches(t *testing.T) {
	body := loadFixtureVkey(t)
	hp := paygate.Sha256HexFor(body)
	h := newPinHarness(t, body)
	pc := &paygate.PinChecker{Resolver: h.resolver, Domain: h.domain}
	// First call seeds cache.
	if _, err := pc.Check(context.Background(), "konareef-pod-step-v1", hp); err != nil {
		t.Fatalf("seed: %v", err)
	}
	// Second call must hit cache and report State B.
	state, err := pc.Check(context.Background(), "konareef-pod-step-v1", hp)
	if err != nil {
		t.Fatalf("State B check: %v", err)
	}
	if state != paygate.PinStateB {
		t.Errorf("cached call must report State B; got %v", state)
	}
}

func TestPinCheckStateCDivergenceHalts(t *testing.T) {
	body := loadFixtureVkey(t)
	cachedPin := paygate.Sha256HexFor(body)
	h := newPinHarness(t, body)
	pc := &paygate.PinChecker{Resolver: h.resolver, Domain: h.domain}
	// Seed cache with body→cachedPin.
	if _, err := pc.Check(context.Background(), "konareef-pod-step-v1", cachedPin); err != nil {
		t.Fatalf("seed: %v", err)
	}
	// Manifest now advertises a DIFFERENT pin (rollover or attack).
	manifestPin := "ff" + cachedPin[2:] // flip first byte
	_, err := pc.Check(context.Background(), "konareef-pod-step-v1", manifestPin)
	if !errors.Is(err, paygate.ErrCircuitPinMismatch) {
		t.Fatalf("State C divergence must surface ErrCircuitPinMismatch; got %v", err)
	}
}

func TestPinCheckStateCNoInSessionAutoAdoption(t *testing.T) {
	// Verify that a State C halt does not silently update the cache.
	body := loadFixtureVkey(t)
	cachedPin := paygate.Sha256HexFor(body)
	h := newPinHarness(t, body)
	pc := &paygate.PinChecker{Resolver: h.resolver, Domain: h.domain}
	_, _ = pc.Check(context.Background(), "konareef-pod-step-v1", cachedPin)
	manifestPin := "ff" + cachedPin[2:]
	_, _ = pc.Check(context.Background(), "konareef-pod-step-v1", manifestPin)
	// A subsequent call with the ORIGINAL cached pin must still be State B.
	state, err := pc.Check(context.Background(), "konareef-pod-step-v1", cachedPin)
	if err != nil || state != paygate.PinStateB {
		t.Errorf("post-halt cache MUST NOT have been overwritten; state=%v err=%v", state, err)
	}
}
