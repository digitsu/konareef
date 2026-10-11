// Copyright 2026 Jerry David Chan, Konareef.ai
// SPDX-License-Identifier: Apache-2.0

package vkeystore_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/digitsu/konareef/internal/vkeystore"
)

// resolverHarness wires a Resolver against an httptest.Server (Tier 1),
// an in-memory anchor map (Tier 2), and a freshly initialised LocalCache.
type resolverHarness struct {
	resolver *vkeystore.Resolver
	cache    *vkeystore.LocalCache
	srv      *httptest.Server
	host     string
	body     []byte
	pin      string
}

type anchorMap map[string]string // circuitID -> anchorHash

func newHarness(t *testing.T, h http.Handler, anchors anchorMap) *resolverHarness {
	t.Helper()
	withTempStateDir(t)
	cache, err := vkeystore.NewLocalCache()
	if err != nil {
		t.Fatalf("NewLocalCache: %v", err)
	}
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	u, _ := url.Parse(srv.URL)
	tier1 := vkeystore.NewTier1HTTPSBackend(srv.Client())
	tier1.BaseURLOverride = srv.URL
	tier2 := vkeystore.AnchorLookupFunc(func(_ context.Context, circuitID string) (string, error) {
		if hash, ok := anchors[circuitID]; ok {
			return hash, nil
		}
		return "", vkeystore.ErrAnchorNotFound
	})
	body := loadFixtureVkey(t)
	pin := vkeystore.Sha256Hex(body)
	r := &vkeystore.Resolver{
		Cache:    cache,
		Tier1:    tier1,
		Tier2:    tier2,
		CacheTTL: 24 * time.Hour,
	}
	return &resolverHarness{
		resolver: r, cache: cache, srv: srv,
		host: u.Host, body: body, pin: pin,
	}
}

func TestResolverCacheHitSkipsNetwork(t *testing.T) {
	calls := 0
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		w.Write([]byte("should not be reached"))
	})
	hr := newHarness(t, h, nil)
	if err := hr.cache.Store("circ", hr.pin, hr.body, vkeystore.SourceWellKnown); err != nil {
		t.Fatalf("seed cache: %v", err)
	}
	got, err := hr.resolver.Resolve(context.Background(), vkeystore.ResolveRequest{
		CircuitID: "circ", VkeySha256: hr.pin, PublisherDomain: "example.com",
	})
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if got.Source != vkeystore.SourceCache {
		t.Errorf("Source = %q, want cache", got.Source)
	}
	if calls != 0 {
		t.Errorf("Tier-1 was called %d times on cache hit; want 0", calls)
	}
}

func TestResolverTier1SuccessPinOK(t *testing.T) {
	hr := newHarness(t, fixtureHandler(t, "circ", loadFixtureVkey(t)), nil)
	got, err := hr.resolver.Resolve(context.Background(), vkeystore.ResolveRequest{
		CircuitID: "circ", VkeySha256: hr.pin, PublisherDomain: "example.com",
	})
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if got.Source != vkeystore.SourceWellKnown {
		t.Errorf("Source = %q, want well-known-url", got.Source)
	}
	// Cache must now have an entry (lookup-before-fetch on next call).
	cached, _ := hr.cache.Lookup("circ", hr.pin)
	if cached == nil {
		t.Error("Tier-1 success must populate cache")
	}
}

func TestResolverTier1PinMismatchHaltsImmediately(t *testing.T) {
	// Server returns a body whose SHA-256 differs from the requested pin.
	srvBody := []byte("WRONG-vkey")
	hr := newHarness(t, fixtureHandler(t, "circ", srvBody), nil)
	_, err := hr.resolver.Resolve(context.Background(), vkeystore.ResolveRequest{
		CircuitID: "circ", VkeySha256: hr.pin, PublisherDomain: "example.com",
	})
	if !errors.Is(err, vkeystore.ErrCircuitPinMismatch) {
		t.Fatalf("Tier-1 pin mismatch must surface ErrCircuitPinMismatch; got %v", err)
	}
}

func TestResolverDualFailureReturnsVkeyUnavailable(t *testing.T) {
	// 404 from server + no anchor → ErrVkeyUnavailable.
	hr := newHarness(t, http.NotFoundHandler(), nil)
	_, err := hr.resolver.Resolve(context.Background(), vkeystore.ResolveRequest{
		CircuitID: "circ-missing", VkeySha256: hr.pin, PublisherDomain: "example.com",
	})
	if !errors.Is(err, vkeystore.ErrVkeyUnavailable) {
		t.Fatalf("dual failure must surface ErrVkeyUnavailable; got %v", err)
	}
}

func TestResolverTier1FailWithAnchorAvailableAndNoCacheIsUnavailable(t *testing.T) {
	// Hermes B2 DoD: Tier 2 is HASH-ONLY cross-validation, NEVER a byte
	// fallback. Even when a Tier-2 backend is wired AND returns a valid
	// anchor hash, a Tier-1 failure with no cache hit MUST surface
	// ErrVkeyUnavailable — the anchor cannot materialise vkey bytes.
	hr := newHarness(t, http.NotFoundHandler(), nil)
	hr.resolver.Tier2 = vkeystore.AnchorLookupFunc(func(_ context.Context, _ string) (string, error) {
		return hr.pin, nil // anchor agrees with the pin, but produces no bytes
	})
	_, err := hr.resolver.Resolve(context.Background(), vkeystore.ResolveRequest{
		CircuitID: "circ-missing", VkeySha256: hr.pin, PublisherDomain: "example.com",
	})
	if !errors.Is(err, vkeystore.ErrVkeyUnavailable) {
		t.Fatalf("Tier-1 fail + Tier-2 available + no cache must surface ErrVkeyUnavailable; got %v", err)
	}
}

func TestResolverTier2CrossCheckAfterTier1Success(t *testing.T) {
	// Anchor for circ-anchored matches the pin → resolution succeeds; the
	// cross-check is exercised but does not change the outcome.
	hr := newHarness(t,
		fixtureHandler(t, "circ-anchored", loadFixtureVkey(t)),
		anchorMap{"circ-anchored": ""}, // filled below
	)
	// Inject the correct anchor hash.
	hr.resolver.Tier2 = vkeystore.AnchorLookupFunc(func(_ context.Context, _ string) (string, error) {
		return hr.pin, nil
	})
	got, err := hr.resolver.Resolve(context.Background(), vkeystore.ResolveRequest{
		CircuitID: "circ-anchored", VkeySha256: hr.pin, PublisherDomain: "example.com",
	})
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if got.Source != vkeystore.SourceWellKnown {
		t.Errorf("Source = %q, want well-known-url", got.Source)
	}
}

func TestResolverTier2CrossCheckDetectsAnchorMismatch(t *testing.T) {
	// Tier 1 returns a body whose SHA-256 matches the pin, BUT the anchor
	// disagrees with the pin. Defence-in-depth: surface
	// ErrCircuitPinMismatch even though Tier 1 alone would have accepted.
	hr := newHarness(t, fixtureHandler(t, "circ-evil", loadFixtureVkey(t)), nil)
	hr.resolver.Tier2 = vkeystore.AnchorLookupFunc(func(_ context.Context, _ string) (string, error) {
		// Anchor says the vkey hash is a different 32-byte value.
		return strings.Repeat("0", 64), nil
	})
	_, err := hr.resolver.Resolve(context.Background(), vkeystore.ResolveRequest{
		CircuitID: "circ-evil", VkeySha256: hr.pin, PublisherDomain: "example.com",
	})
	if !errors.Is(err, vkeystore.ErrCircuitPinMismatch) {
		t.Fatalf("anchor disagreeing with Tier-1 must surface ErrCircuitPinMismatch; got %v", err)
	}
}

func TestResolverTier2NotFoundIsNonFatalWhenTier1Succeeds(t *testing.T) {
	// Tier 1 succeeds; anchor returns ErrAnchorNotFound → still accept.
	// This is the "best-effort v1" semantics: no anchor → trust Tier 1.
	hr := newHarness(t, fixtureHandler(t, "circ-noanchor", loadFixtureVkey(t)), nil)
	hr.resolver.Tier2 = vkeystore.AnchorLookupFunc(func(_ context.Context, _ string) (string, error) {
		return "", vkeystore.ErrAnchorNotFound
	})
	got, err := hr.resolver.Resolve(context.Background(), vkeystore.ResolveRequest{
		CircuitID: "circ-noanchor", VkeySha256: hr.pin, PublisherDomain: "example.com",
	})
	if err != nil {
		t.Fatalf("anchor missing must not fail Tier-1 success: %v", err)
	}
	if got.Source != vkeystore.SourceWellKnown {
		t.Errorf("Source = %q, want well-known-url", got.Source)
	}
}

func TestResolverRejectsInvalidRequest(t *testing.T) {
	hr := newHarness(t, http.NotFoundHandler(), nil)
	_, err := hr.resolver.Resolve(context.Background(), vkeystore.ResolveRequest{})
	if err == nil {
		t.Fatal("zero request must be rejected")
	}
}

func TestResolverStaleCacheServedWhenTier1Absent(t *testing.T) {
	// No Tier 1 backend → resolver serves the cache even past TTL, with Stale=true.
	withTempStateDir(t)
	cache, _ := vkeystore.NewLocalCache()
	body := loadFixtureVkey(t)
	pin := vkeystore.Sha256Hex(body)
	_ = cache.Store("circ", pin, body, vkeystore.SourceWellKnown)
	r := &vkeystore.Resolver{
		Cache:    cache,
		Tier1:    nil, // Cached profile
		Tier2:    nil,
		CacheTTL: time.Nanosecond, // forces stale immediately
	}
	time.Sleep(2 * time.Nanosecond)
	got, err := r.Resolve(context.Background(), vkeystore.ResolveRequest{
		CircuitID: "circ", VkeySha256: pin, PublisherDomain: "example.com",
	})
	if err != nil {
		t.Fatalf("cached-profile stale must still serve: %v", err)
	}
	if !got.Stale {
		t.Error("Vkey.Stale must be true when served past TTL with no Tier-1")
	}
}

func TestResolverStaleCacheTriggersTier1RefreshWhenAvailable(t *testing.T) {
	hr := newHarness(t, fixtureHandler(t, "circ", loadFixtureVkey(t)), nil)
	if err := hr.cache.Store("circ", hr.pin, hr.body, vkeystore.SourceWellKnown); err != nil {
		t.Fatal(err)
	}
	hr.resolver.CacheTTL = time.Nanosecond
	time.Sleep(2 * time.Nanosecond)
	got, err := hr.resolver.Resolve(context.Background(), vkeystore.ResolveRequest{
		CircuitID: "circ", VkeySha256: hr.pin, PublisherDomain: "example.com",
	})
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if got.Source != vkeystore.SourceWellKnown {
		t.Errorf("stale cache + Tier-1 available → Source = %q, want well-known-url", got.Source)
	}
	if got.Stale {
		t.Error("refresh path must not set Stale=true")
	}
}
