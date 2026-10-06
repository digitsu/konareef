// Copyright 2026 Jerry David Chan, Konareef.ai
// SPDX-License-Identifier: Apache-2.0

// internal/paygate/manifest_cache.go — discovery manifest refresh cadence
// per PRD P1.8 Obligation 2. Hard floor 60s, soft ceiling 1h (matches
// the result-retention window per PRD 2 § 4.4).
package paygate

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"
)

const (
	minRefreshCadence     = 60 * time.Second
	maxRefreshCadence     = time.Hour
	defaultRefreshCadence = 15 * time.Minute
)

// ManifestCache caches the discovery manifest in memory with refresh
// cadence. Safe for concurrent use.
type ManifestCache struct {
	BaseURL string // base URL (no trailing slash) of the PayGate ZK service
	HTTP    *http.Client
	Cadence time.Duration

	mu        sync.Mutex
	current   *Manifest
	fetchedAt time.Time
}

// EffectiveCadence returns the configured cadence clamped to [60s, 1h].
// An unset / zero Cadence resolves to defaultRefreshCadence (15 min).
func (mc *ManifestCache) EffectiveCadence() time.Duration {
	c := mc.Cadence
	if c == 0 {
		c = defaultRefreshCadence
	}
	if c < minRefreshCadence {
		return minRefreshCadence
	}
	if c > maxRefreshCadence {
		return maxRefreshCadence
	}
	return c
}

// Get returns the current Manifest, refetching if the cached entry is
// past the effective cadence.
func (mc *ManifestCache) Get(ctx context.Context) (*Manifest, error) {
	mc.mu.Lock()
	defer mc.mu.Unlock()
	if mc.current != nil && time.Since(mc.fetchedAt) < mc.EffectiveCadence() {
		return mc.current, nil
	}
	return mc.refreshLocked(ctx)
}

// Refresh forces a refetch regardless of cadence. Used by the
// schedule_effective_after transition probe in M-1 and by manual
// operator triggers.
func (mc *ManifestCache) Refresh(ctx context.Context) (*Manifest, error) {
	mc.mu.Lock()
	defer mc.mu.Unlock()
	return mc.refreshLocked(ctx)
}

func (mc *ManifestCache) refreshLocked(ctx context.Context) (*Manifest, error) {
	if mc.HTTP == nil {
		mc.HTTP = &http.Client{Timeout: 30 * time.Second}
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, mc.BaseURL+"/v1/.well-known/x402-info", nil)
	if err != nil {
		return nil, fmt.Errorf("paygate: build manifest request: %w", err)
	}
	resp, err := mc.HTTP.Do(req)
	if err != nil {
		return nil, fmt.Errorf("paygate: fetch manifest: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("paygate: manifest http %d", resp.StatusCode)
	}
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	m, err := ParseManifest(raw)
	if err != nil {
		return nil, err
	}
	mc.current = m
	mc.fetchedAt = time.Now().UTC()
	return m, nil
}
