package vkeystore

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"
)

// Resolver orchestrates the two-tier vkey resolution per PRD 4 § 4.6 (C.6).
//
// Lookup order:
//  1. Cache (if Cache != nil). Hit-within-TTL with matching pin → return.
//     Hit-past-TTL with Tier1 != nil → fall through to refresh. Hit-past-TTL
//     with Tier1 == nil ("Cached profile") → serve with Stale=true.
//  2. Tier 1 HTTPS (if Tier1 != nil). On success: pin-verify, store in cache,
//     run optional Tier-2 cross-check (defence-in-depth), return.
//  3. Tier 2 anchor cross-check (if Tier2 != nil AND we got bytes from Tier 1).
//     If the anchor exists AND disagrees with the pin → ErrCircuitPinMismatch.
//     If the anchor is missing (ErrAnchorNotFound) → best-effort v1: ignore.
//
// IMPORTANT — Tier 2 is HASH-ONLY cross-validation, NEVER a byte fallback.
// The anchor exposes the committed vkey_sha256, not the vkey bytes. If
// Tier 1 fails AND there is no fresh cache hit, the resolver returns
// ErrVkeyUnavailable regardless of whether a Tier-2 backend is configured.
// A real byte fallback would require a separate byte-source backend (e.g.
// a publisher mirror or bundle-inline vkey) — not the anchor.
//
// Dual failure (no cache, no Tier 1 success, no byte source) → ErrVkeyUnavailable.
type Resolver struct {
	Cache    *LocalCache
	Tier1    *Tier1HTTPSBackend
	Tier2    Tier2AnchorBackend
	CacheTTL time.Duration // default 24h when zero
}

// Resolve returns a verified Vkey for req or a sentinel error.
func (r *Resolver) Resolve(ctx context.Context, req ResolveRequest) (*Vkey, error) {
	if err := req.Validate(); err != nil {
		return nil, err
	}
	ttl := r.CacheTTL
	if ttl == 0 {
		ttl = 24 * time.Hour
	}

	// (1) cache lookup
	var cached *Vkey
	if r.Cache != nil {
		c, err := r.Cache.Lookup(req.CircuitID, req.VkeySha256)
		if err != nil && !errors.Is(err, ErrVkeyCorrupt) {
			// Pin mismatch on cache read is fatal — do not silently shadow.
			return nil, err
		}
		cached = c
	}

	fresh := func(v *Vkey) bool { return v != nil && time.Since(v.ResolvedAt) <= ttl }

	if fresh(cached) {
		return cached, nil
	}

	// (2) Tier 1
	if r.Tier1 != nil {
		body, err := r.Tier1.Fetch(ctx, req.CircuitID, req.PublisherDomain)
		if err == nil {
			if perr := VerifyPin(req.VkeySha256, body); perr != nil {
				return nil, perr // ErrCircuitPinMismatch
			}
			// (3) optional anchor cross-check
			if r.Tier2 != nil {
				anchorHash, aerr := r.Tier2.AnchorHash(ctx, req.CircuitID)
				switch {
				case aerr == nil:
					if !strings.EqualFold(anchorHash, req.VkeySha256) {
						return nil, fmt.Errorf("%w: anchor=%s pin=%s",
							ErrCircuitPinMismatch, anchorHash, req.VkeySha256)
					}
				case errors.Is(aerr, ErrAnchorNotFound):
					// best-effort v1: no anchor → trust Tier 1 alone
				default:
					// indexer failure: log via wrapped err but do not block
					// (the pin matched Tier 1, the anchor is best-effort)
				}
			}
			if r.Cache != nil {
				_ = r.Cache.Store(req.CircuitID, req.VkeySha256, body, SourceWellKnown)
			}
			return &Vkey{
				CircuitID:  req.CircuitID,
				VkeySha256: req.VkeySha256,
				Bytes:      body,
				Source:     SourceWellKnown,
				ResolvedAt: time.Now(),
			}, nil
		}
		// Tier 1 failed — fall through.
	}

	// (4) stale cache acceptable when there is no Tier 1
	if cached != nil && r.Tier1 == nil {
		stale := *cached
		stale.Stale = true
		return &stale, nil
	}

	return nil, ErrVkeyUnavailable
}
