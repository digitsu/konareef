// Copyright 2026 Jerry David Chan, Konareef.ai
// SPDX-License-Identifier: Apache-2.0

// Package vkeystore resolves konareef circuit verification keys (vkeys)
// for the konareef Go verifier.
//
// Two-tier resolution model per PRD 4 § 4.6 (C.6):
//
//   - Tier 1 (primary, byte source): HTTPS GET to
//     https://paygate-zk.{publisherDomain}/.well-known/circuits/{circuit_id}/vkey
//     where publisherDomain is the publisher BASE domain (e.g.
//     `example.com`). The `paygate-zk.` host prefix is added by the
//     Tier-1 backend itself; callers MUST NOT pre-pend it.
//   - Tier 2 (best-effort v1; HASH-ONLY cross-check, NEVER a byte
//     fallback): on-chain anchor lookup. Yields the committed
//     `vkey_sha256`, not the vkey bytes — used to cross-validate a vkey
//     obtained from Tier 1. Cannot supply vkey bytes when Tier 1 fails.
//
// Every fetched vkey is hashed and compared against the caller-supplied
// pin (`ResolveRequest.VkeySha256`). A mismatch yields ErrCircuitPinMismatch
// and the vkey bytes MUST NOT be used. If Tier 1 fails AND there is no
// fresh cache hit, the resolver yields ErrVkeyUnavailable regardless of
// whether a Tier-2 backend is configured (no anchor-only byte fallback).
//
// Local cache layout (mirrors P1.7.1 storage pattern):
//
//	${KONAREEF_STATE_DIR:-~/.konareef}/vkeys/{circuit_id}/{vkey_sha256}/
//	  vkey.bin   -- the verified vkey bytes
//	  meta.json  -- {circuit_id, vkey_sha256, source, resolved_at}
//
// Default TTL is 24h, configurable via Resolver.CacheTTL.
package vkeystore
