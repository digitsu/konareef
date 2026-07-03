//go:build testhooks

// main_resolver_testhook.go — test-only build of the default vkey
// Resolver constructor used by `konareef pod publish --pin-circuit-vkey`
// and `--zk`.
//
// This file is selected ONLY when the binary is built with
// `-tags testhooks`. It honours the KONAREEF_TEST_VKEY_BASE_URL env
// var: when set to a non-empty value (typically an httptest.Server
// URL), the Tier-1 backend uses it as the BaseURLOverride so the
// e2e tests can route the well-known vkey fetch back to a test stub.
// Production builds NEVER include this file — the `!testhooks`
// counterpart in main_resolver.go is selected instead, and
// KONAREEF_TEST_VKEY_BASE_URL has no effect.
//
// MR !21 round-2 B1 (note 677): the env-var hook is now confined to
// testhooks-tagged builds; release binaries cannot redirect Tier-1
// vkey fetches via this env var.

package main

import (
	"fmt"
	"os"

	"github.com/digitsu/konareef/internal/vkeystore"
)

// newDefaultResolver constructs a Resolver wired to the P1.6 public
// surface. testhooks behaviour: when KONAREEF_TEST_VKEY_BASE_URL is
// set, the Tier-1 backend's BaseURLOverride is populated so e2e tests
// can target an httptest.Server. When unset, behaviour matches
// production (real well-known URL).
func newDefaultResolver() (*vkeystore.Resolver, error) {
	cache, err := vkeystore.NewLocalCache()
	if err != nil {
		return nil, fmt.Errorf("vkeystore cache: %w", err)
	}
	tier1 := vkeystore.NewTier1HTTPSBackend(nil)
	if override := os.Getenv("KONAREEF_TEST_VKEY_BASE_URL"); override != "" {
		tier1.BaseURLOverride = override
	}
	return &vkeystore.Resolver{
		Cache: cache,
		Tier1: tier1,
		Tier2: nil, // owed by P1.8 (BSV indexer client)
	}, nil
}
