// Copyright 2026 Jerry David Chan, Konareef.ai
// SPDX-License-Identifier: Apache-2.0

//go:build !testhooks

// main_resolver.go — production build of the default vkey Resolver
// constructor used by `konareef pod publish --pin-circuit-vkey` and
// `--zk`.
//
// This file is selected when the binary is built WITHOUT the
// `testhooks` build tag (the default for every release build). It
// wires the Resolver to the P1.6 public surface: LocalCache at
// ${KONAREEF_STATE_DIR:-~/.konareef}/vkeys, Tier-1 at the real
// `https://paygate-zk.<domain>` well-known URL via NewTier1HTTPSBackend
// with stdlib's 30s default timeout, and Tier-2 left nil pending P1.8.
// Crucially, production builds IGNORE KONAREEF_TEST_VKEY_BASE_URL —
// the env-var seam used by the e2e tests is only present in the
// testhooks-tagged counterpart (main_resolver_testhook.go).
//
// MR !21 round-2 B1 (note 677): the env-var hook is no longer
// reachable from production binaries.

package main

import (
	"fmt"

	"github.com/digitsu/konareef/internal/vkeystore"
)

// newDefaultResolver constructs a Resolver wired to the P1.6 public
// surface. Production behaviour: Tier-1 hits the real well-known URL.
func newDefaultResolver() (*vkeystore.Resolver, error) {
	cache, err := vkeystore.NewLocalCache()
	if err != nil {
		return nil, fmt.Errorf("vkeystore cache: %w", err)
	}
	tier1 := vkeystore.NewTier1HTTPSBackend(nil)
	return &vkeystore.Resolver{
		Cache: cache,
		Tier1: tier1,
		Tier2: nil, // owed by P1.8 (BSV indexer client)
	}, nil
}
