// Copyright 2026 Jerry David Chan, Konareef.ai
// SPDX-License-Identifier: Apache-2.0

//go:build testhooks

// main_anchor_backend_testhook.go — test-only build of the Tier-2
// anchor backend used by `konareef pod publish --pin-circuit-vkey`.
//
// This file is selected ONLY when the binary is built with
// `-tags testhooks`. It honours the KONAREEF_TEST_ANCHOR_HASH_HEX env
// var so the e2e CLI tests can simulate an already-anchored circuit
// (the EnsureVkeyAnchor AnchorAlreadyExists no-op branch) and the
// mismatched-anchor failure path. Production builds NEVER include this
// file — the `!testhooks` counterpart in main_anchor_backend.go is
// selected instead, and KONAREEF_TEST_ANCHOR_HASH_HEX has no effect.
//
// MR !21 round-2 B1 (note 677): the env-var hook is now confined to
// testhooks-tagged builds; release binaries cannot bypass the
// ErrAnchorNotFound -> ErrAnchorBroadcastUnsupported fail-closed path
// via this env var.

package main

import (
	"context"
	"os"

	"github.com/digitsu/konareef/internal/vkeystore"
)

// publishAnchorBackend is the Tier-2 anchor backend wired into the
// `--pin-circuit-vkey` flow. testhooks behaviour: when
// KONAREEF_TEST_ANCHOR_HASH_HEX is set to a 64-char lowercase hex
// value the backend returns that hash; otherwise it returns
// ErrAnchorNotFound (matching production semantics).
var publishAnchorBackend vkeystore.Tier2AnchorBackend = vkeystore.AnchorLookupFunc(
	func(_ context.Context, _ string) (string, error) {
		if v := os.Getenv("KONAREEF_TEST_ANCHOR_HASH_HEX"); v != "" {
			return v, nil
		}
		return "", vkeystore.ErrAnchorNotFound
	},
)
