//go:build !testhooks

// main_anchor_backend.go — production build of the Tier-2 anchor
// backend used by `konareef pod publish --pin-circuit-vkey`.
//
// This file is selected when the binary is built WITHOUT the
// `testhooks` build tag (the default for every release build). It
// returns ErrAnchorNotFound for every circuit so the CLI fails closed
// with ErrAnchorBroadcastUnsupported until the BSV wallet wiring lands
// in P1.8 / Bittoku. Crucially, production builds IGNORE
// KONAREEF_TEST_ANCHOR_HASH_HEX — the env-var seam used by the e2e
// tests is only present in the testhooks-tagged counterpart
// (main_anchor_backend_testhook.go).
//
// MR !21 round-2 B1 (note 677): the env-var hook is no longer
// reachable from production binaries.

package main

import (
	"context"

	"github.com/digitsu/konareef/internal/vkeystore"
)

// publishAnchorBackend is the Tier-2 anchor backend wired into the
// `--pin-circuit-vkey` flow. Production behaviour: always
// ErrAnchorNotFound. The CLI surfaces this as
// ErrAnchorBroadcastUnsupported (no broadcast path until P1.8).
var publishAnchorBackend vkeystore.Tier2AnchorBackend = vkeystore.AnchorLookupFunc(
	func(_ context.Context, _ string) (string, error) {
		return "", vkeystore.ErrAnchorNotFound
	},
)
