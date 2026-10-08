// Copyright 2026 Jerry David Chan, Konareef.ai
// SPDX-License-Identifier: Apache-2.0

// anchor.go — `--pin-circuit-vkey` trigger for the on-chain vkey
// anchor flow per PRD 4 § 4.3.2.
//
// SCOPE: this PRD wires the trigger surface and the "anchor already
// exists" short-circuit. The live BSV wallet integration (fund + sign
// + broadcast the anchor transaction) is OWED BY a future PRD (P1.8
// or Bittoku). When no anchor exists yet, EnsureVkeyAnchor returns
// ErrAnchorBroadcastUnsupported so the publisher gets a clear "wait
// for P1.8" message instead of a silent no-op.

package publish

import (
	"context"
	"errors"
	"fmt"

	"github.com/digitsu/konareef/internal/vkeystore"
)

// AnchorState reports the result of EnsureVkeyAnchor.
type AnchorState int

const (
	// AnchorAlreadyExists means the on-chain anchor for
	// (circuit_id, SHA-256(vkey)) is already recorded; no new
	// broadcast is needed.
	AnchorAlreadyExists AnchorState = iota

	// AnchorBroadcasted means a new anchor transaction was
	// constructed, signed, and broadcast. Not reachable in v1; the
	// BSV wallet integration is owed by P1.8.
	AnchorBroadcasted
)

// String returns a stable lowercase identifier for logging.
func (s AnchorState) String() string {
	switch s {
	case AnchorAlreadyExists:
		return "anchor-already-exists"
	case AnchorBroadcasted:
		return "anchor-broadcasted"
	default:
		return "anchor-unknown"
	}
}

// EnsureVkeyAnchor implements the --pin-circuit-vkey behaviour:
//
//  1. Look up the existing on-chain anchor hash for circuitID via
//     the Tier-2 backend.
//  2. If an anchor exists AND SHA-256(vkeyBytes) == anchor hash:
//     return AnchorAlreadyExists (the flag is a no-op).
//  3. If an anchor exists but the hash MISMATCHES: return
//     vkeystore.ErrCircuitPinMismatch — the publisher must
//     re-anchor or upgrade the circuit; do not proceed.
//  4. If no anchor exists (ErrAnchorNotFound): return
//     ErrAnchorBroadcastUnsupported — the broadcast path is owed by
//     a future PRD.
//  5. Any other Tier-2 error: propagate verbatim.
//
// The function never has side effects on the chain in v1.
func EnsureVkeyAnchor(ctx context.Context, anchorBackend vkeystore.Tier2AnchorBackend, circuitID string, vkeyBytes []byte) (AnchorState, error) {
	if anchorBackend == nil {
		return 0, fmt.Errorf("EnsureVkeyAnchor: anchor backend is nil")
	}
	existing, err := anchorBackend.AnchorHash(ctx, circuitID)
	if err != nil {
		if errors.Is(err, vkeystore.ErrAnchorNotFound) {
			return 0, fmt.Errorf("%w: no anchor for circuit %q; broadcast path owed by P1.8",
				ErrAnchorBroadcastUnsupported, circuitID)
		}
		return 0, err
	}
	if err := vkeystore.VerifyPin(existing, vkeyBytes); err != nil {
		return 0, err // wraps vkeystore.ErrCircuitPinMismatch
	}
	return AnchorAlreadyExists, nil
}
