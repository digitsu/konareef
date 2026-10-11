// Copyright 2026 Jerry David Chan, Konareef.ai
// SPDX-License-Identifier: Apache-2.0

// internal/paygate/pin_check.go — PRD P1.8 Obligation 6 State A/B/C
// state machine. Auto-refresh applies ONLY to State A; State C is a
// terminal halt with no in-session auto-adoption of the new vkey.
package paygate

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"

	"github.com/digitsu/konareef/internal/vkeystore"
)

// PinState reports which branch of the §6 state machine fired.
type PinState int

const (
	PinStateUnknown PinState = iota
	PinStateA                // no local vkey for this circuit_id; resolver invoked
	PinStateB                // cached vkey matches manifest; PROCEED
	PinStateC                // cached vkey diverges from manifest; HALT (terminal)
)

// String returns the single-letter state label.
func (s PinState) String() string {
	switch s {
	case PinStateA:
		return "A"
	case PinStateB:
		return "B"
	case PinStateC:
		return "C"
	default:
		return "?"
	}
}

// PinChecker runs the pre-session pin check against the discovery
// manifest's vkey_sha256 commitment.
type PinChecker struct {
	Resolver *vkeystore.Resolver
	Domain   string // discovery manifest's paygate-zk service domain
}

// Check applies the State A/B/C machine to (circuitID, manifestPin).
// Returns the state reached and any halt error.
//
//   - State B: cached vkey bytes hash-verify against manifestPin. Proceed.
//     Round-2 B2 fix: this goes through LocalCache.Lookup so the cached
//     vkey.bin is hashed and compared, NOT a bare path-existence check.
//     A corrupted/tampered vkey.bin under the expected directory now
//     surfaces ErrCircuitPinMismatch (or ErrVkeyCorrupt for malformed
//     metadata) instead of silently proceeding to fold submission.
//   - State C: cached vkey hash diverges from manifestPin. Terminal
//     halt with ErrCircuitPinMismatch; cache is NOT updated.
//   - State A: no local cache. Resolver is invoked; if the resolved
//     vkey's hash matches manifestPin, cache it and report State A.
//     If the resolved vkey hashes DIFFERENTLY from manifestPin,
//     vkeystore returns ErrCircuitPinMismatch and we propagate it.
func (pc *PinChecker) Check(ctx context.Context, circuitID, manifestPin string) (PinState, error) {
	if pc.Resolver == nil || pc.Resolver.Cache == nil {
		return PinStateUnknown, errors.New("paygate: PinChecker requires Resolver+Cache")
	}
	// State B (round-2 B2): hash-verify the cached vkey bytes against
	// manifestPin via LocalCache.Lookup. Lookup returns:
	//   - non-nil Vkey + nil err: bytes hashed cleanly to manifestPin
	//   - nil Vkey + nil err: no entry at (circuitID, manifestPin)
	//   - non-nil err: corrupt vkey.bin / mismatched pin / bad meta.json
	//
	// We MUST propagate the err so corruption fails closed; the bare
	// `os.Stat(...)` path-existence check the round-1 implementation
	// used would silently accept a corrupted file.
	vk, err := pc.Resolver.Cache.Lookup(circuitID, manifestPin)
	if err != nil {
		return PinStateC, err
	}
	if vk != nil {
		return PinStateB, nil
	}
	// State C: a DIFFERENT pin for the same circuit_id is cached. Per
	// PRD P1.8 §6, do not refresh: terminal halt; cache untouched.
	if pc.Resolver.Cache.HasAnyPinFor(circuitID) {
		return PinStateC, ErrCircuitPinMismatch
	}
	// State A: no local vkey for this circuit — invoke resolver.
	_, err = pc.Resolver.Resolve(ctx, vkeystore.ResolveRequest{
		CircuitID:       circuitID,
		VkeySha256:      manifestPin,
		PublisherDomain: pc.Domain,
	})
	if err != nil {
		return PinStateUnknown, err
	}
	return PinStateA, nil
}

// Sha256HexFor returns lowercase-hex SHA-256(body); exported for tests.
func Sha256HexFor(body []byte) string {
	sum := sha256.Sum256(body)
	return hex.EncodeToString(sum[:])
}
