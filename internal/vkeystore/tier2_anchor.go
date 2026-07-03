package vkeystore

import (
	"context"
	"errors"
)

// ErrAnchorNotFound means no on-chain anchor exists for this circuit_id.
// Distinct from a network / indexer failure, which is surfaced verbatim
// so the Resolver can treat "no anchor exists yet" vs "we could not reach
// the indexer" differently.
//
// IMPORTANT: this is INTERNAL to the vkeystore package. The Resolver
// translates "no anchor present" + "no Tier-1 success" + "no cache" into
// ErrVkeyUnavailable at the package boundary.
var ErrAnchorNotFound = errors.New("vkeystore: on-chain anchor not found")

// Tier2AnchorBackend resolves the on-chain anchor hash for a circuit_id.
// The anchor commits SHA-256(vkey) — NOT the vkey body itself.
//
// v1: the production wiring (BSV indexer / Bittoku service) is OWED BY P1.8.
// This interface exists so P1.6 ships a fully testable resolver without
// taking a hard dep on any single indexer.
type Tier2AnchorBackend interface {
	// AnchorHash returns the lowercase-hex SHA-256(vkey) committed on-chain
	// for circuitID, or ErrAnchorNotFound if no anchor exists, or another
	// error if the lookup itself failed.
	AnchorHash(ctx context.Context, circuitID string) (string, error)
}

// AnchorLookupFunc is a function-shaped Tier2AnchorBackend — the v1 mock
// and the future P1.8 client both adapt through this seam.
type AnchorLookupFunc func(ctx context.Context, circuitID string) (string, error)

// AnchorHash satisfies Tier2AnchorBackend.
func (f AnchorLookupFunc) AnchorHash(ctx context.Context, circuitID string) (string, error) {
	return f(ctx, circuitID)
}
