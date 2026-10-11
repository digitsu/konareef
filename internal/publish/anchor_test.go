// Copyright 2026 Jerry David Chan, Konareef.ai
// SPDX-License-Identifier: Apache-2.0

// anchor_test.go — EnsureVkeyAnchor tests for --pin-circuit-vkey.
package publish

import (
	"context"
	"errors"
	"testing"

	"github.com/digitsu/konareef/internal/vkeystore"
)

func TestEnsureVkeyAnchorNoOpWhenAlreadyAnchored(t *testing.T) {
	const circuitID = "konareef-pod-step-v1"
	vkeyBytes := make([]byte, 32)
	for i := range vkeyBytes {
		vkeyBytes[i] = 0xCC
	}
	wantHash := vkeystore.Sha256Hex(vkeyBytes)

	// Tier-2 backend reports the exact matching hash → no-op.
	tier2 := vkeystore.AnchorLookupFunc(func(_ context.Context, id string) (string, error) {
		if id != circuitID {
			return "", vkeystore.ErrAnchorNotFound
		}
		return wantHash, nil
	})

	state, err := EnsureVkeyAnchor(context.Background(), tier2, circuitID, vkeyBytes)
	if err != nil {
		t.Fatalf("EnsureVkeyAnchor: %v", err)
	}
	if state != AnchorAlreadyExists {
		t.Errorf("state = %v, want AnchorAlreadyExists", state)
	}
}

func TestEnsureVkeyAnchorBroadcastUnsupportedWhenAnchorMissing(t *testing.T) {
	const circuitID = "fresh-circuit"
	vkeyBytes := []byte{0x01, 0x02, 0x03}

	tier2 := vkeystore.AnchorLookupFunc(func(_ context.Context, _ string) (string, error) {
		return "", vkeystore.ErrAnchorNotFound
	})

	_, err := EnsureVkeyAnchor(context.Background(), tier2, circuitID, vkeyBytes)
	if !errors.Is(err, ErrAnchorBroadcastUnsupported) {
		t.Fatalf("err = %v, want ErrAnchorBroadcastUnsupported", err)
	}
}

func TestEnsureVkeyAnchorMismatchedAnchorHaltsWithPinError(t *testing.T) {
	const circuitID = "c1"
	vkeyBytes := []byte{0x01}
	// On-chain advertises a different hash than SHA-256(vkeyBytes).
	tier2 := vkeystore.AnchorLookupFunc(func(_ context.Context, _ string) (string, error) {
		return "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", nil
	})

	_, err := EnsureVkeyAnchor(context.Background(), tier2, circuitID, vkeyBytes)
	if !errors.Is(err, vkeystore.ErrCircuitPinMismatch) {
		t.Fatalf("err = %v, want vkeystore.ErrCircuitPinMismatch", err)
	}
}

func TestEnsureVkeyAnchorPropagatesIndexerError(t *testing.T) {
	const circuitID = "c1"
	vkeyBytes := []byte{0x01}
	indexerErr := errors.New("indexer 503")
	tier2 := vkeystore.AnchorLookupFunc(func(_ context.Context, _ string) (string, error) {
		return "", indexerErr
	})

	_, err := EnsureVkeyAnchor(context.Background(), tier2, circuitID, vkeyBytes)
	if !errors.Is(err, indexerErr) {
		t.Fatalf("err = %v, want indexerErr propagation", err)
	}
}
