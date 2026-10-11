// Copyright 2026 Jerry David Chan, Konareef.ai
// SPDX-License-Identifier: Apache-2.0

package vkeystore_test

import (
	"context"
	"errors"
	"testing"

	"github.com/digitsu/konareef/internal/vkeystore"
)

func TestAnchorLookupFuncMatchesInterface(t *testing.T) {
	// Compile-time assertion that AnchorLookupFunc satisfies Tier2AnchorBackend.
	var _ vkeystore.Tier2AnchorBackend = vkeystore.AnchorLookupFunc(
		func(ctx context.Context, circuitID string) (string, error) {
			return "", nil
		},
	)
}

func TestAnchorLookupFuncReturnsHash(t *testing.T) {
	const want = "11" + "1111111111111111111111111111111111111111111111111111111111" + "11"
	be := vkeystore.AnchorLookupFunc(func(ctx context.Context, circuitID string) (string, error) {
		if circuitID != "circ-anchored" {
			return "", vkeystore.ErrAnchorNotFound
		}
		return want, nil
	})
	got, err := be.AnchorHash(context.Background(), "circ-anchored")
	if err != nil {
		t.Fatalf("AnchorHash: %v", err)
	}
	if got != want {
		t.Errorf("AnchorHash = %q, want %q", got, want)
	}
}

func TestAnchorLookupFuncSurfacesAnchorNotFound(t *testing.T) {
	be := vkeystore.AnchorLookupFunc(func(ctx context.Context, circuitID string) (string, error) {
		return "", vkeystore.ErrAnchorNotFound
	})
	_, err := be.AnchorHash(context.Background(), "circ-x")
	if !errors.Is(err, vkeystore.ErrAnchorNotFound) {
		t.Fatalf("must propagate ErrAnchorNotFound; got %v", err)
	}
}

func TestAnchorLookupFuncSurfacesIndexerError(t *testing.T) {
	indexerErr := errors.New("indexer 502")
	be := vkeystore.AnchorLookupFunc(func(ctx context.Context, circuitID string) (string, error) {
		return "", indexerErr
	})
	_, err := be.AnchorHash(context.Background(), "circ-x")
	if !errors.Is(err, indexerErr) {
		t.Fatalf("must propagate underlying error; got %v", err)
	}
}
