// Copyright 2026 Jerry David Chan, Konareef.ai
// SPDX-License-Identifier: Apache-2.0

// internal/membridge/capacity_test.go
package membridge

import (
	crand "crypto/rand"
	"encoding/hex"
	"errors"
	mrand "math/rand/v2"
	"testing"
)

// TestEnforceHardCap_Boundary asserts k=500 accepts, k=501 rejects.
func TestEnforceHardCap_Boundary(t *testing.T) {
	if err := EnforceHardCap(500); err != nil {
		t.Errorf("k=500: %v, want nil", err)
	}
	if err := EnforceHardCap(501); !errors.Is(err, ErrCellCapExceeded) {
		t.Fatalf("k=501: err = %v, want ErrCellCapExceeded", err)
	}
}

// TestGenesisAssign_NoCollisionAcceptsFirstSalt asserts that when the
// first sampled salt has no pairwise index collision, GenesisAssign
// returns it on the first attempt with attempts=1.
func TestGenesisAssign_NoCollisionAcceptsFirstSalt(t *testing.T) {
	saltA := bytesRepeat(0xaa, 32)
	sampler := func(attempt int) ([]byte, error) { return saltA, nil }
	tids := []uint64{1, 2, 3}
	salt, attempts, err := GenesisAssign(sampler, tids)
	if err != nil {
		t.Fatalf("GenesisAssign: %v", err)
	}
	if attempts != 1 {
		t.Errorf("attempts = %d, want 1", attempts)
	}
	if hex.EncodeToString(salt) != hex.EncodeToString(saltA) {
		t.Errorf("salt = %x, want %x", salt, saltA)
	}
}

// TestGenesisAssign_RetriesPastCollision asserts that a colliding salt
// is rejected and the next sampler call is invoked. Uses the
// conformance-vector collision salt as attempt 0, a clean salt as
// attempt 1. Expects attempts == 2.
func TestGenesisAssign_RetriesPastCollision(t *testing.T) {
	collisionSalt := hexBytesT(t, "32805988a90f2b71cfb2aa78c36a45062b290e2eb079dd23bc9c77ffd9a22173")
	cleanSalt := bytesRepeat(0xaa, 32)
	salts := [][]byte{collisionSalt, cleanSalt}
	sampler := func(attempt int) ([]byte, error) { return salts[attempt], nil }
	salt, attempts, err := GenesisAssign(sampler, []uint64{0, 1})
	if err != nil {
		t.Fatalf("GenesisAssign: %v", err)
	}
	if attempts != 2 {
		t.Errorf("attempts = %d, want 2", attempts)
	}
	if hex.EncodeToString(salt) != hex.EncodeToString(cleanSalt) {
		t.Errorf("returned salt is not the clean one")
	}
}

// TestGenesisAssign_ExhaustsRMax asserts that 8 attempts each with the
// collision salt fail with terminal ErrGenesisReseedCollision.
func TestGenesisAssign_ExhaustsRMax(t *testing.T) {
	collisionSalt := hexBytesT(t, "32805988a90f2b71cfb2aa78c36a45062b290e2eb079dd23bc9c77ffd9a22173")
	calls := 0
	sampler := func(attempt int) ([]byte, error) {
		calls++
		return collisionSalt, nil
	}
	_, _, err := GenesisAssign(sampler, []uint64{0, 1})
	if !errors.Is(err, ErrGenesisReseedCollision) {
		t.Fatalf("err = %v, want ErrGenesisReseedCollision", err)
	}
	if calls != RMax {
		t.Errorf("sampler called %d times, want %d (R_max)", calls, RMax)
	}
}

// TestAssignCapture_IntraLineageCollisionFailsClosed asserts a captured
// thought whose derived index collides with an already-occupied cell
// returns ErrCellIndexCollision and does NOT relocate.
func TestAssignCapture_IntraLineageCollisionFailsClosed(t *testing.T) {
	salt := hexBytesT(t, "32805988a90f2b71cfb2aa78c36a45062b290e2eb079dd23bc9c77ffd9a22173")
	occupiedIdx, _ := CellIndex(salt, 0)
	occupied := map[uint32]uint64{occupiedIdx: 0}
	_, err := AssignCapture(occupied, salt, 1)
	if !errors.Is(err, ErrCellIndexCollision) {
		t.Fatalf("err = %v, want ErrCellIndexCollision", err)
	}
	// No silent relocation: occupied map remains unchanged.
	if len(occupied) != 1 || occupied[occupiedIdx] != 0 {
		t.Fatalf("occupied map mutated: %#v", occupied)
	}
}

// TestGenesisAssign_RMaxExhaustionStatistical_k500 exercises the R_max=8
// reseed bound using a CSPRNG-derived cell set of k=500.
//
// Part A — success path:
//
//	generate 500 thought_ids using ChaCha8 with a fixed seed (CI-stable);
//	GenesisAssign with a real crypto/rand-backed sampler should accept
//	on attempt ≤ R_max. At k=500 the per-attempt birthday-bound
//	collision probability is ≈ 500²/(2·2²⁰) ≈ 12%; full exhaustion
//	across all 8 attempts has probability ≈ 0.12⁸ ≈ 4e-8.
//
// Part B — exhaustion path:
//
//	force every sampled salt to collide. GenesisAssign MUST return
//	*MembridgeError{Code:"ERR_GENESIS_RESEED_COLLISION"} after exactly
//	R_max sampler calls.
func TestGenesisAssign_RMaxExhaustionStatistical_k500(t *testing.T) {
	t.Parallel()

	const k = 500

	// --- Part A: CSPRNG-seeded success path ---
	seed := [32]byte{0xde, 0xad, 0xbe, 0xef} // fixed seed; remaining bytes zero
	rng := mrand.NewChaCha8(seed)

	tids := make([]uint64, k)
	for i := range tids {
		tids[i] = rng.Uint64()
	}

	csprngSampler := func(int) ([]byte, error) {
		b := make([]byte, 32)
		if _, err := crand.Read(b); err != nil {
			return nil, err
		}
		return b, nil
	}

	salt, attempts, err := GenesisAssign(csprngSampler, tids)
	if err != nil {
		// With k=500 the exhaustion probability is ~4e-8; a failure here
		// almost certainly indicates a bug in the reseed loop, not bad luck.
		t.Fatalf("GenesisAssign CSPRNG path: unexpected error after %d attempts: %v", attempts, err)
	}
	if len(salt) != 32 {
		t.Errorf("salt length = %d, want 32", len(salt))
	}
	if attempts < 1 || attempts > RMax {
		t.Errorf("attempts = %d, want in [1, %d]", attempts, RMax)
	}

	// --- Part B: exhaustion path — every sampled salt forces a collision ---
	collisionSalt := hexBytesT(t, "32805988a90f2b71cfb2aa78c36a45062b290e2eb079dd23bc9c77ffd9a22173")
	var exhaustCalls int
	exhaustSampler := func(int) ([]byte, error) {
		exhaustCalls++
		return collisionSalt, nil
	}

	_, _, exhaustErr := GenesisAssign(exhaustSampler, []uint64{0, 1})
	if exhaustErr == nil {
		t.Fatal("exhaustion path: expected ERR_GENESIS_RESEED_COLLISION, got nil")
	}
	var mbe *MembridgeError
	if !errors.As(exhaustErr, &mbe) || mbe.Code() != "ERR_GENESIS_RESEED_COLLISION" {
		t.Errorf("exhaustion path: error = %v, want *MembridgeError{Code:ERR_GENESIS_RESEED_COLLISION}", exhaustErr)
	}
	if exhaustCalls != RMax {
		t.Errorf("sampler called %d times, want %d (R_max)", exhaustCalls, RMax)
	}
}

// helpers
func bytesRepeat(b byte, n int) []byte {
	out := make([]byte, n)
	for i := range out {
		out[i] = b
	}
	return out
}

func hexBytesT(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("hex: %v", err)
	}
	return b
}
