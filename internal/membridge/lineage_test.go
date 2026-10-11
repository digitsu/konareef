// Copyright 2026 Jerry David Chan, Konareef.ai
// SPDX-License-Identifier: Apache-2.0

// internal/membridge/lineage_test.go
package membridge

import (
	"bytes"
	"errors"
	"testing"
)

// stubSampler returns deterministic salts for testing reseed paths.
func stubSampler(salts ...[]byte) SaltSampler {
	return func(attempt int) ([]byte, error) {
		if attempt >= len(salts) {
			return nil, errors.New("stubSampler exhausted")
		}
		return salts[attempt], nil
	}
}

// TestClone_PreservesSalt confirms Clone returns the same salt bytes.
func TestClone_PreservesSalt(t *testing.T) {
	src := bytesRepeat(0xaa, 32)
	got := Clone(src)
	if !bytes.Equal(got, src) {
		t.Fatalf("Clone changed salt: got %x, want %x", got, src)
	}
	// Mutation isolation: editing the returned slice MUST NOT touch src.
	got[0] ^= 0xff
	if src[0] == got[0] {
		t.Fatalf("Clone returned alias not copy")
	}
}

// TestFork_PreservesSaltForBothBranches.
func TestFork_PreservesSaltForBothBranches(t *testing.T) {
	src := bytesRepeat(0xbb, 32)
	a, b := Fork(src)
	if !bytes.Equal(a, src) || !bytes.Equal(b, src) {
		t.Fatalf("Fork branches diverged from source")
	}
}

// TestMigrate_PreservesSalt.
func TestMigrate_PreservesSalt(t *testing.T) {
	src := bytesRepeat(0xcc, 32)
	got := Migrate(src)
	if !bytes.Equal(got, src) {
		t.Fatalf("Migrate changed salt")
	}
}

// TestNewLineage_Reseeds asserts NewLineage runs the genesis reseed
// loop and returns a fresh salt (which need not equal the source).
func TestNewLineage_Reseeds(t *testing.T) {
	fresh := bytesRepeat(0x11, 32)
	salt, attempts, err := NewLineage(stubSampler(fresh), []uint64{1, 2, 3})
	if err != nil {
		t.Fatalf("NewLineage: %v", err)
	}
	if attempts != 1 {
		t.Errorf("attempts = %d, want 1", attempts)
	}
	if !bytes.Equal(salt, fresh) {
		t.Fatalf("salt = %x, want %x", salt, fresh)
	}
}

// TestNewLineage_ExhaustsRMaxOnPersistentCollision.
func TestNewLineage_ExhaustsRMaxOnPersistentCollision(t *testing.T) {
	collision := hexBytesT(t, "32805988a90f2b71cfb2aa78c36a45062b290e2eb079dd23bc9c77ffd9a22173")
	sampler := stubSampler(collision, collision, collision, collision,
		collision, collision, collision, collision)
	_, _, err := NewLineage(sampler, []uint64{0, 1})
	if !errors.Is(err, ErrGenesisReseedCollision) {
		t.Fatalf("err = %v, want ErrGenesisReseedCollision", err)
	}
}
