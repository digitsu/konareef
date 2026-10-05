// Copyright 2026 Jerry David Chan, Konareef.ai
// SPDX-License-Identifier: Apache-2.0

// internal/membridge/sparse_merkle_test.go
package membridge

import (
	"encoding/hex"
	"errors"
	"testing"
)

// TestSparseRoot_Empty mirrors mem-empty-sentinel: empty cells → EmptyRoots[20].
func TestSparseRoot_Empty(t *testing.T) {
	root, err := SparseRoot(nil)
	if err != nil {
		t.Fatalf("SparseRoot(nil): %v", err)
	}
	if got := hex.EncodeToString(root[:]); got != hex.EncodeToString(EmptyRoots[20][:]) {
		t.Fatalf("empty root mismatch: got %s", got)
	}
}

// TestSparseRoot_PopulatedSingle reproduces the mem-populated-single
// r_init = 2cff…0630 (Poseidon) from the conformance vector file.
func TestSparseRoot_PopulatedSingle(t *testing.T) {
	salt := hexBytes(t, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	ch := hexBytes(t, "aae0a971434ea3f6973aa77b266bd53ddae16abad964cd06ff44ecc799c5679e")
	idx, _ := CellIndex(salt, 42)
	vh, _ := ValueHash(salt, 42, ch)
	root, err := SparseRoot(map[uint32][32]byte{idx: vh})
	if err != nil {
		t.Fatalf("SparseRoot: %v", err)
	}
	want := "2cff847f318a6f449b19b2924fbf1d838a3570dde25c3e2a8ef3b25e4ded0630"
	if got := hex.EncodeToString(root[:]); got != want {
		t.Fatalf("r_init = %s, want %s", got, want)
	}
}

// TestSparseRoot_ThreeCells reproduces mem-multi-cell-root r_init.
func TestSparseRoot_ThreeCells(t *testing.T) {
	salt := hexBytes(t, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	ch1 := hexBytes(t, "aae0a971434ea3f6973aa77b266bd53ddae16abad964cd06ff44ecc799c5679e")
	ch2 := hexBytes(t, "c29aa59cafc9e2437b2c9f0c8772593e63c5fe7b63dee5f9f1b1a8cc3369f919")
	ch3 := hexBytes(t, "72b2ac744cd525b6ed060ef36ebf16496b2db6fed6ab44c82b292976b3338349")
	cells := map[uint32][32]byte{}
	for _, c := range []struct {
		tid uint64
		ch  []byte
	}{{1, ch1}, {2, ch2}, {3, ch3}} {
		idx, _ := CellIndex(salt, c.tid)
		vh, _ := ValueHash(salt, c.tid, c.ch)
		cells[idx] = vh
	}
	root, err := SparseRoot(cells)
	if err != nil {
		t.Fatalf("SparseRoot: %v", err)
	}
	want := "86ec05dda6bd85f65f477160a7cddee1bb0f7e4b1775d09f1b9c88009ee2871f"
	if got := hex.EncodeToString(root[:]); got != want {
		t.Fatalf("r_init = %s, want %s", got, want)
	}
}

// TestAuthPath_RoundTrip asserts BuildAuthPath + VerifyAuthPath round-trip
// for a populated cell at a deliberately non-trivial index. LSB-first
// direction is critical to test.
func TestAuthPath_RoundTrip(t *testing.T) {
	salt := hexBytes(t, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	ch := hexBytes(t, "aae0a971434ea3f6973aa77b266bd53ddae16abad964cd06ff44ecc799c5679e")
	idx, _ := CellIndex(salt, 42)
	vh, _ := ValueHash(salt, 42, ch)
	cells := map[uint32][32]byte{idx: vh}
	root, err := SparseRoot(cells)
	if err != nil {
		t.Fatalf("SparseRoot: %v", err)
	}

	path, err := BuildAuthPath(cells, idx)
	if err != nil {
		t.Fatalf("BuildAuthPath: %v", err)
	}
	if len(path) != D {
		t.Fatalf("path length = %d, want %d", len(path), D)
	}
	lh, err := LeafHash(vh)
	if err != nil {
		t.Fatalf("LeafHash: %v", err)
	}
	got, err := VerifyAuthPath(idx, lh, path)
	if err != nil {
		t.Fatalf("VerifyAuthPath: %v", err)
	}
	if got != root {
		t.Fatalf("recomputed root %x != %x", got[:], root[:])
	}
	// A tampered sibling must not reproduce the root (control above).
	path[3][0] ^= 1
	if bad, err := VerifyAuthPath(idx, lh, path); err == nil && bad == root {
		t.Fatal("a tampered sibling reproduced the root")
	}
}

// TestAuthPath_MultiCellEverySiblingPath authenticates each cell of the
// PRD 4 mem-multi-cell-root set, and an empty slot, against the Poseidon
// root, which is what the pod-step circuit checks at genesis.
func TestAuthPath_MultiCellEverySiblingPath(t *testing.T) {
	salt := hexBytes(t, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	cells := map[uint32][32]byte{}
	for tid, ch := range map[uint64]string{
		1: "aae0a971434ea3f6973aa77b266bd53ddae16abad964cd06ff44ecc799c5679e",
		2: "c29aa59cafc9e2437b2c9f0c8772593e63c5fe7b63dee5f9f1b1a8cc3369f919",
		3: "72b2ac744cd525b6ed060ef36ebf16496b2db6fed6ab44c82b292976b3338349",
	} {
		idx, _ := CellIndex(salt, tid)
		vh, _ := ValueHash(salt, tid, hexBytes(t, ch))
		cells[idx] = vh
	}
	root, err := SparseRoot(cells)
	if err != nil {
		t.Fatalf("SparseRoot: %v", err)
	}
	for idx, vh := range cells {
		path, err := BuildAuthPath(cells, idx)
		if err != nil {
			t.Fatalf("BuildAuthPath(%d): %v", idx, err)
		}
		lh, _ := LeafHash(vh)
		if got, err := VerifyAuthPath(idx, lh, path); err != nil || got != root {
			t.Fatalf("index %d does not authenticate: %v", idx, err)
		}
	}
	const emptySlot = uint32(7)
	path, err := BuildAuthPath(cells, emptySlot)
	if err != nil {
		t.Fatalf("BuildAuthPath(empty): %v", err)
	}
	if got, err := VerifyAuthPath(emptySlot, EmptyRoots[0], path); err != nil || got != root {
		t.Fatalf("empty slot does not authenticate: %v", err)
	}
	if _, err := VerifyAuthPath(1<<D, EmptyRoots[0], path); !errors.Is(err, ErrSparseIndexOutOfRange) {
		t.Fatalf("out-of-range index: err = %v", err)
	}
}

// TestAuthPath_EmptyCellSiblingsAreEmptyRoots asserts an empty-tree
// authentication path returns all EmptyRoots[k] siblings.
func TestAuthPath_EmptyCellSiblingsAreEmptyRoots(t *testing.T) {
	path, err := BuildAuthPath(nil, 0)
	if err != nil {
		t.Fatalf("BuildAuthPath: %v", err)
	}
	for k, sib := range path {
		if sib != EmptyRoots[k] {
			t.Errorf("sibling[%d] != EmptyRoots[%d]", k, k)
		}
	}
}

// TestSparseRoot_RejectsOutOfRange asserts that caller-supplied indices
// >= 2^D are rejected fail-closed rather than silently masked. Two
// callers differing only in bits >= 20 MUST NOT collide silently.
// (Hermes review on MR !7.)
func TestSparseRoot_RejectsOutOfRange(t *testing.T) {
	cells := map[uint32][32]byte{1 << D: {0x01}}
	_, err := SparseRoot(cells)
	if !errors.Is(err, ErrSparseIndexOutOfRange) {
		t.Fatalf("err = %v, want ErrSparseIndexOutOfRange", err)
	}
}

// TestBuildAuthPath_RejectsOutOfRangeIndex asserts the auth-path API
// fail-closes on a caller-supplied index >= 2^D.
func TestBuildAuthPath_RejectsOutOfRangeIndex(t *testing.T) {
	_, err := BuildAuthPath(map[uint32][32]byte{}, 1<<D)
	if !errors.Is(err, ErrSparseIndexOutOfRange) {
		t.Fatalf("err = %v, want ErrSparseIndexOutOfRange", err)
	}
}

// TestBuildAuthPath_RejectsOutOfRangeLeafKey asserts the auth-path API
// fail-closes when any leaves-map key is >= 2^D, even if the requested
// index is in range.
func TestBuildAuthPath_RejectsOutOfRangeLeafKey(t *testing.T) {
	cells := map[uint32][32]byte{1 << D: {0x01}}
	_, err := BuildAuthPath(cells, 0)
	if !errors.Is(err, ErrSparseIndexOutOfRange) {
		t.Fatalf("err = %v, want ErrSparseIndexOutOfRange", err)
	}
}
