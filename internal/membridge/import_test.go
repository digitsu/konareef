// Copyright 2026 Jerry David Chan, Konareef.ai
// SPDX-License-Identifier: Apache-2.0

// internal/membridge/import_test.go
package membridge

import (
	"encoding/hex"
	"errors"
	"testing"
)

// TestImportSnapshot_HappyPath builds a snapshot of three leaves whose
// (thought_id, content_hash) match mem-multi-cell-root, verifies the
// computed r_init equals the conformance vector, and verifies the audit
// trail is ordered by leaf_index.
func TestImportSnapshot_HappyPath(t *testing.T) {
	salt := hexBytesT(t, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	manifestRInit := hexBytesT(t, "86ec05dda6bd85f65f477160a7cddee1bb0f7e4b1775d09f1b9c88009ee2871f")
	leaves := []MemorySnapshotLeaf{
		{LeafIndex: 0, ThoughtID: 1, ContentHash: hexBytesT(t, "aae0a971434ea3f6973aa77b266bd53ddae16abad964cd06ff44ecc799c5679e")},
		{LeafIndex: 1, ThoughtID: 2, ContentHash: hexBytesT(t, "c29aa59cafc9e2437b2c9f0c8772593e63c5fe7b63dee5f9f1b1a8cc3369f919")},
		{LeafIndex: 2, ThoughtID: 3, ContentHash: hexBytesT(t, "72b2ac744cd525b6ed060ef36ebf16496b2db6fed6ab44c82b292976b3338349")},
	}
	root, trail, err := ImportSnapshot(salt, leaves, manifestRInit)
	if err != nil {
		t.Fatalf("ImportSnapshot: %v", err)
	}
	if hex.EncodeToString(root[:]) != hex.EncodeToString(manifestRInit) {
		t.Fatalf("computed root != manifest r_init")
	}
	if len(trail) != 3 {
		t.Fatalf("trail len = %d, want 3", len(trail))
	}
	// Trail order must mirror leaf_index ASC.
	for i, e := range trail {
		if e.ThoughtID != leaves[i].ThoughtID {
			t.Errorf("trail[%d].ThoughtID = %d, want %d", i, e.ThoughtID, leaves[i].ThoughtID)
		}
	}
}

// TestImportSnapshot_OutOfOrderLeavesGetSorted asserts that even if the
// caller hands leaves out of order, the trail emerges sorted ASC by
// leaf_index. (This implements the §B.5 step-1 enumeration order.)
func TestImportSnapshot_OutOfOrderLeavesGetSorted(t *testing.T) {
	salt := hexBytesT(t, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	manifestRInit := hexBytesT(t, "86ec05dda6bd85f65f477160a7cddee1bb0f7e4b1775d09f1b9c88009ee2871f")
	leaves := []MemorySnapshotLeaf{
		{LeafIndex: 2, ThoughtID: 3, ContentHash: hexBytesT(t, "72b2ac744cd525b6ed060ef36ebf16496b2db6fed6ab44c82b292976b3338349")},
		{LeafIndex: 0, ThoughtID: 1, ContentHash: hexBytesT(t, "aae0a971434ea3f6973aa77b266bd53ddae16abad964cd06ff44ecc799c5679e")},
		{LeafIndex: 1, ThoughtID: 2, ContentHash: hexBytesT(t, "c29aa59cafc9e2437b2c9f0c8772593e63c5fe7b63dee5f9f1b1a8cc3369f919")},
	}
	_, trail, err := ImportSnapshot(salt, leaves, manifestRInit)
	if err != nil {
		t.Fatalf("ImportSnapshot: %v", err)
	}
	wantOrder := []uint64{1, 2, 3}
	for i, e := range trail {
		if e.ThoughtID != wantOrder[i] {
			t.Errorf("trail[%d].ThoughtID = %d, want %d", i, e.ThoughtID, wantOrder[i])
		}
	}
}

// TestImportSnapshot_RInitMismatchRejects asserts ErrRInitMismatch when
// computed root != manifest r_init.
func TestImportSnapshot_RInitMismatchRejects(t *testing.T) {
	salt := hexBytesT(t, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	leaves := []MemorySnapshotLeaf{
		{LeafIndex: 0, ThoughtID: 42, ContentHash: hexBytesT(t, "aae0a971434ea3f6973aa77b266bd53ddae16abad964cd06ff44ecc799c5679e")},
	}
	wrongManifest := make([]byte, 32) // all zeros
	_, _, err := ImportSnapshot(salt, leaves, wrongManifest)
	if !errors.Is(err, ErrRInitMismatch) {
		t.Fatalf("err = %v, want ErrRInitMismatch", err)
	}
}

// TestImportSnapshot_SaltLengthRejects asserts that a wrong salt length
// surfaces ErrCellSaltLen (NOT ErrSnapshotImportFailed) so callers
// distinguish the cause.
func TestImportSnapshot_SaltLengthRejects(t *testing.T) {
	leaves := []MemorySnapshotLeaf{
		{LeafIndex: 0, ThoughtID: 1, ContentHash: make([]byte, 32)},
	}
	_, _, err := ImportSnapshot(make([]byte, 31), leaves, make([]byte, 32))
	if !errors.Is(err, ErrCellSaltLen) {
		t.Fatalf("err = %v, want ErrCellSaltLen", err)
	}
}

// TestImportSnapshot_MalformedLeafRejects: content_hash != 32 → ErrSnapshotImportFailed.
func TestImportSnapshot_MalformedLeafRejects(t *testing.T) {
	salt := hexBytesT(t, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	leaves := []MemorySnapshotLeaf{
		{LeafIndex: 0, ThoughtID: 1, ContentHash: []byte{0x01}},
	}
	_, _, err := ImportSnapshot(salt, leaves, make([]byte, 32))
	if !errors.Is(err, ErrSnapshotImportFailed) {
		t.Fatalf("err = %v, want ErrSnapshotImportFailed", err)
	}
}

// TestImportSnapshot_DuplicateThoughtIDRejects: two leaves naming one
// thought id are refused with ErrCellDuplicateID (konareef-rinit/v1
// R-M8). Before the D6 migration a repeated id silently overwrote its
// own cell. The distinct-id control is TestImportSnapshot_HappyPath.
func TestImportSnapshot_DuplicateThoughtIDRejects(t *testing.T) {
	salt := hexBytesT(t, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	ch := hexBytesT(t, "aae0a971434ea3f6973aa77b266bd53ddae16abad964cd06ff44ecc799c5679e")
	leaves := []MemorySnapshotLeaf{
		{LeafIndex: 0, ThoughtID: 1, ContentHash: ch},
		{LeafIndex: 1, ThoughtID: 1, ContentHash: ch},
	}
	if _, _, err := ImportSnapshot(salt, leaves, make([]byte, 32)); !errors.Is(err, ErrCellDuplicateID) {
		t.Fatalf("err = %v, want ErrCellDuplicateID", err)
	}
}

// TestCheckRInitV1 is the salt holder's root check: the control passes
// for the PRD 4 multi-cell set; a changed content hash, a different salt
// and an empty cell list against a populated root all refuse with
// ErrRInitMismatch, and the error text carries no root or salt.
func TestCheckRInitV1(t *testing.T) {
	salt := hexBytesT(t, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	var committed [32]byte
	copy(committed[:], hexBytesT(t, "86ec05dda6bd85f65f477160a7cddee1bb0f7e4b1775d09f1b9c88009ee2871f"))
	cells := []Cell{
		{CellID: 3, ContentHash: hexBytesT(t, "72b2ac744cd525b6ed060ef36ebf16496b2db6fed6ab44c82b292976b3338349")},
		{CellID: 1, ContentHash: hexBytesT(t, "aae0a971434ea3f6973aa77b266bd53ddae16abad964cd06ff44ecc799c5679e")},
		{CellID: 2, ContentHash: hexBytesT(t, "c29aa59cafc9e2437b2c9f0c8772593e63c5fe7b63dee5f9f1b1a8cc3369f919")},
	}
	derived, err := CheckRInitV1(salt, cells, committed)
	if err != nil {
		t.Fatalf("control: %v", err)
	}
	if len(derived) != 3 || derived[0].CellID != 1 || derived[2].CellID != 3 {
		t.Fatalf("derived cells must be in ascending CellID order: %+v", derived)
	}

	changed := append([]Cell(nil), cells...)
	changed[0] = Cell{CellID: 3, ContentHash: make([]byte, 32)}
	otherSalt := hexBytesT(t, "abababababababababababababababababababababababababababababababab")
	for name, run := range map[string]func() error{
		"changed content": func() error { _, err := CheckRInitV1(salt, changed, committed); return err },
		"other salt":      func() error { _, err := CheckRInitV1(otherSalt, cells, committed); return err },
		"no cells":        func() error { _, err := CheckRInitV1(salt, nil, committed); return err },
	} {
		err := run()
		if !errors.Is(err, ErrRInitMismatch) {
			t.Fatalf("%s: err = %v, want ErrRInitMismatch", name, err)
		}
		if err.Error() != "ERR_RINIT_MISMATCH" {
			t.Fatalf("%s: error text must be the bare code, got %q", name, err.Error())
		}
	}
	if _, err := CheckRInitV1(salt, nil, EmptyRoots[D]); err != nil {
		t.Fatalf("no cells against E20: %v", err)
	}
}
