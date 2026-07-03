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
	manifestRInit := hexBytesT(t, "cff958a1a8874dc8349bee656ce44ca805233a3dd934c4e98afdf4303f571217")
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
	manifestRInit := hexBytesT(t, "cff958a1a8874dc8349bee656ce44ca805233a3dd934c4e98afdf4303f571217")
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
