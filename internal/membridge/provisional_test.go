// Copyright 2026 Jerry David Chan, Konareef.ai
// SPDX-License-Identifier: Apache-2.0

// internal/membridge/provisional_test.go
package membridge

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"testing"
)

// TestProvisionalID_KnownAnchor uses a recomputed-in-test expected
// value (independent of the implementation) to anchor B.6.1.
// content_hash = 0x01*32, task_id = 7, ordinal = 0.
func TestProvisionalID_KnownAnchor(t *testing.T) {
	ch := bytesRepeat(0x01, 32)
	const taskID uint64 = 7
	const ordinal uint32 = 0

	// Recompute independently.
	preimage := make([]byte, 0, 1+32+8+4)
	preimage = append(preimage, DTAG_PROV)
	preimage = append(preimage, ch...)
	var b8 [8]byte
	binary.BigEndian.PutUint64(b8[:], taskID)
	preimage = append(preimage, b8[:]...)
	var b4 [4]byte
	binary.BigEndian.PutUint32(b4[:], ordinal)
	preimage = append(preimage, b4[:]...)
	sum := sha256.Sum256(preimage)
	want := binary.BigEndian.Uint64(sum[0:8])

	got, err := ProvisionalID(ch, taskID, ordinal)
	if err != nil {
		t.Fatalf("ProvisionalID: %v", err)
	}
	if got != want {
		t.Fatalf("ProvisionalID = %d, want %d", got, want)
	}
}

// TestProvisionalID_OrdinalDistinguishesIdenticalContent asserts that
// two captures with identical content but different ordinals derive
// distinct provisional ids.
func TestProvisionalID_OrdinalDistinguishesIdenticalContent(t *testing.T) {
	ch := bytesRepeat(0x05, 32)
	a, _ := ProvisionalID(ch, 1, 0)
	b, _ := ProvisionalID(ch, 1, 1)
	if a == b {
		t.Fatalf("provisional ids collided: a=%d b=%d", a, b)
	}
}

// TestReconcileProvisional_MatchAccepts confirms the success path.
func TestReconcileProvisional_MatchAccepts(t *testing.T) {
	ch := bytesRepeat(0x09, 32)
	pid, _ := ProvisionalID(ch, 2, 3)
	if err := ReconcileProvisional(pid, pid); err != nil {
		t.Fatalf("match path returned %v", err)
	}
}

// TestReconcileProvisional_MismatchRejects covers
// capture-provisional-id-mismatch-reject negative vector.
func TestReconcileProvisional_MismatchRejects(t *testing.T) {
	err := ReconcileProvisional(123, 124)
	if !errors.Is(err, ErrProvisionalIDMismatch) {
		t.Fatalf("err = %v, want ErrProvisionalIDMismatch", err)
	}
}

// TestProvisionalID_BadContentHash rejects len != 32.
func TestProvisionalID_BadContentHash(t *testing.T) {
	_, err := ProvisionalID([]byte{0x01}, 1, 0)
	if err == nil {
		t.Fatal("expected error for short content_hash")
	}
}

// TestCaptureProvisionalIDCanonical_FullChain exercises the
// (content_hash, task_id, ordinal) → provisional_id → logical_key →
// index → value_hash chain end-to-end and anchors the provisional_id
// against a HARD-CODED expected value (Hermes review on MR !7: the
// previous wantPID := ProvisionalID(...) self-reference proved nothing
// about the byte encoding). Full golden-vector coverage now lives in
// capture-provisional-id-canonical; this test is the in-package
// quick-reference companion.
func TestCaptureProvisionalIDCanonical_FullChain(t *testing.T) {
	ch := bytesRepeat(0x42, 32)
	salt := bytesRepeat(0xaa, 32)
	const taskID uint64 = 99
	const ordinal uint32 = 4
	// Hard-coded byte-exact anchor independently derived (Python
	// reference generator) — see internal/membridge/testdata/vectors/v1.json
	// capture-provisional-id-canonical for the full chain assertion.
	const wantPID uint64 = 0xfa72ec9a25da1344

	pid, err := ProvisionalID(ch, taskID, ordinal)
	if err != nil {
		t.Fatalf("ProvisionalID: %v", err)
	}
	if pid != wantPID {
		t.Fatalf("provisional_id = %016x, want %016x", pid, wantPID)
	}
	// Feed provisional id into B.1.
	idx, err := CellIndex(salt, pid)
	if err != nil {
		t.Fatalf("CellIndex: %v", err)
	}
	if idx >= 1<<20 {
		t.Fatalf("derived index out of range: %d", idx)
	}
	vh, err := ValueHash(salt, pid, ch)
	if err != nil {
		t.Fatalf("ValueHash: %v", err)
	}
	// SparseRoot single-cell must round-trip through the auth path.
	root, err := SparseRoot(map[uint32][32]byte{idx: vh})
	if err != nil {
		t.Fatalf("SparseRoot: %v", err)
	}
	path, err := BuildAuthPath(map[uint32][32]byte{idx: vh}, idx)
	if err != nil {
		t.Fatalf("BuildAuthPath: %v", err)
	}
	lh, err := LeafHash(vh)
	if err != nil {
		t.Fatalf("LeafHash: %v", err)
	}
	if got, err := VerifyAuthPath(idx, lh, path); err != nil || got != root {
		t.Fatalf("auth-path round-trip failed: %v", err)
	}
}

// TestCaptureProvisionalIDMismatchReject exercises the §B.6.1
// reconciliation fail-closed path against an arbitrary alternate
// persistent id.
func TestCaptureProvisionalIDMismatchReject(t *testing.T) {
	ch := bytesRepeat(0x7e, 32)
	pid, _ := ProvisionalID(ch, 1, 0)
	if err := ReconcileProvisional(pid, pid+1); !errors.Is(err, ErrProvisionalIDMismatch) {
		t.Fatalf("err = %v, want ErrProvisionalIDMismatch", err)
	}
}
