// Copyright 2026 Jerry David Chan, Konareef.ai
// SPDX-License-Identifier: Apache-2.0

// internal/membridge/constants_test.go
package membridge

import (
	"encoding/hex"
	"testing"
)

// TestEmptyRootD20 anchors the depth-20 empty sparse-Merkle root to the
// constant published in the conformance-vector file. Any drift here means
// LEAF_TAG, NODE_TAG, or the iteration is wrong.
func TestEmptyRootD20(t *testing.T) {
	const want = "0f2106fa5d65c0bed55f9298f38695f25d40110494f085cf8a1fcf650e8f7790"
	got := hex.EncodeToString(EmptyRoots[20][:])
	if got != want {
		t.Fatalf("EmptyRoots[20] = %s, want %s", got, want)
	}
}

// TestDomainTagsDisjoint verifies the Part-B tags do not collide with
// PRD 1 §5.5 tree tags or PRD 1 §5.4 T_log tags.
func TestDomainTagsDisjoint(t *testing.T) {
	tags := map[string]byte{
		"DTAG_KEY":  DTAG_KEY,
		"DTAG_CELL": DTAG_CELL,
		"DTAG_PROV": DTAG_PROV,
		"LEAF_TAG":  LEAF_TAG,
		"NODE_TAG":  NODE_TAG,
	}
	seen := map[byte]string{}
	for name, b := range tags {
		if prev, ok := seen[b]; ok {
			t.Fatalf("tag collision: %s and %s both 0x%02x", prev, name, b)
		}
		seen[b] = name
	}
	want := map[string]byte{
		"DTAG_KEY": 0x20, "DTAG_CELL": 0x21, "DTAG_PROV": 0x22,
		"LEAF_TAG": 0x10, "NODE_TAG": 0x11,
	}
	for name, b := range want {
		if tags[name] != b {
			t.Fatalf("%s = 0x%02x, want 0x%02x", name, tags[name], b)
		}
	}
}
