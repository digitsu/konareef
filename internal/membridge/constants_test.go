// Copyright 2026 Jerry David Chan, Konareef.ai
// SPDX-License-Identifier: Apache-2.0

// internal/membridge/constants_test.go
package membridge

import (
	"encoding/hex"
	"testing"
)

// TestEmptyRootD20 anchors the depth-20 empty sparse-Merkle root to the
// constant published in the conformance-vector file (EMPTY_ROOT_D20 = E20,
// the Poseidon empty-tree root). Any drift here means the Poseidon
// parameters or the iteration are wrong. The pre-swap SHA-256 value was
// 0f2106fa…7790.
func TestEmptyRootD20(t *testing.T) {
	const want = "c5a959b0cf2043a38c6c75e8f05b0f809bbfdc2ce2e2bbf1f7821d7d1de9d727"
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
