// Copyright 2026 Jerry David Chan, Konareef.ai
// SPDX-License-Identifier: Apache-2.0

// internal/membridge/derive_test.go
package membridge

import (
	"encoding/hex"
	"errors"
	"testing"
)

// hexBytes decodes a fixed-length hex string into a byte slice; t.Fatal on error.
func hexBytes(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("hex.DecodeString(%q): %v", s, err)
	}
	return b
}

// TestB1_PopulatedSingle reproduces vector "mem-populated-single" from
// the upstream conformance set: SALT_A (0xaa*32), thought_id=42, CH_1
// produces index=863541, value_hash=7ec3..., leaf_hash=dd74..., and a
// single-cell sparse root.
func TestB1_PopulatedSingle(t *testing.T) {
	salt := hexBytes(t, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	ch := hexBytes(t, "aae0a971434ea3f6973aa77b266bd53ddae16abad964cd06ff44ecc799c5679e")

	idx, err := CellIndex(salt, 42)
	if err != nil {
		t.Fatalf("CellIndex: %v", err)
	}
	if idx != 863541 {
		t.Errorf("index = %d, want 863541", idx)
	}

	vh, err := ValueHash(salt, 42, ch)
	if err != nil {
		t.Fatalf("ValueHash: %v", err)
	}
	if got := hex.EncodeToString(vh[:]); got != "7ec3685ee766a8455583697cd485077735b406f47f4651f89b5088afe3e01dc6" {
		t.Errorf("value_hash = %s", got)
	}

	lh := LeafHash(vh)
	if got := hex.EncodeToString(lh[:]); got != "dd7472a24b8be9bd4319fbdbf28b5d54ba61ae8f344a186f7c867b2143326079" {
		t.Errorf("leaf_hash = %s", got)
	}
}

// TestB1_ThoughtIDMin anchors the logical_key bytes for thought_id=0.
// logical_key_hex = "2020 aa*32 0100" — DTAG_KEY||ULEB128(32)||salt||ULEB128(1)||0x00.
func TestB1_ThoughtIDMin(t *testing.T) {
	salt := hexBytes(t, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	lk, err := LogicalKey(salt, 0)
	if err != nil {
		t.Fatalf("LogicalKey: %v", err)
	}
	want := "2020aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa0100"
	if got := hex.EncodeToString(lk); got != want {
		t.Fatalf("logical_key = %s, want %s", got, want)
	}
}

// TestB1_ThoughtIDMax_3byteLEB128 confirms multi-byte LEB128 in B.1.
// thought_id=2097151 (2^21-1) encodes as 0xff 0xff 0x7f.
func TestB1_ThoughtIDMax_3byteLEB128(t *testing.T) {
	salt := hexBytes(t, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	lk, err := LogicalKey(salt, 2097151)
	if err != nil {
		t.Fatalf("LogicalKey: %v", err)
	}
	want := "2020aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa03ffff7f"
	if got := hex.EncodeToString(lk); got != want {
		t.Fatalf("logical_key = %s, want %s", got, want)
	}
}

// TestB1_SaltLengthReject covers the conformance vector mem-salt-length-reject.
func TestB1_SaltLengthReject(t *testing.T) {
	shortSalt := make([]byte, 31)
	_, err := LogicalKey(shortSalt, 1)
	if !errors.Is(err, ErrCellSaltLen) {
		t.Fatalf("err = %v, want ErrCellSaltLen", err)
	}
	if _, err := CellIndex(shortSalt, 1); !errors.Is(err, ErrCellSaltLen) {
		t.Fatalf("CellIndex: err = %v, want ErrCellSaltLen", err)
	}
	if _, err := ValueHash(shortSalt, 1, make([]byte, 32)); !errors.Is(err, ErrCellSaltLen) {
		t.Fatalf("ValueHash: err = %v, want ErrCellSaltLen", err)
	}
}

// TestB1_Trunc20Masking covers mem-trunc20-lowbits: be_u32 raw value has
// high bits set; mask retains low 20 bits only.
func TestB1_Trunc20Masking(t *testing.T) {
	salt := hexBytes(t, "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")
	idx, err := CellIndex(salt, 0)
	if err != nil {
		t.Fatalf("CellIndex: %v", err)
	}
	if idx != 130353 {
		t.Errorf("index = %d (0x%x), want 130353 (0x1fd31)", idx, idx)
	}
	if idx >= 1<<20 {
		t.Errorf("index = %d exceeds 2^20", idx)
	}
}
