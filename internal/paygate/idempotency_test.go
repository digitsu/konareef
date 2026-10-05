// Copyright 2026 Jerry David Chan, Konareef.ai
// SPDX-License-Identifier: Apache-2.0

// internal/paygate/idempotency_test.go — byte-exact golden vectors.
package paygate_test

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/digitsu/konareef/internal/paygate"
)

type canonicalVector struct {
	VectorID string `json:"vector_id"`
	Inputs   struct {
		CircuitID string `json:"circuit_id"`
		StepIndex uint64 `json:"step_index"`
		HPHex     string `json:"h_p_hex"`
	} `json:"inputs"`
	Expected struct {
		CircuitIDBytesHex string `json:"circuit_id_bytes_hex"`
		PreimageHex       string `json:"preimage_hex"`
		IdempotencyKeyHex string `json:"idempotency_key_hex"`
	} `json:"expected"`
}

func TestIdempotencyKeyCanonicalGolden(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("testdata", "idempotency", "canonical.json"))
	if err != nil {
		t.Fatalf("read canonical.json: %v", err)
	}
	var v canonicalVector
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	hp, err := hex.DecodeString(v.Inputs.HPHex)
	if err != nil || len(hp) != 32 {
		t.Fatalf("h_p must be 32 bytes hex: %v / len=%d", err, len(hp))
	}
	var hpArr [32]byte
	copy(hpArr[:], hp)

	gotPreimage := paygate.IdempotencyPreimage(v.Inputs.CircuitID, v.Inputs.StepIndex, hpArr)
	if hex.EncodeToString(gotPreimage) != v.Expected.PreimageHex {
		t.Errorf("preimage:\n got=%s\nwant=%s", hex.EncodeToString(gotPreimage), v.Expected.PreimageHex)
	}

	gotKey := paygate.IdempotencyKey(v.Inputs.CircuitID, v.Inputs.StepIndex, hpArr)
	if gotKey != v.Expected.IdempotencyKeyHex {
		t.Errorf("idempotency_key:\n got=%s\nwant=%s", gotKey, v.Expected.IdempotencyKeyHex)
	}
	if gotKey != strings.ToLower(gotKey) {
		t.Errorf("idempotency_key must be lowercase hex; got %q", gotKey)
	}
	if len(gotKey) != 64 {
		t.Errorf("idempotency_key must be 64 hex chars; got %d", len(gotKey))
	}
}

func TestIdempotencyKeyStepIndexNonZero(t *testing.T) {
	var hp [32]byte
	hpBytes, _ := hex.DecodeString("9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08")
	copy(hp[:], hpBytes)

	preimage := paygate.IdempotencyPreimage("konareef-pod-step-v1", 257, hp)
	// step_index=257 as big-endian uint64 = 0x00 00 00 00 00 00 01 01
	// preimage = ULEB128(20)=0x14 || 20 bytes circuit_id || 8 bytes be_u64(257) || 32 bytes h_p
	wantPrefix, _ := hex.DecodeString("146b6f6e61726565662d706f642d737465702d763100000000000001019f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08")
	if hex.EncodeToString(preimage) != hex.EncodeToString(wantPrefix) {
		t.Errorf("step_index=257 preimage mismatch:\n got=%x\nwant=%x", preimage, wantPrefix)
	}
}

func TestIdempotencyKeyMultiByteULEB128(t *testing.T) {
	circuit := strings.Repeat("a", 200)
	var hp [32]byte
	preimage := paygate.IdempotencyPreimage(circuit, 0, hp)
	// First two bytes must be ULEB128(200) = 0xc8 0x01
	if preimage[0] != 0xc8 || preimage[1] != 0x01 {
		t.Errorf("ULEB128(200) prefix wrong: got %x %x, want c8 01", preimage[0], preimage[1])
	}
	// Next 200 bytes must be 0x61 ('a')
	for i := 0; i < 200; i++ {
		if preimage[2+i] != 0x61 {
			t.Fatalf("circuit_id byte %d = %x, want 0x61", i, preimage[2+i])
		}
	}
}

func TestIdempotencyKeyLengthPrefixDivergence(t *testing.T) {
	var hp [32]byte
	// Under the konareef-local encoding step_index is be_u64(int), NOT ASCII;
	// the test asserts the two PRD 2 § 6.5 erratum collision inputs produce
	// DIFFERENT keys under the canonical encoding.
	keyA := paygate.IdempotencyKey("konareef-pod-step-v10", 42, hp)
	keyB := paygate.IdempotencyKey("konareef-pod-step-v1", 42, hp) // same step_index numerically — only circuit_id differs in byte length
	if keyA == keyB {
		t.Fatalf("length-prefixed encoding must produce distinct keys for distinct circuit_id lengths; both = %s", keyA)
	}
}
