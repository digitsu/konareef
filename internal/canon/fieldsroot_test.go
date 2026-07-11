// Copyright 2026 Jerry David Chan, Konareef.ai
// SPDX-License-Identifier: Apache-2.0

package canon

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"testing"
)

type frVectorFile struct {
	Vectors []struct {
		Name       string   `json:"name"`
		Models     []string `json:"models"`
		Tools      []string `json:"tools"`
		CMax       uint64   `json:"c_max"`
		RInit      string   `json:"r_init"`
		FieldsRoot string   `json:"fields_root"`
	} `json:"vectors"`
}

func loadFRVectors(t *testing.T) frVectorFile {
	t.Helper()
	b, err := os.ReadFile("testdata/fields_root_vectors.json")
	if err != nil {
		t.Fatalf("read fields_root vectors: %v", err)
	}
	var f frVectorFile
	if err := json.Unmarshal(b, &f); err != nil {
		t.Fatalf("parse fields_root vectors: %v", err)
	}
	return f
}

func rInit32(t *testing.T, s string) [32]byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil || len(b) != 32 {
		t.Fatalf("bad r_init hex %q", s)
	}
	var out [32]byte
	copy(out[:], b)
	return out
}

// TestFieldsRoot_OracleVectors pins the konareef-toml/v2 fields_root
// construction against golden vectors from the independent Python oracle
// (scripts/poseidon_pallas.py). Covers empty, one-each, mixed, and the
// full MAX_MODELS/MAX_TOOLS caps.
//
// The one_each/three_five/full_caps roots were REGENERATED 2026-07-05
// (decision 2026-07-05-konareef-digest-tool-ids, PRD 1 §5.3 amendment —
// tools_root leaves now fold tool_id_digest = SHA-256(name) instead of the
// name bytes) from the paygate-zk Rust oracle; empty is UNCHANGED (see
// TestFieldsRootRustOracleParity for the pinned cross-repo contract).
func TestFieldsRoot_OracleVectors(t *testing.T) {
	f := loadFRVectors(t)
	if len(f.Vectors) == 0 {
		t.Fatal("no fields_root vectors")
	}
	for _, v := range f.Vectors {
		got, err := FieldsRoot(v.Models, v.Tools, v.CMax, rInit32(t, v.RInit))
		if err != nil {
			t.Fatalf("%s: FieldsRoot error: %v", v.Name, err)
		}
		if hex.EncodeToString(got[:]) != v.FieldsRoot {
			t.Errorf("%s: FieldsRoot\n got  %x\n want %s", v.Name, got, v.FieldsRoot)
		}
	}
}

// TestFieldsRoot_SortIndependence verifies the fields_root is independent
// of input order (v2 sorts model/tool ids by canonical UTF-8 bytes).
func TestFieldsRoot_SortIndependence(t *testing.T) {
	models := []string{"gpt-4o", "claude-opus-4-8", "llama-3"}
	tools := []string{"write", "search", "read"}
	var r [32]byte
	a, err := FieldsRoot(models, tools, 42, r)
	if err != nil {
		t.Fatalf("FieldsRoot(a): %v", err)
	}
	b, err := FieldsRoot([]string{"llama-3", "gpt-4o", "claude-opus-4-8"}, []string{"read", "write", "search"}, 42, r)
	if err != nil {
		t.Fatalf("FieldsRoot(b): %v", err)
	}
	if a != b {
		t.Errorf("fields_root not order-independent: %x != %x", a, b)
	}
}

// Empty ids must be rejected: an empty id leaf would be indistinguishable
// from the empty-record Z used to pad unused slots (a fixed-max-commitment
// soundness gap). Invalid UTF-8 must be rejected too — the v2 spec commits ids
// as utf8(s) and sorts by canonical UTF-8 bytes, so non-UTF-8 input leaves the
// cross-impl/circuit canonicalization underspecified.
func TestFieldsRoot_RejectsEmptyAndInvalidUTF8Ids(t *testing.T) {
	var r [32]byte
	cases := []struct {
		name          string
		models, tools []string
	}{
		{"empty model id", []string{""}, nil},
		{"empty tool id", nil, []string{""}},
		{"empty among valid models", []string{"gpt-4o", ""}, nil},
		{"invalid utf8 model", []string{"\xff\xfe"}, nil},
		{"invalid utf8 tool", nil, []string{"a\xc3\x28b"}},
	}
	for _, c := range cases {
		if _, err := FieldsRoot(c.models, c.tools, 0, r); err == nil {
			t.Errorf("%s: expected error, got nil", c.name)
		}
	}
}

// TestFieldsRootRustOracleParity pins the four cross-repo parity-anchor
// vectors verbatim — the same inputs/roots as paygate-zk
// crates/konareef-circuit/src/gadgets/fields_root.rs
// fields_root_ref_matches_golden_vectors (its "PARITY ANCHOR" doc-comment
// names this Go test file as the counterpart). Any drift here or there
// breaks Go<->Rust fields_root parity for the whole konareef-toml/v2
// construction; this is intentionally independent of
// testdata/fields_root_vectors.json so a change to that file's shared
// fixture can't silently mask a parity break.
func TestFieldsRootRustOracleParity(t *testing.T) {
	rZero := [32]byte{}
	r7 := [32]byte{0x07}
	var rThreeFive [32]byte
	rThreeFiveHex, err := hex.DecodeString("0000000021eb468cdda89409fc98462200000000000000000000000000000040")
	if err != nil || len(rThreeFiveHex) != 32 {
		t.Fatalf("bad three_five r_init hex: %v", err)
	}
	copy(rThreeFive[:], rThreeFiveHex)

	fullCapsModels := make([]string, 16)
	for i := range fullCapsModels {
		fullCapsModels[i] = fmt.Sprintf("m%02d", i)
	}
	fullCapsTools := make([]string, 32)
	for i := range fullCapsTools {
		fullCapsTools[i] = fmt.Sprintf("t%02d", i)
	}

	cases := []struct {
		name           string
		models, tools  []string
		cMax           uint64
		rInit          [32]byte
		wantFieldsRoot string
	}{
		{
			name: "empty", models: nil, tools: nil, cMax: 0, rInit: rZero,
			// UNCHANGED by the amendment — empty tools ⇒ all-Z tools_root leaves,
			// invariant to the leaf-preimage formula.
			wantFieldsRoot: "25e80065232bae5c6accde72a53d4493cbe472d6e63cf851021fa4d25084270e",
		},
		{
			name: "one_each", models: []string{"gpt-4o"}, tools: []string{"search"}, cMax: 1000, rInit: r7,
			wantFieldsRoot: "a0e9701b7930e8f54c38d336a5697f397d7cb8b0f382c1402012022e58b7d80f",
		},
		{
			name:           "three_five",
			models:         []string{"claude-opus-4-8", "gpt-4o", "llama-3"},
			tools:          []string{"search", "read", "write", "exec", "fetch"},
			cMax:           50000,
			rInit:          rThreeFive,
			wantFieldsRoot: "a3950917487ae070394f5fc45fec389124c762d7379e59421017110c5769d83d",
		},
		{
			name: "full_caps", models: fullCapsModels, tools: fullCapsTools, cMax: 9223372036854775808, rInit: r7,
			wantFieldsRoot: "ad5a6c40872b640c567a5e1282cb50cce8cff6593757cc3648354ae28a70f30c",
		},
	}

	for _, c := range cases {
		got, err := FieldsRoot(c.models, c.tools, c.cMax, c.rInit)
		if err != nil {
			t.Fatalf("%s: FieldsRoot error: %v", c.name, err)
		}
		if hex.EncodeToString(got[:]) != c.wantFieldsRoot {
			t.Errorf("%s: FieldsRoot\n got  %x\n want %s (paygate-zk Rust oracle drift)", c.name, got, c.wantFieldsRoot)
		}
	}
}

func TestFieldsRoot_RejectsCapsAndDuplicates(t *testing.T) {
	var r [32]byte
	tooManyModels := make([]string, 17)
	for i := range tooManyModels {
		tooManyModels[i] = string(rune('a' + i))
	}
	if _, err := FieldsRoot(tooManyModels, nil, 0, r); err == nil {
		t.Error("expected error for 17 models (cap 16)")
	}
	tooManyTools := make([]string, 33)
	for i := range tooManyTools {
		tooManyTools[i] = string(rune('a' + i))
	}
	if _, err := FieldsRoot(nil, tooManyTools, 0, r); err == nil {
		t.Error("expected error for 33 tools (cap 32)")
	}
	if _, err := FieldsRoot([]string{"dup", "dup"}, nil, 0, r); err == nil {
		t.Error("expected error for duplicate model")
	}
	if _, err := FieldsRoot(nil, []string{"dup", "dup"}, 0, r); err == nil {
		t.Error("expected error for duplicate tool")
	}
}
