// Copyright 2026 Jerry David Chan, Konareef.ai
// SPDX-License-Identifier: Apache-2.0

// internal/membridge/rinit_v2_test.go — the production konareef-rinit/v2
// code (rinit_v2.go, leaftable_v2.go) against every shared vector in
// testdata/rinit_v2/vectors.json (CL-4-live step 2, reef-core#84).
//
// rinit_v2_vectors_test.go checks the vectors with a test-local reference
// implementation. This file runs the same vectors through the exported
// production functions: RInitV2, KeyTag, CellIndexV2,
// CanonicalCellPayloadV2, ValueHashV2, TouchedCellID, NewLeafTableV2,
// ParseLeafTableV2, CheckRows, CheckRoot and CheckReadLane. The seam
// vectors (touched_cell_id parsing) are run by the feeder package, which
// owns the seam parser.
package membridge

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"testing"

	"github.com/digitsu/konareef/internal/identity"
)

// TestRInitV2Prod_Constants pins the exported v2 constants to the vector
// file's constants block.
func TestRInitV2Prod_Constants(t *testing.T) {
	c := loadV2(t).Constants
	checks := map[string]any{
		"key_tag_domain":        string(KeyTagDomain),
		"index_domain_v2":       string(IndexDomainSepV2),
		"leaf_table_domain_v2":  string(LeafTableDomainV2),
		"dtag_cell_v2":          hex.EncodeToString([]byte{DTAG_CELL_V2}),
		"payload_len":           float64(PayloadV2Len),
		"leaf_table_header_len": float64(leafTableV2HeaderLen),
		"leaf_table_entry_len":  float64(leafEntryV2Len),
	}
	for k, want := range checks {
		if c[k] != want {
			t.Errorf("constant %s = %v, production has %v", k, c[k], want)
		}
	}
}

// TestRInitV2Prod_CellVectors runs RInitV2 over the PRD 4 cell sets and
// compares the root and every derived field.
func TestRInitV2Prod_CellVectors(t *testing.T) {
	f := loadV2(t)
	for _, v := range f.Cells {
		salt := hx(t, v.PodSalt)
		cells := make([]Cell, len(v.Cells))
		for i, c := range v.Cells {
			cells[i] = Cell{CellID: c.CellID, ContentHash: hx(t, c.ContentHash)}
		}
		root, derived, err := RInitV2(salt, cells)
		if err != nil {
			t.Fatalf("%s: %v", v.ID, err)
		}
		if hex.EncodeToString(root[:]) != v.RInit {
			t.Errorf("%s: r_init mismatch", v.ID)
		}
		checkProdDerived(t, v.ID, salt, derived, v.Derived)
	}
}

// checkProdDerived compares RInitV2's derivation with a vector's derived
// list, field by field, using the production per-cell functions.
func checkProdDerived(t *testing.T, id string, salt []byte, got []DerivedCellV2, want []v2Derived) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("%s: %d derived cells, want %d", id, len(got), len(want))
	}
	for i, d := range got {
		w := want[i]
		var idb [8]byte
		binary.BigEndian.PutUint64(idb[:], d.CellID)
		kt, err := KeyTag(salt, d.CellID)
		if err != nil {
			t.Fatal(err)
		}
		vh, err := ValueHashV2(d.KeyTag, d.ContentHash)
		if err != nil {
			t.Fatal(err)
		}
		leaf, err := LeafHash(d.ValueHash)
		if err != nil {
			t.Fatal(err)
		}
		switch {
		case hex.EncodeToString(idb[:]) != w.CellIDHex,
			hex.EncodeToString(d.ContentHash[:]) != w.ContentHash,
			hex.EncodeToString(d.KeyTag[:]) != w.KeyTag || kt != d.KeyTag,
			hex.EncodeToString(CanonicalCellPayloadV2(d.KeyTag, d.ContentHash)) != w.Payload,
			hex.EncodeToString(d.ValueHash[:]) != w.ValueHash || vh != d.ValueHash,
			hex.EncodeToString(leaf[:]) != w.LeafHash,
			d.Index != w.Index || CellIndexV2(d.KeyTag) != w.Index:
			t.Errorf("%s cell %d: production derivation differs from the vector", id, i)
		}
	}
}

// TestRInitV2Prod_SourceVectorsAndTouchedCell resolves each source vector,
// derives its root, and applies the T-A rule.
func TestRInitV2Prod_SourceVectorsAndTouchedCell(t *testing.T) {
	f := loadV2(t)
	for _, v := range f.Sources {
		salt := hx(t, v.PodSalt)
		cells := v2SourceCells(t, v.Sources)
		root, derived, err := RInitV2(salt, cells)
		if err != nil {
			t.Fatalf("%s: %v", v.ID, err)
		}
		if hex.EncodeToString(root[:]) != v.RInit {
			t.Errorf("%s: r_init mismatch", v.ID)
		}
		checkProdDerived(t, v.ID, salt, derived, v.Derived)
		touched, err := TouchedCellID(cells)
		if err != nil {
			t.Fatal(err)
		}
		var idb [8]byte
		binary.BigEndian.PutUint64(idb[:], touched)
		if hex.EncodeToString(idb[:]) != v.TouchedCellID {
			t.Errorf("%s: touched cell %x, want %s", v.ID, idb, v.TouchedCellID)
		}
		for _, d := range derived {
			if d.CellID == touched && d.Index != v.TouchedIndex {
				t.Errorf("%s: touched index %d, want %d", v.ID, d.Index, v.TouchedIndex)
			}
		}
	}
	if _, err := TouchedCellID(nil); Code(err) != "MEMORY_TOUCHED_CELL_INVALID" {
		t.Errorf("empty cell list: got %v, want MEMORY_TOUCHED_CELL_INVALID", err)
	}
}

// prodLeafTableCheck runs the production feeder steps b, d and e on table
// bytes. Output: "" or the refusal code.
func prodLeafTableCheck(b []byte) string {
	table, err := ParseLeafTableV2(b)
	if err != nil {
		return Code(err)
	}
	if err := table.CheckRows(); err != nil {
		return Code(err)
	}
	if err := table.CheckRoot(); err != nil {
		return Code(err)
	}
	return ""
}

// TestRInitV2Prod_LeafTables rebuilds each accepted table with
// NewLeafTableV2 (byte for byte, and its signature verifies over the
// production bytes), and runs every table through the production checks:
// the full feeder result and the structural (reef-core) result.
func TestRInitV2Prod_LeafTables(t *testing.T) {
	f := loadV2(t)
	sources := map[string]int{}
	for i, s := range f.Sources {
		sources[s.ID] = i
	}
	for _, v := range f.LeafTables {
		b := hx(t, v.TableHex)
		got := prodLeafTableCheck(b)
		structural := "accept"
		if _, err := ParseLeafTableV2(b); err != nil {
			structural = "refuse"
		}
		if structural != v.Structural {
			t.Errorf("%s: structural %s, want %s", v.ID, structural, v.Structural)
		}
		switch v.Expected {
		case "accept":
			if got != "" {
				t.Errorf("%s: refused with %s, want accept", v.ID, got)
			}
			sv := f.Sources[sources[v.Source]]
			root, derived, err := RInitV2(hx(t, sv.PodSalt), v2SourceCells(t, sv.Sources))
			if err != nil {
				t.Fatal(err)
			}
			built, err := NewLeafTableV2(hx32(t, v.PodHash), root, derived)
			if err != nil {
				t.Fatalf("%s: NewLeafTableV2: %v", v.ID, err)
			}
			if !bytes.Equal(built.Bytes(), b) {
				t.Errorf("%s: NewLeafTableV2 bytes differ from the vector", v.ID)
			}
			sig, err := base64.StdEncoding.DecodeString(v.SignatureB64)
			if err != nil {
				t.Fatal(err)
			}
			if ok, err := identity.Verify(v.PubKey, built.Bytes(), sig); err != nil || !ok {
				t.Errorf("%s: the vector signature does not verify over the production bytes", v.ID)
			}
			parsed, err := ParseLeafTableV2(b)
			if err != nil || !SameCells(parsed.Cells(), v2SourceCells(t, sv.Sources)) {
				t.Errorf("%s: parsed cells differ from the source cells", v.ID)
			}
		case "refuse":
			if got != v.ExpectedRefusal {
				t.Errorf("%s: got %q, want %q", v.ID, got, v.ExpectedRefusal)
			}
		}
	}
}

// laneFromVector converts a vector lane to a ReadLane.
func laneFromVector(t *testing.T, l v2Lane) ReadLane {
	t.Helper()
	out := ReadLane{
		RInit: hx32(t, l.RInit), Index: l.Index, ValueHashIn: hx32(t, l.ValueHashIn),
		KeyTag: hx32(t, l.KeyTag), ContentHash: hx32(t, l.ContentHash),
	}
	if len(l.Siblings) != D {
		t.Fatalf("lane has %d siblings, want %d", len(l.Siblings), D)
	}
	for k, s := range l.Siblings {
		out.Siblings[k] = hx32(t, s)
	}
	return out
}

// TestRInitV2Prod_TouchedLanes builds each honest lane from the production
// leaf table (row of the T-A cell, path over the table's value hashes) and
// checks it equals the vector and passes CheckReadLane.
func TestRInitV2Prod_TouchedLanes(t *testing.T) {
	f := loadV2(t)
	for i, v := range f.Touched {
		sv := f.Sources[i]
		cells := v2SourceCells(t, sv.Sources)
		root, derived, err := RInitV2(hx(t, sv.PodSalt), cells)
		if err != nil {
			t.Fatal(err)
		}
		table, err := NewLeafTableV2([32]byte{}, root, derived)
		if err != nil {
			t.Fatal(err)
		}
		touched, _ := TouchedCellID(cells)
		row, ok := table.Leaf(touched)
		if !ok {
			t.Fatalf("%s: no row for the touched cell", v.ID)
		}
		path, err := BuildAuthPath(table.ValueHashes(), row.Index)
		if err != nil {
			t.Fatal(err)
		}
		lane := ReadLane{RInit: root, Index: row.Index, ValueHashIn: row.ValueHash, Siblings: path, KeyTag: row.KeyTag, ContentHash: row.ContentHash}
		if lane != laneFromVector(t, v.Lane) {
			t.Errorf("%s: production lane differs from the vector lane", v.ID)
		}
		payload := CanonicalCellPayloadV2(row.KeyTag, row.ContentHash)
		if hex.EncodeToString(payload) != v.PayloadIn {
			t.Errorf("%s: payload_in differs", v.ID)
		}
		if err := CheckReadLane(lane, payload, hx32(t, v.ValueHashOut)); err != nil {
			t.Errorf("%s: honest lane refused: %v", v.ID, err)
		}
	}
}

// TestRInitV2Prod_NegativeLanes runs every lane-carrying negative vector
// through CheckReadLane and compares the refusal code. The seam negative
// vectors are run in the feeder package.
func TestRInitV2Prod_NegativeLanes(t *testing.T) {
	f := loadV2(t)
	n := 0
	for _, v := range f.Negative {
		if v.Lane == nil {
			continue
		}
		n++
		lane := laneFromVector(t, *v.Lane)
		payload := CanonicalCellPayloadV2(lane.KeyTag, lane.ContentHash)
		if v.PayloadIn != "" {
			payload = hx(t, v.PayloadIn)
		}
		out := lane.ValueHashIn
		if s, ok := v.Facts["value_hash_out"]; ok {
			out = hx32(t, s)
		}
		if got := Code(CheckReadLane(lane, payload, out)); got != v.ExpectedRefusal {
			t.Errorf("%s: got %q, want %q", v.ID, got, v.ExpectedRefusal)
		}
	}
	if n == 0 {
		t.Fatal("no lane negative vectors")
	}
}

// TestRInitV2Prod_DerivationNegative checks RInitV2's refusal codes.
func TestRInitV2Prod_DerivationNegative(t *testing.T) {
	f := loadV2(t)
	for _, v := range f.DerivNeg {
		cells := make([]Cell, len(v.Cells))
		for i, c := range v.Cells {
			cells[i] = Cell{CellID: c.CellID, ContentHash: hx(t, c.ContentHash)}
		}
		if _, _, err := RInitV2(hx(t, v.PodSalt), cells); Code(err) != v.ExpectedRefusal {
			t.Errorf("%s: got %v, want %s", v.ID, err, v.ExpectedRefusal)
		}
	}
}

// TestRInitV2Prod_EmptyAndCap covers the memory-free root and the cap.
func TestRInitV2Prod_EmptyAndCap(t *testing.T) {
	salt := make([]byte, 32)
	root, derived, err := RInitV2(salt, nil)
	if err != nil || root != EmptyRoots[D] || len(derived) != 0 {
		t.Fatalf("empty set: root %x, %d cells, err %v; want E20", root, len(derived), err)
	}
	cells := make([]Cell, HardCapK+1)
	for i := range cells {
		cells[i] = Cell{CellID: uint64(i + 1), ContentHash: make([]byte, 32)}
	}
	if _, _, err := RInitV2(salt, cells); Code(err) != "ERR_CELL_CAP_EXCEEDED" {
		t.Errorf("over cap: got %v", err)
	}
	if _, _, err := RInitV2(salt, []Cell{{CellID: 1, ContentHash: make([]byte, 31)}}); Code(err) != "ERR_SNAPSHOT_IMPORT_FAILED" {
		t.Errorf("short content hash: got %v", err)
	}
}

// TestRInitV2Prod_LeafTableV1Refused checks that a v1 table (same domain
// length, v1 row size) is refused by the v2 parser.
func TestRInitV2Prod_LeafTableV1Refused(t *testing.T) {
	salt := bytes.Repeat([]byte{7}, 32)
	cells := []Cell{{CellID: SourceCellID(SourceKindInline, []byte("x")), ContentHash: bytes.Repeat([]byte{1}, 32)}}
	root, derived, err := RInitV1(salt, cells)
	if err != nil {
		t.Fatal(err)
	}
	v1, err := NewLeafTable([32]byte{}, root, cells, derived)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ParseLeafTableV2(v1.Bytes()); Code(err) != "MEMORY_LEAF_TABLE_INVALID" {
		t.Errorf("v1 table: got %v, want MEMORY_LEAF_TABLE_INVALID", err)
	}
}
