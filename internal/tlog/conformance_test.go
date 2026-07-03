// internal/tlog/conformance_test.go — byte-exact gate against the
// upstream `tlog-from-db-rows` (Part C) conformance vector. This is
// P1.7b's Definition of Done: if this test fails, the package is not
// interoperable with reef-core's writer, the paygate-zk Spartan
// witness, or the TypeScript SDK verifier, and the release is blocked.
package tlog

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// vector mirrors the JSON shape of the upstream tlog-from-db-rows
// entry. Only the fields this test consumes are decoded.
type vector struct {
	ID       string `json:"id"`
	Expected struct {
		LeafHashes []string `json:"leaf_hashes"`
		TRoot      string   `json:"t_root"`
		Verdict    string   `json:"verdict"`
	} `json:"expected"`
	Inputs struct {
		Rows []vectorRow `json:"rows"`
	} `json:"inputs"`
}

type vectorRow struct {
	ToolID     string `json:"tool_id"`
	CallIndex  uint32 `json:"call_index"`
	ArgsHash   string `json:"args_hash"`
	ResultHash string `json:"result_hash"`
	TsUs       int64  `json:"ts_us"`
}

func loadVector(t *testing.T) vector {
	t.Helper()
	p := filepath.Join("testdata", "tlog_from_db_rows.json")
	raw, err := os.ReadFile(p)
	if err != nil {
		t.Fatalf("read %s: %v", p, err)
	}
	var v vector
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatalf("decode %s: %v", p, err)
	}
	if v.ID != "tlog-from-db-rows" {
		t.Fatalf("vector id = %q, want %q (testdata drifted?)", v.ID, "tlog-from-db-rows")
	}
	if v.Expected.Verdict != "accept" {
		t.Fatalf("vector verdict = %q, want %q", v.Expected.Verdict, "accept")
	}
	return v
}

func rowsFromVector(t *testing.T, v vector) []Row {
	t.Helper()
	out := make([]Row, len(v.Inputs.Rows))
	for i, vr := range v.Inputs.Rows {
		out[i] = Row{
			ToolID:     vr.ToolID,
			ArgsHash:   mustHash32(t, vr.ArgsHash),
			ResultHash: mustHash32(t, vr.ResultHash),
			TS:         time.UnixMicro(vr.TsUs).UTC(),
			CallIndex:  vr.CallIndex,
		}
	}
	return out
}

// TestConformanceLeafHashes verifies that LeafHash applied to each row
// reproduces the expected.leaf_hashes entries byte-for-byte. This is
// the cheapest failure to debug: a mismatch here means the leaf
// encoding (record_bytes) is wrong, not the tree shape.
func TestConformanceLeafHashes(t *testing.T) {
	v := loadVector(t)
	rows := rowsFromVector(t, v)
	if len(rows) != len(v.Expected.LeafHashes) {
		t.Fatalf("rows=%d, leaf_hashes=%d", len(rows), len(v.Expected.LeafHashes))
	}
	for i, r := range rows {
		got, err := LeafHash(r)
		if err != nil {
			t.Fatalf("LeafHash(row %d): %v", i, err)
		}
		gotHex := hex.EncodeToString(got[:])
		if gotHex != v.Expected.LeafHashes[i] {
			t.Errorf("leaf_hash[%d] = %s, want %s",
				i, gotHex, v.Expected.LeafHashes[i])
		}
	}
}

// TestConformanceTRoot is the DoD gate. TRootFromRows applied to the
// vector's rows MUST produce the exact 32-byte t_root quoted in
// expected.t_root. If this test fails, do NOT modify the constant —
// the constant is normative; the bug is in this Go package.
func TestConformanceTRoot(t *testing.T) {
	v := loadVector(t)
	rows := rowsFromVector(t, v)
	got, err := TRootFromRows(rows)
	if err != nil {
		t.Fatalf("TRootFromRows: %v", err)
	}
	gotHex := hex.EncodeToString(got[:])
	if gotHex != v.Expected.TRoot {
		t.Errorf("t_root = %s, want %s", gotHex, v.Expected.TRoot)
	}
}

// TestConformanceShuffleStability verifies that the helper sorts rows
// by CallIndex ASC before hashing. Feeding the rows in reverse order
// MUST produce the same t_root.
func TestConformanceShuffleStability(t *testing.T) {
	v := loadVector(t)
	rows := rowsFromVector(t, v)

	// Reverse in place to feed in descending CallIndex order.
	rev := make([]Row, len(rows))
	for i, r := range rows {
		rev[len(rows)-1-i] = r
	}

	gotForward, err := TRootFromRows(rows)
	if err != nil {
		t.Fatalf("TRootFromRows(forward): %v", err)
	}
	gotReversed, err := TRootFromRows(rev)
	if err != nil {
		t.Fatalf("TRootFromRows(reversed): %v", err)
	}
	if gotForward != gotReversed {
		t.Errorf(
			"shuffle stability broken: forward = %x, reversed = %x",
			gotForward, gotReversed,
		)
	}
}
