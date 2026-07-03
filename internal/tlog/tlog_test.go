// internal/tlog/tlog_test.go — unit tests for the PRD 1 § 5.4 (Poseidon)
// T_log reconstruction: record_bytes encoding, the empty-T_log edge case,
// and the minimal-ULEB128 length prefix. Leaf/internal/tree hash behaviour
// is exhaustively covered in internal/poseidon; these tests anchor the tlog
// glue (record_bytes + ordering + delegation) against the regenerated
// Poseidon conformance values.
package tlog

import (
	"encoding/hex"
	"testing"
	"time"
)

// TestEncodeULEB128 anchors the minimal unsigned LEB128 encoder against
// hand-derived byte sequences. PRD 1 § 5.4 requires minimal encoding;
// non-minimal forms (e.g. 0x80 0x00 for 0) are forbidden — this helper
// is the only producer in the tlog package, so its outputs ARE the
// wire form of the record_bytes length prefix.
func TestEncodeULEB128(t *testing.T) {
	cases := []struct {
		in   uint64
		want string // hex
	}{
		{0, "00"},
		{1, "01"},
		{3, "03"},     // the |T_log| for the conformance vector
		{6, "06"},     // canonical len(tool_a/b/c) in the vector
		{127, "7f"},   // last single-byte value
		{128, "8001"}, // first two-byte value
		{255, "ff01"},
		{256, "8002"},
		{16383, "ff7f"}, // last two-byte value
		{16384, "808001"},
		{1 << 32, "8080808010"},
	}
	for _, c := range cases {
		got := encodeULEB128(c.in)
		if hex.EncodeToString(got) != c.want {
			t.Errorf("encodeULEB128(%d) = %x, want %s", c.in, got, c.want)
		}
	}
}

// TestLeafHashConformanceRow0 anchors LeafHash against the first row of
// the regenerated (Poseidon) `tlog-from-db-rows` vector
// (testdata/tlog_from_db_rows.json expected.leaf_hashes[0]):
//
//	record_bytes_0 = ULEB128(6) || "tool_a" || args_hash(32) || result_hash(32) || u64_be(ts)
//	leaf_hash_0    = poseidon.LeafHash(poseidon.RecordToField(record_bytes_0))
func TestLeafHashConformanceRow0(t *testing.T) {
	row := Row{
		ToolID:     "tool_a",
		ArgsHash:   mustHash32(t, "aae0a971434ea3f6973aa77b266bd53ddae16abad964cd06ff44ecc799c5679e"),
		ResultHash: mustHash32(t, "c29aa59cafc9e2437b2c9f0c8772593e63c5fe7b63dee5f9f1b1a8cc3369f919"),
		TS:         time.UnixMicro(1748736000000000).UTC(),
		CallIndex:  0,
	}
	got, err := LeafHash(row)
	if err != nil {
		t.Fatalf("LeafHash(row_0): %v", err)
	}
	const wantHex = "9863395b2f97e01c07db993ca2ae06be80104926a7c099ec061cd603227de913"
	if hex.EncodeToString(got[:]) != wantHex {
		t.Errorf("LeafHash(row_0) = %x, want %s", got, wantHex)
	}
}

// TestTRootEmpty pins the |T_log| == 0 edge case from PRD 1 § 5.4: the
// tree_root_top is the Poseidon empty-leaf Z and t_root binds count 0.
// The expected value is the authoritative Rust golden empty t_root
// (troot_poseidon.rs python_vector_t_roots_match, T0).
func TestTRootEmpty(t *testing.T) {
	got, err := TRootFromRows(nil)
	if err != nil {
		t.Fatalf("TRootFromRows(nil): %v", err)
	}
	const wantHex = "a44396443b0cf0c8def89b9193434c6d1f91f0d4c2ffe17f948618316765aa1a"
	if hex.EncodeToString(got[:]) != wantHex {
		t.Errorf("TRootFromRows(nil) = %x, want %s", got, wantHex)
	}

	// The explicit-empty-slice path must agree with nil.
	got2, err := TRootFromRows([]Row{})
	if err != nil {
		t.Fatalf("TRootFromRows([]Row{}): %v", err)
	}
	if got2 != got {
		t.Errorf("TRootFromRows([]Row{}) != TRootFromRows(nil)")
	}
}

// mustHash32 decodes a 64-character hex string into a [32]byte or
// fails the test. Used by leaf/row construction tests.
func mustHash32(t *testing.T, h string) [32]byte {
	t.Helper()
	b, err := hex.DecodeString(h)
	if err != nil {
		t.Fatalf("decode %q: %v", h, err)
	}
	if len(b) != 32 {
		t.Fatalf("decode %q: len = %d, want 32", h, len(b))
	}
	var out [32]byte
	copy(out[:], b)
	return out
}
