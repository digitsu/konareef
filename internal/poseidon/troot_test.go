// Copyright 2026 Jerry David Chan, Konareef.ai
// SPDX-License-Identifier: Apache-2.0

package poseidon

import (
	"encoding/hex"
	"testing"
)

func unhex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("bad hex %q: %v", s, err)
	}
	return b
}

// TestTRoot_RustGoldenVectors anchors the Go t_root reconstruction to the
// authoritative Rust oracle (troot_poseidon.rs:605-639, python_vector_t_roots_match).
// The fixture records and expected 32-byte LE roots are copied verbatim. This is
// the independent cross-impl anchor; the oracle-differential tests below add
// breadth, but these three are the contract.
func TestTRoot_RustGoldenVectors(t *testing.T) {
	p := Default()
	search0 := unhex(t, "06736561726368e2fd0b997f9f4775fe8221bd787e6f36d2b28b0ce1a136c44039123e8173f55eadcc1fb35dd7266b495bd30b338c5c96aed0e79e57279f0cd3571737ea9ab24c0006366d452a5000")
	read1 := unhex(t, "047265616415220d9b6753a1797969dc94d22f5b66c391174c483b9152f0f478a9679ee49099d7b066c604c9b0868eaba42f7fc4d485f54c4f8d57c9d660807af57bf8bfac0006366d45399240")
	write2 := unhex(t, "057772697465bc40d0ebdb306b8fc01d828ec6e6021da1f1154c5bb2fea5eae477f67ededf8fc0df6a74832f23c04bbe7aadb240e9acbc289829fa9254d0e7390b92466edb2c0006366d4548d480")

	cases := []struct {
		name string
		recs [][]byte
		want string
	}{
		{"empty", nil, "a44396443b0cf0c8def89b9193434c6d1f91f0d4c2ffe17f948618316765aa1a"},
		{"single", [][]byte{search0}, "4cbfa0e3f44c971a6b42e1782b99785914f2cf9779b11c6e7b39c593e05dd50a"},
		{"three", [][]byte{search0, read1, write2}, "f7a3e1f8d14d5a2225fb36d2f21c3aa06a5ded8cd7effe3a8eeacc953d33ea2f"},
	}
	for _, c := range cases {
		got, err := p.TRoot(c.recs)
		if err != nil {
			t.Fatalf("%s: TRoot error: %v", c.name, err)
		}
		if hex.EncodeToString(got[:]) != c.want {
			t.Errorf("%s: TRoot\n got  %x\n want %s", c.name, got, c.want)
		}
	}
}

func TestRecordToField_OracleDifferential(t *testing.T) {
	ov := loadOracle(t)
	p := Default()
	if len(ov.Record) == 0 {
		t.Fatal("no record vectors in oracle corpus")
	}
	for i, v := range ov.Record {
		got, err := p.RecordToField(unhex(t, v.RB))
		if err != nil {
			t.Fatalf("record %d: %v", i, err)
		}
		if hex.EncodeToString(got[:]) != v.RF {
			t.Errorf("record %d (len=%d): RecordToField\n got  %x\n want %s", i, len(v.RB)/2, got, v.RF)
		}
	}
}

func TestTRoot_OracleDifferential(t *testing.T) {
	ov := loadOracle(t)
	p := Default()
	if len(ov.TRoot) == 0 {
		t.Fatal("no troot vectors in oracle corpus")
	}
	for i, v := range ov.TRoot {
		recs := make([][]byte, len(v.Recs))
		for j, s := range v.Recs {
			recs[j] = unhex(t, s)
		}
		got, err := p.TRoot(recs)
		if err != nil {
			t.Fatalf("troot %d: %v", i, err)
		}
		if hex.EncodeToString(got[:]) != v.Root {
			t.Errorf("troot %d (|T|=%d): TRoot\n got  %x\n want %s", i, len(recs), got, v.Root)
		}
	}
}

// Records or counts beyond the pinned circuit caps could not have been proven,
// so the verifier must reject them fail-closed rather than compute a root the
// circuit never constrains.
func TestTRoot_RejectsCaps(t *testing.T) {
	p := Default()
	tooMany := make([][]byte, MaxTLogRecords+1)
	if _, err := p.TRoot(tooMany); err == nil {
		t.Errorf("expected error for %d records (cap %d), got nil", MaxTLogRecords+1, MaxTLogRecords)
	}
	if _, err := p.RecordToField(make([]byte, MaxRecordBytes+1)); err == nil {
		t.Errorf("expected error for %d-byte record (cap %d), got nil", MaxRecordBytes+1, MaxRecordBytes)
	}
}
