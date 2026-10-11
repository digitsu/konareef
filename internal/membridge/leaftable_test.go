// Copyright 2026 Jerry David Chan, Konareef.ai
// SPDX-License-Identifier: Apache-2.0

// leaftable_test.go — the salt-free leaf table (leaftable.go) and
// CommittedCells (sources.go), over the MEM-00 source vectors.
package membridge

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"testing"
)

// multiSourceCells resolves the MEM-00 file-inline-file-multi vector and
// derives it under its salt. Output: the cells, the derivation and root.
func multiSourceCells(t *testing.T) ([]Cell, []DerivedCell, [32]byte, map[string][32]byte, []MemorySource) {
	t.Helper()
	notes := []byte("The pod remembers this line.\n")
	style := []byte("Use short sentences.\n")
	digests := map[string][32]byte{"memory/notes.md": sha256.Sum256(notes), "memory/style.md": sha256.Sum256(style)}
	sources := []MemorySource{
		{Kind: SourceKindFile, Path: "./memory/notes.md", Loaded: notes},
		{Kind: SourceKindInline, Content: "Prefer primary sources."},
		{Kind: SourceKindFile, Path: "./memory/style.md", Loaded: style},
	}
	cells, err := ResolveSources(sources, digests)
	if err != nil {
		t.Fatal(err)
	}
	salt, _ := hex.DecodeString("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
	root, derived, err := RInitV1(salt, cells)
	if err != nil {
		t.Fatal(err)
	}
	if hex.EncodeToString(root[:]) != "8f50797705dfd0300c5eafee6a72be93e69c5ea2e4d81ec5c19e6874bfec3430" {
		t.Fatalf("MEM-00 r_init drifted: %x", root)
	}
	return cells, derived, root, digests, sources
}

// TestLeafTableRoundTrip: the built table serializes, parses back to the
// same bytes, authenticates to its r_init without the salt, and lists the
// resolved cells. Its size is header + 76 bytes per leaf.
func TestLeafTableRoundTrip(t *testing.T) {
	cells, derived, root, _, _ := multiSourceCells(t)
	podHash := sha256.Sum256([]byte("pod"))
	tb, err := NewLeafTable(podHash, root, cells, derived)
	if err != nil {
		t.Fatal(err)
	}
	raw := tb.Bytes()
	if len(raw) != leafTableHeaderLen+leafEntryLen*3 || !bytes.HasPrefix(raw, []byte("konareef-mem-leaves/v1")) {
		t.Fatalf("canonical bytes: %d bytes", len(raw))
	}
	parsed, err := ParseLeafTable(raw)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(parsed.Bytes(), raw) || parsed.PodHash != podHash || parsed.RInit != root {
		t.Fatal("round trip changed the table")
	}
	if err := parsed.CheckRoot(); err != nil {
		t.Fatalf("CheckRoot: %v", err)
	}
	if !SameCells(parsed.Cells(), cells) {
		t.Fatal("table cells differ from the resolved cells")
	}
	for i := 1; i < len(parsed.Leaves); i++ {
		if parsed.Leaves[i-1].CellID >= parsed.Leaves[i].CellID {
			t.Fatal("rows must be in ascending cell_id")
		}
	}
}

// TestParseLeafTableRefusals: each broken rule of the canonical form is
// refused with ErrLeafTableInvalid.
func TestParseLeafTableRefusals(t *testing.T) {
	cells, derived, root, _, _ := multiSourceCells(t)
	tb, err := NewLeafTable([32]byte{1}, root, cells, derived)
	if err != nil {
		t.Fatal(err)
	}
	good := tb.Bytes()
	entry := func(i int) int { return leafTableHeaderLen + i*leafEntryLen }
	mutate := func(f func(b []byte) []byte) []byte { return f(append([]byte(nil), good...)) }
	for name, raw := range map[string][]byte{
		"empty":        nil,
		"wrong domain": mutate(func(b []byte) []byte { b[0] = 'K'; return b }),
		"truncated":    good[:len(good)-1],
		"trailing":     append(append([]byte(nil), good...), 0),
		"zero count": mutate(func(b []byte) []byte {
			binary.BigEndian.PutUint32(b[leafTableHeaderLen-4:], 0)
			return b[:leafTableHeaderLen]
		}),
		"count over cap": mutate(func(b []byte) []byte {
			binary.BigEndian.PutUint32(b[leafTableHeaderLen-4:], HardCapK+1)
			return b
		}),
		"count disagrees":   mutate(func(b []byte) []byte { binary.BigEndian.PutUint32(b[leafTableHeaderLen-4:], 2); return b }),
		"id without bit 63": mutate(func(b []byte) []byte { b[entry(0)] &^= 0x80; return b }),
		"ids out of order": mutate(func(b []byte) []byte {
			first := append([]byte(nil), b[entry(0):entry(1)]...)
			copy(b[entry(0):entry(1)], b[entry(1):entry(2)])
			copy(b[entry(1):entry(2)], first)
			return b
		}),
		"index out of range": mutate(func(b []byte) []byte {
			binary.BigEndian.PutUint32(b[entry(0)+40:], 1<<D)
			return b
		}),
		"index reused": mutate(func(b []byte) []byte {
			copy(b[entry(1)+40:entry(1)+44], b[entry(0)+40:entry(0)+44])
			return b
		}),
		"non-canonical value hash": mutate(func(b []byte) []byte {
			copy(b[entry(0)+44:entry(1)], bytes.Repeat([]byte{0xff}, 32))
			return b
		}),
		"non-canonical r_init": mutate(func(b []byte) []byte {
			copy(b[22+32:22+64], bytes.Repeat([]byte{0xff}, 32))
			return b
		}),
		"zero value hash": mutate(func(b []byte) []byte {
			copy(b[entry(0)+44:entry(1)], make([]byte, 32))
			return b
		}),
	} {
		if _, err := ParseLeafTable(raw); !errors.Is(err, ErrLeafTableInvalid) {
			t.Errorf("%s: err = %v, want ErrLeafTableInvalid", name, err)
		}
	}
	if _, err := NewLeafTable([32]byte{}, root, cells[:1], derived); !errors.Is(err, ErrLeafTableInvalid) {
		t.Fatalf("cells and derivation disagree: %v", err)
	}
}

// TestLeafTableCheckRootRefusals: a table whose leaves do not hash to its
// r_init is refused with ErrRInitMismatch.
func TestLeafTableCheckRootRefusals(t *testing.T) {
	cells, derived, root, _, _ := multiSourceCells(t)
	for name, f := range map[string]func(tb *LeafTable){
		"other r_init":        func(tb *LeafTable) { tb.RInit[0] ^= 1 },
		"indices swapped":     func(tb *LeafTable) { tb.Leaves[0].Index, tb.Leaves[1].Index = tb.Leaves[1].Index, tb.Leaves[0].Index },
		"value hash replaced": func(tb *LeafTable) { tb.Leaves[0].ValueHash = tb.Leaves[1].ValueHash },
		"leaf dropped":        func(tb *LeafTable) { tb.Leaves = tb.Leaves[1:] },
	} {
		tb, err := NewLeafTable([32]byte{}, root, cells, derived)
		if err != nil {
			t.Fatal(err)
		}
		f(tb)
		if err := tb.CheckRoot(); !errors.Is(err, ErrRInitMismatch) {
			t.Errorf("%s: err = %v, want ErrRInitMismatch", name, err)
		}
	}
}

// TestCommittedCells: without loaded bytes, the manifest's own digests
// give the same cells ResolveSources gives over the real bytes; the
// refusals match.
func TestCommittedCells(t *testing.T) {
	cells, _, _, digests, sources := multiSourceCells(t)
	noBytes := make([]MemorySource, len(sources))
	for i, s := range sources {
		noBytes[i] = MemorySource{Kind: s.Kind, Path: s.Path, Content: s.Content}
	}
	committed, err := CommittedCells(noBytes, digests)
	if err != nil {
		t.Fatal(err)
	}
	if !SameCells(committed, cells) {
		t.Fatal("CommittedCells must equal ResolveSources over the committed bytes")
	}
	for name, c := range map[string]struct {
		sources []MemorySource
		want    error
	}{
		"not committed": {[]MemorySource{{Kind: "file", Path: "./other.md"}}, ErrMemoryFileNotCommitted},
		"unsupported":   {[]MemorySource{{Kind: "openbrain"}}, ErrMemorySourceUnsupported},
		"duplicate":     {[]MemorySource{noBytes[0], noBytes[0]}, ErrMemoryDuplicateSource},
	} {
		if _, err := CommittedCells(c.sources, digests); !errors.Is(err, c.want) {
			t.Errorf("%s: err = %v, want %v", name, err, c.want)
		}
	}
}

// TestSameCells: order does not matter; a changed hash, a missing cell and
// a repeated id make the lists differ.
func TestSameCells(t *testing.T) {
	a := []Cell{{CellID: 1, ContentHash: []byte{1}}, {CellID: 2, ContentHash: []byte{2}}}
	if !SameCells(a, []Cell{a[1], a[0]}) {
		t.Fatal("order must not matter")
	}
	if SameCells(a, []Cell{a[0], {CellID: 2, ContentHash: []byte{3}}}) || SameCells(a, a[:1]) {
		t.Fatal("changed or missing cells must differ")
	}
	if SameCells([]Cell{a[0], a[0]}, []Cell{a[0], a[0]}) {
		t.Fatal("a repeated cell_id must not compare equal")
	}
}
