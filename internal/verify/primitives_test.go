package verify

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"sort"
	"testing"
)

// ── ComputeChainHash ────────────────────────────────────────────────

func TestComputeChainHashGenesis(t *testing.T) {
	data := "STRUCTURED_BUNDLE: v1\nBUNDLE_HASH: sha256:0000\n"
	ts := "2026-05-23T15:32:14.123456Z"
	want := sha256.Sum256([]byte(data + ts))
	got := ComputeChainHash("", data, ts)
	if got != want {
		t.Errorf("genesis hash mismatch:\n got=%x\nwant=%x", got, want)
	}
}

func TestComputeChainHashLinked(t *testing.T) {
	prevHex := "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"
	prevBytes, _ := hex.DecodeString(prevHex)
	data := "OPENBRAIN_SNAPSHOT: v1\nROOT: sha256:1234\n"
	ts := "2026-05-23T15:33:01.000000Z"

	var buf bytes.Buffer
	buf.Write(prevBytes)
	buf.WriteString(data)
	buf.WriteString(ts)
	want := sha256.Sum256(buf.Bytes())

	got := ComputeChainHash(prevHex, data, ts)
	if got != want {
		t.Errorf("linked hash mismatch:\n got=%x\nwant=%x", got, want)
	}
}

func TestComputeChainHashAcceptsMixedCaseHex(t *testing.T) {
	upper := "ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789"
	lower := "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"
	data := "x"
	ts := "t"
	if ComputeChainHash(upper, data, ts) != ComputeChainHash(lower, data, ts) {
		t.Errorf("hash differs by hex case")
	}
}

// ── BuildMerkleRoot ─────────────────────────────────────────────────

func TestBuildMerkleRootEmpty(t *testing.T) {
	got := BuildMerkleRoot(nil)
	if got != ([32]byte{}) {
		t.Errorf("empty root = %x, want all-zero", got)
	}
}

func TestBuildMerkleRootSingle(t *testing.T) {
	leaf := bytesOfLen(32, 0xaa)
	var want [32]byte
	copy(want[:], leaf)
	got := BuildMerkleRoot([][]byte{leaf})
	if got != want {
		t.Errorf("single-leaf root = %x, want %x", got, want)
	}
}

func TestBuildMerkleRootTwoSortsBeforeHashing(t *testing.T) {
	a := bytesOfLen(32, 0x01)
	b := bytesOfLen(32, 0x02)
	// Same input in either order → same root (sort is canonical).
	r1 := BuildMerkleRoot([][]byte{a, b})
	r2 := BuildMerkleRoot([][]byte{b, a})
	if r1 != r2 {
		t.Errorf("two-leaf root depends on input order")
	}
	// Expected: SHA-256(sorted_a || sorted_b)
	want := sha256.Sum256(append(append([]byte{}, a...), b...))
	if r1 != want {
		t.Errorf("two-leaf root mismatch")
	}
}

func TestBuildMerkleRootThreeOddLastDuplicated(t *testing.T) {
	a := bytesOfLen(32, 0x01)
	b := bytesOfLen(32, 0x02)
	c := bytesOfLen(32, 0x03)
	// Level 0 sorted: a, b, c. Pair-up: (a,b), (c,c) [last duplicated].
	// Level 1: H(a||b), H(c||c).
	// Level 2 (root): H(H(a||b) || H(c||c)).
	hab := sha256.Sum256(append(append([]byte{}, a...), b...))
	hcc := sha256.Sum256(append(append([]byte{}, c...), c...))
	want := sha256.Sum256(append(append([]byte{}, hab[:]...), hcc[:]...))
	got := BuildMerkleRoot([][]byte{a, b, c})
	if got != want {
		t.Errorf("3-leaf odd-duplicate mismatch")
	}
}

func TestBuildMerkleRootDedupes(t *testing.T) {
	a := bytesOfLen(32, 0x01)
	b := bytesOfLen(32, 0x02)
	got1 := BuildMerkleRoot([][]byte{a, b, a})
	got2 := BuildMerkleRoot([][]byte{a, b})
	if got1 != got2 {
		t.Errorf("dedupe not applied")
	}
}

// ── ComputeAccessLogHash ────────────────────────────────────────────

func TestAccessLogHashEmpty(t *testing.T) {
	want := sha256.Sum256(nil)
	got := ComputeAccessLogHash(nil)
	if got != want {
		t.Errorf("empty access-log hash = %x, want %x", got, want)
	}
}

func TestAccessLogHashConcatenatesSortedDeduped(t *testing.T) {
	a := bytesOfLen(32, 0x01)
	b := bytesOfLen(32, 0x02)
	c := bytesOfLen(32, 0x03)

	// Input duplicates + scrambled order:
	in := [][]byte{c, a, b, a}
	got := ComputeAccessLogHash(in)

	uniq := dedup([][]byte{a, b, c})
	sort.Slice(uniq, func(i, j int) bool { return bytes.Compare(uniq[i], uniq[j]) < 0 })
	want := sha256.Sum256(bytes.Join(uniq, nil))

	if got != want {
		t.Errorf("access-log hash:\n got=%x\nwant=%x", got, want)
	}
}

// ── helpers ─────────────────────────────────────────────────────────

func bytesOfLen(n int, fill byte) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = fill
	}
	return b
}

func dedup(in [][]byte) [][]byte {
	seen := map[string]bool{}
	out := [][]byte{}
	for _, b := range in {
		k := string(b)
		if !seen[k] {
			seen[k] = true
			out = append(out, b)
		}
	}
	return out
}
