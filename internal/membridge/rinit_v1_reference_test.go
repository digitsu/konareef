// Copyright 2026 Jerry David Chan, Konareef.ai
// SPDX-License-Identifier: Apache-2.0

// internal/membridge/rinit_v1_reference_test.go — independent test-only
// reference for the konareef-rinit/v1 derivation (MEM-00, konareef#25;
// accepted with D1-D6).
//
// Spec: docs/reference/konareef-memory-root-v1-spec.md. Fixtures:
// testdata/rinit_v1/fixtures.json.
//
// Scope and status. MEM-03 (konareef#26) promoted the derivation into
// production code (rinit.go, sources.go) and migrated this package's tree
// from SHA-256 to Poseidon (D6). This file keeps the MEM-00 reference as a
// second, separately written oracle: TestRInitV1ProductionMatchesReference
// checks that the production functions agree with it on every fixture, and
// the other tests check the reference against the fixtures, as before.
//
// The reference composes two independently reviewed pieces:
//
//   - the PRD 4 §3.2 host-side address path, which stays SHA-256
//     (LogicalKey, CellIndex, CanonicalCellPayload in this package);
//   - the PRD 1 §5.5 Poseidon-over-Pallas value hash, leaf hash, node hash
//     and empty-subtree roots, called directly on internal/poseidon.
//
// It does NOT call ValueHash, LeafHash, SparseRoot or EmptyRoots from this
// package, so a regression there cannot hide behind the reference. The
// pre-swap SHA-256 tree the spec calls the "legacy SHA sparse root" no
// longer exists in production; legacySHASparseRoot below re-implements it
// for the distinction test only.
//
// The four objects the spec keeps apart are computed side by side in
// TestRInitV1DistinguishesTheFourObjects:
//
//	custody snapshot root — reef-core MemorySnapshot.root (unsalted, dense)
//	legacy SHA sparse root — the pre-D6 SHA-256 tree (stale hash)
//	r_init (konareef-rinit/v1) — PRD 1 §5.5 Poseidon root, a field element
//	label set — DATA-00; not derivable from any of the three roots
package membridge

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"math/big"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/digitsu/konareef/internal/canon"
	"github.com/digitsu/konareef/internal/poseidon"
)

// The spec §9 codes. The owner accepted them, so the reference now reports
// the production sentinels (errors.go), which lets the production-versus-
// reference test compare refusals as well as roots.
var (
	errRefDuplicateCellID    = ErrCellDuplicateID
	errRefValueHashZero      = ErrValueHashZero
	errRefSourceUnsupported  = ErrMemorySourceUnsupported
	errRefFileDigestMismatch = ErrMemoryFileDigestMismatch
	errRefFileNotCommitted   = ErrMemoryFileNotCommitted
	errRefDuplicateSource    = ErrMemoryDuplicateSource
)

// srcCellIDDomain is the proposed domain string for source cell identifiers
// (spec §4.3). It is distinct from IndexDomainSep ("konareef-mem-idx/v1").
var srcCellIDDomain = []byte("konareef-mem-src/v1")

// srcCellIDHighBit marks a cell identifier as source-derived. Open Brain
// thought ids are positive Postgres bigints, so they never set bit 63; the two
// identifier namespaces are therefore disjoint by construction (spec §4.3).
const srcCellIDHighBit = uint64(1) << 63

// refCell is one resolved memory cell: a stable identifier plus the 32-byte
// SHA-256 digest of the exact bytes loaded for it.
type refCell struct {
	CellID      uint64
	ContentHash []byte
}

// refDerived is the per-cell output of the reference derivation.
type refDerived struct {
	CellID    uint64
	Index     uint32
	ValueHash [32]byte
	LeafHash  [32]byte
}

// referenceRInitV1 computes the proposed konareef-rinit/v1 root over cells
// under podSalt (spec §5).
//
// Inputs: a 32-byte podSalt and the resolved cells in any order.
// Output: the 32-byte little-endian Poseidon root, the per-cell derivation in
// ascending CellID order, or the first refusal:
// ErrCellSaltLen, ErrCellCapExceeded, ErrSnapshotImportFailed (content hash
// length), errRefDuplicateCellID, ErrCellIndexCollision, errRefValueHashZero.
//
// Input order never changes the root: the tree is address-indexed, and the
// derivation sorts by CellID before it checks duplicates and collisions, so
// the refusal it reports does not depend on the order either.
func referenceRInitV1(podSalt []byte, cells []refCell) ([32]byte, []refDerived, error) {
	var zero [32]byte
	if len(podSalt) != 32 {
		return zero, nil, ErrCellSaltLen
	}
	if err := EnforceHardCap(len(cells)); err != nil {
		return zero, nil, err
	}
	sorted := append([]refCell(nil), cells...)
	sort.SliceStable(sorted, func(i, j int) bool { return sorted[i].CellID < sorted[j].CellID })

	p := poseidon.Default()
	byIndex := make(map[uint32][32]byte, len(sorted))
	owner := make(map[uint32]uint64, len(sorted))
	derived := make([]refDerived, 0, len(sorted))
	for i, c := range sorted {
		if len(c.ContentHash) != 32 {
			return zero, nil, ErrSnapshotImportFailed
		}
		if i > 0 && sorted[i-1].CellID == c.CellID {
			return zero, nil, errRefDuplicateCellID
		}
		idx, err := CellIndex(podSalt, c.CellID)
		if err != nil {
			return zero, nil, err
		}
		if prev, taken := owner[idx]; taken && prev != c.CellID {
			return zero, nil, ErrCellIndexCollision
		}
		payload, err := CanonicalCellPayload(podSalt, c.CellID, c.ContentHash)
		if err != nil {
			return zero, nil, err
		}
		vh, err := p.ValueHash(payload)
		if err != nil {
			return zero, nil, err
		}
		if vh == ([32]byte{}) {
			return zero, nil, errRefValueHashZero
		}
		lh, err := p.LeafHash(vh)
		if err != nil {
			return zero, nil, err
		}
		owner[idx] = c.CellID
		byIndex[idx] = lh
		derived = append(derived, refDerived{CellID: c.CellID, Index: idx, ValueHash: vh, LeafHash: lh})
	}
	root, err := poseidonSparseRoot(p, byIndex)
	return root, derived, err
}

// poseidonSparseRoot folds a map of index -> leaf hash into the PRD 1 §5.5
// depth-20 root, using the pinned Poseidon empty-subtree roots E0..E20 for
// absent siblings. Input: leaf hashes keyed by index < 2^20. Output: the root,
// which is E20 for an empty map.
func poseidonSparseRoot(p *poseidon.Params, leaves map[uint32][32]byte) ([32]byte, error) {
	empty := p.EmptyRoots()
	level := leaves
	for k := 0; k < D; k++ {
		next := make(map[uint32][32]byte, len(level))
		for idx := range level {
			parent := idx >> 1
			if _, done := next[parent]; done {
				continue
			}
			left, okL := level[parent<<1]
			right, okR := level[parent<<1|1]
			if !okL {
				left = empty[k]
			}
			if !okR {
				right = empty[k]
			}
			h, err := p.InternalHash(left, right)
			if err != nil {
				return [32]byte{}, err
			}
			next[parent] = h
		}
		level = next
	}
	if root, ok := level[0]; ok {
		return root, nil
	}
	return empty[D], nil
}

// refSource is one [[context.memory]] entry together with the bytes the
// resolver loaded for it (spec §4). Loaded is nil for kinds that load nothing
// at publish time.
type refSource struct {
	Kind     string
	Path     string
	URL      string
	Snapshot string
	Content  string
	Loaded   []byte
}

// referenceSourceCellID derives the proposed source cell identifier
// (spec §4.3):
//
//	cell_id = 2^63 | (be_u64(SHA-256("konareef-mem-src/v1"
//	                          ‖ ULEB128(len(kind)) ‖ kind
//	                          ‖ ULEB128(len(locator)) ‖ locator)[0:8]) & (2^63-1))
//
// Inputs: the kind string and its locator bytes. Output: a u64 with bit 63 set.
func referenceSourceCellID(kind string, locator []byte) uint64 {
	h := sha256.New()
	h.Write(srcCellIDDomain)
	h.Write(EncodeThoughtID(uint64(len(kind))))
	h.Write([]byte(kind))
	h.Write(EncodeThoughtID(uint64(len(locator))))
	h.Write(locator)
	sum := h.Sum(nil)
	return srcCellIDHighBit | (binary.BigEndian.Uint64(sum[0:8]) &^ srcCellIDHighBit)
}

// filesKey maps a manifest memory path ("./memory/a.md") to its [_files] key
// ("memory/a.md"): path.Clean, which also drops the leading "./".
func filesKey(p string) string {
	return path.Clean(p)
}

// referenceResolveSourcesV1 turns [[context.memory]] entries into cells under
// the proposed v1 supported set (spec §4.2): kind "file" and kind "inline".
//
// Inputs: the entries in manifest order, and filesDigests, the [_files]
// section of the same canonical manifest (key -> SHA-256 of the file bytes).
// Output: one cell per entry, or the first refusal. "http" and "openbrain"
// are refused with errRefSourceUnsupported: http bytes are mutable after
// publish, and an openbrain snapshot is the spawning user's data, which the
// publisher cannot commit (spec §4.2).
func referenceResolveSourcesV1(sources []refSource, filesDigests map[string][32]byte) ([]refCell, error) {
	cells := make([]refCell, 0, len(sources))
	seen := make(map[uint64]bool, len(sources))
	for _, s := range sources {
		var id uint64
		var content [32]byte
		switch s.Kind {
		case "file":
			key := filesKey(s.Path)
			committed, ok := filesDigests[key]
			if !ok {
				return nil, errRefFileNotCommitted
			}
			content = sha256.Sum256(s.Loaded)
			if content != committed {
				return nil, errRefFileDigestMismatch
			}
			id = referenceSourceCellID("file", []byte(key))
		case "inline":
			content = sha256.Sum256([]byte(s.Content))
			id = referenceSourceCellID("inline", content[:])
		default:
			return nil, errRefSourceUnsupported
		}
		if seen[id] {
			return nil, errRefDuplicateSource
		}
		seen[id] = true
		cells = append(cells, refCell{CellID: id, ContentHash: append([]byte(nil), content[:]...)})
	}
	return cells, nil
}

// referenceCustodyRoot mirrors reef-core ReefCore.Proofs.MerkleTree.build/1
// (lib/pod/proofs/merkle_tree.ex at reef-core 0b7e1c3): dedupe, sort by raw
// bytes, all-zero root for no leaves, the leaf itself for one leaf, else
// SHA-256(left ‖ right) with the last node duplicated on odd levels. It exists
// only to show that the custody snapshot root is a different object.
func referenceCustodyRoot(hashes [][]byte) [32]byte {
	uniq := map[string][]byte{}
	for _, h := range hashes {
		uniq[string(h)] = h
	}
	level := make([][]byte, 0, len(uniq))
	for _, h := range uniq {
		level = append(level, h)
	}
	sort.Slice(level, func(i, j int) bool { return bytes.Compare(level[i], level[j]) < 0 })
	var out [32]byte
	switch len(level) {
	case 0:
		return out
	case 1:
		copy(out[:], level[0])
		return out
	}
	for len(level) > 1 {
		next := make([][]byte, 0, (len(level)+1)/2)
		for i := 0; i < len(level); i += 2 {
			l, r := level[i], level[i]
			if i+1 < len(level) {
				r = level[i+1]
			}
			s := sha256.Sum256(append(append([]byte(nil), l...), r...))
			next = append(next, s[:])
		}
		level = next
	}
	copy(out[:], level[0])
	return out
}

// legacySHASparseRoot re-implements the pre-D6 SHA-256 tree over the same
// cells: value_hash = SHA-256(payload), leaf = SHA-256(LEAF_TAG ‖ vh),
// node = SHA-256(NODE_TAG ‖ L ‖ R), empty subtrees from SHA-256 of the zero
// leaf. Input and output as for referenceRInitV1, without its refusals.
// Production no longer computes this object; it is kept only to show that
// it differs from r_init.
func legacySHASparseRoot(t *testing.T, podSalt []byte, cells []refCell) [32]byte {
	t.Helper()
	leaf := func(vh [32]byte) [32]byte { return sha256.Sum256(append([]byte{LEAF_TAG}, vh[:]...)) }
	node := func(l, r [32]byte) [32]byte {
		return sha256.Sum256(append(append([]byte{NODE_TAG}, l[:]...), r[:]...))
	}
	var empty [D + 1][32]byte
	empty[0] = leaf([32]byte{})
	for k := 1; k <= D; k++ {
		empty[k] = node(empty[k-1], empty[k-1])
	}
	level := map[uint32][32]byte{}
	for _, c := range cells {
		idx, err := CellIndex(podSalt, c.CellID)
		if err != nil {
			t.Fatalf("CellIndex: %v", err)
		}
		payload, err := CanonicalCellPayload(podSalt, c.CellID, c.ContentHash)
		if err != nil {
			t.Fatalf("CanonicalCellPayload: %v", err)
		}
		level[idx] = leaf(sha256.Sum256(payload))
	}
	if len(level) == 0 {
		return empty[D]
	}
	for k := 0; k < D; k++ {
		next := map[uint32][32]byte{}
		for idx := range level {
			p := idx >> 1
			l, okL := level[p<<1]
			r, okR := level[p<<1|1]
			if !okL {
				l = empty[k]
			}
			if !okR {
				r = empty[k]
			}
			next[p] = node(l, r)
		}
		level = next
	}
	return level[0]
}

// isCanonicalFq reports whether b, read as a little-endian integer, is below
// the Pallas Fq modulus (the R-V2.4 rule).
func isCanonicalFq(b [32]byte) bool {
	p, _ := new(big.Int).SetString("40000000000000000000000000000000224698fc0994a8dd8c46eb2100000001", 16)
	be := make([]byte, 32)
	for i := range b {
		be[31-i] = b[i]
	}
	return new(big.Int).SetBytes(be).Cmp(p) < 0
}

// memoryFreeClass is the compatibility classifier proposed in spec §7.2.
// Inputs: the three third-party-recomputable dimensions of a memory-free v2
// manifest and its committed fields_root. Output: "v1-empty" when the manifest
// committed r_init = E20, "legacy-zero" when it committed the provisional zero,
// "unrecognized" otherwise. No salt or memory content is needed, because a
// memory-free r_init has no salted input.
func memoryFreeClass(t *testing.T, models, tools []string, cMax uint64, committed [32]byte) string {
	t.Helper()
	e20 := poseidon.Default().EmptyRoots()[D]
	v1, err := canon.FieldsRoot(models, tools, cMax, e20)
	if err != nil {
		t.Fatalf("FieldsRoot(E20): %v", err)
	}
	legacy, err := canon.FieldsRoot(models, tools, cMax, [32]byte{})
	if err != nil {
		t.Fatalf("FieldsRoot(0): %v", err)
	}
	switch committed {
	case v1:
		return "v1-empty"
	case legacy:
		return "legacy-zero"
	default:
		return "unrecognized"
	}
}

// ---------------------------------------------------------------------------
// Fixture file model
// ---------------------------------------------------------------------------

type rinitFixtures struct {
	Status     string                  `json:"status"`
	EmptyRoots map[string]string       `json:"empty_roots"`
	MemoryFree rinitMemoryFreeFixture  `json:"memory_free"`
	Cells      []rinitCellVector       `json:"cell_vectors"`
	Sources    []rinitSourceVector     `json:"source_vectors"`
	Distinct   rinitDistinctionFixture `json:"distinction"`
}

type rinitMemoryFreeFixture struct {
	RInitV1                 string `json:"r_init_v1"`
	RInitLegacyZero         string `json:"r_init_legacy_zero"`
	LegacySHASparseEmpty    string `json:"legacy_sha_sparse_empty_root"`
	FieldsRootEmptyV1       string `json:"fields_root_empty_manifest_v1"`
	FieldsRootEmptyLegacy   string `json:"fields_root_empty_manifest_legacy_zero"`
	FieldsRootOneEachV1     string `json:"fields_root_one_each_v1"`
	FieldsRootOneEachLegacy string `json:"fields_root_one_each_legacy_zero"`
}

type rinitCellVector struct {
	ID      string `json:"id"`
	Status  string `json:"status"`
	PodSalt string `json:"pod_salt"`
	Cells   []struct {
		CellID      uint64 `json:"cell_id"`
		ContentHash string `json:"content_hash"`
	} `json:"cells"`
	Expected struct {
		Indices     []uint32 `json:"indices"`
		ValueHashes []string `json:"value_hashes"`
		RInit       string   `json:"r_init"`
	} `json:"expected"`
}

type rinitSourceVector struct {
	ID      string `json:"id"`
	Status  string `json:"status"`
	PodSalt string `json:"pod_salt"`
	Sources []struct {
		Kind      string `json:"kind"`
		Path      string `json:"path,omitempty"`
		Content   string `json:"content,omitempty"`
		FileBytes string `json:"file_bytes_utf8,omitempty"`
	} `json:"sources"`
	Expected struct {
		CellIDs       []string `json:"cell_ids_hex"`
		ContentHashes []string `json:"content_hashes"`
		Indices       []uint32 `json:"indices"`
		RInit         string   `json:"r_init"`
	} `json:"expected"`
}

type rinitDistinctionFixture struct {
	PodSalt          string `json:"pod_salt"`
	OtherSalt        string `json:"other_salt"`
	CellVector       string `json:"cell_vector"`
	CustodyRoot      string `json:"custody_snapshot_root"`
	LegacySHARoot    string `json:"legacy_sha_sparse_root"`
	RInitV1          string `json:"r_init_v1"`
	RInitV1OtherSalt string `json:"r_init_v1_other_salt"`
	LabelSet         any    `json:"label_set"`
}

func loadRInitFixtures(t *testing.T) rinitFixtures {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", "rinit_v1", "fixtures.json"))
	if err != nil {
		t.Fatalf("read fixtures: %v", err)
	}
	var f rinitFixtures
	if err := json.Unmarshal(raw, &f); err != nil {
		t.Fatalf("unmarshal fixtures: %v", err)
	}
	return f
}

func mustHex32(t *testing.T, s string) [32]byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil || len(b) != 32 {
		t.Fatalf("bad 32-byte hex %q", s)
	}
	var out [32]byte
	copy(out[:], b)
	return out
}

// mustHex is shared with conformance_test.go.

func vectorCells(t *testing.T, v rinitCellVector) []refCell {
	t.Helper()
	cells := make([]refCell, 0, len(v.Cells))
	for _, c := range v.Cells {
		cells = append(cells, refCell{CellID: c.CellID, ContentHash: mustHex(t, c.ContentHash)})
	}
	return cells
}

func findCellVector(t *testing.T, f rinitFixtures, id string) rinitCellVector {
	t.Helper()
	for _, v := range f.Cells {
		if v.ID == id {
			return v
		}
	}
	t.Fatalf("no cell vector %q", id)
	return rinitCellVector{}
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

// TestRInitV1ReproducesNormativePRD4Vectors checks the reference against the
// PRD 4 Part B Poseidon vectors copied from paygate-zk (generated there by an
// independent Python implementation). Agreement here is the evidence that
// "r_init = PRD 1 §5.5 Poseidon root" is already the normative construction
// and needs no SHA-to-field mapping.
func TestRInitV1ReproducesNormativePRD4Vectors(t *testing.T) {
	f := loadRInitFixtures(t)
	checked := 0
	for _, v := range f.Cells {
		if v.Status != "normative" {
			continue
		}
		t.Run(v.ID, func(t *testing.T) {
			// Keep the fixture's own order for the per-cell comparison.
			cells := vectorCells(t, v)
			root, _, err := referenceRInitV1(mustHex(t, v.PodSalt), cells)
			if err != nil {
				t.Fatalf("referenceRInitV1: %v", err)
			}
			if got := hex.EncodeToString(root[:]); got != v.Expected.RInit {
				t.Fatalf("r_init = %s, want %s", got, v.Expected.RInit)
			}
			p := poseidon.Default()
			salt := mustHex(t, v.PodSalt)
			for i, c := range cells {
				idx, _ := CellIndex(salt, c.CellID)
				if idx != v.Expected.Indices[i] {
					t.Fatalf("cell %d index = %d, want %d", i, idx, v.Expected.Indices[i])
				}
				payload, _ := CanonicalCellPayload(salt, c.CellID, c.ContentHash)
				vh, _ := p.ValueHash(payload)
				if got := hex.EncodeToString(vh[:]); got != v.Expected.ValueHashes[i] {
					t.Fatalf("cell %d value_hash = %s, want %s", i, got, v.Expected.ValueHashes[i])
				}
			}
		})
		checked++
	}
	if checked < 5 {
		t.Fatalf("checked %d normative vectors, want at least 5 (empty, single, multi, type C, type D)", checked)
	}
}

// TestRInitV1MemoryFreeIsEmptyPoseidonRoot pins the memory-free value and the
// compatibility split between it and the shipped provisional zero.
func TestRInitV1MemoryFreeIsEmptyPoseidonRoot(t *testing.T) {
	f := loadRInitFixtures(t)
	mf := f.MemoryFree

	root, _, err := referenceRInitV1(bytes.Repeat([]byte{0xaa}, 32), nil)
	if err != nil {
		t.Fatalf("referenceRInitV1(no cells): %v", err)
	}
	e20 := poseidon.Default().EmptyRoots()[D]
	if root != e20 || hex.EncodeToString(root[:]) != mf.RInitV1 || f.EmptyRoots["E20"] != mf.RInitV1 {
		t.Fatalf("memory-free r_init = %x, want E20 %s", root, mf.RInitV1)
	}
	// The salt has no effect when there are no cells.
	other, _, _ := referenceRInitV1(bytes.Repeat([]byte{0x01}, 32), nil)
	if other != root {
		t.Fatal("memory-free r_init must not depend on the salt")
	}

	// Three different 32-byte values have been called "the empty memory root".
	// After the D6 migration this package's own SparseRoot(nil) is E20.
	if prod, _ := SparseRoot(nil); prod != e20 || EmptyRoots[D] != e20 {
		t.Fatalf("membridge SparseRoot(nil) = %x, want E20 after the D6 migration", prod)
	}
	legacySHA := legacySHASparseRoot(t, bytes.Repeat([]byte{0xaa}, 32), nil)
	if hex.EncodeToString(legacySHA[:]) != mf.LegacySHASparseEmpty {
		t.Fatalf("legacy SHA empty root drifted: %x", legacySHA)
	}
	if isCanonicalFq(legacySHA) {
		t.Fatal("legacy SHA empty root is expected to be non-canonical (it is why publish chose zero)")
	}
	if !isCanonicalFq(e20) {
		t.Fatal("E20 must be a canonical field element; it needs no reduction")
	}
	if root == mustHex32(t, mf.RInitLegacyZero) || root == legacySHA {
		t.Fatal("E20, the provisional zero and the legacy SHA empty root must all differ")
	}

	// fields_root consequences, for the empty manifest and the one_each corpus pod.
	cases := []struct {
		name          string
		models, tools []string
		cMax          uint64
		v1, legacy    string
	}{
		{"empty", nil, nil, 0, mf.FieldsRootEmptyV1, mf.FieldsRootEmptyLegacy},
		{"one_each", []string{"openai/gpt-4o"}, []string{"bash"}, 1000, mf.FieldsRootOneEachV1, mf.FieldsRootOneEachLegacy},
	}
	for _, c := range cases {
		v1, err := canon.FieldsRoot(c.models, c.tools, c.cMax, e20)
		if err != nil {
			t.Fatalf("%s: FieldsRoot(E20): %v", c.name, err)
		}
		legacy, _ := canon.FieldsRoot(c.models, c.tools, c.cMax, [32]byte{})
		if hex.EncodeToString(v1[:]) != c.v1 || hex.EncodeToString(legacy[:]) != c.legacy {
			t.Fatalf("%s: fields_root v1=%x legacy=%x, fixture v1=%s legacy=%s", c.name, v1, legacy, c.v1, c.legacy)
		}
		if got := memoryFreeClass(t, c.models, c.tools, c.cMax, v1); got != "v1-empty" {
			t.Fatalf("%s: classify(v1) = %s", c.name, got)
		}
		if got := memoryFreeClass(t, c.models, c.tools, c.cMax, legacy); got != "legacy-zero" {
			t.Fatalf("%s: classify(legacy) = %s", c.name, got)
		}
		if got := memoryFreeClass(t, c.models, c.tools, c.cMax, mustHex32(t, strings.Repeat("11", 32))); got != "unrecognized" {
			t.Fatalf("%s: classify(other) = %s", c.name, got)
		}
	}
	// The legacy empty-manifest value is the golden anchor that spec §2 of the
	// v2 spec already pins; the v1 value must not overwrite it.
	if mf.FieldsRootEmptyLegacy != "25e80065232bae5c6accde72a53d4493cbe472d6e63cf851021fa4d25084270e" {
		t.Fatal("legacy empty-manifest fields_root must stay the v2 spec golden anchor")
	}
}

// TestRInitV1DistinguishesTheFourObjects computes the custody snapshot root,
// the legacy SHA sparse root and r_init over one cell set, and shows that no
// label set can be read from any of them.
func TestRInitV1DistinguishesTheFourObjects(t *testing.T) {
	f := loadRInitFixtures(t)
	d := f.Distinct
	v := findCellVector(t, f, d.CellVector)
	cells := vectorCells(t, v)
	salt := mustHex(t, d.PodSalt)

	hashes := make([][]byte, 0, len(cells))
	for _, c := range cells {
		hashes = append(hashes, c.ContentHash)
	}
	custody := referenceCustodyRoot(hashes)
	legacy := legacySHASparseRoot(t, salt, cells)
	rinit, _, err := referenceRInitV1(salt, cells)
	if err != nil {
		t.Fatalf("referenceRInitV1: %v", err)
	}
	for name, pair := range map[string][2]string{
		"custody": {hex.EncodeToString(custody[:]), d.CustodyRoot},
		"legacy":  {hex.EncodeToString(legacy[:]), d.LegacySHARoot},
		"r_init":  {hex.EncodeToString(rinit[:]), d.RInitV1},
	} {
		if pair[0] != pair[1] {
			t.Fatalf("%s root = %s, fixture %s", name, pair[0], pair[1])
		}
	}
	if custody == legacy || custody == rinit || legacy == rinit {
		t.Fatal("the three roots must be pairwise distinct")
	}

	// The custody root is unsalted and ignores cell identity; r_init is not.
	otherSalt := mustHex(t, d.OtherSalt)
	rinitOther, _, _ := referenceRInitV1(otherSalt, cells)
	if hex.EncodeToString(rinitOther[:]) != d.RInitV1OtherSalt || rinitOther == rinit {
		t.Fatal("r_init must change with the salt")
	}
	if referenceCustodyRoot(hashes) != custody {
		t.Fatal("custody root has no salt input; recomputation must be identical")
	}
	// Two thoughts with equal content: custody collapses them, r_init does not.
	dup := append([]refCell(nil), cells...)
	dup = append(dup, refCell{CellID: 99, ContentHash: cells[0].ContentHash})
	dupHashes := append(append([][]byte(nil), hashes...), cells[0].ContentHash)
	if referenceCustodyRoot(dupHashes) != custody {
		t.Fatal("custody root is set-semantic: duplicate content must not change it")
	}
	rinitDup, _, err := referenceRInitV1(salt, dup)
	if err != nil {
		t.Fatalf("duplicate content under distinct ids must be accepted: %v", err)
	}
	if rinitDup == rinit {
		t.Fatal("r_init is keyed by cell id: a second cell with equal content must change it")
	}

	// No label set is derivable. The fixture records that as null, and the
	// derivation output carries no label field to read one from.
	if d.LabelSet != nil {
		t.Fatalf("label_set must be null (DATA-00 owns labels), got %v", d.LabelSet)
	}
}

// TestRInitV1ProposedSourceFixtures checks the proposed file/inline source
// mapping against its fixtures. These fixtures are self-generated by this
// reference and are marked "proposed": a second implementation (MEM-02) must
// reproduce them before they count as cross-checked.
func TestRInitV1ProposedSourceFixtures(t *testing.T) {
	f := loadRInitFixtures(t)
	if len(f.Sources) < 2 {
		t.Fatalf("want at least 2 source vectors, got %d", len(f.Sources))
	}
	for _, v := range f.Sources {
		t.Run(v.ID, func(t *testing.T) {
			// The owner accepted the source mapping (D2 sub-question: path-based
			// ids). The fixture's status field still reads "proposed" and is
			// left unchanged, because MEM-02 (reef-core#54) mirrors this file
			// byte for byte; the value that matters is that it is set.
			if v.Status == "" {
				t.Fatal("source vector has no status")
			}
			files := map[string][32]byte{}
			sources := make([]refSource, 0, len(v.Sources))
			for _, s := range v.Sources {
				rs := refSource{Kind: s.Kind, Path: s.Path, Content: s.Content}
				if s.Kind == "file" {
					rs.Loaded = []byte(s.FileBytes)
					files[filesKey(s.Path)] = sha256.Sum256(rs.Loaded)
				}
				sources = append(sources, rs)
			}
			cells, err := referenceResolveSourcesV1(sources, files)
			if err != nil {
				t.Fatalf("resolve: %v", err)
			}
			salt := mustHex(t, v.PodSalt)
			for i, c := range cells {
				var idHex [8]byte
				binary.BigEndian.PutUint64(idHex[:], c.CellID)
				if got := hex.EncodeToString(idHex[:]); got != v.Expected.CellIDs[i] {
					t.Fatalf("source %d cell_id = %s, want %s", i, got, v.Expected.CellIDs[i])
				}
				if got := hex.EncodeToString(c.ContentHash); got != v.Expected.ContentHashes[i] {
					t.Fatalf("source %d content_hash = %s, want %s", i, got, v.Expected.ContentHashes[i])
				}
				idx, _ := CellIndex(salt, c.CellID)
				if idx != v.Expected.Indices[i] {
					t.Fatalf("source %d index = %d, want %d", i, idx, v.Expected.Indices[i])
				}
				payload, _ := CanonicalCellPayload(salt, c.CellID, c.ContentHash)
				if len(payload) > 93 {
					t.Fatalf("source %d payload %d bytes exceeds the 93-byte value_hash cap", i, len(payload))
				}
			}
			root, _, err := referenceRInitV1(salt, cells)
			if err != nil {
				t.Fatalf("referenceRInitV1: %v", err)
			}
			if got := hex.EncodeToString(root[:]); got != v.Expected.RInit {
				t.Fatalf("r_init = %s, want %s", got, v.Expected.RInit)
			}
		})
	}
}

// TestRInitV1Adversarial covers the refusals and non-equalities that the
// MEM-00 work item names: different bytes under the same declaration, stable
// replay, salt mismatch, reordered duplicate cells and index collisions. Each
// case has a positive control beside it.
func TestRInitV1Adversarial(t *testing.T) {
	salt := bytes.Repeat([]byte{0xaa}, 32)
	notes := refSource{Kind: "file", Path: "./memory/notes.md", Loaded: []byte("The pod remembers this line.\n")}
	commit := func(srcs ...refSource) map[string][32]byte {
		m := map[string][32]byte{}
		for _, s := range srcs {
			if s.Kind == "file" {
				m[filesKey(s.Path)] = sha256.Sum256(s.Loaded)
			}
		}
		return m
	}
	rootOf := func(t *testing.T, s []byte, srcs []refSource, files map[string][32]byte) [32]byte {
		t.Helper()
		cells, err := referenceResolveSourcesV1(srcs, files)
		if err != nil {
			t.Fatalf("resolve: %v", err)
		}
		r, _, err := referenceRInitV1(s, cells)
		if err != nil {
			t.Fatalf("root: %v", err)
		}
		return r
	}

	t.Run("same declaration, different bytes, different root", func(t *testing.T) {
		changed := notes
		changed.Loaded = []byte("The pod remembers this line!\n")
		a := rootOf(t, salt, []refSource{notes}, commit(notes))
		b := rootOf(t, salt, []refSource{changed}, commit(changed))
		if a == b {
			t.Fatal("different loaded bytes under one declaration must not give equal r_init")
		}
	})

	t.Run("loaded bytes must match the committed [_files] digest", func(t *testing.T) {
		swapped := notes
		swapped.Loaded = []byte("swapped after publish\n")
		if _, err := referenceResolveSourcesV1([]refSource{swapped}, commit(notes)); !errors.Is(err, errRefFileDigestMismatch) {
			t.Fatalf("err = %v, want %v", err, errRefFileDigestMismatch)
		}
		if _, err := referenceResolveSourcesV1([]refSource{notes}, map[string][32]byte{}); !errors.Is(err, errRefFileNotCommitted) {
			t.Fatalf("err = %v, want %v", err, errRefFileNotCommitted)
		}
		if _, err := referenceResolveSourcesV1([]refSource{notes}, commit(notes)); err != nil {
			t.Fatalf("control: %v", err)
		}
	})

	t.Run("stable replay and order independence", func(t *testing.T) {
		inline := refSource{Kind: "inline", Content: "Prefer primary sources."}
		a := rootOf(t, salt, []refSource{notes, inline}, commit(notes))
		b := rootOf(t, salt, []refSource{notes, inline}, commit(notes))
		c := rootOf(t, salt, []refSource{inline, notes}, commit(notes))
		if a != b || a != c {
			t.Fatal("same sources and salt must replay to the same r_init in any order")
		}
	})

	t.Run("salt mismatch", func(t *testing.T) {
		a := rootOf(t, salt, []refSource{notes}, commit(notes))
		b := rootOf(t, bytes.Repeat([]byte{0xab}, 32), []refSource{notes}, commit(notes))
		if a == b {
			t.Fatal("a different salt must give a different r_init")
		}
		if _, _, err := referenceRInitV1(salt[:31], nil); !errors.Is(err, ErrCellSaltLen) {
			t.Fatalf("31-byte salt: err = %v, want %v", err, ErrCellSaltLen)
		}
	})

	t.Run("reordered duplicate cells refuse in every order", func(t *testing.T) {
		ch := bytes.Repeat([]byte{0x11}, 32)
		ch2 := bytes.Repeat([]byte{0x22}, 32)
		for _, cells := range [][]refCell{
			{{1, ch}, {2, ch2}, {1, ch}},
			{{1, ch}, {1, ch2}, {2, ch2}},
			{{2, ch2}, {1, ch2}, {1, ch}},
		} {
			if _, _, err := referenceRInitV1(salt, cells); !errors.Is(err, errRefDuplicateCellID) {
				t.Fatalf("cells %v: err = %v, want %v", cells, err, errRefDuplicateCellID)
			}
		}
		if _, _, err := referenceRInitV1(salt, []refCell{{1, ch}, {2, ch2}}); err != nil {
			t.Fatalf("control: %v", err)
		}
		inline := refSource{Kind: "inline", Content: "same"}
		if _, err := referenceResolveSourcesV1([]refSource{inline, inline}, nil); !errors.Is(err, errRefDuplicateSource) {
			t.Fatalf("duplicate inline source: err = %v, want %v", err, errRefDuplicateSource)
		}
	})

	t.Run("index collision refuses without relocation", func(t *testing.T) {
		// PRD 4 vector mem-index-collision: ids 0 and 1 share index 964737.
		coll := mustHex(t, "32805988a90f2b71cfb2aa78c36a45062b290e2eb079dd23bc9c77ffd9a22173")
		ch := bytes.Repeat([]byte{0x11}, 32)
		if _, _, err := referenceRInitV1(coll, []refCell{{0, ch}, {1, ch}}); !errors.Is(err, ErrCellIndexCollision) {
			t.Fatalf("err = %v, want %v", err, ErrCellIndexCollision)
		}
		if _, _, err := referenceRInitV1(coll, []refCell{{0, ch}}); err != nil {
			t.Fatalf("control: %v", err)
		}
	})

	t.Run("cap", func(t *testing.T) {
		cells := make([]refCell, HardCapK+1)
		for i := range cells {
			cells[i] = refCell{uint64(i), bytes.Repeat([]byte{0x11}, 32)}
		}
		if _, _, err := referenceRInitV1(salt, cells); !errors.Is(err, ErrCellCapExceeded) {
			t.Fatalf("err = %v, want %v", err, ErrCellCapExceeded)
		}
	})

	t.Run("unsupported kinds refuse; nothing falls back to empty", func(t *testing.T) {
		for _, s := range []refSource{
			{Kind: "http", URL: "https://example.com/notes.md"},
			{Kind: "openbrain", Snapshot: "latest"},
			{Kind: "ftp"},
		} {
			if _, err := referenceResolveSourcesV1([]refSource{notes, s}, commit(notes)); !errors.Is(err, errRefSourceUnsupported) {
				t.Fatalf("kind %q: err = %v, want %v", s.Kind, err, errRefSourceUnsupported)
			}
		}
	})

	t.Run("source ids never meet Open Brain ids", func(t *testing.T) {
		id := referenceSourceCellID("file", []byte("memory/notes.md"))
		if id&srcCellIDHighBit == 0 {
			t.Fatal("source cell ids must set bit 63")
		}
		if referenceSourceCellID("file", []byte("a")) == referenceSourceCellID("inline", []byte("a")) {
			t.Fatal("kind must be inside the id preimage")
		}
	})
}

// TestRInitV1ProductionMatchesReference checks the production derivation
// (RInitV1, ResolveSources, SourceCellID) against the independent MEM-00
// reference on every fixture group, and the production refusals against
// the reference refusals on the adversarial inputs.
func TestRInitV1ProductionMatchesReference(t *testing.T) {
	f := loadRInitFixtures(t)
	toCells := func(rc []refCell) []Cell {
		out := make([]Cell, 0, len(rc))
		for _, c := range rc {
			out = append(out, Cell{CellID: c.CellID, ContentHash: c.ContentHash})
		}
		return out
	}
	for _, v := range f.Cells {
		salt := mustHex(t, v.PodSalt)
		cells := vectorCells(t, v)
		want, wantDerived, werr := referenceRInitV1(salt, cells)
		got, gotDerived, gerr := RInitV1(salt, toCells(cells))
		if !errors.Is(gerr, werr) && !(gerr == nil && werr == nil) {
			t.Fatalf("%s: production err %v, reference err %v", v.ID, gerr, werr)
		}
		if got != want || hex.EncodeToString(got[:]) != v.Expected.RInit {
			t.Fatalf("%s: production r_init %x, reference %x, fixture %s", v.ID, got, want, v.Expected.RInit)
		}
		for i := range wantDerived {
			if gotDerived[i].CellID != wantDerived[i].CellID || gotDerived[i].Index != wantDerived[i].Index ||
				gotDerived[i].ValueHash != wantDerived[i].ValueHash {
				t.Fatalf("%s: derived cell %d differs", v.ID, i)
			}
		}
	}
	for _, v := range f.Sources {
		files := map[string][32]byte{}
		ref := make([]refSource, 0, len(v.Sources))
		prod := make([]MemorySource, 0, len(v.Sources))
		for _, s := range v.Sources {
			rs := refSource{Kind: s.Kind, Path: s.Path, Content: s.Content}
			if s.Kind == "file" {
				rs.Loaded = []byte(s.FileBytes)
				files[FilesKey(s.Path)] = sha256.Sum256(rs.Loaded)
			}
			ref = append(ref, rs)
			prod = append(prod, MemorySource{Kind: rs.Kind, Path: rs.Path, Content: rs.Content, Loaded: rs.Loaded})
		}
		refCells, err := referenceResolveSourcesV1(ref, files)
		if err != nil {
			t.Fatalf("%s: reference resolve: %v", v.ID, err)
		}
		prodCells, err := ResolveSources(prod, files)
		if err != nil {
			t.Fatalf("%s: production resolve: %v", v.ID, err)
		}
		for i := range refCells {
			if prodCells[i].CellID != refCells[i].CellID || !bytes.Equal(prodCells[i].ContentHash, refCells[i].ContentHash) {
				t.Fatalf("%s: source %d cell differs", v.ID, i)
			}
		}
		root, _, err := RInitV1(mustHex(t, v.PodSalt), prodCells)
		if err != nil || hex.EncodeToString(root[:]) != v.Expected.RInit {
			t.Fatalf("%s: production r_init %x (%v), fixture %s", v.ID, root, err, v.Expected.RInit)
		}
	}

	// Refusals agree, with a control beside each.
	salt := bytes.Repeat([]byte{0xaa}, 32)
	ch := bytes.Repeat([]byte{0x11}, 32)
	coll := mustHex(t, "32805988a90f2b71cfb2aa78c36a45062b290e2eb079dd23bc9c77ffd9a22173")
	for name, c := range map[string]struct {
		salt  []byte
		cells []refCell
		want  error
	}{
		"control":        {salt, []refCell{{1, ch}, {2, ch}}, nil},
		"duplicate id":   {salt, []refCell{{2, ch}, {1, ch}, {2, ch}}, ErrCellDuplicateID},
		"collision":      {coll, []refCell{{0, ch}, {1, ch}}, ErrCellIndexCollision},
		"salt length":    {salt[:31], nil, ErrCellSaltLen},
		"content length": {salt, []refCell{{1, ch[:31]}}, ErrSnapshotImportFailed},
	} {
		_, _, rerr := referenceRInitV1(c.salt, c.cells)
		_, _, perr := RInitV1(c.salt, toCells(c.cells))
		if !errors.Is(rerr, c.want) && !(rerr == nil && c.want == nil) {
			t.Fatalf("%s: reference err %v, want %v", name, rerr, c.want)
		}
		if !errors.Is(perr, c.want) && !(perr == nil && c.want == nil) {
			t.Fatalf("%s: production err %v, want %v", name, perr, c.want)
		}
	}
	notes := MemorySource{Kind: "file", Path: "./memory/notes.md", Loaded: []byte("x\n")}
	files := map[string][32]byte{"memory/notes.md": sha256.Sum256(notes.Loaded)}
	for name, c := range map[string]struct {
		srcs  []MemorySource
		files map[string][32]byte
		want  error
	}{
		"control":         {[]MemorySource{notes, {Kind: "inline", Content: "a"}}, files, nil},
		"http":            {[]MemorySource{notes, {Kind: "http"}}, files, ErrMemorySourceUnsupported},
		"openbrain":       {[]MemorySource{{Kind: "openbrain"}}, files, ErrMemorySourceUnsupported},
		"not committed":   {[]MemorySource{notes}, map[string][32]byte{}, ErrMemoryFileNotCommitted},
		"digest mismatch": {[]MemorySource{{Kind: "file", Path: "memory/notes.md", Loaded: []byte("y\n")}}, files, ErrMemoryFileDigestMismatch},
		"duplicate path":  {[]MemorySource{notes, {Kind: "file", Path: "memory/./notes.md", Loaded: notes.Loaded}}, files, ErrMemoryDuplicateSource},
	} {
		if _, err := ResolveSources(c.srcs, c.files); !errors.Is(err, c.want) && !(err == nil && c.want == nil) {
			t.Fatalf("%s: err = %v, want %v", name, err, c.want)
		}
	}
}
