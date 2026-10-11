// Copyright 2026 Jerry David Chan, Konareef.ai
// SPDX-License-Identifier: Apache-2.0

// build.go — assembles every vector group of the konareef-rinit/v2 file.
// See main.go for the derivation helpers and the run command.
package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/digitsu/konareef/internal/membridge"
)

// Hashes reused from the konareef-rinit/v1 fixtures (normative PRD 4 cells).
const (
	chA = "aae0a971434ea3f6973aa77b266bd53ddae16abad964cd06ff44ecc799c5679e"
	chB = "c29aa59cafc9e2437b2c9f0c8772593e63c5fe7b63dee5f9f1b1a8cc3369f919"
	chC = "72b2ac744cd525b6ed060ef36ebf16496b2db6fed6ab44c82b292976b3338349"
)

// Salts reused from the konareef-rinit/v1 fixtures.
var (
	saltA = bytes.Repeat([]byte{0xaa}, 32)
	saltD = bytes.Repeat([]byte{0xdd}, 32)
	saltC = func() []byte {
		b := make([]byte, 32)
		for i := range b {
			b[i] = byte(i)
		}
		return b
	}()
	srcMul = []source{
		{Kind: "file", Path: "./memory/notes.md", FileBytesUTF8: "The pod remembers this line.\n"},
		{Kind: "inline", Content: "Prefer primary sources."},
		{Kind: "file", Path: "./memory/style.md", FileBytesUTF8: "Use short sentences.\n"},
	}
)

// build returns the complete, indented vector file.
//
// Output: the JSON bytes with a trailing newline, or an error from the
// encoder. Any broken internal invariant (a positive vector that does not
// authenticate, a negative vector that does) panics, so a wrong file is
// never written.
func build() ([]byte, error) {
	f := file{
		Title:  "konareef-rinit/v2 shared vectors (CL-4-live step 1)",
		Status: "NORMATIVE for CL-4-live steps 2 and 3 (reef-core#84, owner decisions 2026-10-08: T-A, W-A, O1-b, O1-b.ii, P-A).",
		Spec:   "docs/reference/konareef-rinit-v2-spec.md",
		Generator: "go run ./internal/membridge/testdata/rinit_v2/gen -out internal/membridge/testdata/rinit_v2/vectors.json " +
			"(deterministic; TestRInitV2VectorsGenerator refuses any byte difference)",
		Provenance: map[string]string{
			"derivation":  "Computed by the generator's own v2 implementation over crypto/sha256 and internal/poseidon (pinned konareef-pod-step-v1-poseidon-params-v1.json). No v2 production code exists at generation time.",
			"cross_check": "internal/membridge/rinit_v2_vectors_test.go recomputes every positive and negative vector with a second, separately written reference built on membridge.LogicalKey, membridge.SparseRoot, BuildAuthPath and VerifyAuthPath.",
			"inputs":      "Cell sets, salts and source vectors are the konareef-rinit/v1 MEM-00 inputs (internal/membridge/testdata/rinit_v1/fixtures.json), so each v2 value sits beside its v1 contrast value.",
			"signatures":  "identity.Sign (secp256k1, RFC 6979, deterministic) under the MEM-SEAM public test key. reef-core already pins its public key in test/support/fixtures/step_disclosure/mem_seam_v1.json.",
			"encoding":    "All byte values are lowercase hex. Field elements are 32-byte little-endian Pallas Fq. The wire encodes the same bytes as base64 (spec §6).",
			"error_codes": "Refusal codes are the spec §9 codes and the konareef-rinit/v1 codes that §9 keeps (ERR_CELL_*, ERR_RINIT_MISMATCH, MEMORY_LEAF_TABLE_INVALID, MEMORY_LEAF_TABLE_MISMATCH). Spec §4 names the code of each leaf-table check. Layers in refused_by: reef-core (seam writer), feeder (konareef sidecar), ps1 (paygate-zk prove service), circuit (konareef-pod-step-v1.2), verifier.",
		},
		Constants: map[string]any{
			"key_tag_domain":            keyTagDomain,
			"index_domain_v2":           indexDomainV2,
			"source_cell_id_domain":     sourceIDDomain,
			"dtag_key":                  "20",
			"dtag_cell_v2":              "23",
			"payload_len":               payloadLenV2,
			"value_hash_payload_cap":    93,
			"index_mask":                "0fffff",
			"tree_depth":                treeDepth,
			"leaf_table_domain_v2":      leafTableDomainV2,
			"leaf_table_header_len":     leafTableHeader,
			"leaf_table_entry_len":      leafTableEntry,
			"leaf_table_max_cells":      membridge.HardCapK,
			"seam_version":              seamVersion,
			"seam_touched_key":          seamTouchedKey,
			"seam_memory_scheme":        "konareef-mem-src/v1",
			"r_init_scheme":             rInitSchemeV2,
			"circuit_id_memory_bearing": circuitV12,
			"circuit_id_memory_free":    circuitV11,
			"E0":                        h(emptyRoots[0][:]),
			"E20":                       h(emptyRoots[treeDepth][:]),
		},
		Signer: map[string]string{
			"public_key_hex": testIdentity().PublicKeyHex,
			"scalar":         "SHA-256 of the ASCII phrase below; a public test key, never for real signing",
			"phrase":         testKeyPhrase,
		},
	}

	f.CellVectors = buildCellVectors()
	var multi derived
	f.SourceVecs, multi = buildSourceVectors()
	f.LeafTables = buildLeafTables(f.SourceVecs)
	f.Touched = buildTouched(f.SourceVecs)
	f.MemoryFree = memoryFreeVector{
		ID:                "memory-free",
		InitialMemoryJSON: `{"cells":[],"scheme":"konareef-mem-src/v1"}`,
		TouchedCellID:     nil,
		RInit:             h(emptyRoots[treeDepth][:]),
		Lane:              nil,
		CircuitID:         circuitV11,
		Why:               "A memory-free run has no touched cell. The seam/3 file MUST NOT carry touched_cell_id, no leaf table is fetched, no memory lane is sent and r_init = E20 (the same under v1 and v2). A touched_cell_id key on a memory-free run is refused with MEMORY_TOUCHED_CELL_INVALID.",
	}
	f.SeamDocs = buildSeamDocs(f.SourceVecs)
	f.Negative = buildNegative(multi)
	f.DerivNeg = buildDerivationNegative()

	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	if err := enc.Encode(f); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// buildCellVectors derives v2 over the v1 normative PRD 4 cell sets.
func buildCellVectors() []cellVector {
	sets := []struct {
		id    string
		salt  []byte
		cells []cellIn
	}{
		{"mem-empty-sentinel", saltA, []cellIn{}},
		{"mem-populated-single", saltA, []cellIn{{42, chA}}},
		{"mem-multi-cell-root", saltA, []cellIn{{1, chA}, {2, chB}, {3, chC}}},
		{"mem-typeC-disclosed-salt", saltC, []cellIn{{7, chA}}},
		{"mem-typeD-committed-salt", saltD, []cellIn{{7, chA}}},
	}
	out := []cellVector{}
	for _, s := range sets {
		d := deriveV2(s.salt, s.cells)
		cells := d.cells
		if cells == nil {
			cells = []cellOut{}
		}
		out = append(out, cellVector{
			ID: s.id, PodSalt: h(s.salt), Cells: s.cells, Derived: cells,
			RInit: h(d.root[:]), RInitV1: rInitV1(s.salt, s.cells),
			Contrast: "r_init_v1 and index_v1 are the konareef-rinit/v1 values for the same input. A v2 implementation MUST NOT produce them, except the empty set, whose root is E20 under both.",
		})
	}
	return out
}

// buildSourceVectors derives v2 over the MEM-00 source vectors, plus one
// where the touched cell is declared last. It also returns the derivation
// of file-inline-file-multi, the base of the negative vectors.
func buildSourceVectors() ([]sourceVector, derived) {
	reordered := []source{srcMul[1], srcMul[2], srcMul[0]}
	sets := []struct {
		id   string
		salt []byte
		srcs []source
	}{
		{"file-single", saltA, srcMul[:1]},
		{"file-inline-file-multi", saltC, srcMul},
		{"touched-declared-last", saltC, reordered},
	}
	out := []sourceVector{}
	var multi derived
	for _, s := range sets {
		cells := sourceCells(s.srcs)
		d := deriveV2(s.salt, cells)
		pos := -1
		for i, c := range cells {
			if c.CellID == d.ids[0] {
				pos = i
			}
		}
		out = append(out, sourceVector{
			ID: s.id, PodSalt: h(s.salt), Sources: s.srcs, Derived: d.cells,
			RInit: h(d.root[:]), RInitV1: rInitV1(s.salt, cells),
			TouchedCellID: idHex(d.ids[0]), TouchedIndex: d.idx[0], TouchedDeclaredAt: pos,
		})
		if s.id == "file-inline-file-multi" {
			multi = d
		}
	}
	return out, multi
}

// podHashFor is the fixed pod_hash of a leaf-table vector.
func podHashFor(id string) [32]byte {
	return sha256.Sum256([]byte("konareef-rinit/v2 leaf table vector " + id))
}

// buildLeafTables signs one v2 table per source vector, then the tables a
// v2 check MUST refuse.
func buildLeafTables(svs []sourceVector) []leafTableVector {
	pub := testIdentity().PublicKeyHex
	out := []leafTableVector{}
	var mul derived
	var mulSV sourceVector
	for _, sv := range svs {
		salt := mustHex(sv.PodSalt)
		d := deriveV2(salt, sourceCells(sv.Sources))
		ph := podHashFor(sv.ID)
		tb := leafTableV2(ph, d.root, d.ids, d.ch, d.keyT, d.idx, d.vh)
		sum := sha256.Sum256(tb)
		out = append(out, leafTableVector{
			ID: sv.ID, Source: sv.ID, PodHash: h(ph[:]), PublisherPubkeyHex: pub, RInit: h(d.root[:]),
			TableHex: h(tb), TableSHA256: h(sum[:]), SignatureB64: sign(tb), Expected: "accept",
			RefusedBy: []string{}, ReefCoreStructural: "accept",
			Why: "Canonical v2 table. Every row's index equals IDX_v2(key_tag), every value_hash equals VH(0x23 ‖ key_tag ‖ content_hash), and the leaves authenticate to r_init.",
		})
		if sv.ID == "file-inline-file-multi" {
			mul, mulSV = d, sv
		}
	}
	ph := podHashFor(mulSV.ID)
	// Only the feeder recomputes rows and the root. reef-core applies the
	// structural rules only (spec §3), so it accepts every structurally
	// valid table and refuses only the v1-domain one.
	add := func(id, refusal, why string, rInit [32]byte, tb []byte) {
		sum := sha256.Sum256(tb)
		by, structural := []string{"feeder"}, "accept"
		if !bytes.HasPrefix(tb, []byte(leafTableDomainV2)) {
			by, structural = []string{"reef-core", "feeder"}, "refuse"
		}
		out = append(out, leafTableVector{
			ID: id, Source: mulSV.ID, PodHash: h(ph[:]), PublisherPubkeyHex: pub, RInit: h(rInit[:]),
			TableHex: h(tb), TableSHA256: h(sum[:]), SignatureB64: sign(tb), Expected: "refuse",
			ExpectedRefusal: refusal, RefusedBy: by, ReefCoreStructural: structural, Why: why,
		})
	}

	// Key tags of rows 0 and 1 swapped. The root still holds (index and
	// value_hash are unchanged) and the publisher signed it, but the
	// salt-free row check fails.
	kt := append([][32]byte(nil), mul.keyT...)
	kt[0], kt[1] = kt[1], kt[0]
	add("leaf-table-v2-key-tag-swapped", "MEMORY_LEAF_TABLE_INVALID",
		"Rows 0 and 1 swap key_tag. Signature valid and root valid, but index ≠ IDX_v2(key_tag) and value_hash ≠ VH(0x23 ‖ key_tag ‖ content_hash) on both rows.",
		mul.root, leafTableV2(ph, mul.root, mul.ids, mul.ch, kt, mul.idx, mul.vh))

	// Row 0 value_hash replaced, r_init recomputed so the root check passes.
	vh := append([][32]byte(nil), mul.vh...)
	vh[0] = mustVH(payloadV2(mul.keyT[0], sha256.Sum256([]byte("forged content"))))
	leaves := map[uint32][32]byte{}
	for i := range mul.idx {
		leaves[mul.idx[i]] = vh[i]
	}
	forgedRoot := newTree(leaves).root()
	add("leaf-table-v2-value-hash-forged", "MEMORY_LEAF_TABLE_INVALID",
		"Row 0 value_hash = VH(0x23 ‖ key_tag ‖ SHA-256(\"forged content\")) and r_init recomputed over the forged leaves. Signature and root valid; value_hash ≠ VH(0x23 ‖ key_tag ‖ content_hash) for row 0. (fields_root would also fail, R-M20 step 3.)",
		forgedRoot, leafTableV2(ph, forgedRoot, mul.ids, mul.ch, mul.keyT, mul.idx, vh))

	// r_init replaced by the v1 root of the same cells.
	var v1Root [32]byte
	copy(v1Root[:], mustHex(mulSV.RInitV1))
	add("leaf-table-v2-root-mismatch", "ERR_RINIT_MISMATCH",
		"r_init field holds the konareef-rinit/v1 root of the same cells. Rows are valid; the leaves do not authenticate to it.",
		v1Root, leafTableV2(ph, v1Root, mul.ids, mul.ch, mul.keyT, mul.idx, mul.vh))

	// A v1 table for the same cells: refused for a konareef-rinit/v2 manifest.
	cells := sourceCells(mulSV.Sources)
	mc := make([]membridge.Cell, len(cells))
	for i, c := range cells {
		mc[i] = membridge.Cell{CellID: c.CellID, ContentHash: mustHex(c.ContentHash)}
	}
	r1, d1, err := membridge.RInitV1(mustHex(mulSV.PodSalt), mc)
	if err != nil {
		panic(err)
	}
	t1, err := membridge.NewLeafTable(ph, r1, mc, d1)
	if err != nil {
		panic(err)
	}
	add("leaf-table-v1-domain", "MEMORY_LEAF_TABLE_INVALID",
		"A valid konareef-mem-leaves/v1 table (76-byte rows, no key_tag). A memory-bearing konareef-rinit/v2 manifest accepts only the v2 domain.",
		r1, t1.Bytes())
	return out
}

// laneFor builds the honest PS-1 lane for row i of d.
func laneFor(d derived, i int) lane {
	return lane{
		RInit: h(d.root[:]), Index: d.idx[i], ValueHashIn: h(d.vh[i][:]),
		Siblings: hexList(d.tree.siblings(d.idx[i])), KeyTag: h(d.keyT[i][:]), ContentHash: h(d.ch[i][:]),
	}
}

// buildTouched builds the T-A touched-cell vector of each source vector.
func buildTouched(svs []sourceVector) []touchedVector {
	out := []touchedVector{}
	for _, sv := range svs {
		d := deriveV2(mustHex(sv.PodSalt), sourceCells(sv.Sources))
		l := laneFor(d, 0)
		ok := authenticate(d.idx[0], mustLeaf(d.vh[0]), d.tree.siblings(d.idx[0])) == d.root
		if !ok || d.idx[0] == 0 || mustVH(payloadV2(d.keyT[0], d.ch[0])) != d.vh[0] {
			panic("touched vector invariant broken: " + sv.ID)
		}
		out = append(out, touchedVector{
			ID: "touched-" + sv.ID, Source: sv.ID, SeamVersion: seamVersion, SeamStepIndex: 0,
			SeamTouchedJSON: fmt.Sprintf(`"%s":"%s"`, seamTouchedKey, idHex(d.ids[0])),
			TouchedCellID:   idHex(d.ids[0]), Lane: l,
			PayloadIn:    h(payloadV2(d.keyT[0], d.ch[0])),
			ValueHashOut: h(d.vh[0][:]), ROut: h(d.root[:]), CircuitID: circuitV12,
			AuthenticatesToR: ok,
		})
	}
	return out
}

// buildNegative builds the refusal vectors over file-inline-file-multi.
func buildNegative(d derived) []negativeVector {
	base := "file-inline-file-multi"
	honest := laneFor(d, 0)
	out := []negativeVector{}
	seam := func(id, value, refusal, mutation string) {
		out = append(out, negativeVector{
			ID: id, Base: base, Layer: []string{"feeder"}, ExpectedRefusal: refusal, Mutation: mutation,
			Seam: fmt.Sprintf(`"%s":%s`, seamTouchedKey, value), Facts: map[string]string{"rule_value": idHex(d.ids[0])},
		})
	}
	last := len(d.ids) - 1
	seam("touched-cell-not-lowest", `"`+idHex(d.ids[last])+`"`, "MEMORY_TOUCHED_CELL_MISMATCH",
		"seam names a committed cell that is not the lowest cell_id (T-A)")
	seam("touched-cell-uncommitted", `"`+idHex(sourceCellID("file", []byte("memory/absent.md")))+`"`, "MEMORY_TOUCHED_CELL_MISMATCH",
		"seam names a well-formed source cell id that the manifest does not commit")
	seam("touched-cell-uppercase", `"`+strings.ToUpper(idHex(d.ids[0]))+`"`, "MEMORY_TOUCHED_CELL_INVALID",
		"rule value in uppercase hex; only 16 lowercase hex digits are valid")
	seam("touched-cell-short", `"`+idHex(d.ids[0])[1:]+`"`, "MEMORY_TOUCHED_CELL_INVALID",
		"15 hex digits")
	noBit := d.ids[0] &^ (1 << 63)
	seam("touched-cell-not-source-id", `"`+idHex(noBit)+`"`, "MEMORY_TOUCHED_CELL_INVALID",
		"bit 63 cleared; a source cell id always has bit 63 set")
	seam("touched-cell-number", fmt.Sprintf("%d", d.ids[0]), "MEMORY_TOUCHED_CELL_INVALID",
		"JSON number instead of a string")
	seam("touched-cell-non-hex", `"`+idHex(d.ids[0])[:14]+`gz"`, "MEMORY_TOUCHED_CELL_INVALID",
		"16 lowercase characters, the last two not hex digits; passes a length and lowercase check alone")
	out = append(out, negativeVector{
		ID: "touched-cell-on-memory-free", Base: "memory-free", Layer: []string{"feeder"},
		ExpectedRefusal: "MEMORY_TOUCHED_CELL_INVALID",
		Mutation:        "seam/3 step-disclosure of a memory-free run (initial_memory.cells empty) that carries touched_cell_id; reef-core MUST NOT write this key for a memory-free run (R-M24)",
		Seam:            fmt.Sprintf(`"%s":"%s"`, seamTouchedKey, idHex(d.ids[0])),
		Facts:           map[string]string{"rule_value": "none: a memory-free run has no touched cell"},
	})
	out = append(out, negativeVector{
		ID: "touched-cell-missing", Base: base, Layer: []string{"feeder"}, ExpectedRefusal: "MEMORY_TOUCHED_CELL_INVALID",
		Mutation: "seam/3 step-disclosure of a memory-bearing run with a non-empty initial_memory and no touched_cell_id key",
		Facts:    map[string]string{"rule_value": idHex(d.ids[0])},
	})

	lanePayload := func(id, refusal, mutation string, layers []string, l lane, payload []byte, extra map[string]string) {
		facts := map[string]string{
			"value_hash_of_payload_in": h(func() []byte { v := mustVH(payload); return v[:] }()),
			"value_hash_in":            l.ValueHashIn,
		}
		for k, v := range extra {
			facts[k] = v
		}
		ll := l
		out = append(out, negativeVector{ID: id, Base: base, Layer: layers, ExpectedRefusal: refusal,
			Mutation: mutation, Lane: &ll, PayloadIn: h(payload), Facts: facts})
	}

	// Forged content_hash: last byte flipped.
	fch := d.ch[0]
	fch[31] ^= 0x01
	l := honest
	l.ContentHash = h(fch[:])
	p := payloadV2(d.keyT[0], fch)
	if mustVH(p) == d.vh[0] {
		panic("forged payload hashes to the committed value")
	}
	lanePayload("forged-payload-content", "MEMORY_PAYLOAD_MISMATCH",
		"lane content_hash with its last byte XOR 0x01; PS-1 builds payload_in from it", []string{"ps1", "circuit"}, l, p, nil)

	// Forged key_tag: the key_tag of another committed cell.
	l = honest
	l.KeyTag = h(d.keyT[1][:])
	p = payloadV2(d.keyT[1], d.ch[0])
	lanePayload("forged-payload-key-tag", "MEMORY_PAYLOAD_MISMATCH",
		"lane key_tag replaced by the key_tag of cell "+idHex(d.ids[1]), []string{"ps1", "circuit"}, l, p,
		map[string]string{"index_v2_of_key_tag": fmt.Sprint(indexV2(d.keyT[1])), "lane_index": fmt.Sprint(honest.Index)})

	// Circuit-level layout forgeries (a malicious prover's payload_in).
	p = payloadV2(d.keyT[0], d.ch[0])
	p[0] = 0x21
	lanePayload("forged-payload-dtag-v1", "MEMORY_PAYLOAD_MISMATCH",
		"payload_in byte 0 = 0x21 (the v1 cell tag); the circuit fixes byte 0 = 0x23", []string{"circuit"}, honest, p, nil)
	p = payloadV2(d.keyT[0], d.ch[0])[:64]
	lanePayload("forged-payload-length-64", "MEMORY_PAYLOAD_MISMATCH",
		"payload_in truncated to 64 bytes; the circuit fixes the length at 65", []string{"circuit"}, honest, p, nil)

	// Wrong index with the honest siblings.
	wrong := func(id string, idx uint32, mutation string) {
		l := honest
		l.Index = idx
		got := authenticate(idx, mustLeaf(d.vh[0]), d.tree.siblings(d.idx[0]))
		if got == d.root {
			panic("wrong index authenticates")
		}
		out = append(out, negativeVector{ID: id, Base: base, Layer: []string{"ps1", "circuit"},
			ExpectedRefusal: "MEMORY_INDEX_MISMATCH", Mutation: mutation, Lane: &l,
			Facts: map[string]string{
				"recomputed_root":     h(got[:]),
				"r_init":              h(d.root[:]),
				"index_v2_of_key_tag": fmt.Sprint(honest.Index),
			}})
	}
	wrong("wrong-index-other-cell", d.idx[1], "lane index = the index of cell "+idHex(d.ids[1])+"; value, key_tag and siblings unchanged")
	wrong("wrong-index-flip-bit0", d.idx[0]^1, "lane index with bit 0 flipped; value, key_tag and siblings unchanged")

	// Empty-slot read: the smallest index that holds no cell.
	taken := map[uint32]bool{}
	for _, i := range d.idx {
		taken[i] = true
	}
	var empty uint32
	for taken[empty] {
		empty++
	}
	sibs := d.tree.siblings(empty)
	if authenticate(empty, emptyRoots[0], sibs) != d.root {
		panic("empty slot does not authenticate")
	}
	l = honest
	l.Index = empty
	l.ValueHashIn = h(make([]byte, 32))
	l.Siblings = hexList(sibs)
	out = append(out, negativeVector{ID: "empty-slot-read", Base: base, Layer: []string{"feeder", "ps1", "circuit"},
		ExpectedRefusal: "MEMORY_EMPTY_SLOT_READ",
		Mutation:        "lane names an empty index with value_hash_in = 0 and a valid empty-leaf path; key_tag and content_hash of the touched cell",
		Lane:            &l, PayloadIn: h(payloadV2(d.keyT[0], d.ch[0])),
		Facts: map[string]string{
			"authenticates_with_empty_leaf": "true (accepted by konareef-pod-step-v1.1, design fact T4)",
			"value_hash_of_payload_in":      h(d.vh[0][:]),
			"index_in_leaf_table":           "false",
		}})

	// A write under W-A: value_hash_out differs from value_hash_in.
	newVH := mustVH(payloadV2(d.keyT[0], sha256.Sum256([]byte("written by the run"))))
	rOut := authenticate(d.idx[0], mustLeaf(newVH), d.tree.siblings(d.idx[0]))
	out = append(out, negativeVector{ID: "write-under-read-only", Base: base, Layer: []string{"ps1", "circuit", "verifier"},
		ExpectedRefusal: "MEMORY_WRITE_REFUSED",
		Mutation:        "honest lane, but the step writes value_hash_out = VH(0x23 ‖ key_tag ‖ SHA-256(\"written by the run\")) (W-A forbids any write)",
		Lane:            &honest,
		Facts: map[string]string{
			"value_hash_out": h(newVH[:]),
			"r_out":          h(rOut[:]),
			"r_in":           h(d.root[:]),
		}})
	return out
}

// buildDerivationNegative builds the refusals of the v2 derivation itself.
func buildDerivationNegative() []derivationNegative {
	out := []derivationNegative{{
		ID: "derivation-duplicate-cell-id", PodSalt: h(saltA), Cells: []cellIn{{1, chA}, {1, chB}},
		ExpectedRefusal: "ERR_CELL_DUPLICATE_ID", Indices: []uint32{},
		Why: "two cells with one cell_id",
	}, {
		ID: "derivation-salt-31-bytes", PodSalt: h(saltA[:31]), Cells: []cellIn{{1, chA}},
		ExpectedRefusal: "ERR_CELL_SALT_LEN", Indices: []uint32{},
		Why: "pod_salt must be exactly 32 bytes",
	}}
	// Deterministic search for a salt under which cells 1 and 2 share a v2 index.
	for ctr := uint32(0); ; ctr++ {
		var c [4]byte
		binary.BigEndian.PutUint32(c[:], ctr)
		s := sha([]byte("konareef-rinit/v2 collision search"), c[:])
		i1 := indexV2(keyTag(logicalKey(s[:], 1)))
		i2 := indexV2(keyTag(logicalKey(s[:], 2)))
		if i1 != i2 {
			continue
		}
		out = append(out, derivationNegative{
			ID: "derivation-index-collision", PodSalt: h(s[:]), Cells: []cellIn{{1, chA}, {2, chB}},
			ExpectedRefusal: "ERR_CELL_INDEX_COLLISION", Indices: []uint32{i1, i2},
			Why: fmt.Sprintf("salt = SHA-256(\"konareef-rinit/v2 collision search\" ‖ be_u32(%d)), the first counter under which cells 1 and 2 share a v2 index; no relocation (R-M8)", ctr),
		})
		return out
	}
}

// The step and tool-log fields of the seam/3 document vectors. They are the
// values of reef-core test/support/fixtures/step_disclosure/
// qualified_model_id.json, so only the memory keys are new.
const seamDocBase = `"c":1234,"index":0,` + "%s" + `"model":"claude-sonnet-4-5","model_id":"anthropic/claude-sonnet-4-5",` +
	`"p":"c2F5IGhlbGxv","r":"ZG9uZQ==",` +
	`"tool_log":[{"args_hash":"q6urq6urq6urq6urq6urq6urq6urq6urq6urq6urq6s=","result_hash":"zc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc0=","tool_id":"bash","ts_us":42}]` +
	"%s"

// initialMemoryJSON is the seam/2 initial_memory value (konareef
// feeder.EncodeSeamMemory, reef-core encode_initial_memory/1) for cells in
// ascending cell_id.
func initialMemoryJSON(ids []uint64, ch [][32]byte) string {
	entries := make([]string, len(ids))
	for i := range ids {
		entries[i] = `{"cell_id":"` + idHex(ids[i]) + `","content_hash":"` + base64.StdEncoding.EncodeToString(ch[i][:]) + `"}`
	}
	return `{"cells":[` + strings.Join(entries, ",") + `],"scheme":"konareef-mem-src/v1"}`
}

// buildSeamDocs builds the whole seam/3 step-disclosure.json for one
// memory-bearing source vector and for a memory-free run. Keys are in
// ascending byte order with no white space, as reef-core's writer emits
// them (Jason over a map; compare the existing reef-core golden files).
func buildSeamDocs(svs []sourceVector) []seamDocVector {
	out := []seamDocVector{}
	add := func(id, source, memory, touched, why string) {
		doc := "{" + fmt.Sprintf(seamDocBase, memory, touched) + "}"
		var check map[string]any
		if err := json.Unmarshal([]byte(doc), &check); err != nil {
			panic(err)
		}
		sum := sha256.Sum256([]byte(doc))
		out = append(out, seamDocVector{ID: id, Source: source, StepDisclosure: doc, StepDisclosureSHA: h(sum[:]), Why: why})
	}
	for _, sv := range svs {
		if sv.ID != "file-inline-file-multi" {
			continue
		}
		d := deriveV2(mustHex(sv.PodSalt), sourceCells(sv.Sources))
		add("seam3-"+sv.ID, sv.ID, `"initial_memory":`+initialMemoryJSON(d.ids, d.ch)+",",
			`,"touched_cell_id":"`+idHex(d.ids[0])+`"`,
			"Memory-bearing run: initial_memory lists every committed cell; touched_cell_id is the lowest cell_id (R-M23); index stays the step index 0.")
	}
	add("seam3-memory-free", "", `"initial_memory":`+initialMemoryJSON(nil, nil)+",", "",
		"Memory-free run of a published v2/v3 manifest: empty cells and no touched_cell_id key (R-M24).")
	return out
}
