// Copyright 2026 Jerry David Chan, Konareef.ai
// SPDX-License-Identifier: Apache-2.0

// Command gen writes the konareef-rinit/v2 shared vectors
// (internal/membridge/testdata/rinit_v2/vectors.json).
//
// Spec: docs/reference/konareef-rinit-v2-spec.md (CL-4-live step 1,
// reef-core#84, owner decisions 2026-10-08: T-A, W-A, O1-b, O1-b.ii).
//
// The vectors are the contract for CL-4-live steps 2 and 3: konareef
// membridge/publish/feeder/verify v2, paygate-zk PS-1 and
// konareef-pod-step-v1.2, and reef-core. This program is a standalone
// implementation of the v2 derivation. It uses only crypto/sha256, the
// pinned Poseidon primitive (internal/poseidon), the deterministic
// RFC 6979 signer (internal/identity) and, for contrast fields only, the
// production konareef-rinit/v1 code (internal/membridge). It does not call
// any v2 production code, because none exists yet.
//
// Output is deterministic: the same source gives the same bytes. Run from
// the repository root:
//
//	go run ./internal/membridge/testdata/rinit_v2/gen -out internal/membridge/testdata/rinit_v2/vectors.json
//
// With -out - the file is written to stdout. TestRInitV2VectorsGenerator
// (internal/membridge/rinit_v2_vectors_test.go) runs this program and
// refuses any byte difference from the committed file.
//
// The directory is under testdata/, so `go build ./...`, `go vet ./...`
// and `go test ./...` skip it; build it by its explicit path.
package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"flag"
	"fmt"
	"os"
	"path"
	"sort"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"

	"github.com/digitsu/konareef/internal/identity"
	"github.com/digitsu/konareef/internal/membridge"
	"github.com/digitsu/konareef/internal/poseidon"
)

// Constants of konareef-rinit/v2 (spec §2, §3, §5).
const (
	keyTagDomain      = "konareef-mem-ktag/v1"   // 20 bytes
	indexDomainV2     = "konareef-mem-idx/v2"    // 19 bytes
	sourceIDDomain    = "konareef-mem-src/v1"    // 19 bytes, unchanged from v1
	leafTableDomainV2 = "konareef-mem-leaves/v2" // 22 bytes
	dtagKey           = 0x20                     // logical-key tag, unchanged from v1
	dtagCellV2        = 0x23                     // v2 payload tag
	payloadLenV2      = 65
	treeDepth         = 20
	indexMask         = 0x0FFFFF
	leafTableHeader   = 22 + 32 + 32 + 4
	leafTableEntry    = 8 + 32 + 32 + 4 + 32
	seamVersion       = "seam/3"
	seamTouchedKey    = "touched_cell_id"
	circuitV12        = "konareef-pod-step-v1.2"
	circuitV11        = "konareef-pod-step-v1.1"
	rInitSchemeV2     = "konareef-rinit/v2"
	testKeyPhrase     = "konareef MEM-SEAM public test key; never use for real signing"
)

// uleb128 returns the minimal unsigned LEB128 encoding of n.
func uleb128(n uint64) []byte {
	out := []byte{}
	for {
		b := byte(n & 0x7f)
		n >>= 7
		if n != 0 {
			out = append(out, b|0x80)
			continue
		}
		return append(out, b)
	}
}

// sha concatenates parts and returns their SHA-256 digest.
func sha(parts ...[]byte) [32]byte {
	return sha256.Sum256(bytes.Join(parts, nil))
}

// logicalKey is the v1 logical key (PRD 4 §3.2.4), unchanged in v2.
// Input: a 32-byte salt and a cell id. Output: the key bytes.
func logicalKey(salt []byte, cellID uint64) []byte {
	id := uleb128(cellID)
	out := []byte{dtagKey}
	out = append(out, uleb128(uint64(len(salt)))...)
	out = append(out, salt...)
	out = append(out, uleb128(uint64(len(id)))...)
	return append(out, id...)
}

// keyTag is SHA-256("konareef-mem-ktag/v1" ‖ logical_key).
func keyTag(lk []byte) [32]byte { return sha([]byte(keyTagDomain), lk) }

// payloadV2 is 0x23 ‖ key_tag ‖ content_hash (65 bytes).
func payloadV2(kt, ch [32]byte) []byte {
	out := []byte{dtagCellV2}
	out = append(out, kt[:]...)
	return append(out, ch[:]...)
}

// indexV2 is be_u32(SHA-256("konareef-mem-idx/v2" ‖ key_tag)[0:4]) & 0x0FFFFF.
func indexV2(kt [32]byte) uint32 {
	d := sha([]byte(indexDomainV2), kt[:])
	return binary.BigEndian.Uint32(d[0:4]) & indexMask
}

// mustVH returns the Poseidon value hash of payload; it panics on error
// because every payload this program hashes is at most 93 bytes.
func mustVH(payload []byte) [32]byte {
	v, err := poseidon.Default().ValueHash(payload)
	if err != nil {
		panic(err)
	}
	return v
}

// mustLeaf returns the Poseidon leaf hash of a value hash.
func mustLeaf(vh [32]byte) [32]byte {
	v, err := poseidon.Default().LeafHash(vh)
	if err != nil {
		panic(err)
	}
	return v
}

// mustNode returns the Poseidon node hash of (l, r).
func mustNode(l, r [32]byte) [32]byte {
	v, err := poseidon.Default().InternalHash(l, r)
	if err != nil {
		panic(err)
	}
	return v
}

// emptyRoots is E0..E20, computed here from the node and leaf hashes.
var emptyRoots = func() [treeDepth + 1][32]byte {
	var e [treeDepth + 1][32]byte
	e[0] = mustLeaf([32]byte{})
	for k := 1; k <= treeDepth; k++ {
		e[k] = mustNode(e[k-1], e[k-1])
	}
	return e
}()

// tree is a depth-20 sparse tree: levels[k] maps a level-k position to its
// hash; absent positions are emptyRoots[k].
type tree struct {
	levels [treeDepth + 1]map[uint32][32]byte
}

// newTree builds the tree over index → value_hash.
func newTree(leaves map[uint32][32]byte) *tree {
	t := &tree{}
	t.levels[0] = map[uint32][32]byte{}
	for i, vh := range leaves {
		t.levels[0][i] = mustLeaf(vh)
	}
	for k := 1; k <= treeDepth; k++ {
		t.levels[k] = map[uint32][32]byte{}
		for pos := range t.levels[k-1] {
			parent := pos >> 1
			if _, done := t.levels[k][parent]; done {
				continue
			}
			t.levels[k][parent] = mustNode(t.at(k-1, parent<<1), t.at(k-1, parent<<1|1))
		}
	}
	return t
}

// at returns the hash at (level, pos).
func (t *tree) at(level int, pos uint32) [32]byte {
	if h, ok := t.levels[level][pos]; ok {
		return h
	}
	return emptyRoots[level]
}

// root returns the tree root.
func (t *tree) root() [32]byte { return t.at(treeDepth, 0) }

// siblings returns the 20 LSB-first siblings of index, level 0 first.
func (t *tree) siblings(index uint32) [][32]byte {
	out := make([][32]byte, treeDepth)
	pos := index
	for k := 0; k < treeDepth; k++ {
		out[k] = t.at(k, pos^1)
		pos >>= 1
	}
	return out
}

// authenticate walks leaf up to the root with LSB-first path bits.
func authenticate(index uint32, leaf [32]byte, sibs [][32]byte) [32]byte {
	cur := leaf
	for k := 0; k < treeDepth; k++ {
		if (index>>uint(k))&1 == 0 {
			cur = mustNode(cur, sibs[k])
		} else {
			cur = mustNode(sibs[k], cur)
		}
	}
	return cur
}

// sourceCellID is the v1 source cell identifier (spec v1 §4.3), unchanged.
func sourceCellID(kind string, locator []byte) uint64 {
	d := sha([]byte(sourceIDDomain), uleb128(uint64(len(kind))), []byte(kind), uleb128(uint64(len(locator))), locator)
	return 1<<63 | binary.BigEndian.Uint64(d[0:8])&^(1<<63)
}

// h is lowercase hex of b.
func h(b []byte) string { return hex.EncodeToString(b) }

// idHex is the 16-lowercase-hex form of a cell id.
func idHex(id uint64) string {
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], id)
	return h(b[:])
}

// mustHex decodes a hex literal of this program.
func mustHex(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}

// hexList renders a list of 32-byte values as hex.
func hexList(xs [][32]byte) []string {
	out := make([]string, len(xs))
	for i, x := range xs {
		out[i] = h(x[:])
	}
	return out
}

// cellIn is one input cell.
type cellIn struct {
	CellID      uint64 `json:"cell_id"`
	ContentHash string `json:"content_hash"`
}

// cellOut is the full v2 derivation of one cell.
type cellOut struct {
	CellIDHex   string `json:"cell_id_hex"`
	ContentHash string `json:"content_hash"`
	LogicalKey  string `json:"logical_key"`
	KeyTag      string `json:"key_tag"`
	Payload     string `json:"payload"`
	ValueHash   string `json:"value_hash"`
	LeafHash    string `json:"leaf_hash"`
	Index       uint32 `json:"index"`
	IndexV1     uint32 `json:"index_v1"`
}

// derived is a cell set after the v2 derivation, ascending cell_id.
type derived struct {
	cells []cellOut
	keyT  [][32]byte
	ch    [][32]byte
	vh    [][32]byte
	idx   []uint32
	ids   []uint64
	tree  *tree
	root  [32]byte
	rootV []byte
}

// deriveV2 runs konareef-rinit/v2 over cells (any order) under salt. It
// panics on a duplicate id or an index collision: the positive vectors
// never contain one, and the negative vectors build theirs separately.
func deriveV2(salt []byte, cells []cellIn) derived {
	sorted := append([]cellIn(nil), cells...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].CellID < sorted[j].CellID })
	d := derived{}
	leaves := map[uint32][32]byte{}
	for _, c := range sorted {
		var ch [32]byte
		copy(ch[:], mustHex(c.ContentHash))
		lk := logicalKey(salt, c.CellID)
		kt := keyTag(lk)
		p := payloadV2(kt, ch)
		vh := mustVH(p)
		idx := indexV2(kt)
		if _, taken := leaves[idx]; taken {
			panic("index collision in a positive vector")
		}
		leaves[idx] = vh
		lf := mustLeaf(vh)
		v1, err := membridge.CellIndex(salt, c.CellID)
		if err != nil {
			panic(err)
		}
		d.cells = append(d.cells, cellOut{
			CellIDHex: idHex(c.CellID), ContentHash: h(ch[:]), LogicalKey: h(lk), KeyTag: h(kt[:]),
			Payload: h(p), ValueHash: h(vh[:]), LeafHash: h(lf[:]), Index: idx, IndexV1: v1,
		})
		d.keyT = append(d.keyT, kt)
		d.ch = append(d.ch, ch)
		d.vh = append(d.vh, vh)
		d.idx = append(d.idx, idx)
		d.ids = append(d.ids, c.CellID)
	}
	d.tree = newTree(leaves)
	d.root = d.tree.root()
	return d
}

// rInitV1 is the production konareef-rinit/v1 root, for contrast fields.
func rInitV1(salt []byte, cells []cellIn) string {
	mc := make([]membridge.Cell, len(cells))
	for i, c := range cells {
		mc[i] = membridge.Cell{CellID: c.CellID, ContentHash: mustHex(c.ContentHash)}
	}
	r, _, err := membridge.RInitV1(salt, mc)
	if err != nil {
		panic(err)
	}
	return h(r[:])
}

// cellVector is one cell_vectors entry.
type cellVector struct {
	ID       string    `json:"id"`
	PodSalt  string    `json:"pod_salt"`
	Cells    []cellIn  `json:"cells"`
	Derived  []cellOut `json:"derived"`
	RInit    string    `json:"r_init"`
	RInitV1  string    `json:"r_init_v1"`
	Contrast string    `json:"contrast"`
}

// source is one [[context.memory]] entry of a source vector.
type source struct {
	Kind          string `json:"kind"`
	Path          string `json:"path,omitempty"`
	FileBytesUTF8 string `json:"file_bytes_utf8,omitempty"`
	Content       string `json:"content,omitempty"`
}

// sourceVector is one source_vectors entry.
type sourceVector struct {
	ID                string    `json:"id"`
	PodSalt           string    `json:"pod_salt"`
	Sources           []source  `json:"sources"`
	Derived           []cellOut `json:"derived"`
	RInit             string    `json:"r_init"`
	RInitV1           string    `json:"r_init_v1"`
	TouchedCellID     string    `json:"touched_cell_id"`
	TouchedIndex      uint32    `json:"touched_index"`
	TouchedDeclaredAt int       `json:"touched_declared_position"`
}

// sourceCells resolves sources the v1 way (spec v1 §4.2–§4.3).
func sourceCells(srcs []source) []cellIn {
	out := []cellIn{}
	for _, s := range srcs {
		switch s.Kind {
		case "file":
			loc := path.Clean(s.Path)
			ch := sha256.Sum256([]byte(s.FileBytesUTF8))
			out = append(out, cellIn{CellID: sourceCellID("file", []byte(loc)), ContentHash: h(ch[:])})
		case "inline":
			ch := sha256.Sum256([]byte(s.Content))
			out = append(out, cellIn{CellID: sourceCellID("inline", ch[:]), ContentHash: h(ch[:])})
		default:
			panic("unsupported kind in a vector")
		}
	}
	return out
}

// leafTableV2 returns the canonical v2 leaf-table bytes (spec §3).
func leafTableV2(podHash, rInit [32]byte, ids []uint64, ch, kt [][32]byte, idx []uint32, vh [][32]byte) []byte {
	out := []byte(leafTableDomainV2)
	out = append(out, podHash[:]...)
	out = append(out, rInit[:]...)
	out = binary.BigEndian.AppendUint32(out, uint32(len(ids)))
	for i := range ids {
		out = binary.BigEndian.AppendUint64(out, ids[i])
		out = append(out, ch[i][:]...)
		out = append(out, kt[i][:]...)
		out = binary.BigEndian.AppendUint32(out, idx[i])
		out = append(out, vh[i][:]...)
	}
	return out
}

// leafTableVector is one leaf_table_vectors entry.
type leafTableVector struct {
	ID                 string   `json:"id"`
	Source             string   `json:"source_vector"`
	PodHash            string   `json:"pod_hash"`
	PublisherPubkeyHex string   `json:"publisher_pubkey_hex"`
	RInit              string   `json:"r_init"`
	TableHex           string   `json:"table_hex"`
	TableSHA256        string   `json:"table_sha256"`
	SignatureB64       string   `json:"signature_b64"`
	Expected           string   `json:"expected"`
	ExpectedRefusal    string   `json:"expected_refusal,omitempty"`
	RefusedBy          []string `json:"refused_by"`
	ReefCoreStructural string   `json:"reef_core_structural"`
	Why                string   `json:"why"`
}

// seamDocVector is one seam3_document_vectors entry: the whole
// step-disclosure.json a seam/3 writer produces, byte for byte.
type seamDocVector struct {
	ID                string `json:"id"`
	Source            string `json:"source_vector"`
	StepDisclosure    string `json:"step_disclosure_json"`
	StepDisclosureSHA string `json:"step_disclosure_sha256"`
	Why               string `json:"why"`
}

// lane is the PS-1 pod_record.memory lane v2 in hex (spec §6).
type lane struct {
	RInit       string   `json:"r_init"`
	Index       uint32   `json:"index"`
	ValueHashIn string   `json:"value_hash_in"`
	Siblings    []string `json:"siblings"`
	KeyTag      string   `json:"key_tag"`
	ContentHash string   `json:"content_hash"`
}

// touchedVector is one touched_cell_vectors entry.
type touchedVector struct {
	ID               string `json:"id"`
	Source           string `json:"source_vector"`
	SeamVersion      string `json:"seam_version"`
	SeamStepIndex    int    `json:"seam_step_index"`
	SeamTouchedJSON  string `json:"seam_touched_cell_id_json"`
	TouchedCellID    string `json:"touched_cell_id"`
	Lane             lane   `json:"ps1_memory_lane"`
	PayloadIn        string `json:"payload_in"`
	ValueHashOut     string `json:"value_hash_out"`
	ROut             string `json:"r_out"`
	CircuitID        string `json:"circuit_id"`
	AuthenticatesToR bool   `json:"authenticates_to_r_init"`
}

// negativeVector is one negative_vectors entry: a mutated input and the
// refusal every listed layer must give.
type negativeVector struct {
	ID              string            `json:"id"`
	Base            string            `json:"base"`
	Layer           []string          `json:"refused_by"`
	ExpectedRefusal string            `json:"expected_refusal"`
	Mutation        string            `json:"mutation"`
	Seam            string            `json:"seam_touched_cell_id_json,omitempty"`
	Lane            *lane             `json:"ps1_memory_lane,omitempty"`
	PayloadIn       string            `json:"payload_in,omitempty"`
	Facts           map[string]string `json:"facts"`
}

// derivationNegative is one derivation_negative_vectors entry.
type derivationNegative struct {
	ID              string   `json:"id"`
	PodSalt         string   `json:"pod_salt"`
	Cells           []cellIn `json:"cells"`
	ExpectedRefusal string   `json:"expected_refusal"`
	Indices         []uint32 `json:"indices_v2"`
	Why             string   `json:"why"`
}

// memoryFreeVector is the memory-free seam and witness rule.
type memoryFreeVector struct {
	ID                string `json:"id"`
	InitialMemoryJSON string `json:"initial_memory_json"`
	TouchedCellID     any    `json:"touched_cell_id"`
	RInit             string `json:"r_init"`
	Lane              any    `json:"ps1_memory_lane"`
	CircuitID         string `json:"circuit_id"`
	Why               string `json:"why"`
}

// file is the whole vector file.
type file struct {
	Title       string               `json:"title"`
	Status      string               `json:"status"`
	Spec        string               `json:"spec"`
	Generator   string               `json:"generator"`
	Provenance  map[string]string    `json:"provenance"`
	Constants   map[string]any       `json:"constants"`
	Signer      map[string]string    `json:"signer"`
	CellVectors []cellVector         `json:"cell_vectors"`
	SourceVecs  []sourceVector       `json:"source_vectors"`
	LeafTables  []leafTableVector    `json:"leaf_table_vectors"`
	Touched     []touchedVector      `json:"touched_cell_vectors"`
	MemoryFree  memoryFreeVector     `json:"memory_free_vector"`
	SeamDocs    []seamDocVector      `json:"seam3_document_vectors"`
	Negative    []negativeVector     `json:"negative_vectors"`
	DerivNeg    []derivationNegative `json:"derivation_negative_vectors"`
}

// testIdentity is the MEM-SEAM public test key (internal/feeder
// mem_seam_golden_test.go). It signs only test vectors.
func testIdentity() *identity.Identity {
	scalar := sha256.Sum256([]byte(testKeyPhrase))
	priv := secp256k1.PrivKeyFromBytes(scalar[:])
	return &identity.Identity{
		Handle:        "rinit-v2-fixture",
		PublicKeyHex:  hex.EncodeToString(priv.PubKey().SerializeCompressed()),
		PrivateKeyHex: hex.EncodeToString(priv.Serialize()),
	}
}

// sign signs b with the test key (deterministic, RFC 6979).
func sign(b []byte) string {
	sig, err := testIdentity().Sign(b)
	if err != nil {
		panic(err)
	}
	return base64.StdEncoding.EncodeToString(sig)
}

func main() {
	out := flag.String("out", "-", "output path, or - for stdout")
	flag.Parse()
	b, err := build()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	if *out == "-" {
		os.Stdout.Write(b)
		return
	}
	if err := os.WriteFile(*out, b, 0o644); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
