// Copyright 2026 Jerry David Chan, Konareef.ai
// SPDX-License-Identifier: Apache-2.0

// internal/membridge/rinit_v2_vectors_test.go — second, independent check
// of the konareef-rinit/v2 shared vectors (CL-4-live step 1, reef-core#84).
//
// Spec: docs/reference/konareef-rinit-v2-spec.md. Vectors:
// testdata/rinit_v2/vectors.json, written by the generator in
// testdata/rinit_v2/gen.
//
// The generator has its own v2 implementation. This file re-derives every
// value with a second implementation that reuses the reviewed v1 pieces
// of this package (LogicalKey, CellIndex, SourceCellID, ResolveSources,
// RInitV1, SparseRoot, BuildAuthPath, VerifyAuthPath) and the pinned
// Poseidon primitive. It also holds test-local versions of the spec's
// run-time refusals (refV2LeafTableCheck, refV2SeamCheck, refV2LaneCheck)
// and checks that each negative vector gets exactly its expected code.
//
// CL-4-live step 2 added the v2 production code; rinit_v2_test.go runs
// the same vectors through it.
package membridge

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/digitsu/konareef/internal/identity"
	"github.com/digitsu/konareef/internal/poseidon"
)

// rinitV2VectorsPath is the committed vector file.
var rinitV2VectorsPath = filepath.Join("testdata", "rinit_v2", "vectors.json")

// Spec §2–§5 constants, written out again here on purpose.
var (
	refV2KeyTagDomain = []byte("konareef-mem-ktag/v1")
	refV2IndexDomain  = []byte("konareef-mem-idx/v2")
	refV2TableDomain  = []byte("konareef-mem-leaves/v2")
)

const (
	refV2DTagCell   = 0x23
	refV2PayloadLen = 65
	refV2EntryLen   = 108
	refV2HeaderLen  = 90
)

// v2Lane is the PS-1 memory lane in vector form.
type v2Lane struct {
	RInit       string   `json:"r_init"`
	Index       uint32   `json:"index"`
	ValueHashIn string   `json:"value_hash_in"`
	Siblings    []string `json:"siblings"`
	KeyTag      string   `json:"key_tag"`
	ContentHash string   `json:"content_hash"`
}

// v2Derived is one derived cell of a vector.
type v2Derived struct {
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

// v2Source is one [[context.memory]] entry of a source vector.
type v2Source struct {
	Kind          string `json:"kind"`
	Path          string `json:"path"`
	FileBytesUTF8 string `json:"file_bytes_utf8"`
	Content       string `json:"content"`
}

// v2File is the parsed vector file (only the fields the checks read).
type v2File struct {
	Constants map[string]any    `json:"constants"`
	Signer    map[string]string `json:"signer"`
	Cells     []struct {
		ID      string `json:"id"`
		PodSalt string `json:"pod_salt"`
		Cells   []struct {
			CellID      uint64 `json:"cell_id"`
			ContentHash string `json:"content_hash"`
		} `json:"cells"`
		Derived []v2Derived `json:"derived"`
		RInit   string      `json:"r_init"`
		RInitV1 string      `json:"r_init_v1"`
	} `json:"cell_vectors"`
	Sources []struct {
		ID                string      `json:"id"`
		PodSalt           string      `json:"pod_salt"`
		Sources           []v2Source  `json:"sources"`
		Derived           []v2Derived `json:"derived"`
		RInit             string      `json:"r_init"`
		RInitV1           string      `json:"r_init_v1"`
		TouchedCellID     string      `json:"touched_cell_id"`
		TouchedIndex      uint32      `json:"touched_index"`
		TouchedDeclaredAt int         `json:"touched_declared_position"`
	} `json:"source_vectors"`
	LeafTables []struct {
		ID              string   `json:"id"`
		Source          string   `json:"source_vector"`
		PodHash         string   `json:"pod_hash"`
		PubKey          string   `json:"publisher_pubkey_hex"`
		RInit           string   `json:"r_init"`
		TableHex        string   `json:"table_hex"`
		TableSHA256     string   `json:"table_sha256"`
		SignatureB64    string   `json:"signature_b64"`
		Expected        string   `json:"expected"`
		ExpectedRefusal string   `json:"expected_refusal"`
		RefusedBy       []string `json:"refused_by"`
		Structural      string   `json:"reef_core_structural"`
	} `json:"leaf_table_vectors"`
	SeamDocs []struct {
		ID     string `json:"id"`
		Source string `json:"source_vector"`
		Doc    string `json:"step_disclosure_json"`
		SHA    string `json:"step_disclosure_sha256"`
	} `json:"seam3_document_vectors"`
	Touched []struct {
		ID              string `json:"id"`
		Source          string `json:"source_vector"`
		SeamVersion     string `json:"seam_version"`
		SeamStepIndex   int    `json:"seam_step_index"`
		SeamTouchedJSON string `json:"seam_touched_cell_id_json"`
		TouchedCellID   string `json:"touched_cell_id"`
		Lane            v2Lane `json:"ps1_memory_lane"`
		PayloadIn       string `json:"payload_in"`
		ValueHashOut    string `json:"value_hash_out"`
		ROut            string `json:"r_out"`
		CircuitID       string `json:"circuit_id"`
	} `json:"touched_cell_vectors"`
	MemoryFree struct {
		InitialMemoryJSON string `json:"initial_memory_json"`
		TouchedCellID     any    `json:"touched_cell_id"`
		RInit             string `json:"r_init"`
		Lane              any    `json:"ps1_memory_lane"`
		CircuitID         string `json:"circuit_id"`
	} `json:"memory_free_vector"`
	Negative []struct {
		ID              string            `json:"id"`
		Base            string            `json:"base"`
		RefusedBy       []string          `json:"refused_by"`
		ExpectedRefusal string            `json:"expected_refusal"`
		Seam            string            `json:"seam_touched_cell_id_json"`
		Lane            *v2Lane           `json:"ps1_memory_lane"`
		PayloadIn       string            `json:"payload_in"`
		Facts           map[string]string `json:"facts"`
	} `json:"negative_vectors"`
	DerivNeg []struct {
		ID      string `json:"id"`
		PodSalt string `json:"pod_salt"`
		Cells   []struct {
			CellID      uint64 `json:"cell_id"`
			ContentHash string `json:"content_hash"`
		} `json:"cells"`
		ExpectedRefusal string   `json:"expected_refusal"`
		Indices         []uint32 `json:"indices_v2"`
	} `json:"derivation_negative_vectors"`
}

// loadV2 reads and parses the vector file.
func loadV2(t *testing.T) v2File {
	t.Helper()
	raw, err := os.ReadFile(rinitV2VectorsPath)
	if err != nil {
		t.Fatal(err)
	}
	var f v2File
	if err := json.Unmarshal(raw, &f); err != nil {
		t.Fatal(err)
	}
	return f
}

// hx decodes hex or fails the test.
func hx(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("bad hex %q: %v", s, err)
	}
	return b
}

// hx32 decodes 32-byte hex or fails the test.
func hx32(t *testing.T, s string) [32]byte {
	t.Helper()
	var out [32]byte
	b := hx(t, s)
	if len(b) != 32 {
		t.Fatalf("want 32 bytes, got %d", len(b))
	}
	copy(out[:], b)
	return out
}

// refV2KeyTag is SHA-256("konareef-mem-ktag/v1" ‖ logical_key).
func refV2KeyTag(lk []byte) [32]byte {
	return sha256.Sum256(append(append([]byte(nil), refV2KeyTagDomain...), lk...))
}

// refV2Index is be_u32(SHA-256("konareef-mem-idx/v2" ‖ key_tag)[0:4]) & 0x0FFFFF.
func refV2Index(kt [32]byte) uint32 {
	d := sha256.Sum256(append(append([]byte(nil), refV2IndexDomain...), kt[:]...))
	return binary.BigEndian.Uint32(d[:4]) & 0x0FFFFF
}

// refV2Payload is 0x23 ‖ key_tag ‖ content_hash.
func refV2Payload(kt, ch [32]byte) []byte {
	return append(append([]byte{refV2DTagCell}, kt[:]...), ch[:]...)
}

// refV2VH is the Poseidon value hash of a payload.
func refV2VH(t *testing.T, payload []byte) [32]byte {
	t.Helper()
	v, err := poseidon.Default().ValueHash(payload)
	if err != nil {
		t.Fatal(err)
	}
	return v
}

// refV2RInit is the reference konareef-rinit/v2 derivation (spec §2).
//
// Inputs: a salt and cells in any order. Output: the root, the
// index → value_hash map, or the first refusal in spec order.
func refV2RInit(t *testing.T, salt []byte, cells []Cell) ([32]byte, map[uint32][32]byte, error) {
	t.Helper()
	if len(salt) != 32 {
		return [32]byte{}, nil, ErrCellSaltLen
	}
	if err := EnforceHardCap(len(cells)); err != nil {
		return [32]byte{}, nil, err
	}
	sorted := append([]Cell(nil), cells...)
	sort.SliceStable(sorted, func(i, j int) bool { return sorted[i].CellID < sorted[j].CellID })
	leaves := map[uint32][32]byte{}
	for i, c := range sorted {
		if i > 0 && sorted[i-1].CellID == c.CellID {
			return [32]byte{}, nil, ErrCellDuplicateID
		}
		lk, err := LogicalKey(salt, c.CellID)
		if err != nil {
			return [32]byte{}, nil, err
		}
		kt := refV2KeyTag(lk)
		var ch [32]byte
		copy(ch[:], c.ContentHash)
		idx := refV2Index(kt)
		if _, taken := leaves[idx]; taken {
			return [32]byte{}, nil, ErrCellIndexCollision
		}
		vh := refV2VH(t, refV2Payload(kt, ch))
		if vh == EmptyValueHash {
			return [32]byte{}, nil, ErrValueHashZero
		}
		leaves[idx] = vh
	}
	root, err := SparseRoot(leaves)
	return root, leaves, err
}

// v2Row is one parsed v2 leaf-table row.
type v2Row struct {
	CellID                     uint64
	ContentHash, KeyTag, Value [32]byte
	Index                      uint32
}

// refV2LeafTableCheck applies the spec §3 canonical form and the §4 R-M20
// v2 salt-free row and root checks. Output: "" or the refusal code.
func refV2LeafTableCheck(t *testing.T, b []byte) string {
	t.Helper()
	if len(b) < refV2HeaderLen || !bytes.Equal(b[:22], refV2TableDomain) {
		return "MEMORY_LEAF_TABLE_INVALID"
	}
	var rInit [32]byte
	copy(rInit[:], b[54:86])
	n := binary.BigEndian.Uint32(b[86:90])
	body := b[90:]
	if n == 0 || n > HardCapK || uint64(len(body)) != uint64(n)*refV2EntryLen || !canonicalFq(rInit) {
		return "MEMORY_LEAF_TABLE_INVALID"
	}
	leaves := map[uint32][32]byte{}
	var prev uint64
	for i := 0; i < int(n); i++ {
		e := body[i*refV2EntryLen : (i+1)*refV2EntryLen]
		var r v2Row
		r.CellID = binary.BigEndian.Uint64(e[0:8])
		copy(r.ContentHash[:], e[8:40])
		copy(r.KeyTag[:], e[40:72])
		r.Index = binary.BigEndian.Uint32(e[72:76])
		copy(r.Value[:], e[76:108])
		if r.CellID>>63 != 1 || (i > 0 && r.CellID <= prev) || r.Index >= 1<<D {
			return "MEMORY_LEAF_TABLE_INVALID"
		}
		if _, dup := leaves[r.Index]; dup || r.Value == EmptyValueHash || !canonicalFq(r.Value) {
			return "MEMORY_LEAF_TABLE_INVALID"
		}
		if r.Index != refV2Index(r.KeyTag) || r.Value != refV2VH(t, refV2Payload(r.KeyTag, r.ContentHash)) {
			return "MEMORY_LEAF_TABLE_INVALID"
		}
		leaves[r.Index] = r.Value
		prev = r.CellID
	}
	root, err := SparseRoot(leaves)
	if err != nil || root != rInit {
		return "ERR_RINIT_MISMATCH"
	}
	return ""
}

// refV2LeafTableStructural applies only the spec §3 structural rules, the
// part reef-core runs: no index, key_tag, value_hash or root recompute.
// Output: "accept" or "refuse".
func refV2LeafTableStructural(b []byte) string {
	if len(b) < refV2HeaderLen || !bytes.Equal(b[:22], refV2TableDomain) {
		return "refuse"
	}
	var rInit [32]byte
	copy(rInit[:], b[54:86])
	n := binary.BigEndian.Uint32(b[86:90])
	body := b[90:]
	if n == 0 || n > HardCapK || uint64(len(body)) != uint64(n)*refV2EntryLen || !canonicalFq(rInit) {
		return "refuse"
	}
	seen := map[uint32]bool{}
	var prev uint64
	for i := 0; i < int(n); i++ {
		e := body[i*refV2EntryLen : (i+1)*refV2EntryLen]
		id := binary.BigEndian.Uint64(e[0:8])
		idx := binary.BigEndian.Uint32(e[72:76])
		var vh [32]byte
		copy(vh[:], e[76:108])
		if id>>63 != 1 || (i > 0 && id <= prev) || idx >= 1<<D || seen[idx] || vh == EmptyValueHash || !canonicalFq(vh) {
			return "refuse"
		}
		seen[idx], prev = true, id
	}
	return "accept"
}

// refV2SeamCheck applies the spec §5 seam rule to a `"touched_cell_id":…`
// fragment ("" = key absent). Output: "" or the refusal code.
func refV2SeamCheck(fragment string, committed []uint64) string {
	if fragment == "" {
		if len(committed) > 0 {
			return "MEMORY_TOUCHED_CELL_INVALID"
		}
		return ""
	}
	if len(committed) == 0 {
		return "MEMORY_TOUCHED_CELL_INVALID"
	}
	var obj map[string]json.RawMessage
	if err := json.Unmarshal([]byte("{"+fragment+"}"), &obj); err != nil {
		return "MEMORY_TOUCHED_CELL_INVALID"
	}
	var s string
	if json.Unmarshal(obj["touched_cell_id"], &s) != nil || len(s) != 16 || strings.ToLower(s) != s {
		return "MEMORY_TOUCHED_CELL_INVALID"
	}
	b, err := hex.DecodeString(s)
	if err != nil {
		return "MEMORY_TOUCHED_CELL_INVALID"
	}
	id := binary.BigEndian.Uint64(b)
	if id>>63 != 1 {
		return "MEMORY_TOUCHED_CELL_INVALID"
	}
	lowest := committed[0]
	for _, c := range committed {
		if c < lowest {
			lowest = c
		}
	}
	if id != lowest {
		return "MEMORY_TOUCHED_CELL_MISMATCH"
	}
	return ""
}

// refV2LaneCheck applies the spec §6 PS-1 checks and the v1.2 circuit
// relation to a lane and a payload_in. It holds no leaf table, as PS-1
// holds none. valueHashOut is the step's written value.
// Output: "" or the first refusal code, in spec §6 order.
func refV2LaneCheck(t *testing.T, l v2Lane, payload []byte, valueHashOut [32]byte) string {
	t.Helper()
	rInit, vhIn := hx32(t, l.RInit), hx32(t, l.ValueHashIn)
	kt, ch := hx32(t, l.KeyTag), hx32(t, l.ContentHash)
	if vhIn == EmptyValueHash {
		return "MEMORY_EMPTY_SLOT_READ"
	}
	if len(payload) != refV2PayloadLen || payload[0] != refV2DTagCell || !bytes.Equal(payload, refV2Payload(kt, ch)) ||
		refV2VH(t, payload) != vhIn {
		return "MEMORY_PAYLOAD_MISMATCH"
	}
	var path [D][32]byte
	for k, s := range l.Siblings {
		path[k] = hx32(t, s)
	}
	leaf, err := LeafHash(vhIn)
	if err != nil {
		t.Fatal(err)
	}
	got, err := VerifyAuthPath(l.Index, leaf, path)
	if err != nil || got != rInit || l.Index != refV2Index(kt) {
		return "MEMORY_INDEX_MISMATCH"
	}
	if valueHashOut != vhIn {
		return "MEMORY_WRITE_REFUSED"
	}
	return ""
}

// v2SourceCells resolves a vector's sources with the production v1 resolver.
func v2SourceCells(t *testing.T, srcs []v2Source) []Cell {
	t.Helper()
	ms := make([]MemorySource, 0, len(srcs))
	digests := map[string][32]byte{}
	for _, s := range srcs {
		m := MemorySource{Kind: s.Kind, Path: s.Path, Content: s.Content}
		if s.Kind == SourceKindFile {
			m.Loaded = []byte(s.FileBytesUTF8)
			digests[FilesKey(s.Path)] = sha256.Sum256(m.Loaded)
		}
		ms = append(ms, m)
	}
	cells, err := ResolveSources(ms, digests)
	if err != nil {
		t.Fatal(err)
	}
	return cells
}

// checkDerived re-derives each listed cell and compares every field.
func checkDerived(t *testing.T, id string, salt []byte, cells []Cell, got []v2Derived) {
	t.Helper()
	sorted := append([]Cell(nil), cells...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].CellID < sorted[j].CellID })
	if len(got) != len(sorted) {
		t.Fatalf("%s: %d derived cells, want %d", id, len(got), len(sorted))
	}
	for i, c := range sorted {
		lk, err := LogicalKey(salt, c.CellID)
		if err != nil {
			t.Fatal(err)
		}
		kt := refV2KeyTag(lk)
		var ch [32]byte
		copy(ch[:], c.ContentHash)
		p := refV2Payload(kt, ch)
		vh := refV2VH(t, p)
		lf, err := LeafHash(vh)
		if err != nil {
			t.Fatal(err)
		}
		v1, err := CellIndex(salt, c.CellID)
		if err != nil {
			t.Fatal(err)
		}
		var idb [8]byte
		binary.BigEndian.PutUint64(idb[:], c.CellID)
		want := v2Derived{
			CellIDHex: hex.EncodeToString(idb[:]), ContentHash: hex.EncodeToString(ch[:]),
			LogicalKey: hex.EncodeToString(lk), KeyTag: hex.EncodeToString(kt[:]), Payload: hex.EncodeToString(p),
			ValueHash: hex.EncodeToString(vh[:]), LeafHash: hex.EncodeToString(lf[:]), Index: refV2Index(kt), IndexV1: v1,
		}
		if got[i] != want {
			t.Errorf("%s cell %d:\n got %+v\nwant %+v", id, i, got[i], want)
		}
		if len(p) != refV2PayloadLen {
			t.Errorf("%s cell %d: payload %d bytes", id, i, len(p))
		}
	}
}

// TestRInitV2VectorsGenerator runs the committed generator and refuses any
// byte difference from the committed file (determinism and drift).
func TestRInitV2VectorsGenerator(t *testing.T) {
	if testing.Short() {
		t.Skip("runs the generator with the go tool")
	}
	goTool, err := exec.LookPath("go")
	if err != nil {
		t.Skip("go tool not on PATH")
	}
	cmd := exec.Command(goTool, "run", "./testdata/rinit_v2/gen", "-out", "-")
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("generator: %v\n%s", err, stderr.String())
	}
	want, err := os.ReadFile(rinitV2VectorsPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(out, want) {
		t.Fatalf("generator output differs from %s; regenerate it (see the file's generator field)", rinitV2VectorsPath)
	}
}

// TestRInitV2Constants pins the spec constants in the file.
func TestRInitV2Constants(t *testing.T) {
	f := loadV2(t)
	want := map[string]any{
		"key_tag_domain": "konareef-mem-ktag/v1", "index_domain_v2": "konareef-mem-idx/v2",
		"leaf_table_domain_v2": "konareef-mem-leaves/v2", "dtag_cell_v2": "23", "payload_len": float64(65),
		"leaf_table_entry_len": float64(108), "leaf_table_header_len": float64(90), "seam_version": "seam/3",
		"seam_touched_key": "touched_cell_id", "r_init_scheme": "konareef-rinit/v2",
		"circuit_id_memory_bearing": "konareef-pod-step-v1.2", "circuit_id_memory_free": "konareef-pod-step-v1.1",
		"E20": hex.EncodeToString(EmptyRoots[D][:]), "E0": hex.EncodeToString(EmptyRoots[0][:]),
	}
	for k, v := range want {
		if f.Constants[k] != v {
			t.Errorf("constant %s = %v, want %v", k, f.Constants[k], v)
		}
	}
}

// TestRInitV2CellVectors re-derives the PRD 4 cell sets under v2 and
// checks that v2 differs from v1 except on the empty set.
func TestRInitV2CellVectors(t *testing.T) {
	f := loadV2(t)
	if len(f.Cells) != 5 {
		t.Fatalf("want 5 cell vectors, got %d", len(f.Cells))
	}
	for _, v := range f.Cells {
		salt := hx(t, v.PodSalt)
		cells := make([]Cell, len(v.Cells))
		for i, c := range v.Cells {
			cells[i] = Cell{CellID: c.CellID, ContentHash: hx(t, c.ContentHash)}
		}
		checkDerived(t, v.ID, salt, cells, v.Derived)
		root, _, err := refV2RInit(t, salt, cells)
		if err != nil {
			t.Fatal(err)
		}
		if hex.EncodeToString(root[:]) != v.RInit {
			t.Errorf("%s: r_init %x, want %s", v.ID, root, v.RInit)
		}
		v1, _, err := RInitV1(salt, cells)
		if err != nil {
			t.Fatal(err)
		}
		if hex.EncodeToString(v1[:]) != v.RInitV1 {
			t.Errorf("%s: r_init_v1 %x, want %s", v.ID, v1, v.RInitV1)
		}
		if (len(cells) == 0) != (v.RInit == v.RInitV1) {
			t.Errorf("%s: v2 root equals v1 root only for the empty set", v.ID)
		}
	}
}

// TestRInitV2SourceVectorsAndTouchedRule checks the source derivation and
// the T-A rule: the touched cell is the lowest cell_id, wherever declared.
func TestRInitV2SourceVectorsAndTouchedRule(t *testing.T) {
	f := loadV2(t)
	declaredLast := false
	for _, v := range f.Sources {
		salt := hx(t, v.PodSalt)
		cells := v2SourceCells(t, v.Sources)
		checkDerived(t, v.ID, salt, cells, v.Derived)
		root, leaves, err := refV2RInit(t, salt, cells)
		if err != nil {
			t.Fatal(err)
		}
		if hex.EncodeToString(root[:]) != v.RInit {
			t.Errorf("%s: r_init mismatch", v.ID)
		}
		lowest, pos := cells[0].CellID, 0
		for i, c := range cells {
			if c.CellID < lowest {
				lowest, pos = c.CellID, i
			}
		}
		var idb [8]byte
		binary.BigEndian.PutUint64(idb[:], lowest)
		if v.TouchedCellID != hex.EncodeToString(idb[:]) || v.TouchedDeclaredAt != pos {
			t.Errorf("%s: touched %s at %d, want %x at %d", v.ID, v.TouchedCellID, v.TouchedDeclaredAt, idb, pos)
		}
		if v.TouchedIndex == 0 || leaves[v.TouchedIndex] == EmptyValueHash {
			t.Errorf("%s: touched index %d is zero or empty", v.ID, v.TouchedIndex)
		}
		if pos == len(cells)-1 && len(cells) > 1 {
			declaredLast = true
		}
	}
	if !declaredLast {
		t.Error("want a source vector whose touched cell is declared last")
	}
}

// TestRInitV2LeafTables checks every table: canonical bytes, digest,
// signature, and the accept or refusal the vector names.
func TestRInitV2LeafTables(t *testing.T) {
	f := loadV2(t)
	tables := map[string]string{}
	for _, v := range f.LeafTables {
		b := hx(t, v.TableHex)
		sum := sha256.Sum256(b)
		if hex.EncodeToString(sum[:]) != v.TableSHA256 {
			t.Errorf("%s: table_sha256 mismatch", v.ID)
		}
		sig, err := base64.StdEncoding.DecodeString(v.SignatureB64)
		if err != nil {
			t.Fatal(err)
		}
		ok, err := identity.Verify(v.PubKey, b, sig)
		if err != nil || !ok || v.PubKey != f.Signer["public_key_hex"] {
			t.Errorf("%s: signature does not verify", v.ID)
		}
		got := refV2LeafTableCheck(t, b)
		structural := refV2LeafTableStructural(b)
		byReef := false
		for _, l := range v.RefusedBy {
			byReef = byReef || l == "reef-core"
		}
		if structural != v.Structural || byReef != (structural == "refuse") {
			t.Errorf("%s: reef-core structural %s, vector says %s (refused_by %v)", v.ID, structural, v.Structural, v.RefusedBy)
		}
		switch v.Expected {
		case "accept":
			if got != "" {
				t.Errorf("%s: refused with %s, want accept", v.ID, got)
			}
			if !bytes.Equal(b[22:54], hx(t, v.PodHash)) || !bytes.Equal(b[54:86], hx(t, v.RInit)) {
				t.Errorf("%s: header mismatch", v.ID)
			}
			tables[v.ID] = v.RInit
		case "refuse":
			if got != v.ExpectedRefusal {
				t.Errorf("%s: got %q, want %q", v.ID, got, v.ExpectedRefusal)
			}
		default:
			t.Errorf("%s: unknown expected %q", v.ID, v.Expected)
		}
	}
	for _, s := range f.Sources {
		if tables[s.ID] != s.RInit {
			t.Errorf("source vector %s has no accepted table with its r_init", s.ID)
		}
	}
}

// TestRInitV2TouchedVectors checks the honest lane of each source vector:
// it equals the tree's path, passes every check, and reads (r_out = r_init).
func TestRInitV2TouchedVectors(t *testing.T) {
	f := loadV2(t)
	if len(f.Touched) != len(f.Sources) {
		t.Fatalf("want one touched vector per source vector")
	}
	for i, v := range f.Touched {
		sv := f.Sources[i]
		_, leaves, err := refV2RInit(t, hx(t, sv.PodSalt), v2SourceCells(t, sv.Sources))
		if err != nil {
			t.Fatal(err)
		}
		path, err := BuildAuthPath(leaves, v.Lane.Index)
		if err != nil {
			t.Fatal(err)
		}
		for k := range path {
			if hex.EncodeToString(path[k][:]) != v.Lane.Siblings[k] {
				t.Errorf("%s: sibling %d mismatch", v.ID, k)
			}
		}
		if code := refV2LaneCheck(t, v.Lane, hx(t, v.PayloadIn), hx32(t, v.ValueHashOut)); code != "" {
			t.Errorf("%s: honest lane refused with %s", v.ID, code)
		}
		if v.TouchedCellID != sv.TouchedCellID || v.Lane.Index != sv.TouchedIndex || v.ROut != sv.RInit ||
			v.Lane.RInit != sv.RInit || v.ValueHashOut != v.Lane.ValueHashIn {
			t.Errorf("%s: lane does not match its source vector or is not a read", v.ID)
		}
		if v.SeamVersion != "seam/3" || v.SeamStepIndex != 0 || v.CircuitID != "konareef-pod-step-v1.2" {
			t.Errorf("%s: seam or circuit fields wrong", v.ID)
		}
		ids := []uint64{}
		for _, c := range v2SourceCells(t, sv.Sources) {
			ids = append(ids, c.CellID)
		}
		if code := refV2SeamCheck(v.SeamTouchedJSON, ids); code != "" {
			t.Errorf("%s: honest seam refused with %s", v.ID, code)
		}
	}
	mf := f.MemoryFree
	if mf.TouchedCellID != nil || mf.Lane != nil || mf.RInit != hex.EncodeToString(EmptyRoots[D][:]) ||
		mf.CircuitID != "konareef-pod-step-v1.1" || refV2SeamCheck("", nil) != "" ||
		refV2SeamCheck(`"touched_cell_id":"81ed77926d26caf9"`, nil) != "MEMORY_TOUCHED_CELL_INVALID" {
		t.Error("memory-free vector or rule wrong")
	}
}

// TestRInitV2NegativeVectors checks that each negative vector gets
// exactly its expected refusal, and that the facts it states hold.
func TestRInitV2NegativeVectors(t *testing.T) {
	f := loadV2(t)
	var base struct {
		ids    []uint64
		leaves map[uint32][32]byte
		honest v2Lane
	}
	for i, sv := range f.Sources {
		if sv.ID != "file-inline-file-multi" {
			continue
		}
		cells := v2SourceCells(t, sv.Sources)
		for _, c := range cells {
			base.ids = append(base.ids, c.CellID)
		}
		_, base.leaves, _ = refV2RInit(t, hx(t, sv.PodSalt), cells)
		base.honest = f.Touched[i].Lane
	}
	idx := map[uint32]bool{}
	for i := range base.leaves {
		idx[i] = true
	}
	want := map[string]bool{
		"touched-cell-not-lowest": true, "touched-cell-uncommitted": true, "touched-cell-missing": true,
		"forged-payload-content": true, "forged-payload-key-tag": true, "wrong-index-other-cell": true,
		"empty-slot-read": true, "write-under-read-only": true,
		"touched-cell-non-hex": true, "touched-cell-on-memory-free": true,
	}
	for _, v := range f.Negative {
		delete(want, v.ID)
		var got string
		switch {
		case v.Lane == nil && v.Base == "memory-free":
			got = refV2SeamCheck(v.Seam, nil)
		case v.Lane == nil:
			got = refV2SeamCheck(v.Seam, base.ids)
		default:
			payload := hx(t, v.PayloadIn)
			if v.PayloadIn == "" {
				kt, ch := hx32(t, v.Lane.KeyTag), hx32(t, v.Lane.ContentHash)
				payload = refV2Payload(kt, ch)
			}
			out := hx32(t, v.Lane.ValueHashIn)
			if s, ok := v.Facts["value_hash_out"]; ok {
				out = hx32(t, s)
			}
			got = refV2LaneCheck(t, *v.Lane, payload, out)
		}
		if got != v.ExpectedRefusal {
			t.Errorf("%s: got %q, want %q", v.ID, got, v.ExpectedRefusal)
		}
		if s, ok := v.Facts["value_hash_of_payload_in"]; ok && hex.EncodeToString(func() []byte { x := refV2VH(t, hx(t, v.PayloadIn)); return x[:] }()) != s {
			t.Errorf("%s: value_hash_of_payload_in fact wrong", v.ID)
		}
		if v.ID == "empty-slot-read" {
			// The forged lane authenticates with the empty leaf, as the
			// v1.1 circuit accepts (design T4); v2 refuses it anyway.
			var path [D][32]byte
			for k, s := range v.Lane.Siblings {
				path[k] = hx32(t, s)
			}
			r, err := VerifyAuthPath(v.Lane.Index, EmptyRoots[0], path)
			if err != nil || hex.EncodeToString(r[:]) != v.Lane.RInit || idx[v.Lane.Index] {
				t.Errorf("empty-slot-read: lane does not authenticate as an empty slot")
			}
		}
		if s, ok := v.Facts["recomputed_root"]; ok {
			var path [D][32]byte
			for k, sib := range v.Lane.Siblings {
				path[k] = hx32(t, sib)
			}
			leaf, _ := LeafHash(hx32(t, v.Lane.ValueHashIn))
			r, _ := VerifyAuthPath(v.Lane.Index, leaf, path)
			if hex.EncodeToString(r[:]) != s || s == v.Lane.RInit {
				t.Errorf("%s: recomputed_root fact wrong", v.ID)
			}
		}
	}
	if len(want) != 0 {
		t.Errorf("missing negative vectors: %v", want)
	}
}

// TestRInitV2DerivationNegative checks the derivation refusals.
func TestRInitV2DerivationNegative(t *testing.T) {
	f := loadV2(t)
	for _, v := range f.DerivNeg {
		cells := make([]Cell, len(v.Cells))
		for i, c := range v.Cells {
			cells[i] = Cell{CellID: c.CellID, ContentHash: hx(t, c.ContentHash)}
		}
		_, _, err := refV2RInit(t, hx(t, v.PodSalt), cells)
		if Code(err) != v.ExpectedRefusal {
			t.Errorf("%s: got %v, want %s", v.ID, err, v.ExpectedRefusal)
		}
		if v.ID == "derivation-index-collision" {
			salt := hx(t, v.PodSalt)
			var got []uint32
			for _, c := range cells {
				lk, _ := LogicalKey(salt, c.CellID)
				got = append(got, refV2Index(refV2KeyTag(lk)))
			}
			if fmt.Sprint(got) != fmt.Sprint(v.Indices) || got[0] != got[1] {
				t.Errorf("collision indices %v, want %v", got, v.Indices)
			}
			if _, _, err := RInitV1(salt, cells); err != nil {
				t.Errorf("the v1 derivation should not collide under this salt: %v", err)
			}
		}
	}
}

// TestRInitV2SeamDocuments checks the whole seam/3 step-disclosure.json
// vectors: canonical form (ascending keys, no white space), digest,
// initial_memory bytes, and the touched_cell_id rule.
func TestRInitV2SeamDocuments(t *testing.T) {
	f := loadV2(t)
	if len(f.SeamDocs) != 2 {
		t.Fatalf("want 2 seam/3 document vectors, got %d", len(f.SeamDocs))
	}
	for _, v := range f.SeamDocs {
		sum := sha256.Sum256([]byte(v.Doc))
		if hex.EncodeToString(sum[:]) != v.SHA {
			t.Errorf("%s: sha256 mismatch", v.ID)
		}
		var top map[string]json.RawMessage
		if err := json.Unmarshal([]byte(v.Doc), &top); err != nil {
			t.Fatal(err)
		}
		// json.Marshal sorts map keys and compacts, so equal bytes mean
		// the vector is in the canonical form reef-core writes.
		again, err := json.Marshal(top)
		if err != nil || string(again) != v.Doc {
			t.Errorf("%s: not ascending-key compact JSON", v.ID)
		}
		var ids []uint64
		var chs [][]byte
		for _, sv := range f.Sources {
			if sv.ID == v.Source {
				for _, c := range sortedCells(v2SourceCells(t, sv.Sources)) {
					ids = append(ids, c.CellID)
					chs = append(chs, c.ContentHash)
				}
			}
		}
		entries := make([]string, len(ids))
		for i := range ids {
			var b [8]byte
			binary.BigEndian.PutUint64(b[:], ids[i])
			entries[i] = `{"cell_id":"` + hex.EncodeToString(b[:]) + `","content_hash":"` + base64.StdEncoding.EncodeToString(chs[i]) + `"}`
		}
		wantMem := `{"cells":[` + strings.Join(entries, ",") + `],"scheme":"konareef-mem-src/v1"}`
		if string(top["initial_memory"]) != wantMem || string(top["index"]) != "0" {
			t.Errorf("%s: initial_memory or index wrong", v.ID)
		}
		fragment := ""
		if raw, ok := top["touched_cell_id"]; ok {
			fragment = `"touched_cell_id":` + string(raw)
		}
		if code := refV2SeamCheck(fragment, ids); code != "" {
			t.Errorf("%s: refused with %s", v.ID, code)
		}
	}
}
