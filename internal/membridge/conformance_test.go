// internal/membridge/conformance_test.go — runs the 13 PRD 4 Part B
// conformance vectors plus the Part C tlog-from-db-rows index check
// (only the trail/structural fields owned by membridge). T_log root
// derivation is owned by a separate package (P1.1 reef-core wiring).
package membridge

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

type vectorFile struct {
	Vectors []rawVector `json:"vectors"`
}

type rawVector struct {
	ID          string          `json:"id"`
	Description string          `json:"description"`
	Inputs      json.RawMessage `json:"inputs"`
	Expected    json.RawMessage `json:"expected"`
}

func loadVectors(t *testing.T) []rawVector {
	t.Helper()
	path := filepath.Join("testdata", "vectors", "v1.json")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read vectors: %v", err)
	}
	var vf vectorFile
	if err := json.Unmarshal(raw, &vf); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	return vf.Vectors
}

// TestConformanceVectors runs every Part B vector + the two
// provisional-ID vectors (capture-provisional-id-canonical and
// capture-provisional-id-mismatch-reject) + the Part C tlog-from-db-rows
// boundary check. Membridge owns the Part B + provisional vectors;
// tlog t_root derivation belongs to a sibling package and is skipped
// here.
func TestConformanceVectors(t *testing.T) {
	vectors := loadVectors(t)
	if len(vectors) < 15 {
		t.Fatalf("expected at least 15 vectors, got %d", len(vectors))
	}
	ran := 0
	for _, v := range vectors {
		v := v
		t.Run(v.ID, func(t *testing.T) {
			runOne(t, v)
		})
		ran++
	}
	if ran < 15 {
		t.Fatalf("ran only %d vectors", ran)
	}
}

// runOne dispatches to a per-id handler. New vectors get an explicit
// case; an unknown id triggers a t.Skip (lets the upstream add Part C
// or future vectors without breaking the suite).
func runOne(t *testing.T, v rawVector) {
	switch v.ID {
	case "mem-populated-single":
		runPopulatedSingle(t, v)
	case "mem-empty-sentinel":
		runEmptySentinel(t, v)
	case "mem-multi-cell-root":
		runMultiCellRoot(t, v)
	case "mem-leb128-nonminimal-reject":
		runLeb128NonMinimalReject(t, v)
	case "mem-salt-length-reject":
		runSaltLengthReject(t, v)
	case "mem-trunc20-lowbits":
		runTrunc20Lowbits(t, v)
	case "mem-thoughtid-min":
		runThoughtIDMin(t, v)
	case "mem-thoughtid-max":
		runThoughtIDMax(t, v)
	case "mem-typeC-disclosed-salt":
		runTypeCDisclosedSalt(t, v)
	case "mem-typeD-committed-salt":
		runTypeDCommittedSalt(t, v)
	case "mem-genesis-reseed-collision":
		runGenesisReseedCollision(t, v)
	case "mem-cap-exceeded":
		runCapExceeded(t, v)
	case "mem-index-collision":
		runIndexCollision(t, v)
	case "capture-provisional-id-canonical":
		runCaptureProvisionalIDCanonical(t, v)
	case "capture-provisional-id-mismatch-reject":
		runCaptureProvisionalIDMismatchReject(t, v)
	case "tlog-from-db-rows":
		t.Skip("Part C tlog root owned by sibling package; covered by P1.1 wiring tests")
	default:
		t.Fatalf("unknown vector id: %s", v.ID)
	}
}

// --- shared helpers ---

type inAcceptSingle struct {
	PodSalt     string `json:"pod_salt"`
	ThoughtID   uint64 `json:"thought_id"`
	ContentHash string `json:"content_hash"`
}

type expAcceptSingle struct {
	Index     uint32 `json:"index"`
	ValueHash string `json:"value_hash"`
	LeafHash  string `json:"leaf_hash"`
	RInit     string `json:"r_init"`
}

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("hex decode %q: %v", s, err)
	}
	return b
}

func unmarshal(t *testing.T, raw json.RawMessage, into any) {
	t.Helper()
	if err := json.Unmarshal(raw, into); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
}

// --- per-vector handlers ---

func runPopulatedSingle(t *testing.T, v rawVector) {
	var in inAcceptSingle
	var exp expAcceptSingle
	unmarshal(t, v.Inputs, &in)
	unmarshal(t, v.Expected, &exp)
	salt := mustHex(t, in.PodSalt)
	ch := mustHex(t, in.ContentHash)
	idx, err := CellIndex(salt, in.ThoughtID)
	if err != nil {
		t.Fatalf("CellIndex: %v", err)
	}
	if idx != exp.Index {
		t.Errorf("index = %d, want %d", idx, exp.Index)
	}
	vh, err := ValueHash(salt, in.ThoughtID, ch)
	if err != nil {
		t.Fatalf("ValueHash: %v", err)
	}
	if hex.EncodeToString(vh[:]) != exp.ValueHash {
		t.Errorf("value_hash mismatch")
	}
	lh := LeafHash(vh)
	if hex.EncodeToString(lh[:]) != exp.LeafHash {
		t.Errorf("leaf_hash mismatch")
	}
	root, err := SparseRoot(map[uint32][32]byte{idx: vh})
	if err != nil {
		t.Fatalf("SparseRoot: %v", err)
	}
	if hex.EncodeToString(root[:]) != exp.RInit {
		t.Errorf("r_init mismatch")
	}
}

func runEmptySentinel(t *testing.T, v rawVector) {
	var exp struct {
		RInit         string `json:"r_init"`
		EmptyLeafHash string `json:"empty_leaf_hash"`
	}
	unmarshal(t, v.Expected, &exp)
	root, err := SparseRoot(nil)
	if err != nil {
		t.Fatalf("SparseRoot: %v", err)
	}
	if hex.EncodeToString(root[:]) != exp.RInit {
		t.Errorf("empty r_init mismatch")
	}
	emptyLeaf := LeafHash(EmptyValueHash)
	if hex.EncodeToString(emptyLeaf[:]) != exp.EmptyLeafHash {
		t.Errorf("empty_leaf_hash mismatch")
	}
}

func runMultiCellRoot(t *testing.T, v rawVector) {
	var in struct {
		PodSalt string `json:"pod_salt"`
		Cells   []struct {
			ThoughtID   uint64 `json:"thought_id"`
			ContentHash string `json:"content_hash"`
		} `json:"cells"`
	}
	var exp struct {
		Indices     []uint32 `json:"indices"`
		ValueHashes []string `json:"value_hashes"`
		RInit       string   `json:"r_init"`
	}
	unmarshal(t, v.Inputs, &in)
	unmarshal(t, v.Expected, &exp)
	salt := mustHex(t, in.PodSalt)
	cells := map[uint32][32]byte{}
	for i, c := range in.Cells {
		ch := mustHex(t, c.ContentHash)
		idx, err := CellIndex(salt, c.ThoughtID)
		if err != nil {
			t.Fatalf("CellIndex: %v", err)
		}
		if idx != exp.Indices[i] {
			t.Errorf("indices[%d] = %d, want %d", i, idx, exp.Indices[i])
		}
		vh, err := ValueHash(salt, c.ThoughtID, ch)
		if err != nil {
			t.Fatalf("ValueHash: %v", err)
		}
		if hex.EncodeToString(vh[:]) != exp.ValueHashes[i] {
			t.Errorf("value_hashes[%d] mismatch", i)
		}
		cells[idx] = vh
	}
	root, err := SparseRoot(cells)
	if err != nil {
		t.Fatalf("SparseRoot: %v", err)
	}
	if hex.EncodeToString(root[:]) != exp.RInit {
		t.Errorf("r_init mismatch")
	}
}

func runLeb128NonMinimalReject(t *testing.T, v rawVector) {
	// Upstream conformance vector mem-leb128-nonminimal-reject specifies
	// bytes 0x80 0x80 0x01 with verdict ERR_LEB128_NONMINIMAL, but under
	// the standard ULEB128 minimality rule those bytes are the canonical
	// minimal encoding of 16384 (well within the v1 thought_id range of
	// 2^21-1 = 2097151) and the parser correctly accepts them. The
	// vector text and bytes are inconsistent; tracking in paygate-zk
	// issue #1 (intends either reword to acknowledge 16384, or replace
	// bytes with 0x80 0x00 — both of which the implementation already
	// handles correctly).
	t.Skipf("upstream vector pending fix per paygate-zk issue #1 — bytes 0x80 0x80 0x01 are the standard minimal encoding of 16384; vector intends reject but cannot be tested by parser alone")
}

func runSaltLengthReject(t *testing.T, v rawVector) {
	var in struct {
		PodSalt string `json:"pod_salt"`
	}
	unmarshal(t, v.Inputs, &in)
	salt := mustHex(t, in.PodSalt)
	if len(salt) == 32 {
		t.Fatalf("test fixture wrong length: %d", len(salt))
	}
	_, err := CellIndex(salt, 1)
	if !errors.Is(err, ErrCellSaltLen) {
		t.Fatalf("err = %v, want ErrCellSaltLen", err)
	}
}

func runTrunc20Lowbits(t *testing.T, v rawVector) {
	var in inAcceptSingle
	var exp struct {
		Index     uint32 `json:"index"`
		ValueHash string `json:"value_hash"`
	}
	unmarshal(t, v.Inputs, &in)
	unmarshal(t, v.Expected, &exp)
	salt := mustHex(t, in.PodSalt)
	idx, err := CellIndex(salt, in.ThoughtID)
	if err != nil {
		t.Fatalf("CellIndex: %v", err)
	}
	if idx != exp.Index {
		t.Errorf("index = %d, want %d", idx, exp.Index)
	}
	if idx >= 1<<20 {
		t.Errorf("index exceeds 2^20")
	}
}

func runThoughtIDMin(t *testing.T, v rawVector) {
	var in inAcceptSingle
	var exp struct {
		LogicalKeyHex string `json:"logical_key_hex"`
		Index         uint32 `json:"index"`
		ValueHash     string `json:"value_hash"`
		LeafHash      string `json:"leaf_hash"`
	}
	unmarshal(t, v.Inputs, &in)
	unmarshal(t, v.Expected, &exp)
	salt := mustHex(t, in.PodSalt)
	lk, err := LogicalKey(salt, in.ThoughtID)
	if err != nil {
		t.Fatalf("LogicalKey: %v", err)
	}
	if hex.EncodeToString(lk) != exp.LogicalKeyHex {
		t.Errorf("logical_key_hex mismatch")
	}
	idx, _ := CellIndex(salt, in.ThoughtID)
	if idx != exp.Index {
		t.Errorf("index = %d, want %d", idx, exp.Index)
	}
}

func runThoughtIDMax(t *testing.T, v rawVector) {
	var in inAcceptSingle
	var exp struct {
		LogicalKeyHex string `json:"logical_key_hex"`
		Index         uint32 `json:"index"`
		ValueHash     string `json:"value_hash"`
	}
	unmarshal(t, v.Inputs, &in)
	unmarshal(t, v.Expected, &exp)
	salt := mustHex(t, in.PodSalt)
	lk, err := LogicalKey(salt, in.ThoughtID)
	if err != nil {
		t.Fatalf("LogicalKey: %v", err)
	}
	if hex.EncodeToString(lk) != exp.LogicalKeyHex {
		t.Errorf("logical_key_hex mismatch")
	}
}

func runTypeCDisclosedSalt(t *testing.T, v rawVector) {
	var in inAcceptSingle
	var exp struct {
		LogicalKeyHex string `json:"logical_key_hex"`
		Index         uint32 `json:"index"`
		ValueHash     string `json:"value_hash"`
		RInit         string `json:"r_init"`
	}
	unmarshal(t, v.Inputs, &in)
	unmarshal(t, v.Expected, &exp)
	salt := mustHex(t, in.PodSalt)
	ch := mustHex(t, in.ContentHash)
	lk, _ := LogicalKey(salt, in.ThoughtID)
	if hex.EncodeToString(lk) != exp.LogicalKeyHex {
		t.Errorf("logical_key_hex mismatch")
	}
	idx, _ := CellIndex(salt, in.ThoughtID)
	vh, _ := ValueHash(salt, in.ThoughtID, ch)
	root, err := SparseRoot(map[uint32][32]byte{idx: vh})
	if err != nil {
		t.Fatalf("SparseRoot: %v", err)
	}
	if hex.EncodeToString(root[:]) != exp.RInit {
		t.Errorf("r_init mismatch")
	}
	// Confidentiality: Type-C serialize MUST emit pod_salt.
	view, err := PublicBundleView{Policy: PolicyTypeC, PodSalt: salt, RInit: root}.Serialize()
	if err != nil || view.PodSaltHex == "" {
		t.Errorf("Type-C bundle missing pod_salt")
	}
}

func runTypeDCommittedSalt(t *testing.T, v rawVector) {
	var in inAcceptSingle
	var exp struct {
		Index     uint32 `json:"index"`
		ValueHash string `json:"value_hash"`
		RInit     string `json:"r_init"`
	}
	unmarshal(t, v.Inputs, &in)
	unmarshal(t, v.Expected, &exp)
	salt := mustHex(t, in.PodSalt)
	ch := mustHex(t, in.ContentHash)
	idx, _ := CellIndex(salt, in.ThoughtID)
	vh, _ := ValueHash(salt, in.ThoughtID, ch)
	root, err := SparseRoot(map[uint32][32]byte{idx: vh})
	if err != nil {
		t.Fatalf("SparseRoot: %v", err)
	}
	if hex.EncodeToString(root[:]) != exp.RInit {
		t.Errorf("r_init mismatch")
	}
	// Confidentiality: Type-D serialize MUST redact pod_salt.
	view, err := PublicBundleView{Policy: PolicyTypeD, PodSalt: salt, RInit: root}.Serialize()
	if err != nil {
		t.Fatalf("Type-D serialize: %v", err)
	}
	if view.PodSaltHex != "" {
		t.Fatal("Type-D bundle leaked pod_salt")
	}
}

func runGenesisReseedCollision(t *testing.T, v rawVector) {
	var in struct {
		PodSalt    string `json:"pod_salt"`
		ThoughtIDA uint64 `json:"thought_id_a"`
		ThoughtIDB uint64 `json:"thought_id_b"`
	}
	unmarshal(t, v.Inputs, &in)
	collisionSalt := mustHex(t, in.PodSalt)
	// Force R_max collisions to assert terminal error.
	sampler := func(int) ([]byte, error) { return collisionSalt, nil }
	_, _, err := GenesisAssign(sampler, []uint64{in.ThoughtIDA, in.ThoughtIDB})
	if !errors.Is(err, ErrGenesisReseedCollision) {
		t.Fatalf("err = %v, want ErrGenesisReseedCollision", err)
	}
}

func runCapExceeded(t *testing.T, v rawVector) {
	var in struct {
		CellCount int `json:"cell_count"`
	}
	unmarshal(t, v.Inputs, &in)
	err := EnforceHardCap(in.CellCount)
	if !errors.Is(err, ErrCellCapExceeded) {
		t.Fatalf("err = %v, want ErrCellCapExceeded", err)
	}
}

func runIndexCollision(t *testing.T, v rawVector) {
	var in struct {
		PodSalt           string `json:"pod_salt"`
		OccupiedThoughtID uint64 `json:"occupied_thought_id"`
		NewThoughtID      uint64 `json:"new_thought_id"`
	}
	unmarshal(t, v.Inputs, &in)
	salt := mustHex(t, in.PodSalt)
	occupiedIdx, _ := CellIndex(salt, in.OccupiedThoughtID)
	occupied := map[uint32]uint64{occupiedIdx: in.OccupiedThoughtID}
	_, err := AssignCapture(occupied, salt, in.NewThoughtID)
	if !errors.Is(err, ErrCellIndexCollision) {
		t.Fatalf("err = %v, want ErrCellIndexCollision", err)
	}
}

// runCaptureProvisionalIDCanonical asserts byte-exact provisional_id +
// full B.1 chain (logical_key, index, value_hash, leaf_hash) against
// hard-coded expected values from the vector. Replaces the previous
// self-referential `wantPID := ProvisionalID(...)` test with a real
// golden anchor (Hermes review on MR !7).
func runCaptureProvisionalIDCanonical(t *testing.T, v rawVector) {
	var in struct {
		ContentHash string `json:"content_hash"`
		Ordinal     uint32 `json:"ordinal"`
		PodSalt     string `json:"pod_salt"`
		TaskID      uint64 `json:"task_id"`
	}
	var exp struct {
		ExpectedIndex            uint32 `json:"expected_index"`
		ExpectedLeafHash         string `json:"expected_leaf_hash"`
		ExpectedLogicalKeyHex    string `json:"expected_logical_key_hex"`
		ExpectedProvisionalIDHex string `json:"expected_provisional_id_hex"`
		ExpectedValueHash        string `json:"expected_value_hash"`
	}
	unmarshal(t, v.Inputs, &in)
	unmarshal(t, v.Expected, &exp)
	ch := mustHex(t, in.ContentHash)
	salt := mustHex(t, in.PodSalt)

	pid, err := ProvisionalID(ch, in.TaskID, in.Ordinal)
	if err != nil {
		t.Fatalf("ProvisionalID: %v", err)
	}
	gotPIDHex := hex.EncodeToString([]byte{
		byte(pid >> 56), byte(pid >> 48), byte(pid >> 40), byte(pid >> 32),
		byte(pid >> 24), byte(pid >> 16), byte(pid >> 8), byte(pid),
	})
	if gotPIDHex != exp.ExpectedProvisionalIDHex {
		t.Fatalf("provisional_id = %s, want %s", gotPIDHex, exp.ExpectedProvisionalIDHex)
	}

	// Chain the provisional_id through the B.1 derivation.
	lk, err := LogicalKey(salt, pid)
	if err != nil {
		t.Fatalf("LogicalKey: %v", err)
	}
	if got := hex.EncodeToString(lk); got != exp.ExpectedLogicalKeyHex {
		t.Errorf("logical_key = %s, want %s", got, exp.ExpectedLogicalKeyHex)
	}
	idx, err := CellIndex(salt, pid)
	if err != nil {
		t.Fatalf("CellIndex: %v", err)
	}
	if idx != exp.ExpectedIndex {
		t.Errorf("index = %d, want %d", idx, exp.ExpectedIndex)
	}
	vh, err := ValueHash(salt, pid, ch)
	if err != nil {
		t.Fatalf("ValueHash: %v", err)
	}
	if got := hex.EncodeToString(vh[:]); got != exp.ExpectedValueHash {
		t.Errorf("value_hash = %s, want %s", got, exp.ExpectedValueHash)
	}
	lh := LeafHash(vh)
	if got := hex.EncodeToString(lh[:]); got != exp.ExpectedLeafHash {
		t.Errorf("leaf_hash = %s, want %s", got, exp.ExpectedLeafHash)
	}
}

// runCaptureProvisionalIDMismatchReject asserts the §B.6.1 reconciliation
// fail-closed gate: ReconcileProvisional(recomputed, claimed) surfaces
// ERR_PROVISIONAL_ID_MISMATCH when claimed != recomputed.
func runCaptureProvisionalIDMismatchReject(t *testing.T, v rawVector) {
	var in struct {
		ClaimedProvisionalIDHex string `json:"claimed_provisional_id_hex"`
		ContentHash             string `json:"content_hash"`
		Ordinal                 uint32 `json:"ordinal"`
		TaskID                  uint64 `json:"task_id"`
	}
	unmarshal(t, v.Inputs, &in)
	ch := mustHex(t, in.ContentHash)
	pid, err := ProvisionalID(ch, in.TaskID, in.Ordinal)
	if err != nil {
		t.Fatalf("ProvisionalID: %v", err)
	}
	claimedBytes := mustHex(t, in.ClaimedProvisionalIDHex)
	if len(claimedBytes) != 8 {
		t.Fatalf("claimed_provisional_id_hex must decode to 8 bytes, got %d", len(claimedBytes))
	}
	var claimed uint64
	for _, b := range claimedBytes {
		claimed = (claimed << 8) | uint64(b)
	}
	if err := ReconcileProvisional(pid, claimed); !errors.Is(err, ErrProvisionalIDMismatch) {
		t.Fatalf("err = %v, want ErrProvisionalIDMismatch", err)
	}
}
