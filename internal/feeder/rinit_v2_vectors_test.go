// Copyright 2026 Jerry David Chan, Konareef.ai
// SPDX-License-Identifier: Apache-2.0

// rinit_v2_vectors_test.go — the feeder side of the konareef-rinit/v2
// shared vectors (internal/membridge/testdata/rinit_v2/vectors.json,
// CL-4-live step 2, reef-core#84).
//
//   - every seam negative vector, and the honest seam fragments, through
//     CheckTouchedCellID (R-M24, R-M25);
//   - both seam3_document_vectors through ReadSeamMemory and
//     CheckTouchedCellID (the whole seam/3 file, byte for byte);
//   - every honest touched-cell lane through memoryLaneFor, byte for byte;
//   - every PS-1-side lane negative vector through validateMemoryLane.
//
// The membridge package runs the derivation, leaf-table and circuit-side
// vectors through the production functions (rinit_v2_test.go).
package feeder

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/digitsu/konareef/internal/canon"
	"github.com/digitsu/konareef/internal/membridge"
	"github.com/digitsu/konareef/internal/vkeystore"
)

// v2VectorLane is a PS-1 memory lane in vector form (lowercase hex).
type v2VectorLane struct {
	RInit       string   `json:"r_init"`
	Index       uint32   `json:"index"`
	ValueHashIn string   `json:"value_hash_in"`
	Siblings    []string `json:"siblings"`
	KeyTag      string   `json:"key_tag"`
	ContentHash string   `json:"content_hash"`
}

// v2VectorSource is one [[context.memory]] entry of a source vector.
type v2VectorSource struct {
	Kind          string `json:"kind"`
	Path          string `json:"path"`
	FileBytesUTF8 string `json:"file_bytes_utf8"`
	Content       string `json:"content"`
}

// v2Vectors is the part of vectors.json the feeder tests read.
type v2Vectors struct {
	Sources []struct {
		ID            string           `json:"id"`
		PodSalt       string           `json:"pod_salt"`
		Sources       []v2VectorSource `json:"sources"`
		RInit         string           `json:"r_init"`
		TouchedCellID string           `json:"touched_cell_id"`
	} `json:"source_vectors"`
	Touched []struct {
		ID      string       `json:"id"`
		Source  string       `json:"source_vector"`
		Seam    string       `json:"seam_touched_cell_id_json"`
		Lane    v2VectorLane `json:"ps1_memory_lane"`
		Circuit string       `json:"circuit_id"`
	} `json:"touched_cell_vectors"`
	SeamDocs []struct {
		ID     string `json:"id"`
		Source string `json:"source_vector"`
		Doc    string `json:"step_disclosure_json"`
		SHA    string `json:"step_disclosure_sha256"`
	} `json:"seam3_document_vectors"`
	Negative []struct {
		ID        string            `json:"id"`
		Base      string            `json:"base"`
		RefusedBy []string          `json:"refused_by"`
		Expected  string            `json:"expected_refusal"`
		Seam      *string           `json:"seam_touched_cell_id_json"`
		Lane      *v2VectorLane     `json:"ps1_memory_lane"`
		PayloadIn string            `json:"payload_in"`
		Facts     map[string]string `json:"facts"`
	} `json:"negative_vectors"`
}

// loadFeederV2Vectors reads the shared vector file.
func loadFeederV2Vectors(t *testing.T) v2Vectors {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "membridge", "testdata", "rinit_v2", "vectors.json"))
	if err != nil {
		t.Fatal(err)
	}
	var v v2Vectors
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatal(err)
	}
	return v
}

// mustHex decodes lowercase hex or fails the test.
func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("hex %q: %v", s, err)
	}
	return b
}

// v2Fixture is one source vector resolved and derived with the production
// v2 code: its committed cells, root, v2 leaf table and touched row.
type v2Fixture struct {
	cells   []membridge.Cell
	rInit   [32]byte
	table   *membridge.LeafTableV2
	touched membridge.LeafV2
}

// buildV2Fixture resolves and derives the named source vector.
func buildV2Fixture(t *testing.T, v v2Vectors, id string) v2Fixture {
	t.Helper()
	for _, sv := range v.Sources {
		if sv.ID != id {
			continue
		}
		var srcs []membridge.MemorySource
		digests := map[string][32]byte{}
		for _, s := range sv.Sources {
			m := membridge.MemorySource{Kind: s.Kind, Path: s.Path, Content: s.Content}
			if s.Kind == membridge.SourceKindFile {
				m.Loaded = []byte(s.FileBytesUTF8)
				digests[membridge.FilesKey(s.Path)] = sha256.Sum256(m.Loaded)
			}
			srcs = append(srcs, m)
		}
		cells, err := membridge.CommittedCells(srcs, digests)
		if err != nil {
			t.Fatal(err)
		}
		root, derived, err := membridge.RInitV2(mustHex(t, sv.PodSalt), cells)
		if err != nil {
			t.Fatal(err)
		}
		if hex.EncodeToString(root[:]) != sv.RInit {
			t.Fatalf("%s: r_init drifted", id)
		}
		table, err := membridge.NewLeafTableV2([32]byte{}, root, derived)
		if err != nil {
			t.Fatal(err)
		}
		touchedID, err := membridge.TouchedCellID(cells)
		if err != nil {
			t.Fatal(err)
		}
		row, ok := table.Leaf(touchedID)
		if !ok {
			t.Fatalf("%s: no touched row", id)
		}
		return v2Fixture{cells: cells, rInit: root, table: table, touched: row}
	}
	t.Fatalf("no source vector %q", id)
	return v2Fixture{}
}

// manifestCommittingV2 is manifestCommitting with the konareef-rinit/v2
// marker, the marker of a memory-bearing publish (R-M29).
func manifestCommittingV2(t *testing.T, rInit [32]byte) []byte {
	t.Helper()
	mp := validManifestParams()
	fr, err := canon.FieldsRoot(mp.Models, mp.Tools, mp.CMax, rInit)
	if err != nil {
		t.Fatal(err)
	}
	return append([]byte("#!konareef-toml/v2\n[pod]\nname = \"x\"\n[_files]\n"),
		canon.CommitTrailerBytes(canon.CommitTrailer{FieldsRoot: fr, RInitScheme: canon.RInitSchemeV2})...)
}

// memoryBearingParams returns params for a fixture as the loader returns
// them for a memory-bearing konareef-rinit/v2 manifest.
func memoryBearingParams(t *testing.T, fx v2Fixture) ManifestParams {
	t.Helper()
	mp := validManifestParams()
	mp.Manifest = manifestCommittingV2(t, fx.rInit)
	mp.RInit, mp.MemoryCells = fx.rInit, fx.table.ValueHashes()
	touched := fx.touched
	mp.MemoryTouched = &touched
	return mp
}

// laneHex renders a lane in vector form.
func laneHex(l *MemoryLane) v2VectorLane {
	out := v2VectorLane{
		RInit: hex.EncodeToString(l.RInit), Index: l.Index, ValueHashIn: hex.EncodeToString(l.ValueHashIn),
		KeyTag: hex.EncodeToString(l.KeyTag), ContentHash: hex.EncodeToString(l.ContentHash),
	}
	for _, s := range l.Siblings {
		out.Siblings = append(out.Siblings, hex.EncodeToString(s))
	}
	return out
}

// laneFromHex converts a vector lane to a MemoryLane.
func laneFromHex(t *testing.T, l v2VectorLane) *MemoryLane {
	t.Helper()
	out := &MemoryLane{
		RInit: mustHex(t, l.RInit), Index: l.Index, ValueHashIn: mustHex(t, l.ValueHashIn),
		KeyTag: mustHex(t, l.KeyTag), ContentHash: mustHex(t, l.ContentHash),
	}
	for _, s := range l.Siblings {
		out.Siblings = append(out.Siblings, mustHex(t, s))
	}
	return out
}

// codeSentinels maps a spec refusal code to its membridge sentinel.
var codeSentinels = map[string]error{
	"MEMORY_TOUCHED_CELL_INVALID":  membridge.ErrMemoryTouchedCellInvalid,
	"MEMORY_TOUCHED_CELL_MISMATCH": membridge.ErrMemoryTouchedCellMismatch,
	"MEMORY_PAYLOAD_MISMATCH":      membridge.ErrMemoryPayloadMismatch,
	"MEMORY_INDEX_MISMATCH":        membridge.ErrMemoryIndexMismatch,
	"MEMORY_EMPTY_SLOT_READ":       membridge.ErrMemoryEmptySlotRead,
	"MEMORY_WRITE_REFUSED":         membridge.ErrMemoryWriteRefused,
}

// rawFragmentValue extracts the raw JSON value of a
// `"touched_cell_id":<value>` fragment; "" (key absent) gives nil.
func rawFragmentValue(t *testing.T, fragment string) json.RawMessage {
	t.Helper()
	if fragment == "" {
		return nil
	}
	var obj map[string]json.RawMessage
	if err := json.Unmarshal([]byte("{"+fragment+"}"), &obj); err != nil {
		t.Fatalf("fragment %q: %v", fragment, err)
	}
	return obj["touched_cell_id"]
}

// TestRInitV2_SeamVectors runs every honest seam fragment and every seam
// negative vector through CheckTouchedCellID.
func TestRInitV2_SeamVectors(t *testing.T) {
	v := loadFeederV2Vectors(t)
	for _, tv := range v.Touched {
		fx := buildV2Fixture(t, v, tv.Source)
		got, err := CheckTouchedCellID(rawFragmentValue(t, tv.Seam), fx.cells)
		if err != nil || got != fx.touched.CellID {
			t.Errorf("%s: honest seam: got %x, %v", tv.ID, got, err)
		}
	}
	n := 0
	for _, nv := range v.Negative {
		if nv.Lane != nil {
			continue
		}
		n++
		var committed []membridge.Cell
		if nv.Base != "memory-free" {
			committed = buildV2Fixture(t, v, nv.Base).cells
		}
		fragment := ""
		if nv.Seam != nil {
			fragment = *nv.Seam
		}
		_, err := CheckTouchedCellID(rawFragmentValue(t, fragment), committed)
		if !errors.Is(err, codeSentinels[nv.Expected]) || membridge.Code(err) != nv.Expected {
			t.Errorf("%s: got %v, want %s", nv.ID, err, nv.Expected)
		}
	}
	if n < 9 {
		t.Fatalf("ran %d seam negative vectors, want at least 9", n)
	}
}

// TestRInitV2_SeamDocuments reads each whole seam/3 file with the
// production reader and checks it end to end.
func TestRInitV2_SeamDocuments(t *testing.T) {
	v := loadFeederV2Vectors(t)
	for _, d := range v.SeamDocs {
		sum := sha256.Sum256([]byte(d.Doc))
		if hex.EncodeToString(sum[:]) != d.SHA {
			t.Fatalf("%s: sha256 drifted", d.ID)
		}
		path := filepath.Join(t.TempDir(), "step-disclosure.json")
		if err := os.WriteFile(path, []byte(d.Doc), 0o644); err != nil {
			t.Fatal(err)
		}
		got, err := ReadSeamMemory(path)
		if err != nil || !got.Present {
			t.Fatalf("%s: ReadSeamMemory: %+v, %v", d.ID, got, err)
		}
		var committed []membridge.Cell
		var wantTouched uint64
		if d.Source != "" { // "" is the memory-free document
			fx := buildV2Fixture(t, v, d.Source)
			committed, wantTouched = fx.cells, fx.touched.CellID
		}
		if !membridge.SameCells(got.Cells, committed) {
			t.Errorf("%s: disclosed cells differ from the committed cells", d.ID)
		}
		touched, err := CheckTouchedCellID(got.TouchedCellID, committed)
		if err != nil || touched != wantTouched {
			t.Errorf("%s: touched %x, %v; want %x", d.ID, touched, err, wantTouched)
		}
	}
}

// TestRInitV2_TouchedLanesFromParams builds each honest lane through
// WriteWitness and checks it equals the vector lane byte for byte, with
// the seam step index 0 or any other value.
func TestRInitV2_TouchedLanesFromParams(t *testing.T) {
	v := loadFeederV2Vectors(t)
	for _, tv := range v.Touched {
		fx := buildV2Fixture(t, v, tv.Source)
		for _, stepIndex := range []uint32{0, 5} {
			dir := t.TempDir()
			seam := writeSeamFixture(t, dir, StepDisclosure{Index: stepIndex, P: []byte("p"), R: []byte("r"), C: 1,
				Model: "claude-sonnet-4-5", ModelID: "anthropic/claude-sonnet-4-5"})
			out := filepath.Join(dir, "witness.json")
			if err := WriteWitness(seam, memoryBearingParams(t, fx), out); err != nil {
				t.Fatalf("%s: WriteWitness: %v", tv.ID, err)
			}
			raw, _ := os.ReadFile(out)
			var w Witness
			if err := json.Unmarshal(raw, &w); err != nil {
				t.Fatal(err)
			}
			if w.Memory == nil {
				t.Fatalf("%s: no lane", tv.ID)
			}
			got, want := laneHex(w.Memory), tv.Lane
			if got.RInit != want.RInit || got.Index != want.Index || got.ValueHashIn != want.ValueHashIn ||
				got.KeyTag != want.KeyTag || got.ContentHash != want.ContentHash ||
				strings.Join(got.Siblings, ",") != strings.Join(want.Siblings, ",") {
				t.Errorf("%s (step index %d): lane differs from the vector", tv.ID, stepIndex)
			}
			if w.Index != stepIndex || tv.Circuit != "konareef-pod-step-v1.2" {
				t.Errorf("%s: step index %d or circuit %s wrong", tv.ID, w.Index, tv.Circuit)
			}
		}
	}
}

// TestRInitV2_LaneNegativeVectors runs every lane negative vector that
// the feeder's PS-1-rule self-check can see through validateMemoryLane.
// Two kinds are out of its reach and are run by membridge's CheckReadLane
// instead: a forged payload_in (the feeder builds payload_in from the
// lane, as PS-1 does; circuit-only vectors) and a write (the feeder never
// writes, W-A).
func TestRInitV2_LaneNegativeVectors(t *testing.T) {
	v := loadFeederV2Vectors(t)
	n := 0
	for _, nv := range v.Negative {
		if nv.Lane == nil {
			continue
		}
		lane := laneFromHex(t, *nv.Lane)
		var kt, ch [32]byte
		copy(kt[:], lane.KeyTag)
		copy(ch[:], lane.ContentHash)
		if nv.PayloadIn != "" && nv.PayloadIn != hex.EncodeToString(membridge.CanonicalCellPayloadV2(kt, ch)) {
			continue // a payload_in PS-1 never builds: circuit-only
		}
		if _, writes := nv.Facts["value_hash_out"]; writes {
			continue
		}
		n++
		err := validateMemoryLane(lane)
		if !errors.Is(err, ErrMemoryLaneInvalid) || !errors.Is(err, codeSentinels[nv.Expected]) {
			t.Errorf("%s: got %v, want %s", nv.ID, err, nv.Expected)
		}
	}
	if n < 5 {
		t.Fatalf("ran %d lane negative vectors, want at least 5", n)
	}
	for _, tv := range v.Touched {
		if err := validateMemoryLane(laneFromHex(t, tv.Lane)); err != nil {
			t.Errorf("%s: honest lane refused: %v", tv.ID, err)
		}
	}
}

// TestRun_MemoryWitnessNeedsV1_2 checks that a witness with a memory lane
// is refused before PS-1 is called under v1 or v1.1 (konareef-rinit/v2
// R-M30, R-M31). While this build has no v1.2 pin, v1.2 itself is refused
// as unsupported, so no memory-bearing proof can be requested at all. The
// empty request is covered by TestCircuitForWitness.
func TestRun_MemoryWitnessNeedsV1_2(t *testing.T) {
	fx := buildV2Fixture(t, loadFeederV2Vectors(t), "file-inline-file-multi")
	lane, err := BuildMemoryLane(fx.rInit, fx.table.ValueHashes(), fx.touched)
	if err != nil {
		t.Fatal(err)
	}
	base := validManifestParams()
	w := Witness{Manifest: manifestCommittingV2(t, fx.rInit), P: []byte("p"), R: []byte("r"), Model: base.Models[0],
		Models: base.Models, Tools: base.Tools, CMax: base.CMax, SigManifest: validSigLane(), PkPub: validPubKeyBytes(), Memory: lane}
	path := filepath.Join(t.TempDir(), "witness.json")
	raw, _ := json.Marshal(w)
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{vkeystore.CircuitIDPodStepV1, vkeystore.CircuitIDPodStepV1_1} {
		err := Run(context.Background(), Opts{WitnessPath: path, PaygateURL: "http://192.0.2.1:9", IngestURL: "http://192.0.2.1:9",
			IngestToken: "tok", CircuitID: id})
		if !errors.Is(err, ErrMemoryCircuitRequired) {
			t.Errorf("circuit %q: err = %v, want ErrMemoryCircuitRequired", id, err)
		}
	}
	if !vkeystore.IsSupportedCircuitID(vkeystore.CircuitIDPodStepV1_2) {
		err := Run(context.Background(), Opts{WitnessPath: path, PaygateURL: "http://192.0.2.1:9", IngestURL: "http://192.0.2.1:9",
			IngestToken: "tok", CircuitID: vkeystore.CircuitIDPodStepV1_2})
		if err == nil || errors.Is(err, ErrMemoryCircuitRequired) {
			t.Errorf("unpinned v1.2: err = %v, want the unsupported-circuit refusal", err)
		}
	}
}

// TestCircuitForWitness checks the circuit pick (konareef-rinit/v2 R-M28,
// R-M31): a memory-free record is proved with v1.1 when v1.2 or nothing is
// requested, and keeps an explicit v1 or v1.1; a memory-bearing record
// gets v1.2 (once pinned) for an empty or v1.2 request, and v1 or v1.1 is
// refused with ErrMemoryCircuitRequired.
func TestCircuitForWitness(t *testing.T) {
	free := PodRecord{}
	for requested, want := range map[string]string{
		"":                             vkeystore.CircuitIDPodStepV1_1,
		vkeystore.CircuitIDPodStepV1_2: vkeystore.CircuitIDPodStepV1_1,
		vkeystore.CircuitIDPodStepV1_1: vkeystore.CircuitIDPodStepV1_1,
		vkeystore.CircuitIDPodStepV1:   vkeystore.CircuitIDPodStepV1,
	} {
		got, err := CircuitForWitness(free, requested)
		if err != nil || got != want {
			t.Errorf("memory-free, requested %q: got %q, %v; want %q", requested, got, err, want)
		}
	}

	fx := buildV2Fixture(t, loadFeederV2Vectors(t), "file-inline-file-multi")
	lane, err := BuildMemoryLane(fx.rInit, fx.table.ValueHashes(), fx.touched)
	if err != nil {
		t.Fatal(err)
	}
	bearing := PodRecord{Memory: lane}
	for _, requested := range []string{vkeystore.CircuitIDPodStepV1, vkeystore.CircuitIDPodStepV1_1} {
		if _, err := CircuitForWitness(bearing, requested); !errors.Is(err, ErrMemoryCircuitRequired) {
			t.Errorf("memory-bearing, requested %q: err = %v, want ErrMemoryCircuitRequired", requested, err)
		}
	}
	for _, requested := range []string{"", vkeystore.CircuitIDPodStepV1_2} {
		got, err := CircuitForWitness(bearing, requested)
		if vkeystore.IsSupportedCircuitID(vkeystore.CircuitIDPodStepV1_2) {
			if err != nil || got != vkeystore.CircuitIDPodStepV1_2 {
				t.Errorf("memory-bearing, requested %q: got %q, %v; want v1.2", requested, got, err)
			}
		} else if err == nil || errors.Is(err, ErrMemoryCircuitRequired) {
			t.Errorf("memory-bearing, unpinned v1.2, requested %q: err = %v, want the unsupported-circuit refusal", requested, err)
		}
	}
}

// TestRun_MemoryFreeProvesWithV1_1 checks end to end that a memory-free
// witness with no circuit requested reaches PS-1 as konareef-pod-step-v1.1
// and carries no memory lane.
func TestRun_MemoryFreeProvesWithV1_1(t *testing.T) {
	var sent struct {
		CircuitID string          `json:"circuit_id"`
		PodRecord json.RawMessage `json:"pod_record"`
	}
	b64 := base64.StdEncoding.EncodeToString
	ps1 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&sent)
		_ = json.NewEncoder(w).Encode(map[string]string{
			"spartan_snark": b64([]byte("snark")), "first_step_public_inputs": b64(make([]byte, 298)),
			"last_step_public_inputs": b64(make([]byte, 298)), "vkey_hash": b64(make([]byte, 32)),
			"genesis_fields_root": b64(make([]byte, 32)),
			"z0":                  b64(make([]byte, 736)), "vkey": b64(make([]byte, 32)),
			"circuit_id": vkeystore.CircuitIDPodStepV1_1,
		})
	}))
	defer ps1.Close()
	ingest := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusCreated) }))
	defer ingest.Close()

	wit := Witness{Manifest: []byte("m"), P: []byte("p"), R: []byte("r"), Model: "claude", Models: []string{"claude"},
		SigManifest: validSigLane(), PkPub: validPubKeyBytes()}
	path := filepath.Join(t.TempDir(), "witness.json")
	raw, _ := json.Marshal(wit)
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := Run(context.Background(), Opts{WitnessPath: path, PaygateURL: ps1.URL, IngestURL: ingest.URL, IngestToken: "tok"}); err != nil {
		t.Fatalf("run: %v", err)
	}
	if sent.CircuitID != vkeystore.CircuitIDPodStepV1_1 || strings.Contains(string(sent.PodRecord), `"memory"`) {
		t.Fatalf("PS-1 got circuit %q and record %s; want v1.1 and no memory lane", sent.CircuitID, sent.PodRecord)
	}
}

// TestCheckTouchedCellID_RefusesEscapes checks that the honest value
// written with a JSON escape (backslash-u0038 is "8") is refused: only the
// canonical byte form reef-core writes is accepted.
func TestCheckTouchedCellID_RefusesEscapes(t *testing.T) {
	fx := buildV2Fixture(t, loadFeederV2Vectors(t), "file-inline-file-multi")
	honest := touchedHex(fx.touched.CellID)
	if _, err := CheckTouchedCellID(json.RawMessage(`"`+honest+`"`), fx.cells); err != nil {
		t.Fatalf("control: %v", err)
	}
	if honest[0] != '8' {
		t.Fatalf("fixture: touched id %s must start with 8", honest)
	}
	escaped := json.RawMessage(`"` + "\\" + "u0038" + honest[1:] + `"`)
	if _, err := CheckTouchedCellID(escaped, fx.cells); !errors.Is(err, membridge.ErrMemoryTouchedCellInvalid) {
		t.Fatalf("escaped value: err = %v, want MEMORY_TOUCHED_CELL_INVALID", err)
	}
}

// touchedHex renders a cell_id as 16 lowercase hex digits.
func touchedHex(id uint64) string {
	var b [8]byte
	for i := 7; i >= 0; i-- {
		b[i] = byte(id)
		id >>= 8
	}
	return hex.EncodeToString(b[:])
}

// TestRun_BareWitnessMemoryBearingManifestRefused covers the bare
// --witness path: a witness file with no memory lane over a memory-bearing
// konareef-rinit/v2 manifest is refused with ErrMemoryRootNotCommitted for
// every circuit request (empty, v1, v1.1, v1.2), and PS-1 is never called.
// So the v1.1 default can never prove a memory-bearing manifest.
func TestRun_BareWitnessMemoryBearingManifestRefused(t *testing.T) {
	fx := buildV2Fixture(t, loadFeederV2Vectors(t), "file-inline-file-multi")
	calls := 0
	ps1 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer ps1.Close()
	base := validManifestParams()
	w := Witness{Manifest: manifestCommittingV2(t, fx.rInit), P: []byte("p"), R: []byte("r"), Model: base.Models[0],
		Models: base.Models, Tools: base.Tools, CMax: base.CMax, SigManifest: validSigLane(), PkPub: validPubKeyBytes()}
	path := filepath.Join(t.TempDir(), "witness.json")
	raw, _ := json.Marshal(w)
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	for _, id := range vkeystore.SupportedCircuitIDs() {
		for _, requested := range []string{"", id} {
			err := Run(context.Background(), Opts{WitnessPath: path, PaygateURL: ps1.URL, IngestURL: ps1.URL,
				IngestToken: "tok", CircuitID: requested})
			if !errors.Is(err, ErrMemoryRootNotCommitted) {
				t.Errorf("requested %q: err = %v, want ErrMemoryRootNotCommitted", requested, err)
			}
		}
	}
	if calls != 0 {
		t.Fatalf("PS-1 was called %d times; a memory-bearing manifest without a lane must never reach it", calls)
	}
}

// laneManifestVariants returns, for a populated rInit, manifests that a
// memory lane must not be accepted under (Hermes konareef!174 note 9472):
// no trailer (a legacy manifest with no magic line, and a v1 manifest), a
// legacy v2 trailer without a marker, the konareef-rinit/v1 marker, and an
// unknown scheme. Each one commits fields_root over rInit where it has a
// trailer, so only the marker rule can refuse it.
func laneManifestVariants(t *testing.T, rInit [32]byte) map[string][]byte {
	t.Helper()
	mp := validManifestParams()
	fr, err := canon.FieldsRoot(mp.Models, mp.Tools, mp.CMax, rInit)
	if err != nil {
		t.Fatal(err)
	}
	body := "#!konareef-toml/v2\n[pod]\nname = \"x\"\n[_files]\n"
	root := "[_commit]\nfields_root = \"poseidon:" + hex.EncodeToString(fr[:]) + "\"\n"
	return map[string][]byte{
		"no trailer, no magic": []byte("legacy manifest without commit trailer"),
		"no trailer, v1 magic": []byte("#!konareef-toml/v1\n[pod]\nname = \"x\"\n"),
		"legacy trailer":       []byte(body + root),
		"konareef-rinit/v1":    []byte(body + root + "r_init_scheme = \"konareef-rinit/v1\"\n"),
		"unknown scheme":       []byte(body + root + "r_init_scheme = \"konareef-rinit/unassigned\"\n"),
	}
}

// TestRun_BareWitnessLaneNeedsRInitV2Manifest covers Hermes blocker 1 on
// the bare --witness path: a self-consistent memory lane over a manifest
// that does not name konareef-rinit/v2 is refused for every circuit
// request, and PS-1 is never called. Control: the same lane over the v2
// manifest reaches PS-1.
func TestRun_BareWitnessLaneNeedsRInitV2Manifest(t *testing.T) {
	fx := buildV2Fixture(t, loadFeederV2Vectors(t), "file-inline-file-multi")
	lane, err := BuildMemoryLane(fx.rInit, fx.table.ValueHashes(), fx.touched)
	if err != nil {
		t.Fatal(err)
	}
	calls := 0
	ps1 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer ps1.Close()
	write := func(manifest []byte) string {
		base := validManifestParams()
		w := Witness{Manifest: manifest, P: []byte("p"), R: []byte("r"), Model: base.Models[0], Models: base.Models,
			Tools: base.Tools, CMax: base.CMax, SigManifest: validSigLane(), PkPub: validPubKeyBytes(), Memory: lane}
		path := filepath.Join(t.TempDir(), "witness.json")
		raw, _ := json.Marshal(w)
		if err := os.WriteFile(path, raw, 0o600); err != nil {
			t.Fatal(err)
		}
		return path
	}
	for name, manifest := range laneManifestVariants(t, fx.rInit) {
		path := write(manifest)
		for _, requested := range []string{"", vkeystore.CircuitIDPodStepV1_2} {
			err := Run(context.Background(), Opts{WitnessPath: path, PaygateURL: ps1.URL, IngestURL: ps1.URL,
				IngestToken: "tok", CircuitID: requested})
			if !errors.Is(err, ErrMemoryLaneManifestNotV2) {
				t.Errorf("%s, requested %q: err = %v, want ErrMemoryLaneManifestNotV2", name, requested, err)
			}
		}
	}
	if calls != 0 {
		t.Fatalf("PS-1 was called %d times for a lane without a konareef-rinit/v2 manifest", calls)
	}
	// Control: under the v2 manifest the same lane is sent to PS-1.
	_ = Run(context.Background(), Opts{WitnessPath: write(manifestCommittingV2(t, fx.rInit)), PaygateURL: ps1.URL,
		IngestURL: ps1.URL, IngestToken: "tok", CircuitID: vkeystore.CircuitIDPodStepV1_2})
	if calls != 1 {
		t.Fatalf("control: PS-1 calls = %d, want 1", calls)
	}
}
