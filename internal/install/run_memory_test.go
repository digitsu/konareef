// Copyright 2026 Jerry David Chan, Konareef.ai
// SPDX-License-Identifier: Apache-2.0

// run_memory_test.go — the sidecar's salt-free run memory check
// (konareef-rinit/v2 R-M20 and R-M25; MEM-SEAM A1/B1/C1/S-7,
// run_memory.go): a memory-bearing konareef-rinit/v2 manifest loads only
// with a disclosed cell list equal to the manifest's committed list, the
// R-M23 touched_cell_id, and a publisher-signed v2 leaf table that passes
// every check; every missing or changed input refuses and returns no
// params. The memory-free and v1 controls check the C1 presence rule and
// the touched_cell_id absence rule.
package install

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/digitsu/konareef/internal/canon"
	"github.com/digitsu/konareef/internal/feeder"
	"github.com/digitsu/konareef/internal/identity"
	"github.com/digitsu/konareef/internal/membridge"
	"github.com/digitsu/konareef/internal/publish"
)

// leafFixture is a cached memory-bearing v2 install plus everything a test
// needs to build leaf tables for it.
type leafFixture struct {
	home    string
	f       *FetchedPod
	id      *identity.Identity
	salt    [32]byte
	cells   []membridge.Cell
	derived []membridge.DerivedCellV2
	rInit   [32]byte
	scheme  string
}

// newLeafFixture writes memoryPodTOML's pod, derives the
// konareef-rinit/v2 r_init with a fixed salt, signs a v2 manifest with the
// konareef-rinit/v2 marker over it with a fresh key, and caches it.
func newLeafFixture(t *testing.T) *leafFixture {
	t.Helper()
	return newLeafFixtureScheme(t, canon.RInitSchemeV2)
}

// newLeafFixtureScheme is newLeafFixture with the given r_init_scheme
// marker, so a test can reproduce a retired konareef-rinit/v1
// memory-bearing manifest (R-M30) over the same root.
func newLeafFixtureScheme(t *testing.T, scheme string) *leafFixture {
	t.Helper()
	models, tools, cMax := zkParams(t)
	podDir := writeZKSamplePod(t)
	if err := os.WriteFile(filepath.Join(podDir, "pod.toml"), []byte(memoryPodTOML), 0o644); err != nil {
		t.Fatal(err)
	}
	notes := []byte("The pod remembers this line.\n")
	if err := os.MkdirAll(filepath.Join(podDir, "memory"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(podDir, "memory", "notes.md"), notes, 0o644); err != nil {
		t.Fatal(err)
	}
	cells, err := membridge.ResolveSources([]membridge.MemorySource{
		{Kind: "file", Path: "./memory/notes.md", Loaded: notes},
		{Kind: "inline", Content: "Prefer primary sources."},
	}, map[string][32]byte{"memory/notes.md": sha256.Sum256(notes)})
	if err != nil {
		t.Fatal(err)
	}
	lf := &leafFixture{cells: cells, scheme: scheme}
	for i := range lf.salt {
		lf.salt[i] = byte(0x30 + i)
	}
	if lf.rInit, lf.derived, err = membridge.RInitV2(lf.salt[:], cells); err != nil {
		t.Fatal(err)
	}
	body, _ := os.ReadFile(filepath.Join(podDir, "pod.toml"))
	canonBytes, err := canon.CanonicalizeV2(body, podDir, canon.CommitParams{
		Models: models, Tools: tools, CMax: cMax, RInit: lf.rInit, RInitScheme: scheme,
	})
	if err != nil {
		t.Fatal(err)
	}
	if lf.id, err = identity.Generate("alice"); err != nil {
		t.Fatal(err)
	}
	sig, err := lf.id.Sign(canonBytes)
	if err != nil {
		t.Fatal(err)
	}
	tarball, err := publish.PackTarball(podDir)
	if err != nil {
		t.Fatal(err)
	}
	lf.f = &FetchedPod{
		Handle: lf.id.Handle, PodName: "research-bot", PodVersion: "1.0.0",
		PodHash: sha256.Sum256(canonBytes), ManifestCanonical: canonBytes, Signature: sig,
		PublisherPubkeyHex: lf.id.PublicKeyHex, ContentTarball: tarball,
	}
	if err := Verify(lf.f); err != nil {
		t.Fatalf("fixture must install: %v", err)
	}
	lf.home = t.TempDir()
	if _, err := Cache(lf.home, lf.f); err != nil {
		t.Fatal(err)
	}
	return lf
}

// table builds and signs a v2 leaf table. mutate may change the table
// before it is signed; signer defaults to the publisher.
func (lf *leafFixture) table(t *testing.T, mutate func(*membridge.LeafTableV2), signer *identity.Identity) *LeafTableEvidence {
	t.Helper()
	tb, err := membridge.NewLeafTableV2(lf.f.PodHash, lf.rInit, lf.derived)
	if err != nil {
		t.Fatal(err)
	}
	if mutate != nil {
		mutate(tb)
	}
	if signer == nil {
		signer = lf.id
	}
	raw := tb.Bytes()
	sig, err := signer.Sign(raw)
	if err != nil {
		t.Fatal(err)
	}
	return &LeafTableEvidence{Table: raw, Signature: sig}
}

// touchedJSON renders a seam/3 touched_cell_id value for a cell_id.
func touchedJSON(id uint64) json.RawMessage {
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], id)
	return json.RawMessage(`"` + hex.EncodeToString(b[:]) + `"`)
}

// disclosure is the honest seam/3 memory disclosure of the fixture: its
// committed cells and its R-M23 touched cell.
func (lf *leafFixture) disclosure(t *testing.T) feeder.SeamMemory {
	t.Helper()
	touched, err := membridge.TouchedCellID(lf.cells)
	if err != nil {
		t.Fatal(err)
	}
	return feeder.SeamMemory{Present: true, Cells: lf.cells, TouchedCellID: touchedJSON(touched)}
}

// touchedDerived returns the fixture's derivation of the R-M23 cell.
func (lf *leafFixture) touchedDerived(t *testing.T) membridge.DerivedCellV2 {
	t.Helper()
	touched, _ := membridge.TouchedCellID(lf.cells)
	for _, d := range lf.derived {
		if d.CellID == touched {
			return d
		}
	}
	t.Fatal("no touched cell")
	return membridge.DerivedCellV2{}
}

// load runs LoadManifestParamsForRun with the given disclosure and table.
// It reports whether the fetch was called.
func (lf *leafFixture) load(disclosed feeder.SeamMemory, ev *LeafTableEvidence, fetchErr error) (feeder.ManifestParams, bool, error) {
	fetched := false
	mp, err := LoadManifestParamsForRun(lf.home, lf.f.Handle, lf.f.PodName, lf.f.PodVersion, RunMemory{
		Disclosed: disclosed,
		FetchLeafTable: func() (*LeafTableEvidence, error) {
			fetched = true
			return ev, fetchErr
		},
	})
	return mp, fetched, err
}

// TestLoadManifestParamsForRunMemoryBearing is the control and every
// refusal of the salt-free path, in R-M20 order.
func TestLoadManifestParamsForRunMemoryBearing(t *testing.T) {
	lf := newLeafFixture(t)
	disclosed := lf.disclosure(t)

	// Control: the checked table's r_init, leaves and touched row become
	// the params.
	mp, fetched, err := lf.load(disclosed, lf.table(t, nil, nil), nil)
	if err != nil {
		t.Fatalf("control: %v", err)
	}
	if !fetched || mp.RInit != lf.rInit || len(mp.MemoryCells) != len(lf.derived) {
		t.Fatalf("control: fetched=%v RInit=%x cells=%d", fetched, mp.RInit, len(mp.MemoryCells))
	}
	for _, d := range lf.derived {
		if mp.MemoryCells[d.Index] != d.ValueHash {
			t.Fatalf("control: cell at %d has the wrong value hash", d.Index)
		}
	}
	td := lf.touchedDerived(t)
	if mp.MemoryTouched == nil || mp.MemoryTouched.CellID != td.CellID || mp.MemoryTouched.KeyTag != td.KeyTag ||
		mp.MemoryTouched.Index != td.Index || mp.MemoryTouched.ValueHash != td.ValueHash {
		t.Fatalf("control: touched row %+v, want the lowest cell_id %x", mp.MemoryTouched, td.CellID)
	}
	committed, _ := canon.ParseCommitFieldsRoot(lf.f.ManifestCanonical)
	if fr, _ := canon.FieldsRoot(mp.Models, mp.Tools, mp.CMax, mp.RInit); fr != committed {
		t.Fatal("control: params must reproduce the committed fields_root")
	}

	other, err := identity.Generate("mallory")
	if err != nil {
		t.Fatal(err)
	}
	otherSalt := lf.salt
	otherSalt[0] ^= 1
	otherRoot, otherDerived, err := membridge.RInitV2(otherSalt[:], lf.cells)
	if err != nil {
		t.Fatal(err)
	}
	changed := append([]membridge.Cell(nil), lf.cells...)
	changed[0] = membridge.Cell{CellID: lf.cells[0].CellID, ContentHash: bytes.Repeat([]byte{0x42}, 32)}
	tampered := lf.table(t, nil, nil)
	tampered.Table = append([]byte(nil), tampered.Table...)
	tampered.Table[len(tampered.Table)-1] ^= 1
	v1Table := func() *LeafTableEvidence {
		root, derived, err := membridge.RInitV1(lf.salt[:], lf.cells)
		if err != nil {
			t.Fatal(err)
		}
		tb, err := membridge.NewLeafTable(lf.f.PodHash, root, lf.cells, derived)
		if err != nil {
			t.Fatal(err)
		}
		sig, _ := lf.id.Sign(tb.Bytes())
		return &LeafTableEvidence{Table: tb.Bytes(), Signature: sig}
	}()
	var notTouched uint64
	for _, c := range lf.cells {
		if c.CellID != td.CellID {
			notTouched = c.CellID
		}
	}
	withTouched := func(raw json.RawMessage) feeder.SeamMemory {
		d := lf.disclosure(t)
		d.TouchedCellID = raw
		return d
	}

	cases := map[string]struct {
		disclosed feeder.SeamMemory
		ev        *LeafTableEvidence
		fetchErr  error
		want      error
	}{
		"no initial_memory (C1)":          {feeder.SeamMemory{}, lf.table(t, nil, nil), nil, ErrSeamMemoryMissing},
		"disclosed content changed":       {feeder.SeamMemory{Present: true, Cells: changed}, lf.table(t, nil, nil), nil, ErrSeamMemoryMismatch},
		"disclosed cell dropped":          {feeder.SeamMemory{Present: true, Cells: lf.cells[:1]}, lf.table(t, nil, nil), nil, ErrSeamMemoryMismatch},
		"disclosed empty":                 {feeder.SeamMemory{Present: true, Cells: []membridge.Cell{}}, lf.table(t, nil, nil), nil, ErrSeamMemoryMismatch},
		"no table":                        {disclosed, nil, nil, ErrLeafTableUnavailable},
		"fetch failed":                    {disclosed, nil, errors.New("status 404"), ErrLeafTableUnavailable},
		"(a) table signed by another key": {disclosed, lf.table(t, nil, other), nil, membridge.ErrLeafTableInvalid},
		"(a) table bytes changed":         {disclosed, tampered, nil, ErrLeafTableSignature},
		"(b) v1 table":                    {disclosed, v1Table, nil, membridge.ErrLeafTableInvalid},
		"(c) table for another pod_hash": {disclosed, lf.table(t, func(tb *membridge.LeafTableV2) {
			tb.PodHash[0] ^= 1
		}, nil), nil, membridge.ErrLeafTableMismatch},
		"(c) table content hashes swapped": {disclosed, lf.table(t, func(tb *membridge.LeafTableV2) {
			tb.Leaves[0].ContentHash, tb.Leaves[1].ContentHash = tb.Leaves[1].ContentHash, tb.Leaves[0].ContentHash
		}, nil), nil, membridge.ErrLeafTableMismatch},
		"(d) table indices swapped": {disclosed, lf.table(t, func(tb *membridge.LeafTableV2) {
			tb.Leaves[0].Index, tb.Leaves[1].Index = tb.Leaves[1].Index, tb.Leaves[0].Index
		}, nil), nil, membridge.ErrLeafTableInvalid},
		"(d) table key_tags swapped": {disclosed, lf.table(t, func(tb *membridge.LeafTableV2) {
			tb.Leaves[0].KeyTag, tb.Leaves[1].KeyTag = tb.Leaves[1].KeyTag, tb.Leaves[0].KeyTag
		}, nil), nil, membridge.ErrLeafTableInvalid},
		"(d) table value hash changed": {disclosed, lf.table(t, func(tb *membridge.LeafTableV2) {
			tb.Leaves[0].ValueHash = tb.Leaves[1].ValueHash
		}, nil), nil, membridge.ErrLeafTableInvalid},
		"(e) table root changed": {disclosed, lf.table(t, func(tb *membridge.LeafTableV2) {
			tb.RInit = otherRoot
		}, nil), nil, membridge.ErrRInitMismatch},
		"(f) table from another salt, self-consistent": {disclosed, lf.table(t, func(tb *membridge.LeafTableV2) {
			tb.RInit = otherRoot
			for i := range tb.Leaves {
				for _, d := range otherDerived {
					if d.CellID == tb.Leaves[i].CellID {
						tb.Leaves[i].KeyTag, tb.Leaves[i].Index, tb.Leaves[i].ValueHash = d.KeyTag, d.Index, d.ValueHash
					}
				}
			}
		}, nil), nil, ErrCommittedFieldsRootMismatch},
		"(b) table bytes malformed": {disclosed, func() *LeafTableEvidence {
			raw := []byte("konareef-mem-leaves/v2 truncated")
			sig, _ := lf.id.Sign(raw)
			return &LeafTableEvidence{Table: raw, Signature: sig}
		}(), nil, membridge.ErrLeafTableInvalid},
		"touched_cell_id absent":       {withTouched(nil), lf.table(t, nil, nil), nil, membridge.ErrMemoryTouchedCellInvalid},
		"touched_cell_id not lowest":   {withTouched(touchedJSON(notTouched)), lf.table(t, nil, nil), nil, membridge.ErrMemoryTouchedCellMismatch},
		"touched_cell_id uncommitted":  {withTouched(touchedJSON(1<<63 | 12345)), lf.table(t, nil, nil), nil, membridge.ErrMemoryTouchedCellMismatch},
		"touched_cell_id number":       {withTouched(json.RawMessage(`12345`)), lf.table(t, nil, nil), nil, membridge.ErrMemoryTouchedCellInvalid},
		"touched_cell_id bit 63 clear": {withTouched(touchedJSON(12345)), lf.table(t, nil, nil), nil, membridge.ErrMemoryTouchedCellInvalid},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			mp, _, err := lf.load(c.disclosed, c.ev, c.fetchErr)
			if !errors.Is(err, c.want) {
				t.Fatalf("err = %v, want %v", err, c.want)
			}
			// ErrLeafTableSignature wraps MEMORY_LEAF_TABLE_INVALID, so
			// tell step a apart from steps b and d explicitly.
			switch {
			case strings.HasPrefix(name, "(a)") && !errors.Is(err, ErrLeafTableSignature):
				t.Fatalf("err = %v, want the step a signature refusal", err)
			case (strings.HasPrefix(name, "(b)") || strings.HasPrefix(name, "(d)")) && errors.Is(err, ErrLeafTableSignature):
				t.Fatalf("err = %v, refused at step a, want step %s", err, name[1:2])
			}
			if mp.Manifest != nil {
				t.Fatal("params returned on refusal")
			}
		})
	}
}

// TestLoadManifestParamsForRunStepFBeforeTouched: when step f (the root
// against fields_root) and the touched-cell check both fail, the refusal
// is step f's, as R-M20 orders them.
func TestLoadManifestParamsForRunStepFBeforeTouched(t *testing.T) {
	lf := newLeafFixture(t)
	otherSalt := lf.salt
	otherSalt[0] ^= 1
	otherRoot, otherDerived, err := membridge.RInitV2(otherSalt[:], lf.cells)
	if err != nil {
		t.Fatal(err)
	}
	ev := lf.table(t, func(tb *membridge.LeafTableV2) {
		tb.RInit = otherRoot
		for i := range tb.Leaves {
			for _, d := range otherDerived {
				if d.CellID == tb.Leaves[i].CellID {
					tb.Leaves[i].KeyTag, tb.Leaves[i].Index, tb.Leaves[i].ValueHash = d.KeyTag, d.Index, d.ValueHash
				}
			}
		}
	}, nil)
	d := lf.disclosure(t)
	d.TouchedCellID = nil
	_, _, err = lf.load(d, ev, nil)
	if !errors.Is(err, ErrCommittedFieldsRootMismatch) || errors.Is(err, membridge.ErrMemoryTouchedCellInvalid) {
		t.Fatalf("err = %v, want the step f refusal", err)
	}
}

// TestLoadManifestParamsForRunRefusesRInitV1MemoryBearing: a
// memory-bearing manifest that names konareef-rinit/v1 is not
// proof-eligible (R-M30). It is refused before any table is fetched.
func TestLoadManifestParamsForRunRefusesRInitV1MemoryBearing(t *testing.T) {
	lf := newLeafFixtureScheme(t, canon.RInitSchemeV1)
	mp, fetched, err := lf.load(lf.disclosure(t), lf.table(t, nil, nil), nil)
	if !errors.Is(err, ErrMemoryRInitV1Retired) || fetched || mp.Manifest != nil {
		t.Fatalf("err = %v, fetched = %v; want ErrMemoryRInitV1Retired and no fetch", err, fetched)
	}
	_, err = LoadManifestParamsWithMemory(lf.home, lf.f.Handle, lf.f.PodName, lf.f.PodVersion,
		&MemoryEvidence{Salt: lf.salt, Cells: lf.cells})
	if !errors.Is(err, ErrMemoryRInitV1Retired) {
		t.Fatalf("salt holder path: err = %v, want ErrMemoryRInitV1Retired", err)
	}
}

// TestLoadManifestParamsForRunMemoryFree: a memory-free v2 run loads with
// an empty disclosed list and makes no table request; a missing key or a
// disclosed cell refuses.
func TestLoadManifestParamsForRunMemoryFree(t *testing.T) {
	home, _, f := cacheZKFixture(t)
	load := func(d feeder.SeamMemory) (feeder.ManifestParams, bool, error) {
		fetched := false
		mp, err := LoadManifestParamsForRun(home, f.Handle, f.PodName, f.PodVersion, RunMemory{
			Disclosed:      d,
			FetchLeafTable: func() (*LeafTableEvidence, error) { fetched = true; return nil, nil },
		})
		return mp, fetched, err
	}
	mp, fetched, err := load(feeder.SeamMemory{Present: true, Cells: []membridge.Cell{}})
	if err != nil || fetched || mp.RInit != canon.EmptyMemoryRoot() || mp.MemoryCells != nil || mp.MemoryTouched != nil {
		t.Fatalf("control: err=%v fetched=%v RInit=%x cells=%v", err, fetched, mp.RInit, mp.MemoryCells)
	}
	// R-M20 step 2: touched_cell_id on a memory-free run is refused.
	withTouched := feeder.SeamMemory{Present: true, Cells: []membridge.Cell{}, TouchedCellID: touchedJSON(1<<63 | 5)}
	if _, fetched, err := load(withTouched); !errors.Is(err, membridge.ErrMemoryTouchedCellInvalid) || fetched {
		t.Fatalf("touched_cell_id on a memory-free run: err = %v, fetched = %v", err, fetched)
	}
	if _, _, err := load(feeder.SeamMemory{}); !errors.Is(err, ErrSeamMemoryMissing) {
		t.Fatalf("missing key: err = %v, want ErrSeamMemoryMissing", err)
	}
	extra := []membridge.Cell{{CellID: 1<<63 | 5, ContentHash: make([]byte, 32)}}
	if _, _, err := load(feeder.SeamMemory{Present: true, Cells: extra}); !errors.Is(err, ErrSeamMemoryMismatch) {
		t.Fatalf("extra cell: err = %v, want ErrSeamMemoryMismatch", err)
	}
}

// TestLoadManifestParamsForRunV1: a konareef-toml/v1 manifest commits no
// fields_root, so reef-core omits initial_memory (C1). A present key is a
// mismatch and refuses.
func TestLoadManifestParamsForRunV1(t *testing.T) {
	podDir := writeZKSamplePod(t)
	id, err := identity.Generate("alice")
	if err != nil {
		t.Fatal(err)
	}
	prep, err := publish.Prepare(podDir, id, publish.PrepareOptions{})
	if err != nil {
		t.Fatal(err)
	}
	f := &FetchedPod{
		Handle: prep.Handle, PodName: prep.PodName, PodVersion: prep.PodVersion, PodHash: prep.PodHash,
		ManifestCanonical: prep.CanonicalBytes, Signature: prep.Signature,
		PublisherPubkeyHex: prep.PublicKeyHex, ContentTarball: prep.ContentTarball,
	}
	home := t.TempDir()
	if _, err := Cache(home, f); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadManifestParamsForRun(home, f.Handle, f.PodName, f.PodVersion, RunMemory{}); err != nil {
		t.Fatalf("v1 without initial_memory: %v", err)
	}
	_, err = LoadManifestParamsForRun(home, f.Handle, f.PodName, f.PodVersion, RunMemory{
		Disclosed: feeder.SeamMemory{Present: true, Cells: []membridge.Cell{}},
	})
	if !errors.Is(err, ErrSeamMemoryUnexpected) {
		t.Fatalf("v1 with initial_memory: err = %v, want ErrSeamMemoryUnexpected", err)
	}
	_, err = LoadManifestParamsForRun(home, f.Handle, f.PodName, f.PodVersion, RunMemory{
		Disclosed: feeder.SeamMemory{TouchedCellID: touchedJSON(1<<63 | 5)},
	})
	if !errors.Is(err, membridge.ErrMemoryTouchedCellInvalid) {
		t.Fatalf("v1 with touched_cell_id: err = %v, want MEMORY_TOUCHED_CELL_INVALID", err)
	}
}

// TestRunMemoryThroughWriteWitness composes the loader with
// feeder.WriteWitness, as the CLI does: the witness gets the R-M23 touched
// cell's read lane over the committed r_init, whatever the seam's step
// index is (konareef-rinit/v2 R-M24).
func TestRunMemoryThroughWriteWitness(t *testing.T) {
	lf := newLeafFixture(t)
	mp, _, err := lf.load(lf.disclosure(t), lf.table(t, nil, nil), nil)
	if err != nil {
		t.Fatal(err)
	}
	td := lf.touchedDerived(t)
	for _, stepIndex := range []uint32{0, td.Index + 1} {
		dir := t.TempDir()
		sd := feeder.StepDisclosure{
			Index: stepIndex, P: []byte("p"), R: []byte("r"), C: 1, Model: "gpt-4o", ModelID: mp.Models[0],
		}
		raw, _ := json.Marshal(sd)
		seam := filepath.Join(dir, "step-disclosure.json")
		if err := os.WriteFile(seam, raw, 0o644); err != nil {
			t.Fatal(err)
		}
		out := filepath.Join(dir, "witness.json")
		if err := feeder.WriteWitness(seam, mp, out); err != nil {
			t.Fatalf("step index %d: %v", stepIndex, err)
		}
		raw, err = os.ReadFile(out)
		if err != nil {
			t.Fatal(err)
		}
		var w feeder.Witness
		if err := json.Unmarshal(raw, &w); err != nil {
			t.Fatal(err)
		}
		if w.Memory == nil || !bytes.Equal(w.Memory.RInit, lf.rInit[:]) || w.Memory.Index != td.Index ||
			!bytes.Equal(w.Memory.KeyTag, td.KeyTag[:]) || !bytes.Equal(w.Memory.ContentHash, td.ContentHash[:]) {
			t.Fatalf("step index %d: lane = %+v, want the touched cell at %d", stepIndex, w.Memory, td.Index)
		}
		if bytes.Contains(raw, lf.salt[:]) {
			t.Fatal("the witness must not carry the salt")
		}
	}
}
