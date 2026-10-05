// Copyright 2026 Jerry David Chan, Konareef.ai
// SPDX-License-Identifier: Apache-2.0

// run_memory_test.go — the sidecar's salt-free run memory check
// (MEM-SEAM A1/B1/C1/S-7, run_memory.go): a memory-bearing manifest loads
// only with a disclosed cell list equal to the manifest's committed list
// and a publisher-signed leaf table that matches both and its root; every
// missing or changed input refuses and returns no params. The memory-free
// and v1 controls check the C1 presence rule.
package install

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
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
	derived []membridge.DerivedCell
	rInit   [32]byte
}

// newLeafFixture writes memoryPodTOML's pod, derives r_init with a fixed
// salt, signs a v2 manifest over it with a fresh key, and caches it.
func newLeafFixture(t *testing.T) *leafFixture {
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
	lf := &leafFixture{cells: cells}
	for i := range lf.salt {
		lf.salt[i] = byte(0x30 + i)
	}
	if lf.rInit, lf.derived, err = membridge.RInitV1(lf.salt[:], cells); err != nil {
		t.Fatal(err)
	}
	body, _ := os.ReadFile(filepath.Join(podDir, "pod.toml"))
	canonBytes, err := canon.CanonicalizeV2(body, podDir, canon.CommitParams{
		Models: models, Tools: tools, CMax: cMax, RInit: lf.rInit, RInitScheme: canon.RInitSchemeV1,
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

// table builds and signs a leaf table. mutate may change the table before
// it is signed; signer defaults to the publisher.
func (lf *leafFixture) table(t *testing.T, mutate func(*membridge.LeafTable), signer *identity.Identity) *LeafTableEvidence {
	t.Helper()
	tb, err := membridge.NewLeafTable(lf.f.PodHash, lf.rInit, lf.cells, lf.derived)
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
// refusal of the salt-free path.
func TestLoadManifestParamsForRunMemoryBearing(t *testing.T) {
	lf := newLeafFixture(t)
	disclosed := feeder.SeamMemory{Present: true, Cells: lf.cells}

	// Control: the checked table's r_init and leaves become the params.
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
	otherRoot, otherDerived, err := membridge.RInitV1(otherSalt[:], lf.cells)
	if err != nil {
		t.Fatal(err)
	}
	changed := append([]membridge.Cell(nil), lf.cells...)
	changed[0] = membridge.Cell{CellID: lf.cells[0].CellID, ContentHash: bytes.Repeat([]byte{0x42}, 32)}
	tampered := lf.table(t, nil, nil)
	tampered.Table = append([]byte(nil), tampered.Table...)
	tampered.Table[len(tampered.Table)-1] ^= 1

	cases := map[string]struct {
		disclosed feeder.SeamMemory
		ev        *LeafTableEvidence
		fetchErr  error
		want      error
	}{
		"no initial_memory (C1)":            {feeder.SeamMemory{}, lf.table(t, nil, nil), nil, ErrSeamMemoryMissing},
		"disclosed content changed":         {feeder.SeamMemory{Present: true, Cells: changed}, lf.table(t, nil, nil), nil, ErrSeamMemoryMismatch},
		"disclosed cell dropped":            {feeder.SeamMemory{Present: true, Cells: lf.cells[:1]}, lf.table(t, nil, nil), nil, ErrSeamMemoryMismatch},
		"disclosed empty":                   {feeder.SeamMemory{Present: true, Cells: []membridge.Cell{}}, lf.table(t, nil, nil), nil, ErrSeamMemoryMismatch},
		"no table":                          {disclosed, nil, nil, ErrLeafTableUnavailable},
		"fetch failed":                      {disclosed, nil, errors.New("status 404"), ErrLeafTableUnavailable},
		"table signed by another key":       {disclosed, lf.table(t, nil, other), nil, ErrLeafTableSignature},
		"table bytes changed after signing": {disclosed, tampered, nil, ErrLeafTableSignature},
		"table for another pod_hash": {disclosed, lf.table(t, func(tb *membridge.LeafTable) {
			tb.PodHash[0] ^= 1
		}, nil), nil, membridge.ErrLeafTableMismatch},
		"table content hashes swapped": {disclosed, lf.table(t, func(tb *membridge.LeafTable) {
			tb.Leaves[0].ContentHash, tb.Leaves[1].ContentHash = tb.Leaves[1].ContentHash, tb.Leaves[0].ContentHash
		}, nil), nil, membridge.ErrLeafTableMismatch},
		"table indices swapped": {disclosed, lf.table(t, func(tb *membridge.LeafTable) {
			tb.Leaves[0].Index, tb.Leaves[1].Index = tb.Leaves[1].Index, tb.Leaves[0].Index
		}, nil), nil, membridge.ErrRInitMismatch},
		"table value hash changed": {disclosed, lf.table(t, func(tb *membridge.LeafTable) {
			tb.Leaves[0].ValueHash = tb.Leaves[1].ValueHash
		}, nil), nil, membridge.ErrRInitMismatch},
		"table from another salt, self-consistent": {disclosed, lf.table(t, func(tb *membridge.LeafTable) {
			tb.RInit = otherRoot
			for i := range tb.Leaves {
				for _, d := range otherDerived {
					if d.CellID == tb.Leaves[i].CellID {
						tb.Leaves[i].Index, tb.Leaves[i].ValueHash = d.Index, d.ValueHash
					}
				}
			}
		}, nil), nil, ErrCommittedFieldsRootMismatch},
		"table bytes malformed": {disclosed, func() *LeafTableEvidence {
			raw := []byte("konareef-mem-leaves/v1 truncated")
			sig, _ := lf.id.Sign(raw)
			return &LeafTableEvidence{Table: raw, Signature: sig}
		}(), nil, membridge.ErrLeafTableInvalid},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			mp, _, err := lf.load(c.disclosed, c.ev, c.fetchErr)
			if !errors.Is(err, c.want) {
				t.Fatalf("err = %v, want %v", err, c.want)
			}
			if mp.Manifest != nil {
				t.Fatal("params returned on refusal")
			}
		})
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
	if err != nil || fetched || mp.RInit != canon.EmptyMemoryRoot() || mp.MemoryCells != nil {
		t.Fatalf("control: err=%v fetched=%v RInit=%x cells=%v", err, fetched, mp.RInit, mp.MemoryCells)
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
}

// TestRunMemoryThroughWriteWitness composes the loader with
// feeder.WriteWitness, as the CLI does: a touched index that names a
// checked cell gets a lane over the committed r_init; an index that names
// no cell is refused (S-7) and no witness is written.
func TestRunMemoryThroughWriteWitness(t *testing.T) {
	lf := newLeafFixture(t)
	mp, _, err := lf.load(feeder.SeamMemory{Present: true, Cells: lf.cells}, lf.table(t, nil, nil), nil)
	if err != nil {
		t.Fatal(err)
	}
	write := func(index uint32) (string, error) {
		dir := t.TempDir()
		sd := feeder.StepDisclosure{
			Index: index, P: []byte("p"), R: []byte("r"), C: 1, Model: "gpt-4o", ModelID: mp.Models[0],
		}
		raw, _ := json.Marshal(sd)
		seam := filepath.Join(dir, "step-disclosure.json")
		if err := os.WriteFile(seam, raw, 0o644); err != nil {
			t.Fatal(err)
		}
		out := filepath.Join(dir, "witness.json")
		return out, feeder.WriteWitness(seam, mp, out)
	}

	out, err := write(lf.derived[0].Index)
	if err != nil {
		t.Fatalf("tracked index: %v", err)
	}
	raw, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	var w feeder.Witness
	if err := json.Unmarshal(raw, &w); err != nil {
		t.Fatal(err)
	}
	if w.Memory == nil || !bytes.Equal(w.Memory.RInit, lf.rInit[:]) || w.Memory.Index != lf.derived[0].Index {
		t.Fatalf("lane = %+v, want r_init %x at %d", w.Memory, lf.rInit, lf.derived[0].Index)
	}

	untracked := (lf.derived[0].Index + 1) % (1 << membridge.D)
	for _, d := range lf.derived {
		if d.Index == untracked {
			untracked = (untracked + 1) % (1 << membridge.D)
		}
	}
	out, err = write(untracked)
	if !errors.Is(err, feeder.ErrMemoryIndexUntracked) {
		t.Fatalf("untracked index: err = %v, want ErrMemoryIndexUntracked", err)
	}
	if _, statErr := os.Stat(out); statErr == nil {
		t.Fatal("no witness may be written for an untracked index")
	}
}
