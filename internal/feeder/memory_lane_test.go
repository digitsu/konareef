// Copyright 2026 Jerry David Chan, Konareef.ai
// SPDX-License-Identifier: Apache-2.0

// memory_lane_test.go — the optional pod_record.memory lane (MEM-01 §7,
// O1-A): memory-free witnesses carry no lane and marshal as before; a
// memory-bearing witness carries a lane that authenticates against the
// committed r_init; a populated r_init without evidence, a tampered lane
// or a lane for another index is refused before witness.json is written.
package feeder

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/digitsu/konareef/internal/canon"
	"github.com/digitsu/konareef/internal/membridge"
)

// prd4MultiCell returns the PRD 4 mem-multi-cell-root cells (index →
// value hash) and their root 86ec05…871f.
func prd4MultiCell(t *testing.T) (map[uint32][32]byte, [32]byte) {
	t.Helper()
	salt := bytes.Repeat([]byte{0xaa}, 32)
	var cells []membridge.Cell
	for id, ch := range map[uint64]string{
		1: "aae0a971434ea3f6973aa77b266bd53ddae16abad964cd06ff44ecc799c5679e",
		2: "c29aa59cafc9e2437b2c9f0c8772593e63c5fe7b63dee5f9f1b1a8cc3369f919",
		3: "72b2ac744cd525b6ed060ef36ebf16496b2db6fed6ab44c82b292976b3338349",
	} {
		b, _ := hex.DecodeString(ch)
		cells = append(cells, membridge.Cell{CellID: id, ContentHash: b})
	}
	root, derived, err := membridge.RInitV1(salt, cells)
	if err != nil {
		t.Fatal(err)
	}
	if hex.EncodeToString(root[:]) != "86ec05dda6bd85f65f477160a7cddee1bb0f7e4b1775d09f1b9c88009ee2871f" {
		t.Fatalf("PRD 4 multi-cell root drifted: %x", root)
	}
	out := map[uint32][32]byte{}
	for _, d := range derived {
		out[d.Index] = d.ValueHash
	}
	return out, root
}

// manifestCommitting returns a minimal v2 manifest whose [_commit]
// trailer commits fields_root over the validManifestParams dimensions and
// rInit, with the konareef-rinit/v1 marker.
func manifestCommitting(t *testing.T, rInit [32]byte) []byte {
	t.Helper()
	mp := validManifestParams()
	fr, err := canon.FieldsRoot(mp.Models, mp.Tools, mp.CMax, rInit)
	if err != nil {
		t.Fatal(err)
	}
	return append([]byte("#!konareef-toml/v2\n[pod]\nname = \"x\"\n[_files]\n"),
		canon.CommitTrailerBytes(canon.CommitTrailer{FieldsRoot: fr, RInitScheme: canon.RInitSchemeV1})...)
}

// TestMemoryFreeWitnessHasNoLane: E20 or unset RInit with no cells gives
// no lane, and the marshalled witness has no "memory" key, so the
// memory-free PS-1 wire is byte-identical to before.
func TestMemoryFreeWitnessHasNoLane(t *testing.T) {
	for name, rInit := range map[string][32]byte{"unset": {}, "E20": canon.EmptyMemoryRoot()} {
		dir := t.TempDir()
		seam := writeSeamFixture(t, dir, StepDisclosure{Index: 5, P: []byte("p"), R: []byte("r"), C: 1,
			Model: "claude-sonnet-4-5", ModelID: "anthropic/claude-sonnet-4-5"})
		out := filepath.Join(dir, "witness.json")
		mp := validManifestParams()
		mp.RInit = rInit
		if err := WriteWitness(seam, mp, out); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		raw, _ := os.ReadFile(out)
		if bytes.Contains(raw, []byte(`"memory"`)) {
			t.Fatalf("%s: memory-free witness must not carry a memory key: %s", name, raw)
		}
	}
}

// TestMemoryBearingWitnessCarriesAuthenticatedLane: with checked cells
// the lane is built for a touched index that names a populated cell and
// survives AssemblePodRecord; the JSON uses the §7 field names. An empty
// slot is refused (MEM-SEAM S-7) and no witness is written.
func TestMemoryBearingWitnessCarriesAuthenticatedLane(t *testing.T) {
	cells, root := prd4MultiCell(t)
	var populated uint32
	for idx := range cells {
		populated = idx
		break
	}

	emptyDir := t.TempDir()
	emptySeam := writeSeamFixture(t, emptyDir, StepDisclosure{Index: 7, P: []byte("p"), R: []byte("r"), C: 1,
		Model: "claude-sonnet-4-5", ModelID: "anthropic/claude-sonnet-4-5"})
	emptyOut := filepath.Join(emptyDir, "witness.json")
	emptyMP := validManifestParams()
	emptyMP.Manifest = manifestCommitting(t, root)
	emptyMP.RInit, emptyMP.MemoryCells = root, cells
	if _, taken := cells[7]; taken {
		t.Fatal("fixture: index 7 must be an empty slot")
	}
	if err := WriteWitness(emptySeam, emptyMP, emptyOut); !errors.Is(err, ErrMemoryIndexUntracked) {
		t.Fatalf("empty slot: err = %v, want ErrMemoryIndexUntracked", err)
	}
	if _, err := os.Stat(emptyOut); err == nil {
		t.Fatal("empty slot: no witness may be written")
	}

	for name, index := range map[string]uint32{"populated": populated} {
		dir := t.TempDir()
		seam := writeSeamFixture(t, dir, StepDisclosure{Index: index, P: []byte("p"), R: []byte("r"), C: 1,
			Model: "claude-sonnet-4-5", ModelID: "anthropic/claude-sonnet-4-5"})
		out := filepath.Join(dir, "witness.json")
		mp := validManifestParams()
		mp.Manifest = manifestCommitting(t, root)
		mp.RInit, mp.MemoryCells = root, cells
		if err := WriteWitness(seam, mp, out); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		raw, _ := os.ReadFile(out)
		var w Witness
		if err := json.Unmarshal(raw, &w); err != nil {
			t.Fatal(err)
		}
		if w.Memory == nil || w.Memory.Index != index || !bytes.Equal(w.Memory.RInit, root[:]) || len(w.Memory.Siblings) != membridge.D {
			t.Fatalf("%s: bad lane %+v", name, w.Memory)
		}
		want := cells[index]
		if !bytes.Equal(w.Memory.ValueHashIn, want[:]) {
			t.Fatalf("%s: value_hash_in = %x, want %x", name, w.Memory.ValueHashIn, want)
		}
		pr, err := AssemblePodRecord(w)
		if err != nil || pr.Memory == nil {
			t.Fatalf("%s: AssemblePodRecord: %v", name, err)
		}
		wire, _ := json.Marshal(pr)
		for _, key := range []string{`"memory":{`, `"r_init":`, `"value_hash_in":`, `"siblings":[`} {
			if !bytes.Contains(wire, []byte(key)) {
				t.Fatalf("%s: wire lacks %s", name, key)
			}
		}
	}
}

// TestMemoryLaneRefusals: no evidence for a populated root, cells that do
// not hash to the claimed root, a tampered sibling and a lane for another
// index are all refused, and witness.json is not written.
func TestMemoryLaneRefusals(t *testing.T) {
	cells, root := prd4MultiCell(t)
	// The touched index names a populated cell, so each refusal below is
	// the one under test and not the S-7 empty-slot refusal.
	var touched uint32
	for idx := range cells {
		touched = idx
		break
	}
	write := func(mp ManifestParams) (error, bool) {
		dir := t.TempDir()
		seam := writeSeamFixture(t, dir, StepDisclosure{Index: touched, P: []byte("p"), R: []byte("r"), C: 1,
			Model: "claude-sonnet-4-5", ModelID: "anthropic/claude-sonnet-4-5"})
		out := filepath.Join(dir, "witness.json")
		err := WriteWitness(seam, mp, out)
		_, statErr := os.Stat(out)
		return err, statErr == nil
	}

	mp := validManifestParams()
	mp.RInit = root
	if err, wrote := write(mp); !errors.Is(err, ErrMemoryEvidenceMissing) || wrote {
		t.Fatalf("no evidence: err = %v, wrote = %v", err, wrote)
	}
	mp.MemoryCells = cells
	mp.RInit = canon.EmptyMemoryRoot()
	if err, wrote := write(mp); !errors.Is(err, ErrMemoryLaneInvalid) || wrote {
		t.Fatalf("cells against another root: err = %v, wrote = %v", err, wrote)
	}

	// A zero or E20 RInit without cells must still match the trailer: a
	// legacy-zero or memory-bearing manifest cannot pass as memory-free.
	for name, committed := range map[string][32]byte{"legacy zero": {}, "populated": root} {
		mp := validManifestParams()
		mp.Manifest = manifestCommitting(t, committed)
		if err, wrote := write(mp); !errors.Is(err, ErrMemoryRootNotCommitted) || wrote {
			t.Fatalf("%s manifest, no RInit: err = %v, wrote = %v", name, err, wrote)
		}
	}
	mpE20 := validManifestParams()
	mpE20.Manifest = manifestCommitting(t, canon.EmptyMemoryRoot())
	if err, wrote := write(mpE20); err != nil || !wrote {
		t.Fatalf("E20 control: err = %v", err)
	}

	lane, err := BuildMemoryLane(root, cells, 7)
	if err != nil {
		t.Fatalf("control lane: %v", err)
	}
	base := validManifestParams()
	w := Witness{Manifest: manifestCommitting(t, root), Index: 7, Model: base.Models[0], Models: base.Models,
		Tools: base.Tools, CMax: base.CMax, SigManifest: validSigLane(), PkPub: validPubKeyBytes(), Memory: lane}
	if _, err := AssemblePodRecord(w); err != nil {
		t.Fatalf("control assemble: %v", err)
	}
	// A self-consistent lane over a root the manifest does not commit.
	wOther := w
	wOther.Manifest = manifestCommitting(t, canon.EmptyMemoryRoot())
	if _, err := AssemblePodRecord(wOther); !errors.Is(err, ErrMemoryRootNotCommitted) {
		t.Fatalf("lane over an uncommitted root: err = %v", err)
	}
	w.Index = 8
	if _, err := AssemblePodRecord(w); !errors.Is(err, ErrMemoryLaneInvalid) {
		t.Fatalf("index mismatch: err = %v", err)
	}
	w.Index = 7
	lane.Siblings[4] = append([]byte(nil), lane.Siblings[4]...)
	lane.Siblings[4][0] ^= 1
	if _, err := AssemblePodRecord(w); !errors.Is(err, ErrMemoryLaneInvalid) {
		t.Fatalf("tampered sibling: err = %v", err)
	}
	if _, err := BuildMemoryLane(root, cells, 1<<membridge.D); !errors.Is(err, ErrMemoryLaneInvalid) {
		t.Fatalf("out-of-range index: err = %v", err)
	}
}
