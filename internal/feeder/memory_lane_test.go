// Copyright 2026 Jerry David Chan, Konareef.ai
// SPDX-License-Identifier: Apache-2.0

// memory_lane_test.go — the optional pod_record.memory lane
// (konareef-rinit/v2 R-M26, R-M27): memory-free witnesses carry no lane
// and marshal as before; a memory-bearing witness carries the touched
// cell's read lane, which passes the PS-1 checks against the committed
// r_init; a populated r_init without evidence, an empty slot or a
// tampered lane is refused before witness.json is written.
package feeder

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/digitsu/konareef/internal/canon"
	"github.com/digitsu/konareef/internal/membridge"
)

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

// TestMemoryBearingWitnessCarriesTouchedLane: with a checked v2 table and
// touched row the lane is built for the touched cell, survives
// AssemblePodRecord, and the JSON uses the R-M26 field names. The step
// index does not move the lane.
func TestMemoryBearingWitnessCarriesTouchedLane(t *testing.T) {
	fx := buildV2Fixture(t, loadFeederV2Vectors(t), "file-inline-file-multi")
	dir := t.TempDir()
	seam := writeSeamFixture(t, dir, StepDisclosure{Index: 0, P: []byte("p"), R: []byte("r"), C: 1,
		Model: "claude-sonnet-4-5", ModelID: "anthropic/claude-sonnet-4-5"})
	out := filepath.Join(dir, "witness.json")
	if err := WriteWitness(seam, memoryBearingParams(t, fx), out); err != nil {
		t.Fatal(err)
	}
	raw, _ := os.ReadFile(out)
	var w Witness
	if err := json.Unmarshal(raw, &w); err != nil {
		t.Fatal(err)
	}
	if w.Memory == nil || w.Memory.Index != fx.touched.Index || w.Memory.Index == 0 ||
		!bytes.Equal(w.Memory.RInit, fx.rInit[:]) || len(w.Memory.Siblings) != membridge.D ||
		!bytes.Equal(w.Memory.ValueHashIn, fx.touched.ValueHash[:]) ||
		!bytes.Equal(w.Memory.KeyTag, fx.touched.KeyTag[:]) || !bytes.Equal(w.Memory.ContentHash, fx.touched.ContentHash[:]) {
		t.Fatalf("bad lane %+v", w.Memory)
	}
	pr, err := AssemblePodRecord(w)
	if err != nil || pr.Memory == nil {
		t.Fatalf("AssemblePodRecord: %v", err)
	}
	wire, _ := json.Marshal(pr)
	for _, key := range []string{`"memory":{`, `"r_init":`, `"value_hash_in":`, `"siblings":[`, `"key_tag":`, `"content_hash":`} {
		if !bytes.Contains(wire, []byte(key)) {
			t.Fatalf("wire lacks %s", key)
		}
	}
}

// TestMemoryLaneRefusals: no evidence for a populated root, cells without
// a touched cell, a touched index that holds no cell, cells that do not
// hash to the claimed root, and a tampered lane are all refused, and
// witness.json is not written.
func TestMemoryLaneRefusals(t *testing.T) {
	fx := buildV2Fixture(t, loadFeederV2Vectors(t), "file-inline-file-multi")
	write := func(mp ManifestParams) (error, bool) {
		dir := t.TempDir()
		seam := writeSeamFixture(t, dir, StepDisclosure{Index: 0, P: []byte("p"), R: []byte("r"), C: 1,
			Model: "claude-sonnet-4-5", ModelID: "anthropic/claude-sonnet-4-5"})
		out := filepath.Join(dir, "witness.json")
		err := WriteWitness(seam, mp, out)
		_, statErr := os.Stat(out)
		return err, statErr == nil
	}

	mp := validManifestParams()
	mp.RInit = fx.rInit
	if err, wrote := write(mp); !errors.Is(err, ErrMemoryEvidenceMissing) || wrote {
		t.Fatalf("no evidence: err = %v, wrote = %v", err, wrote)
	}
	mp = memoryBearingParams(t, fx)
	mp.MemoryTouched = nil
	if err, wrote := write(mp); !errors.Is(err, ErrMemoryEvidenceMissing) || wrote {
		t.Fatalf("no touched cell: err = %v, wrote = %v", err, wrote)
	}
	mp = memoryBearingParams(t, fx)
	mp.MemoryCells = nil
	if err, wrote := write(mp); !errors.Is(err, ErrMemoryLaneInvalid) || wrote {
		t.Fatalf("touched cell without cells: err = %v, wrote = %v", err, wrote)
	}
	mp = memoryBearingParams(t, fx)
	empty := *mp.MemoryTouched
	empty.Index = 7
	if _, taken := mp.MemoryCells[7]; taken {
		t.Fatal("fixture: index 7 must be an empty slot")
	}
	mp.MemoryTouched = &empty
	if err, wrote := write(mp); !errors.Is(err, ErrMemoryIndexUntracked) || !errors.Is(err, membridge.ErrMemoryEmptySlotRead) || wrote {
		t.Fatalf("empty slot: err = %v, wrote = %v", err, wrote)
	}
	mp = memoryBearingParams(t, fx)
	mp.RInit = canon.EmptyMemoryRoot()
	if err, wrote := write(mp); !errors.Is(err, membridge.ErrMemoryIndexMismatch) || wrote {
		t.Fatalf("cells against another root: err = %v, wrote = %v", err, wrote)
	}

	// A zero or E20 RInit without cells must still match the trailer: a
	// legacy-zero or memory-bearing manifest cannot pass as memory-free.
	for name, committed := range map[string][32]byte{"legacy zero": {}, "populated": fx.rInit} {
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

	lane, err := BuildMemoryLane(fx.rInit, fx.table.ValueHashes(), fx.touched)
	if err != nil {
		t.Fatalf("control lane: %v", err)
	}
	base := validManifestParams()
	w := Witness{Manifest: manifestCommittingV2(t, fx.rInit), Index: 0, Model: base.Models[0], Models: base.Models,
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
	// Each tamper is refused with its PS-1 code.
	tampers := map[string]struct {
		mutate func(l *MemoryLane)
		want   error
	}{
		"sibling":      {func(l *MemoryLane) { l.Siblings[4][0] ^= 1 }, membridge.ErrMemoryIndexMismatch},
		"index":        {func(l *MemoryLane) { l.Index ^= 1 }, membridge.ErrMemoryIndexMismatch},
		"key_tag":      {func(l *MemoryLane) { l.KeyTag[0] ^= 1 }, membridge.ErrMemoryPayloadMismatch},
		"content_hash": {func(l *MemoryLane) { l.ContentHash[31] ^= 1 }, membridge.ErrMemoryPayloadMismatch},
		"empty slot":   {func(l *MemoryLane) { l.ValueHashIn = make([]byte, 32) }, membridge.ErrMemoryEmptySlotRead},
		"short tag":    {func(l *MemoryLane) { l.KeyTag = l.KeyTag[:31] }, ErrMemoryLaneInvalid},
	}
	for name, tc := range tampers {
		l, _ := BuildMemoryLane(fx.rInit, fx.table.ValueHashes(), fx.touched)
		tc.mutate(l)
		wt := w
		wt.Memory = l
		if _, err := AssemblePodRecord(wt); !errors.Is(err, ErrMemoryLaneInvalid) || !errors.Is(err, tc.want) {
			t.Errorf("tampered %s: err = %v, want %v", name, err, tc.want)
		}
	}
	outOfRange := fx.touched
	outOfRange.Index = 1 << membridge.D
	if _, err := BuildMemoryLane(fx.rInit, fx.table.ValueHashes(), outOfRange); !errors.Is(err, ErrMemoryIndexUntracked) {
		t.Fatalf("out-of-range index: err = %v", err)
	}
}
