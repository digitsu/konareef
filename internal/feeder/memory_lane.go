// Copyright 2026 Jerry David Chan, Konareef.ai
// SPDX-License-Identifier: Apache-2.0

// memory_lane.go — the optional PS-1 memory-witness lane for
// memory-bearing konareef-toml/v2 manifests (paygate-zk
// docs/prds/konareef-memory-root-v1-proof-path.md §7, owner decision O1-A).
//
// Wire shape (additive, optional; absent means memory-free, r_init = E20):
//
//	pod_record.memory = {
//	  r_init:        b64(32)          LE Fq; MUST equal the r_init inside [_commit].fields_root
//	  index:         u32 < 2^20       the touched cell
//	  value_hash_in: b64(32)          LE Fq; 0 for an empty slot
//	  siblings:      [b64(32)] x 20   LSB-first authentication path
//	}
//
// The feeder builds the lane only from memory evidence the salt holder
// has already checked against the signed commitment
// (install.LoadManifestParamsWithMemory → membridge.CheckRInitV1). It
// never substitutes E20 or zero for a missing lane, and it refuses to
// build a witness for a manifest that commits a populated root when no
// evidence is present. The salt and the cell contents never enter the
// lane; only value hashes and siblings do.
//
// PS-1 does not accept this lane yet (MEM-04). Memory-bearing publish is
// refused in every build until then, so no production witness carries it.
package feeder

import (
	"errors"
	"fmt"

	"github.com/digitsu/konareef/internal/canon"
	"github.com/digitsu/konareef/internal/membridge"
)

// MemoryLane is pod_record.memory. Byte fields are raw bytes; encoding/json
// renders them as base64, matching the rest of the PS-1 wire.
type MemoryLane struct {
	RInit       []byte   `json:"r_init"`
	Index       uint32   `json:"index"`
	ValueHashIn []byte   `json:"value_hash_in"`
	Siblings    [][]byte `json:"siblings"`
}

// ErrMemoryEvidenceMissing means the manifest commits a populated memory
// root but the feeder was given no checked memory cells. No witness is
// built: a witness over the empty tree would prove a root the manifest
// does not commit.
var ErrMemoryEvidenceMissing = errors.New(
	"feeder: manifest commits a populated memory root but no checked memory evidence was supplied; no witness is built")

// ErrMemoryRootNotCommitted means the witness r_init (the lane's, or E20
// for a witness without a lane) does not reproduce the manifest's
// committed [_commit].fields_root over the witness models, tools and
// c_max. A legacy zero-root manifest fails here too.
var ErrMemoryRootNotCommitted = errors.New("feeder: witness r_init does not reproduce the committed fields_root")

// ErrMemoryIndexUntracked means the step's touched index names no cell of
// a memory-bearing manifest's checked memory (MEM-SEAM S-7). The index is
// read from step-disclosure.json, which the pod can write, so an
// empty-slot read is refused rather than proved.
var ErrMemoryIndexUntracked = errors.New(
	"feeder: the step's touched index is not a cell of the manifest's committed memory; an empty-slot read is refused")

// ErrMemoryLaneInvalid means a memory lane does not authenticate against
// its own r_init, or is malformed.
var ErrMemoryLaneInvalid = errors.New("feeder: memory lane does not authenticate against r_init")

// BuildMemoryLane builds the lane for the cell at index.
//
// Inputs: the checked r_init, the checked cells (index → value hash, from
// membridge.CheckRInitV1) and the touched index. Output: the lane, whose
// authentication path is re-verified against rInit before it is returned,
// or ErrMemoryLaneInvalid (index out of range, cells that do not hash to
// rInit). An empty index gets value_hash_in = 0.
func BuildMemoryLane(rInit [32]byte, cells map[uint32][32]byte, index uint32) (*MemoryLane, error) {
	path, err := membridge.BuildAuthPath(cells, index)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrMemoryLaneInvalid, err)
	}
	vhIn := cells[index] // zero value for an empty slot
	lane := &MemoryLane{
		RInit:       append([]byte(nil), rInit[:]...),
		Index:       index,
		ValueHashIn: append([]byte(nil), vhIn[:]...),
		Siblings:    make([][]byte, len(path)),
	}
	for k := range path {
		lane.Siblings[k] = append([]byte(nil), path[k][:]...)
	}
	if err := validateMemoryLane(lane); err != nil {
		return nil, err
	}
	return lane, nil
}

// memoryLaneFor decides the lane for a witness.
//
// Inputs: the manifest params and the touched index. Output: nil for a
// memory-free manifest (no cells and an r_init that is E20, or unset for
// callers that predate the field); a lane when checked cells are present
// and the index names one of them; ErrMemoryIndexUntracked when it does
// not (S-7); ErrMemoryEvidenceMissing when the params name a populated
// r_init without cells. When the manifest carries a parseable [_commit] trailer
// the chosen r_init (E20 without a lane) must reproduce it
// (checkCommittedRInit), so a zero RInit cannot smuggle a legacy-zero or
// memory-bearing manifest through as memory-free.
func memoryLaneFor(mp ManifestParams, index uint32) (*MemoryLane, error) {
	if mp.MemoryCells == nil {
		if mp.RInit != ([32]byte{}) && mp.RInit != canon.EmptyMemoryRoot() {
			return nil, ErrMemoryEvidenceMissing
		}
		if err := checkCommittedRInit(mp.Manifest, mp.Models, mp.Tools, mp.CMax, canon.EmptyMemoryRoot()); err != nil {
			return nil, err
		}
		return nil, nil
	}
	// MEM-SEAM S-7 (owner decision 2026-09-26): the touched index comes
	// from step-disclosure.json, which a pod can write. For a
	// memory-bearing manifest it must name a checked cell; an empty-slot
	// read is refused, not proved.
	if _, ok := mp.MemoryCells[index]; !ok {
		return nil, ErrMemoryIndexUntracked
	}
	return BuildMemoryLane(mp.RInit, mp.MemoryCells, index)
}

// checkCommittedRInit binds a witness r_init to the manifest.
//
// Inputs: the manifest bytes, the witness models, tools and c_max, and
// the r_init the witness will prove. Output: nil when the manifest
// commits no trailer (konareef-toml/v1, or no magic line), or when FieldsRoot(models, tools, c_max, rInit) equals
// the committed fields_root; ErrMemoryRootNotCommitted otherwise,
// including for a v2 or v3 manifest whose trailer does not parse.
func checkCommittedRInit(manifest []byte, models, tools []string, cMax uint64, rInit [32]byte) error {
	trailer, err := canon.ParseCommitTrailer(manifest)
	if err != nil {
		// A konareef-toml/v2 or v3 manifest always carries a trailer. One
		// that does not parse is not "commits nothing": it is refused, so
		// an unreadable trailer can never pass a memory-bearing manifest
		// through as memory-free (MEM-SEAM security review, L6).
		if version, ok := canon.VersionIdentifier(manifest); ok && (version == "v2" || version == "v3") {
			return fmt.Errorf("%w: the %s manifest's [_commit] trailer does not parse", ErrMemoryRootNotCommitted, version)
		}
		return nil
	}
	got, err := canon.FieldsRoot(models, tools, cMax, rInit)
	if err != nil || got != trailer.FieldsRoot {
		return ErrMemoryRootNotCommitted
	}
	return nil
}

// validateMemoryLane checks the lane's shape and recomputes
// authenticate(value_hash_in, index, siblings); it must equal r_init.
// This is the PS-1 host rule of MEM-01 §7, applied at the producer so a
// bad lane never reaches the prover.
func validateMemoryLane(l *MemoryLane) error {
	if len(l.RInit) != 32 || len(l.ValueHashIn) != 32 || len(l.Siblings) != membridge.D {
		return fmt.Errorf("%w: malformed lane", ErrMemoryLaneInvalid)
	}
	var path [membridge.D][32]byte
	for k, s := range l.Siblings {
		if len(s) != 32 {
			return fmt.Errorf("%w: sibling %d is %d bytes", ErrMemoryLaneInvalid, k, len(s))
		}
		copy(path[k][:], s)
	}
	var vh, rInit [32]byte
	copy(vh[:], l.ValueHashIn)
	copy(rInit[:], l.RInit)
	leaf, err := membridge.LeafHash(vh)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrMemoryLaneInvalid, err)
	}
	root, err := membridge.VerifyAuthPath(l.Index, leaf, path)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrMemoryLaneInvalid, err)
	}
	if root != rInit {
		return ErrMemoryLaneInvalid
	}
	return nil
}
