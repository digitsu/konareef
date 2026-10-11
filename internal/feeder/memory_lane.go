// Copyright 2026 Jerry David Chan, Konareef.ai
// SPDX-License-Identifier: Apache-2.0

// memory_lane.go — the optional PS-1 memory-witness lane for
// memory-bearing konareef-toml/v2 and v3 manifests (konareef-rinit/v2
// spec §6, R-M26; paygate-zk konareef-pod-step-v1.2).
//
// Wire shape (additive, optional; absent means memory-free, r_init = E20):
//
//	pod_record.memory = {
//	  r_init:        b64(32)          LE Fq; MUST equal the r_init inside [_commit].fields_root
//	  index:         u32 < 2^20       the touched cell's index (from the v2 leaf table)
//	  value_hash_in: b64(32)          LE Fq; never 0
//	  siblings:      [b64(32)] x 20   LSB-first authentication path
//	  key_tag:       b64(32)          the touched cell's key_tag
//	  content_hash:  b64(32)          the touched cell's content hash
//	}
//
// The feeder builds the lane only for the touched cell the R-M23 rule
// picks (the committed cell with the lowest cell_id), from memory evidence
// already checked against the signed commitment: the sidecar's v2 leaf
// table (install.LoadManifestParamsForRun) or the salt holder's own
// derivation (install.LoadManifestParamsWithMemory). It never reads the
// step index as a memory index, never substitutes E20 or zero for a
// missing lane, and refuses to build a witness for a manifest that commits
// a populated root when no evidence is present. The salt never enters the
// lane. The run is a read (W-A): the step proves value_hash_out =
// value_hash_in, so r_out = r_in.
//
// Scope of the R-M23 rule: the WitnessWriter path (--step-disclosure,
// which reef-core always uses) fetches the leaf table and builds the lane
// only for the R-M23 touched cell. The bare --witness path (an operator or
// debug path) reads a lane someone else built: it checks the PS-1 lane
// rules, the konareef-rinit/v2 marker and the committed r_init, but it
// cannot run R-M20 or R-M23, so it accepts a lane for any committed cell.
// Whoever writes that witness file can call PS-1 directly, so this is no
// weaker than PS-1 itself (spec §6 residual).
//
// Memory-bearing publish is refused in every build (the gate is off), so
// no production witness carries this lane yet.
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
	KeyTag      []byte   `json:"key_tag"`
	ContentHash []byte   `json:"content_hash"`
}

// ErrMemoryEvidenceMissing means the manifest commits a populated memory
// root but the feeder was given no checked memory cells or no touched
// cell. No witness is built: a witness over the empty tree would prove a
// root the manifest does not commit.
var ErrMemoryEvidenceMissing = errors.New(
	"feeder: manifest commits a populated memory root but no checked memory evidence was supplied; no witness is built")

// ErrMemoryRootNotCommitted means the witness r_init (the lane's, or E20
// for a witness without a lane) does not reproduce the manifest's
// committed [_commit].fields_root over the witness models, tools and
// c_max. A legacy zero-root manifest fails here too.
var ErrMemoryRootNotCommitted = errors.New("feeder: witness r_init does not reproduce the committed fields_root")

// ErrMemoryIndexUntracked means the touched cell's index holds no checked
// cell of a memory-bearing manifest. An empty-slot read is refused rather
// than proved. It wraps membridge.ErrMemoryEmptySlotRead
// (MEMORY_EMPTY_SLOT_READ, rinit/v2 R-M20 step 4).
var ErrMemoryIndexUntracked = fmt.Errorf(
	"feeder: the touched index is not a cell of the manifest's committed memory; an empty-slot read is refused: %w",
	membridge.ErrMemoryEmptySlotRead)

// ErrMemoryLaneManifestNotV2 means a witness carries a memory lane but its
// manifest has no parseable [_commit] trailer with
// r_init_scheme = "konareef-rinit/v2": no trailer, a legacy trailer
// without a marker, the konareef-rinit/v1 marker, or an unknown scheme.
// Only a konareef-rinit/v2 manifest can bind a memory lane (R-M29, R-M30),
// so nothing is sent to PS-1.
var ErrMemoryLaneManifestNotV2 = errors.New(
	"feeder: a memory lane needs a manifest whose [_commit] trailer names konareef-rinit/v2; no proof is requested")

// requireMemoryLaneManifest refuses a memory lane over a manifest that is
// not a konareef-rinit/v2 commitment.
//
// Input: the manifest bytes. Output: nil when the [_commit] trailer
// parses and its r_init_scheme is exactly canon.RInitSchemeV2; otherwise
// an error wrapping ErrMemoryLaneManifestNotV2 (and ErrMemoryRootNotCommitted).
func requireMemoryLaneManifest(manifest []byte) error {
	trailer, err := canon.ParseCommitTrailer(manifest)
	if err != nil {
		return fmt.Errorf("%w: %w: the [_commit] trailer is missing or does not parse", ErrMemoryRootNotCommitted, ErrMemoryLaneManifestNotV2)
	}
	if trailer.RInitScheme != canon.RInitSchemeV2 {
		return fmt.Errorf("%w: %w: r_init_scheme is not konareef-rinit/v2", ErrMemoryRootNotCommitted, ErrMemoryLaneManifestNotV2)
	}
	return nil
}

// ErrMemoryLaneInvalid means a memory lane is malformed or fails a PS-1
// lane check (membridge.CheckReadLane). The error that carries it also
// wraps the membridge refusal code when there is one.
var ErrMemoryLaneInvalid = errors.New("feeder: memory lane is invalid")

// BuildMemoryLane builds the read lane for the touched cell.
//
// Inputs: the checked r_init, the checked cells (index → value hash) and
// the touched cell's checked v2 row. Output: the lane, re-checked with
// the PS-1 rules (validateMemoryLane) before it is returned, or an error
// wrapping ErrMemoryLaneInvalid (index out of range, cells that do not
// hash to rInit, a row that does not match its key_tag) or
// ErrMemoryIndexUntracked (the touched index holds no checked cell, or
// another value hash).
func BuildMemoryLane(rInit [32]byte, cells map[uint32][32]byte, touched membridge.LeafV2) (*MemoryLane, error) {
	if vh, ok := cells[touched.Index]; !ok || vh != touched.ValueHash {
		return nil, ErrMemoryIndexUntracked
	}
	path, err := membridge.BuildAuthPath(cells, touched.Index)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrMemoryLaneInvalid, err)
	}
	lane := &MemoryLane{
		RInit:       append([]byte(nil), rInit[:]...),
		Index:       touched.Index,
		ValueHashIn: append([]byte(nil), touched.ValueHash[:]...),
		Siblings:    make([][]byte, len(path)),
		KeyTag:      append([]byte(nil), touched.KeyTag[:]...),
		ContentHash: append([]byte(nil), touched.ContentHash[:]...),
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
// Input: the manifest params. Output: nil for a memory-free manifest (no
// cells and an r_init that is E20, or unset for callers that predate the
// field); the touched cell's lane for a memory-bearing one; or
// ErrMemoryEvidenceMissing when the params name a populated r_init without
// cells, or cells without a touched cell; ErrMemoryLaneInvalid when a
// memory-free manifest carries a touched cell. When the manifest carries a
// parseable [_commit] trailer the chosen r_init (E20 without a lane) must
// reproduce it (checkCommittedRInit), so a zero RInit cannot smuggle a
// legacy-zero or memory-bearing manifest through as memory-free.
//
// The step index of the seam is not an input: the lane index is the
// touched cell's (R-M24).
func memoryLaneFor(mp ManifestParams) (*MemoryLane, error) {
	if mp.MemoryCells == nil {
		if mp.MemoryTouched != nil {
			return nil, fmt.Errorf("%w: a touched cell without checked memory cells", ErrMemoryLaneInvalid)
		}
		if mp.RInit != ([32]byte{}) && mp.RInit != canon.EmptyMemoryRoot() {
			return nil, ErrMemoryEvidenceMissing
		}
		if err := checkCommittedRInit(mp.Manifest, mp.Models, mp.Tools, mp.CMax, canon.EmptyMemoryRoot()); err != nil {
			return nil, err
		}
		return nil, nil
	}
	if mp.MemoryTouched == nil {
		return nil, ErrMemoryEvidenceMissing
	}
	return BuildMemoryLane(mp.RInit, mp.MemoryCells, *mp.MemoryTouched)
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

// validateMemoryLane checks the lane's shape and applies the PS-1 lane
// checks of konareef-rinit/v2 R-M27 and the v1.2 read relation
// (membridge.CheckReadLane, with payload_in built from the lane as PS-1
// builds it and value_hash_out = value_hash_in). It runs at the producer
// so a bad lane never reaches the prover.
//
// Input: the lane. Output: nil, or an error wrapping ErrMemoryLaneInvalid
// and, for a failed check, the membridge refusal
// (MEMORY_EMPTY_SLOT_READ, MEMORY_PAYLOAD_MISMATCH, MEMORY_INDEX_MISMATCH).
func validateMemoryLane(l *MemoryLane) error {
	if len(l.RInit) != 32 || len(l.ValueHashIn) != 32 || len(l.Siblings) != membridge.D ||
		len(l.KeyTag) != 32 || len(l.ContentHash) != 32 {
		return fmt.Errorf("%w: malformed lane", ErrMemoryLaneInvalid)
	}
	var lane membridge.ReadLane
	for k, s := range l.Siblings {
		if len(s) != 32 {
			return fmt.Errorf("%w: sibling %d is %d bytes", ErrMemoryLaneInvalid, k, len(s))
		}
		copy(lane.Siblings[k][:], s)
	}
	copy(lane.RInit[:], l.RInit)
	copy(lane.ValueHashIn[:], l.ValueHashIn)
	copy(lane.KeyTag[:], l.KeyTag)
	copy(lane.ContentHash[:], l.ContentHash)
	lane.Index = l.Index
	payloadIn := membridge.CanonicalCellPayloadV2(lane.KeyTag, lane.ContentHash)
	if err := membridge.CheckReadLane(lane, payloadIn, lane.ValueHashIn); err != nil {
		return fmt.Errorf("%w: %w", ErrMemoryLaneInvalid, err)
	}
	return nil
}
