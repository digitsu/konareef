// Copyright 2026 Jerry David Chan, Konareef.ai
// SPDX-License-Identifier: Apache-2.0

// manifest_identity.go — identity and commitment checks on an installed
// manifest before the feeder uses it (IB-03, konareef#21).
//
// LoadManifestParams feeds the witness. Before this file, it trusted the
// cache: it did not check that manifest.canon was still the manifest
// install verified, and it did not check the v2 [_commit] trailer at all.
// A trailer with a well-formed 32-byte root that the declared fields do not
// produce then reached PS-1 and failed there, or not at all.
//
// The two checks here are:
//
//   - checkInstalledManifestHash: SHA-256(manifest.canon) equals meta.json's
//     pod_hash. This is check 1 of Verify (install.go), applied again to
//     the cached bytes.
//   - checkCommittedFieldsRoot: the manifest's version is one this build
//     reads, and for konareef-toml/v2 the root recomputed from the loaded
//     Models, Tools, CMax and the classified r_init (konareef-rinit/v1
//     R-M17: E20, legacy zero, or a salt-holder-checked populated root)
//     equals the committed [_commit].fields_root. The version and trailer
//     decision is commission.ManifestFieldsRoot, the same function
//     `commission draft` and the binding gate use.
package install

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/digitsu/konareef/internal/canon"
	"github.com/digitsu/konareef/internal/commission"
	"github.com/digitsu/konareef/internal/membridge"
)

// ErrInstalledManifestHashMismatch: manifest.canon does not hash to the
// pod_hash recorded in meta.json.
var ErrInstalledManifestHashMismatch = errors.New("installed manifest.canon does not match its pod_hash")

// ErrCommittedFieldsRootMismatch: the fields_root recomputed from the
// manifest's declared fields is not the committed [_commit].fields_root.
var ErrCommittedFieldsRootMismatch = errors.New("declared fields do not reproduce the committed fields_root")

// checkInstalledManifestHash compares SHA-256(manifest) with podHashHex.
//
// Input: the manifest.canon bytes and meta.json's pod_hash (64 lowercase
// or uppercase hex characters). Output: nil when they match; an error
// wrapping ErrInstalledManifestHashMismatch when they differ or the hex is
// not a 32-byte value.
func checkInstalledManifestHash(manifest []byte, podHashHex string) error {
	want, err := hex.DecodeString(podHashHex)
	if err != nil || len(want) != sha256.Size {
		return fmt.Errorf("%w: meta.json pod_hash %q is not 32 hex-encoded bytes",
			ErrInstalledManifestHashMismatch, podHashHex)
	}
	got := sha256.Sum256(manifest)
	if !bytes.Equal(got[:], want) {
		return fmt.Errorf("%w: SHA-256(manifest.canon) = %x, pod_hash = %x",
			ErrInstalledManifestHashMismatch, got, want)
	}
	return nil
}

// ErrLegacyZeroMemoryRoot: the manifest commits the legacy zero memory
// root (konareef-rinit/v1 R-M17 class memory_free_legacy_zero). It stays a
// valid, signed, installable artifact, but no proof can exist for it
// (MEM-01 §4) and PS-1 refuses it (rinit_legacy_zero), so no witness is
// built. The publisher upgrades by publishing a new version (R-M18).
var ErrLegacyZeroMemoryRoot = errors.New(
	"manifest commits the legacy zero memory root; it is not proof-eligible (republish to commit r_init = E20)")

// ErrMemoryEvidenceRequired: the manifest commits a populated memory root
// (class not_memory_free) and the caller supplied no memory evidence. Only
// the salt holder can check such a root (spec §6.2).
var ErrMemoryEvidenceRequired = errors.New(
	"manifest commits a populated memory root; the salt holder's memory evidence is required to build a witness")

// MemoryEvidence is what the salt holder supplies for a memory-bearing
// manifest (konareef-rinit/v1 spec §8 "root check", under the
// konareef-rinit/v2 derivation): the lineage salt and the ordered
// (cell_id, content_hash) list the runtime loaded. It is used locally and
// never written to the cache, the witness or any log.
type MemoryEvidence struct {
	Salt  [32]byte
	Cells []membridge.Cell
}

// committedMemory is the checked memory side of a manifest: the r_init
// its fields_root commits, and, for a memory-bearing manifest, the
// checked cells keyed by tree index and the v2 row of the R-M23 touched
// cell (for the feeder's memory lane).
type committedMemory struct {
	rInit   [32]byte
	cells   map[uint32][32]byte
	touched *membridge.LeafV2
}

// checkCommittedFieldsRoot checks the manifest's version and, when it
// commits one, its fields_root, and classifies its memory root (R-M17).
//
// Input: the manifest bytes, the Models, Tools and CMax that
// LoadManifestParams derived from them, whether the manifest declares any
// [[context.memory]] entry, optional salt-holder memory evidence, and an
// optional v2 leaf table and touched row checkRunMemory has already
// checked.
//
// Output:
//
//   - no commitment (no magic line, or konareef-toml/v1): zero value, nil.
//   - memory_free_rinit_v1 with no memory declared: r_init = E20.
//     Evidence, if supplied, must hold no cells.
//   - memory_free_legacy_zero with no memory declared:
//     ErrLegacyZeroMemoryRoot.
//   - not_memory_free with memory declared and a trailer that does not
//     name konareef-rinit/v2: ErrMemoryRInitV1Retired (R-M30).
//   - not_memory_free with memory declared and a v2 leaf table already
//     checked by checkRunMemory (the sidecar's salt-free path): r_init =
//     the table's r_init, which must reproduce the committed fields_root
//     (R-M20 step f); then the touched-cell check (step 4).
//   - not_memory_free with memory declared: ErrMemoryEvidenceRequired
//     without evidence; otherwise r_init = membridge.RInitV2(salt, cells),
//     and the root recomputed over it must equal the committed fields_root
//     (ErrCommittedFieldsRootMismatch wrapping membridge.ErrRInitMismatch
//     when it does not). The touched cell is the evidence's lowest
//     cell_id (R-M23). This is the salt holder's root check: on any error
//     no witness is built.
//   - every other combination: ErrCommittedFieldsRootMismatch. The
//     declaration and the root must agree: a manifest that declares no
//     memory cannot commit a populated root (that is a changed field or a
//     forged trailer, not a memory-bearing pod), and one that declares
//     memory cannot commit an empty root (no fallback, R-M5).
//
// Errors also wrap commission.ErrManifestVersionUnsupported (a version
// this build does not read) and commission.ErrManifestCommitmentUnreadable
// (v2 without a parseable trailer, including an unknown r_init_scheme).
// No error carries the salt or a content hash.
func checkCommittedFieldsRoot(manifest []byte, models, tools []string, cMax uint64, declaresMemory bool, mem *MemoryEvidence, run *runMemoryCheck) (committedMemory, error) {
	var none committedMemory
	committed, err := commission.ManifestFieldsRoot(manifest)
	if err != nil {
		return none, err
	}
	if committed == nil {
		return none, nil
	}
	// ManifestFieldsRoot has already parsed the trailer successfully, so
	// this second parse only adds the r_init_scheme marker.
	trailer, err := canon.ParseCommitTrailer(manifest)
	if err != nil {
		return none, fmt.Errorf("%w: %w", commission.ErrManifestCommitmentUnreadable, err)
	}
	class, err := canon.ClassifyMemoryRoot(trailer, models, tools, cMax)
	if err != nil {
		return none, fmt.Errorf("%w: recompute: %w", ErrCommittedFieldsRootMismatch, err)
	}
	switch {
	case declaresMemory && (class == canon.MemoryFreeRInitV1 || class == canon.MemoryFreeLegacyZero):
		return none, fmt.Errorf("%w: the manifest declares [[context.memory]] but commits an empty memory root",
			ErrCommittedFieldsRootMismatch)
	case class == canon.MemoryFreeRInitV1:
		if mem != nil && len(mem.Cells) > 0 {
			return none, fmt.Errorf("%w: memory evidence has %d cells but the manifest commits the empty memory root: %w",
				ErrCommittedFieldsRootMismatch, len(mem.Cells), membridge.ErrRInitMismatch)
		}
		return committedMemory{rInit: canon.EmptyMemoryRoot()}, nil
	case class == canon.MemoryFreeLegacyZero:
		return none, ErrLegacyZeroMemoryRoot
	case class == canon.NotMemoryFree && declaresMemory && trailer.RInitScheme != canon.RInitSchemeV2:
		return none, ErrMemoryRInitV1Retired
	case class == canon.NotMemoryFree && declaresMemory && mem == nil && run != nil:
		// The sidecar's salt-free path (MEM-SEAM A1, rinit/v2 R-M20):
		// checkRunMemory has already run steps a to e. What is left is step
		// f (the table's r_init is the one fields_root commits) and then
		// step 4, the touched cell.
		got, err := canon.FieldsRoot(models, tools, cMax, run.table.RInit)
		if err != nil || got != trailer.FieldsRoot {
			return none, fmt.Errorf("%w: the leaf table's r_init does not reproduce the committed root: %w",
				ErrCommittedFieldsRootMismatch, membridge.ErrRInitMismatch)
		}
		touched, err := run.touchedRow()
		if err != nil {
			return none, err
		}
		return committedMemory{rInit: run.table.RInit, cells: run.table.ValueHashes(), touched: &touched}, nil
	case class == canon.NotMemoryFree && declaresMemory:
		if mem == nil {
			return none, ErrMemoryEvidenceRequired
		}
		rInit, derived, err := membridge.RInitV2(mem.Salt[:], mem.Cells)
		if err != nil {
			return none, fmt.Errorf("%w: memory evidence: %w", ErrCommittedFieldsRootMismatch, err)
		}
		got, err := canon.FieldsRoot(models, tools, cMax, rInit)
		if err != nil || got != trailer.FieldsRoot {
			return none, fmt.Errorf("%w: memory evidence does not reproduce the committed root: %w",
				ErrCommittedFieldsRootMismatch, membridge.ErrRInitMismatch)
		}
		touchedID, err := membridge.TouchedCellID(mem.Cells)
		if err != nil {
			return none, fmt.Errorf("%w: memory evidence: %w", ErrCommittedFieldsRootMismatch, err)
		}
		cells := make(map[uint32][32]byte, len(derived))
		var touched *membridge.LeafV2
		for _, d := range derived {
			cells[d.Index] = d.ValueHash
			if d.CellID == touchedID {
				touched = &membridge.LeafV2{CellID: d.CellID, ContentHash: d.ContentHash, KeyTag: d.KeyTag, Index: d.Index, ValueHash: d.ValueHash}
			}
		}
		return committedMemory{rInit: rInit, cells: cells, touched: touched}, nil
	default:
		return none, fmt.Errorf("%w: recomputed from models=%q tools=%q c_max=%d, committed %x (neither memory-free root, no r_init_scheme marker)",
			ErrCommittedFieldsRootMismatch, models, tools, cMax, trailer.FieldsRoot)
	}
}
