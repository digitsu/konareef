// Copyright 2026 Jerry David Chan, Konareef.ai
// SPDX-License-Identifier: Apache-2.0

// run_memory.go — the sidecar's salt-free memory check for one run
// (konareef-rinit/v1 spec §6.4 and §8, MEM-SEAM A1/B1/C1/S-7).
//
// The co-located feeder runs on the reef-core host, which never holds a
// Type-D salt (D3-A). It checks a run's initial memory with three inputs:
//
//   - the signed, installed manifest: its [[context.memory]] entries and
//     [_files] digests give the committed cell list (CommittedCells);
//   - the cell list reef-core disclosed in step-disclosure.json
//     (initial_memory, seam/2), which must equal the committed list;
//   - for a memory-bearing manifest, the publisher-signed leaf table that
//     reef-core serves only to the sidecar. Its signature is checked
//     against the manifest's publisher key, its pod_hash against the
//     manifest, its cells against the committed list, and its leaves
//     against its r_init. checkCommittedFieldsRoot then binds that r_init
//     to the committed fields_root.
//
// Every mismatch or missing input fails closed: no params, so no witness.
// No error names a cell, a hash or table bytes.
package install

import (
	"encoding/hex"
	"errors"
	"fmt"
	"strings"

	"github.com/BurntSushi/toml"

	"github.com/digitsu/konareef/internal/commission"
	"github.com/digitsu/konareef/internal/feeder"
	"github.com/digitsu/konareef/internal/identity"
	"github.com/digitsu/konareef/internal/membridge"
	"github.com/digitsu/konareef/internal/pod"
)

// Refusals of the run memory check.
var (
	// ErrSeamMemoryMissing: the manifest commits a fields_root (v2/v3) but
	// the step disclosure has no initial_memory key (C1).
	ErrSeamMemoryMissing = errors.New("step-disclosure has no initial_memory for a manifest that commits a fields_root")
	// ErrSeamMemoryUnexpected: the step disclosure carries initial_memory
	// for a manifest that commits no fields_root (v1, or no magic line).
	ErrSeamMemoryUnexpected = errors.New("step-disclosure carries initial_memory for a manifest that commits no fields_root")
	// ErrSeamMemoryMismatch: the disclosed cell list differs from the cell
	// list the signed manifest commits (S-7).
	ErrSeamMemoryMismatch = errors.New("step-disclosure initial_memory does not match the manifest's committed memory")
	// ErrLeafTableUnavailable: a memory-bearing manifest, and no leaf
	// table could be fetched.
	ErrLeafTableUnavailable = errors.New("the memory leaf table for this memory-bearing manifest is unavailable")
	// ErrLeafTableSignature: the leaf table is not signed by the
	// manifest's publisher key.
	ErrLeafTableSignature = errors.New("the memory leaf table is not signed by the manifest's publisher")
)

// LeafTableEvidence is the leaf table reef-core served for a run: the
// canonical table bytes and the publisher's DER signature over SHA-256 of
// them. It holds no salt.
type LeafTableEvidence struct {
	Table     []byte
	Signature []byte
}

// RunMemory is the sidecar's memory input for one run.
//
// Disclosed is the initial_memory the step disclosure carried.
// FetchLeafTable returns the leaf table; it is called only for a
// memory-bearing manifest, so a memory-free run makes no request. A nil
// FetchLeafTable refuses a memory-bearing manifest.
type RunMemory struct {
	Disclosed      feeder.SeamMemory
	FetchLeafTable func() (*LeafTableEvidence, error)
}

// LoadManifestParamsForRun is LoadManifestParams for the feeder sidecar
// of one run. It adds the salt-free run memory check (this file's header)
// before the fields_root check.
//
// Inputs: as LoadManifestParams, plus the run's memory input. Output: the
// params, with RInit and, for a memory-bearing manifest, MemoryCells taken
// from the checked leaf table; or an error wrapping one of this file's
// refusals, membridge.ErrLeafTableInvalid, membridge.ErrLeafTableMismatch,
// membridge.ErrRInitMismatch or ErrCommittedFieldsRootMismatch. On any
// error no params are returned.
func LoadManifestParamsForRun(home, handle, podName, version string, run RunMemory) (feeder.ManifestParams, error) {
	return loadManifestParams(home, handle, podName, version, nil, &run)
}

// checkRunMemory runs the salt-free memory check for one run.
//
// Inputs: the installed manifest bytes and parsed spec, whether it
// declares memory, its pod_hash (already checked against the bytes), the
// publisher key from meta.json, and the run's memory input. Output: the
// checked leaf table for a memory-bearing manifest, nil for any other,
// or a refusal.
func checkRunMemory(manifest []byte, spec *pod.Spec, declaresMemory bool, podHash [32]byte, publisherKeyHex string, run RunMemory) (*membridge.LeafTable, error) {
	committedRoot, err := commission.ManifestFieldsRoot(manifest)
	if err != nil {
		return nil, err
	}
	if committedRoot == nil {
		if run.Disclosed.Present {
			return nil, ErrSeamMemoryUnexpected
		}
		return nil, nil
	}
	if !run.Disclosed.Present {
		return nil, ErrSeamMemoryMissing
	}

	committed, err := committedMemoryCells(manifest, spec)
	if err != nil {
		return nil, err
	}
	if !membridge.SameCells(run.Disclosed.Cells, committed) {
		return nil, ErrSeamMemoryMismatch
	}
	if !declaresMemory {
		return nil, nil
	}

	if run.FetchLeafTable == nil {
		return nil, ErrLeafTableUnavailable
	}
	ev, err := run.FetchLeafTable()
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrLeafTableUnavailable, err)
	}
	if ev == nil || len(ev.Table) == 0 || len(ev.Signature) == 0 {
		return nil, ErrLeafTableUnavailable
	}
	ok, err := identity.Verify(publisherKeyHex, ev.Table, ev.Signature)
	if err != nil || !ok {
		return nil, ErrLeafTableSignature
	}
	table, err := membridge.ParseLeafTable(ev.Table)
	if err != nil {
		return nil, err
	}
	if table.PodHash != podHash {
		return nil, fmt.Errorf("%w: another pod_hash", membridge.ErrLeafTableMismatch)
	}
	if !membridge.SameCells(table.Cells(), committed) {
		return nil, fmt.Errorf("%w: another cell list", membridge.ErrLeafTableMismatch)
	}
	if err := table.CheckRoot(); err != nil {
		return nil, err
	}
	return table, nil
}

// committedMemoryCells derives the cell list a signed manifest commits:
// its [[context.memory]] entries over its own [_files] digests
// (membridge.CommittedCells). An unsupported kind, an uncommitted file or
// a duplicate source is refused with its membridge code.
func committedMemoryCells(manifest []byte, spec *pod.Spec) ([]membridge.Cell, error) {
	if spec.Context == nil || len(spec.Context.Memory) == 0 {
		return []membridge.Cell{}, nil
	}
	digests, err := manifestFilesDigests(manifest)
	if err != nil {
		return nil, err
	}
	sources := make([]membridge.MemorySource, 0, len(spec.Context.Memory))
	for _, m := range spec.Context.Memory {
		sources = append(sources, membridge.MemorySource{Kind: m.Kind, Path: m.Path, Content: m.Content})
	}
	return membridge.CommittedCells(sources, digests)
}

// manifestFilesDigests reads the [_files] table of canonical manifest
// bytes: key → 32-byte digest. An entry that is not exactly
// "sha256:<64 lowercase hex>" is dropped, so a memory source naming it is
// refused as not committed.
func manifestFilesDigests(manifest []byte) (map[string][32]byte, error) {
	var doc struct {
		Files map[string]string `toml:"_files"`
	}
	if _, err := toml.Decode(string(manifest), &doc); err != nil {
		return nil, fmt.Errorf("read [_files]: %w", err)
	}
	out := make(map[string][32]byte, len(doc.Files))
	for key, value := range doc.Files {
		hexDigest, ok := strings.CutPrefix(value, "sha256:")
		if !ok || len(hexDigest) != 64 || strings.ToLower(hexDigest) != hexDigest {
			continue
		}
		raw, err := hex.DecodeString(hexDigest)
		if err != nil {
			continue
		}
		var d [32]byte
		copy(d[:], raw)
		out[key] = d
	}
	return out, nil
}
