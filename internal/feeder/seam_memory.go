// Copyright 2026 Jerry David Chan, Konareef.ai
// SPDX-License-Identifier: Apache-2.0

// seam_memory.go — the step-disclosure `initial_memory` key (seam/2,
// MEM-SEAM option B1, konareef-rinit/v1 spec §8 "byte check").
//
// reef-core writes the key for every run of a published konareef-toml/v2
// or v3 manifest, and omits it for a v1 or unpublished run (C1):
//
//	"initial_memory": {
//	  "cells": [
//	    {"cell_id": "<16 lowercase hex>", "content_hash": "<base64 of 32 bytes>"}
//	  ],
//	  "scheme": "konareef-mem-src/v1"
//	}
//
// cells is the (cell_id, content_hash) list of the bytes the run was given,
// in strictly ascending cell_id; it is empty for a manifest that declares
// no memory. cell_id is a hex string because bit 63 is always set and JSON
// numbers above 2^53 lose precision in many readers.
//
// The list holds no salt and no content, and every entry of a valid run is
// derivable from the signed manifest. It is a cross-check: the sidecar
// re-derives the list from the manifest (membridge.CommittedCells) and
// refuses any difference (S-7), because a pod can write the file.
package feeder

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"

	"github.com/digitsu/konareef/internal/membridge"
)

// maxSeamFileBytes bounds the step-disclosure file ReadSeamMemory reads.
// It carries one step's prompt and response bytes, as base64, and a cell
// list of at most 500 entries; 64 MiB is far above any real step.
const maxSeamFileBytes = 64 << 20

// SeamMemoryScheme is the only initial_memory scheme this build reads.
const SeamMemoryScheme = "konareef-mem-src/v1"

// ErrSeamMemoryInvalid means the initial_memory key is present but
// malformed: an unknown or repeated key, an unknown scheme, a cell_id
// that is not 16 lowercase hex digits with bit 63 set, a content_hash
// that is not base64 of 32 bytes, cells out of strictly ascending order,
// or more than membridge.HardCapK cells.
var ErrSeamMemoryInvalid = errors.New("feeder: step-disclosure initial_memory is malformed")

// seamMemoryKeys and seamCellKeys are the only field names the
// initial_memory object and its cells may carry.
var (
	seamMemoryKeys = []string{"cells", "scheme"}
	seamCellKeys   = []string{"cell_id", "content_hash"}
)

// SeamMemory is what one step-disclosure file says about the run's
// initial memory. Present is false when the key is absent (a v1 or
// unpublished run); Cells is then nil.
type SeamMemory struct {
	Present bool
	Cells   []membridge.Cell
}

// ReadSeamMemory reads the initial_memory key of the step-disclosure file
// at seamPath.
//
// Input: the file path. Output: the parsed SeamMemory, or an error for an
// unreadable file, a duplicate or case-variant top-level key, or a
// malformed key (ErrSeamMemoryInvalid). No error carries a cell value.
func ReadSeamMemory(seamPath string) (SeamMemory, error) {
	f, err := os.Open(seamPath)
	if err != nil {
		return SeamMemory{}, fmt.Errorf("feeder: read step-disclosure: %w", err)
	}
	defer f.Close()
	// The pod can write this file, so its size is bounded before it is
	// read: an oversized file is refused, not buffered (MEM-SEAM review L3).
	raw, err := io.ReadAll(io.LimitReader(f, maxSeamFileBytes+1))
	if err != nil {
		return SeamMemory{}, fmt.Errorf("feeder: read step-disclosure: %w", err)
	}
	if len(raw) > maxSeamFileBytes {
		return SeamMemory{}, fmt.Errorf("%w: step-disclosure is larger than %d bytes", ErrSeamMemoryInvalid, maxSeamFileBytes)
	}
	top, err := scanObjectKeys(raw, seamTopKeys, "step-disclosure")
	if err != nil {
		return SeamMemory{}, fmt.Errorf("feeder: parse step-disclosure: %w", err)
	}
	value, ok := top["initial_memory"]
	if !ok {
		return SeamMemory{}, nil
	}
	cells, err := ParseSeamMemory(value)
	if err != nil {
		return SeamMemory{}, err
	}
	return SeamMemory{Present: true, Cells: cells}, nil
}

// ParseSeamMemory parses one initial_memory JSON value.
//
// Input: the raw value. Output: the cells in ascending cell_id (an empty,
// non-nil slice for "cells": []), or ErrSeamMemoryInvalid.
func ParseSeamMemory(raw json.RawMessage) ([]membridge.Cell, error) {
	raw = bytes.TrimSpace(raw)
	if len(raw) == 0 || raw[0] != '{' {
		return nil, fmt.Errorf("%w: not an object", ErrSeamMemoryInvalid)
	}
	keys, err := scanObjectKeys(raw, seamMemoryKeys, "initial_memory")
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrSeamMemoryInvalid, err)
	}
	if err := onlyKeys(keys, seamMemoryKeys); err != nil {
		return nil, err
	}
	var scheme string
	if err := json.Unmarshal(keys["scheme"], &scheme); err != nil || scheme != SeamMemoryScheme {
		return nil, fmt.Errorf("%w: unknown scheme", ErrSeamMemoryInvalid)
	}
	var entries []json.RawMessage
	cellsRaw := bytes.TrimSpace(keys["cells"])
	if len(cellsRaw) == 0 || cellsRaw[0] != '[' {
		return nil, fmt.Errorf("%w: cells is not an array", ErrSeamMemoryInvalid)
	}
	if err := json.Unmarshal(cellsRaw, &entries); err != nil {
		return nil, fmt.Errorf("%w: cells: %v", ErrSeamMemoryInvalid, err)
	}
	if len(entries) > membridge.HardCapK {
		return nil, fmt.Errorf("%w: more than %d cells", ErrSeamMemoryInvalid, membridge.HardCapK)
	}
	cells := make([]membridge.Cell, 0, len(entries))
	for i, e := range entries {
		c, err := parseSeamCell(e, i)
		if err != nil {
			return nil, err
		}
		if i > 0 && cells[i-1].CellID >= c.CellID {
			return nil, fmt.Errorf("%w: cells[%d] is not in strictly ascending cell_id order", ErrSeamMemoryInvalid, i)
		}
		cells = append(cells, c)
	}
	return cells, nil
}

// parseSeamCell parses one cells[] entry at position i.
func parseSeamCell(raw json.RawMessage, i int) (membridge.Cell, error) {
	raw = bytes.TrimSpace(raw)
	if len(raw) == 0 || raw[0] != '{' {
		return membridge.Cell{}, fmt.Errorf("%w: cells[%d] is not an object", ErrSeamMemoryInvalid, i)
	}
	keys, err := scanObjectKeys(raw, seamCellKeys, fmt.Sprintf("initial_memory.cells[%d]", i))
	if err != nil {
		return membridge.Cell{}, fmt.Errorf("%w: %v", ErrSeamMemoryInvalid, err)
	}
	if err := onlyKeys(keys, seamCellKeys); err != nil {
		return membridge.Cell{}, err
	}
	var idHex, hashB64 string
	if json.Unmarshal(keys["cell_id"], &idHex) != nil || json.Unmarshal(keys["content_hash"], &hashB64) != nil {
		return membridge.Cell{}, fmt.Errorf("%w: cells[%d] fields must be strings", ErrSeamMemoryInvalid, i)
	}
	idBytes, err := hex.DecodeString(idHex)
	if err != nil || len(idHex) != 16 || strings.ToLower(idHex) != idHex {
		return membridge.Cell{}, fmt.Errorf("%w: cells[%d].cell_id is not 16 lowercase hex digits", ErrSeamMemoryInvalid, i)
	}
	id := binary.BigEndian.Uint64(idBytes)
	if id>>63 != 1 {
		return membridge.Cell{}, fmt.Errorf("%w: cells[%d].cell_id is not a source cell id", ErrSeamMemoryInvalid, i)
	}
	hash, err := base64.StdEncoding.Strict().DecodeString(hashB64)
	if err != nil || len(hash) != 32 {
		return membridge.Cell{}, fmt.Errorf("%w: cells[%d].content_hash is not base64 of 32 bytes", ErrSeamMemoryInvalid, i)
	}
	return membridge.Cell{CellID: id, ContentHash: hash}, nil
}

// onlyKeys refuses a missing or unknown key: the object must hold
// exactly the names in want.
func onlyKeys(keys map[string]json.RawMessage, want []string) error {
	if len(keys) != len(want) {
		return fmt.Errorf("%w: want exactly the keys %v", ErrSeamMemoryInvalid, want)
	}
	for _, k := range want {
		if _, ok := keys[k]; !ok {
			return fmt.Errorf("%w: missing key %q", ErrSeamMemoryInvalid, k)
		}
	}
	return nil
}

// EncodeSeamMemory renders cells as the initial_memory JSON value, in the
// byte form reef-core writes: keys in ascending order, no white space,
// cells in ascending cell_id.
//
// Input: the cells in any order. Output: the JSON bytes, or
// ErrSeamMemoryInvalid for a content hash that is not 32 bytes or a
// repeated cell_id. It is the reference encoder for the shared golden
// fixture (testdata/seam_initial_memory/initial_memory_v1.json).
func EncodeSeamMemory(cells []membridge.Cell) ([]byte, error) {
	type wireCell struct {
		CellID      string `json:"cell_id"`
		ContentHash string `json:"content_hash"`
	}
	type wire struct {
		Cells  []wireCell `json:"cells"`
		Scheme string     `json:"scheme"`
	}
	sorted := append([]membridge.Cell(nil), cells...)
	sortCellsByID(sorted)
	w := wire{Cells: make([]wireCell, 0, len(sorted)), Scheme: SeamMemoryScheme}
	for i, c := range sorted {
		if len(c.ContentHash) != 32 || (i > 0 && sorted[i-1].CellID == c.CellID) {
			return nil, ErrSeamMemoryInvalid
		}
		var id [8]byte
		binary.BigEndian.PutUint64(id[:], c.CellID)
		w.Cells = append(w.Cells, wireCell{
			CellID:      hex.EncodeToString(id[:]),
			ContentHash: base64.StdEncoding.EncodeToString(c.ContentHash),
		})
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(w); err != nil {
		return nil, err
	}
	return bytes.TrimSuffix(buf.Bytes(), []byte("\n")), nil
}

// sortCellsByID sorts cells in ascending cell_id, in place.
func sortCellsByID(cells []membridge.Cell) {
	sort.Slice(cells, func(i, j int) bool { return cells[i].CellID < cells[j].CellID })
}
