// Copyright 2026 Jerry David Chan, Konareef.ai
// SPDX-License-Identifier: Apache-2.0

// internal/membridge/sources.go — the konareef-rinit/v1 source-to-cell
// mapping for [[context.memory]] entries
// (docs/reference/konareef-memory-root-v1-spec.md §4).
//
// Supported sources (v1):
//
//	kind = "file"   locator = path.Clean(path), the [_files] key
//	                content_hash = SHA-256(raw file bytes), which MUST equal
//	                the [_files] digest of the locator (R-M3)
//	kind = "inline" locator = content_hash = SHA-256(UTF-8 content) (R-M4)
//
// Every other kind ("http", "openbrain", anything unknown) is refused with
// MEMORY_SOURCE_UNSUPPORTED. There is no fallback to an empty tree, to
// zero or to an earlier derivation (R-M5).
//
// The cell identifier lives in a namespace disjoint from Open Brain
// thought ids (§4.3):
//
//	cell_id = 2^63 | (be_u64(SHA-256("konareef-mem-src/v1"
//	                          ‖ ULEB128(len(kind)) ‖ kind
//	                          ‖ ULEB128(len(locator)) ‖ locator)[0:8]) & (2^63-1))
package membridge

import (
	"crypto/sha256"
	"encoding/binary"
	"path"
)

// SourceKindFile and SourceKindInline are the two [[context.memory]]
// kinds konareef-rinit/v1 supports.
const (
	SourceKindFile   = "file"
	SourceKindInline = "inline"
)

// SourceCellIDDomain is the 19-byte domain string of source cell
// identifiers. It differs from IndexDomainSep ("konareef-mem-idx/v1").
var SourceCellIDDomain = []byte("konareef-mem-src/v1")

// sourceCellIDHighBit marks a cell identifier as source-derived. Open
// Brain thought ids are positive Postgres bigints and never set bit 63.
const sourceCellIDHighBit = uint64(1) << 63

// MemorySource is one [[context.memory]] entry together with the bytes a
// resolver loaded for it.
//
// Kind is the declared kind. Path is the declared path (kind "file").
// Content is the decoded TOML string value (kind "inline"). Loaded is the
// exact raw bytes read for a file source, with no normalization; it is
// ignored for other kinds.
type MemorySource struct {
	Kind    string
	Path    string
	Content string
	Loaded  []byte
}

// SourceCellID derives the source cell identifier for (kind, locator).
//
// Inputs: the kind string and the locator bytes. Output: a u64 with bit
// 63 set.
func SourceCellID(kind string, locator []byte) uint64 {
	h := sha256.New()
	h.Write(SourceCellIDDomain)
	h.Write(EncodeThoughtID(uint64(len(kind))))
	h.Write([]byte(kind))
	h.Write(EncodeThoughtID(uint64(len(locator))))
	h.Write(locator)
	sum := h.Sum(nil)
	return sourceCellIDHighBit | (binary.BigEndian.Uint64(sum[0:8]) &^ sourceCellIDHighBit)
}

// FilesKey maps a declared memory path ("./memory/a.md") to its [_files]
// key ("memory/a.md") with path.Clean, which also drops a leading "./".
func FilesKey(declared string) string {
	return path.Clean(declared)
}

// ResolveSources turns [[context.memory]] entries into cells.
//
// Inputs: the entries in manifest order, and filesDigests — the [_files]
// table of the same manifest (key → SHA-256 of the file bytes).
//
// Output: one Cell per entry, in entry order, or the first refusal:
// ErrMemorySourceUnsupported (a kind other than file or inline),
// ErrMemoryFileNotCommitted (a file whose key has no [_files] entry),
// ErrMemoryFileDigestMismatch (loaded bytes that do not hash to the
// [_files] digest) or ErrMemoryDuplicateSource (two entries with one
// (kind, locator)). Two different sources with equal bytes are two cells.
// Errors never include file content.
func ResolveSources(sources []MemorySource, filesDigests map[string][32]byte) ([]Cell, error) {
	return resolveCells(sources, filesDigests, true)
}

// CommittedCells is ResolveSources without loaded bytes: the cells a
// signed manifest commits to, derived from its [[context.memory]] entries
// and its [_files] digests alone (konareef-rinit/v1 spec §6.2: every v1
// source is pinned by the manifest). A file source takes its [_files]
// digest as content_hash; MemorySource.Loaded is ignored.
//
// The sidecar uses it to re-derive the cell list reef-core discloses in
// step-disclosure.json and refuse any difference (MEM-SEAM S-7), so the
// disclosed list is a cross-check, never the source of truth.
//
// Inputs and refusals are those of ResolveSources, except that
// ErrMemoryFileDigestMismatch cannot occur. Output is in entry order.
func CommittedCells(sources []MemorySource, filesDigests map[string][32]byte) ([]Cell, error) {
	return resolveCells(sources, filesDigests, false)
}

// resolveCells is the shared body of ResolveSources and CommittedCells.
// With useLoaded, a file's content_hash is SHA-256(Loaded) and must equal
// its [_files] digest; without it, the digest is the content_hash.
func resolveCells(sources []MemorySource, filesDigests map[string][32]byte, useLoaded bool) ([]Cell, error) {
	cells := make([]Cell, 0, len(sources))
	seen := make(map[uint64]bool, len(sources))
	for _, s := range sources {
		var id uint64
		var content [32]byte
		switch s.Kind {
		case SourceKindFile:
			key := FilesKey(s.Path)
			committed, ok := filesDigests[key]
			if !ok {
				return nil, ErrMemoryFileNotCommitted
			}
			content = committed
			if useLoaded {
				content = sha256.Sum256(s.Loaded)
				if content != committed {
					return nil, ErrMemoryFileDigestMismatch
				}
			}
			id = SourceCellID(SourceKindFile, []byte(key))
		case SourceKindInline:
			content = sha256.Sum256([]byte(s.Content))
			id = SourceCellID(SourceKindInline, content[:])
		default:
			return nil, ErrMemorySourceUnsupported
		}
		if seen[id] {
			return nil, ErrMemoryDuplicateSource
		}
		seen[id] = true
		cells = append(cells, Cell{CellID: id, ContentHash: append([]byte(nil), content[:]...)})
	}
	return cells, nil
}
