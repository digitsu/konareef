// Copyright 2026 Jerry David Chan, Konareef.ai
// SPDX-License-Identifier: Apache-2.0

// memoryroot.go — publish-side r_init resolution
// (docs/reference/konareef-memory-root-v1-spec.md §4-§6, §8 "publish",
// amended by docs/reference/konareef-rinit-v2-spec.md).
//
// Two paths:
//
//   - memory-free pod (no [[context.memory]]): r_init = E20 and the
//     trailer carries r_init_scheme = "konareef-rinit/v1" (D1-A, D2-A,
//     unchanged by rinit/v2 R-M29). This path is always on.
//   - memory-bearing pod: resolve every declared source from the pod
//     directory, read the lineage salt, and compute r_init with
//     membridge.RInitV2; the trailer carries r_init_scheme =
//     "konareef-rinit/v2" (R-M29). konareef-rinit/v1 is never used for a
//     memory-bearing publish (R-M30). This path stays behind
//     memoryPublishEnabled, which is false in every build: memory-bearing
//     --zk publish keeps refusing with COMMIT_MEMORY_RESOLUTION_UNAVAILABLE
//     until the gate preconditions hold (reef-core CL-4-live design § 9).
//
// The salt never appears in a log line, an error or a return value other
// than the committed root (R-M14).
package publish

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/BurntSushi/toml"

	"github.com/digitsu/konareef/internal/canon"
	"github.com/digitsu/konareef/internal/membridge"
	"github.com/digitsu/konareef/internal/pod"
)

// memoryPublishEnabled gates the memory-bearing publish path (spec §12
// phase 3: "MEM-02 + MEM-03 behind a disabled flag"). It is a package
// variable with no setter, so only this package's own tests can turn it
// on. Enabling it for users is the phase-4 change, which needs MEM-04
// acceptance and PS-1's memory-witness lane first.
var memoryPublishEnabled = false

// MemoryPublishEnabled reports whether this build accepts memory-bearing
// --zk publishes. It is false in every build; the CLI uses it to avoid
// provisioning a salt for a publish that will be refused anyway.
func MemoryPublishEnabled() bool { return memoryPublishEnabled }

// MemoryCommitInput is what the memory-bearing path needs beyond the
// manifest: the pod directory the sources are read from, the sealed
// disclosure policy, and the lineage salt (R-M12). It is nil for a
// memory-free pod.
type MemoryCommitInput struct {
	// PodDir is the pod root; file sources are read from it.
	PodDir string
	// DisclosurePolicy is the --disclosure-policy value ("C" or "D").
	// Type C is refused until a Type-C salt publication path exists (D3,
	// spec E14).
	DisclosurePolicy string
	// Salt is the 32-byte per-lineage salt from the saltstore. It is read
	// locally and never leaves this process except inside r_init.
	Salt [32]byte
}

// memoryResolution is what resolveMemoryRInit decided for one publish.
//
//   - rInit, scheme: the committed r_init and its r_init_scheme marker.
//   - used: the [_files] entries a memory-bearing root was computed over,
//     for checkMemoryFilesUnchanged (nil for a memory-free pod).
//   - derived: RInitV2's per-cell output (cell, key_tag, index, value
//     hash), from which Prepare builds the signed v2 leaf table (nil for a
//     memory-free pod). It holds no salt.
type memoryResolution struct {
	rInit   [32]byte
	scheme  string
	used    map[string]bodyFile
	derived []membridge.DerivedCellV2
}

// memoryBearing reports whether the resolution is for a memory-bearing
// pod, which is the case exactly when it carries derived cells.
func (m memoryResolution) memoryBearing() bool { return len(m.derived) > 0 }

// resolveMemoryRInit computes the r_init and the r_init_scheme marker a
// v2 publish of spec commits.
//
// Inputs: the parsed spec and, for a memory-bearing pod, mem. Output:
// (E20, RInitSchemeV1) with no cells for a memory-free pod; for a
// memory-bearing pod with the gate on, the RInitV2 root, RInitSchemeV2,
// the [_files] entries the root was computed over (for
// checkMemoryFilesUnchanged) and the derivation the v2 leaf table is
// built from. Otherwise a coded
// *canon.Error:
//
//   - COMMIT_MEMORY_RESOLUTION_UNAVAILABLE — the gate is off, mem is nil,
//     or the policy is not Type D;
//   - the membridge code of the first source or derivation refusal
//     (MEMORY_SOURCE_UNSUPPORTED, MEMORY_FILE_NOT_COMMITTED,
//     MEMORY_FILE_DIGEST_MISMATCH, MEMORY_DUPLICATE_SOURCE,
//     ERR_CELL_INDEX_COLLISION, ERR_CELL_CAP_EXCEEDED, …).
//
// There is no fallback: an unsupported shape never becomes E20 or zero
// (R-M5). An index collision is refused rather than resampling the salt:
// R-M13 allows (MAY) a reseed only at a lineage's first memory-bearing
// publish, and this build does not track that state, so it takes the
// always-safe branch the spec requires after the first publish.
func resolveMemoryRInit(spec *pod.Spec, mem *MemoryCommitInput) (memoryResolution, error) {
	if spec.Context == nil || len(spec.Context.Memory) == 0 {
		return memoryResolution{rInit: canon.EmptyMemoryRoot(), scheme: canon.RInitSchemeV1}, nil
	}
	if !memoryPublishEnabled || mem == nil {
		return memoryResolution{}, canon.NewError(canon.ErrCommitMemoryResolutionUnavailable,
			"this pod declares [[context.memory]]; memory-bearing --zk publish is not enabled in this "+
				"build: the companion spec (konareef-rinit/v1, docs/reference/konareef-memory-root-v1-spec.md) "+
				"lifts the refusal only at rollout phase 4, after MEM-04 end-to-end acceptance. "+
				"Publish without --zk, or remove the memory entries.")
	}
	if mem.DisclosurePolicy != "D" {
		return memoryResolution{}, canon.NewError(canon.ErrCommitMemoryResolutionUnavailable,
			"memory-bearing --zk publish needs --disclosure-policy D: no Type-C salt publication "+
				"path exists yet (konareef-rinit/v1 spec D3)")
	}

	wanted := map[string]bool{}
	for _, m := range spec.Context.Memory {
		if m.Kind == membridge.SourceKindFile {
			wanted[membridge.FilesKey(m.Path)] = true
		}
	}
	digests, err := bodyFileDigests(mem.PodDir, wanted)
	if err != nil {
		return memoryResolution{}, err
	}
	sources := make([]membridge.MemorySource, 0, len(spec.Context.Memory))
	for _, m := range spec.Context.Memory {
		src := membridge.MemorySource{Kind: m.Kind, Path: m.Path, Content: m.Content}
		if m.Kind == membridge.SourceKindFile {
			// Only a path the [_files] walk already covers was read. A path
			// outside it (including any "../" escape, a hidden file or
			// pod.toml itself) is refused by ResolveSources as not
			// committed, without being read.
			key := membridge.FilesKey(m.Path)
			if d, ok := digests[key]; ok {
				src.Loaded = d.bytes
			}
		}
		sources = append(sources, src)
	}
	committed := make(map[string][32]byte, len(digests))
	for k, d := range digests {
		committed[k] = d.sum
	}
	cells, err := membridge.ResolveSources(sources, committed)
	if err != nil {
		return memoryResolution{}, memoryRefusal(err)
	}
	root, derived, err := membridge.RInitV2(mem.Salt[:], cells)
	if err != nil {
		return memoryResolution{}, memoryRefusal(err)
	}
	return memoryResolution{
		rInit: root, scheme: canon.RInitSchemeV2, used: digests, derived: derived,
	}, nil
}

// bodyFile is one [_files] entry read once: its bytes and their digest.
type bodyFile struct {
	bytes []byte
	sum   [32]byte
}

// bodyFileDigests reads the memory files that the `[_files]` table
// commits to.
//
// Inputs: the pod root, and the [_files] keys the file memory sources
// name. Output: key → (bytes, SHA-256) for every wanted key that
// canon.BodyFiles (the canonicalizer's own walk, which refuses symlinks)
// lists; a wanted key the walk does not list is left out, and
// ResolveSources then refuses it as not committed. Only wanted files are
// read. Each is Lstat-checked again just before the read, so a symlink
// or non-regular file swapped in after the walk is refused. Each file is
// read once, so the digest and the bytes that enter r_init are the same.
func bodyFileDigests(podDir string, wanted map[string]bool) (map[string]bodyFile, error) {
	paths, err := canon.BodyFiles(podDir)
	if err != nil {
		return nil, err
	}
	out := make(map[string]bodyFile, len(wanted))
	for _, rel := range paths {
		if !wanted[rel] {
			continue
		}
		full := filepath.Join(podDir, filepath.FromSlash(rel))
		info, err := os.Lstat(full)
		if err != nil {
			return nil, fmt.Errorf("stat committed memory file %q: %w", rel, err)
		}
		if !info.Mode().IsRegular() {
			return nil, fmt.Errorf("committed memory file %q is not a regular file", rel)
		}
		b, err := os.ReadFile(full)
		if err != nil {
			return nil, fmt.Errorf("read committed memory file %q: %w", rel, err)
		}
		out[rel] = bodyFile{bytes: b, sum: sha256.Sum256(b)}
	}
	return out, nil
}

// memoryRefusal maps a membridge refusal to a coded *canon.Error with
// the same code. The message names only the code, never salt or content.
func memoryRefusal(err error) error {
	code := membridge.Code(err)
	if code == "" {
		return err
	}
	return canon.NewError(code, "memory resolution refused: "+code)
}

// errMemoryFilesChanged is returned when a memory file's [_files] digest
// in the canonical output differs from the digest r_init was computed
// over, i.e. the file changed between the two reads.
var errMemoryFilesChanged = errors.New(
	"a [[context.memory]] file changed while publishing; its [_files] digest no longer matches r_init")

// checkMemoryFilesUnchanged re-reads the `[_files]` table from the
// canonical v2 bytes and checks that every file memory source still has
// the digest r_init was computed over. It closes the window between the
// resolver's read and the canonicalizer's read.
//
// Inputs: the parsed spec, the canonical bytes and the digests the
// resolver used. Output: nil, errMemoryFilesChanged, or a parse error.
func checkMemoryFilesUnchanged(spec *pod.Spec, canonBytes []byte, used map[string]bodyFile) error {
	if spec.Context == nil || len(spec.Context.Memory) == 0 {
		return nil
	}
	var doc struct {
		Files map[string]string `toml:"_files"`
	}
	if _, err := toml.Decode(string(canonBytes), &doc); err != nil {
		return fmt.Errorf("re-read [_files]: %w", err)
	}
	for _, m := range spec.Context.Memory {
		if m.Kind != membridge.SourceKindFile {
			continue
		}
		key := membridge.FilesKey(m.Path)
		want, ok := used[key]
		if !ok || doc.Files[key] != fmt.Sprintf("sha256:%x", want.sum) {
			return errMemoryFilesChanged
		}
	}
	return nil
}
