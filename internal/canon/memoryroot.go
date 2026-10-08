// Copyright 2026 Jerry David Chan, Konareef.ai
// SPDX-License-Identifier: Apache-2.0

// memoryroot.go — the memory-free r_init value and the R-M17 memory-root
// classifier of the konareef-rinit/v1 spec
// (docs/reference/konareef-memory-root-v1-spec.md §5, §7.2, §7.3).
//
// Two conventions exist for the r_init inside a memory-free v2 manifest's
// fields_root:
//
//   - konareef-rinit/v1 (owner decision D1-A): r_init = E20, the Poseidon
//     empty depth-20 tree root. This is what the circuit proves for empty
//     memory, so only this convention is proof-eligible.
//   - legacy zero: r_init = 0, which konareef publish committed between
//     konareef !106 (2026-09-21) and this change. The bytes of those
//     manifests stay valid and are never rewritten (R-M16), but no proof
//     for them can exist (MEM-01 §4, confirmed with the real prover).
//
// ClassifyMemoryRoot tells them apart with no salt and no memory content,
// because the other three fields_root dimensions are public (R-M17).
package canon

import "github.com/digitsu/konareef/internal/poseidon"

// MemoryRootClass is the R-M17 classification of a v2 manifest's
// committed memory root. The string values match the `class` field of
// the shared MEM-01 fixture (paygate-zk
// docs/prds/konareef-memory-root-v1-vectors.json, commit_classification).
type MemoryRootClass string

const (
	// MemoryFreeRInitV1: fields_root commits r_init = E20. Proof-eligible.
	MemoryFreeRInitV1 MemoryRootClass = "memory_free_rinit_v1"
	// MemoryFreeLegacyZero: fields_root commits r_init = 0. A signed,
	// readable artifact, but NOT proof-eligible for the memory dimension
	// (R-M18). Admission and assurance output must name it "legacy zero
	// memory root".
	MemoryFreeLegacyZero MemoryRootClass = "memory_free_legacy_zero"
	// NotMemoryFree: the trailer carries the konareef-rinit/v1 marker and
	// the root is neither memory-free value, so the manifest commits a
	// populated memory root. Only the salt holder can check it (spec §6.2).
	NotMemoryFree MemoryRootClass = "not_memory_free"
	// MemoryRootUnrecognized: no marker and neither memory-free value. No
	// publisher has emitted such a trailer (memory-bearing publish was
	// refused before the marker existed), so it is refused.
	MemoryRootUnrecognized MemoryRootClass = "unrecognized"
)

// EmptyMemoryRoot returns E20, the konareef-rinit/v1 r_init of a pod with
// no initial memory (R-M10): the PRD 1 §5.5 Poseidon root of the empty
// depth-20 tree, c5a959b0…d727 in little-endian hex. It does not depend
// on any salt.
//
// Input: none. Output: the 32-byte little-endian field element.
func EmptyMemoryRoot() [32]byte {
	return poseidon.Default().EmptyRoots()[20]
}

// ClassifyMemoryRoot applies R-M17 to a parsed `[_commit]` trailer.
//
// Inputs: the trailer (from ParseCommitTrailer, so its scheme is already
// "" or RInitSchemeV1) and the three public fields_root dimensions the
// manifest declares — models ("<provider>/<name>"), tools and c_max.
//
// Output: the class and a nil error, or an error when FieldsRoot refuses
// the dimensions (over-cap, duplicate, empty or non-UTF-8 ids). The rule:
//
//	committed == FieldsRoot(models, tools, c_max, E20) → MemoryFreeRInitV1
//	committed == FieldsRoot(models, tools, c_max, 0)   → MemoryFreeLegacyZero
//	otherwise, marker present                          → NotMemoryFree
//	otherwise, no marker                               → MemoryRootUnrecognized
//
// A marker beside a zero root is still MemoryFreeLegacyZero: the root, not
// the marker, decides proof eligibility, and PS-1 refuses that trailer
// with rinit_legacy_zero too.
func ClassifyMemoryRoot(t CommitTrailer, models, tools []string, cMax uint64) (MemoryRootClass, error) {
	v1, err := FieldsRoot(models, tools, cMax, EmptyMemoryRoot())
	if err != nil {
		return "", err
	}
	if t.FieldsRoot == v1 {
		return MemoryFreeRInitV1, nil
	}
	legacy, err := FieldsRoot(models, tools, cMax, [32]byte{})
	if err != nil {
		return "", err
	}
	if t.FieldsRoot == legacy {
		return MemoryFreeLegacyZero, nil
	}
	if t.RInitScheme == RInitSchemeV1 {
		return NotMemoryFree, nil
	}
	return MemoryRootUnrecognized, nil
}
