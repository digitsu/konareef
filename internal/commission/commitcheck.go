// Copyright 2026 Jerry David Chan, Konareef.ai
// SPDX-License-Identifier: Apache-2.0

// commitcheck.go — recompute a canonical manifest's committed fields_root
// from the fields the manifest itself declares.
//
// ManifestFieldsRoot only READS the root a trailer states. A signed
// manifest whose trailer commits a tool its content does not declare (for
// example `evil.x`) then passes every check that compares against that
// root: commission containment reads the content, the verifier's CL-5(a)
// reads the trailer, and the circuit accepts records for `evil.x`. This
// file closes that gap. CheckManifestCommitment is called by
// Binding.ValidateAgainstManifest (commission check, sign-time verify and
// `commission verify`), by `commission draft`, and by the verifier's
// CL-5(a) block, so all of them refuse a trailer the content does not
// reproduce.
//
// install.LoadManifestParams performs the same recomputation with its own
// function (checkCommittedFieldsRoot), because it also accepts the salt
// holder's memory evidence. Both derive models, tools and c_max the same
// way: canon.ModelID, canon.CommittedTools over pod.CommitToolInputs, and
// [budget].max_sats.
package commission

import (
	"errors"
	"fmt"

	"github.com/digitsu/konareef/internal/canon"
	"github.com/digitsu/konareef/internal/pod"
)

// ErrManifestCommitmentMismatch means the manifest's declared fields do not
// reproduce the fields_root its [_commit] trailer states. The trailer
// commits something other than what the manifest declares, for example an
// extra tool.
var ErrManifestCommitmentMismatch = errors.New("manifest's declared fields do not reproduce its committed fields_root")

// ErrManifestCommitmentUnverifiable means the manifest commits a populated
// memory root. Its tools, models and c_max cannot be checked against the
// root without knowing r_init, so a caller with neither the salt holder's
// memory evidence nor a proven r_init refuses the manifest instead of
// trusting the trailer. The verifier, which reads r_init from a
// konareef-pod-step-v1.2 proof, uses CheckManifestMemoryCommitment.
var ErrManifestCommitmentUnverifiable = errors.New("manifest commits a populated memory root; its tools binding cannot be verified without the salt holder's memory evidence")

// CheckManifestCommitment recomputes the fields_root a canonical manifest
// commits and compares it with the trailer.
//
// Input: the manifest bytes (the h_manifest preimage).
//
// Output: nil when the manifest commits no fields_root (no magic line, or
// konareef-toml/v1), or when the root recomputed from its own declared
// fields — models (canon.ModelID), declared_tools (canon.CommittedTools for
// its version, so v3 includes the brokered MCP tool ids) and c_max
// ([budget].max_sats) — with a memory-free r_init (E20, or the legacy zero)
// equals the committed root. Otherwise an error wrapping:
//   - ErrManifestVersionUnsupported or ErrManifestCommitmentUnreadable
//     (from ManifestFieldsRoot);
//   - ErrManifestCommitmentMismatch: the manifest cannot be parsed, has no
//     [budget].max_sats, has an invalid [model] or tool list, or its fields
//     do not reproduce the root;
//   - ErrManifestCommitmentUnverifiable: it declares [[context.memory]] and
//     commits a populated memory root (fail closed; see that error).
func CheckManifestCommitment(manifest []byte) error {
	d, err := committedDimensions(manifest)
	if err != nil || d == nil {
		return err
	}
	class, err := canon.ClassifyMemoryRoot(d.trailer, d.models, d.tools, d.cMax)
	if err != nil {
		return fmt.Errorf("%w: recompute: %w", ErrManifestCommitmentMismatch, err)
	}
	switch {
	case !d.declaresMemory && (class == canon.MemoryFreeRInitV1 || class == canon.MemoryFreeLegacyZero):
		return nil
	case d.declaresMemory && class == canon.NotMemoryFree:
		return ErrManifestCommitmentUnverifiable
	default:
		return fmt.Errorf("%w: recomputed from models=%q tools=%q c_max=%d (memory declared: %v), committed %x",
			ErrManifestCommitmentMismatch, d.models, d.tools, d.cMax, d.declaresMemory, d.trailer.FieldsRoot)
	}
}

// ErrManifestMemoryRInitV1 means a manifest declares memory and commits a
// populated root, but its trailer does not name konareef-rinit/v2. A
// konareef-rinit/v1 memory-bearing manifest is not proof-eligible
// (konareef-rinit/v2 R-M30).
var ErrManifestMemoryRInitV1 = errors.New("memory-bearing manifest does not name konareef-rinit/v2; it is not proof-eligible")

// CheckManifestMemoryCommitment is CheckManifestCommitment for a
// memory-bearing konareef-rinit/v2 manifest whose r_init is known from a
// proof: the verifier reads it from the proof's r_in public input, which
// the circuit binds to z0[Z_R_MEM] at genesis.
//
// Inputs: the manifest bytes and the proven r_init (32-byte LE Fq).
// Output: nil when the manifest declares [[context.memory]], its trailer
// names konareef-rinit/v2, and FieldsRoot(models, declared_tools, c_max,
// rInit) over its own declared fields equals the committed fields_root.
// Otherwise an error wrapping ErrManifestVersionUnsupported or
// ErrManifestCommitmentUnreadable (from ManifestFieldsRoot),
// ErrManifestMemoryRInitV1 (another or no scheme), or
// ErrManifestCommitmentMismatch (no memory declared, no trailer, or a root
// the declared fields and rInit do not reproduce).
//
// It does not check that rInit is the konareef-rinit/v2 root of the
// declared memory: that needs the salt or the signed leaf table, which a
// public bundle does not carry (konareef-rinit/v2 §3, §8, D5 = P-A). The
// publisher's signature over the trailer is what binds the root to the
// memory.
func CheckManifestMemoryCommitment(manifest []byte, rInit [32]byte) error {
	d, err := committedDimensions(manifest)
	if err != nil {
		return err
	}
	if d == nil {
		return fmt.Errorf("%w: the manifest commits no fields_root", ErrManifestCommitmentMismatch)
	}
	if !d.declaresMemory {
		return fmt.Errorf("%w: the manifest declares no [[context.memory]]", ErrManifestCommitmentMismatch)
	}
	if d.trailer.RInitScheme != canon.RInitSchemeV2 {
		return ErrManifestMemoryRInitV1
	}
	got, err := canon.FieldsRoot(d.models, d.tools, d.cMax, rInit)
	if err != nil {
		return fmt.Errorf("%w: recompute: %w", ErrManifestCommitmentMismatch, err)
	}
	if got != d.trailer.FieldsRoot {
		return fmt.Errorf("%w: the declared fields over the proven r_init do not reproduce the committed root",
			ErrManifestCommitmentMismatch)
	}
	return nil
}

// CommittedMemoryFreeRoot returns the r_init a memory-free committed
// manifest proves over: E20 for the memory_free_rinit_v1 class, the zero
// root for the memory_free_legacy_zero class (R-M17).
//
// Input: the manifest bytes. Output: the root and true for a manifest
// that CheckManifestCommitment accepts as memory-free; a zero root and
// false for a manifest that commits no fields_root; or the error
// CheckManifestCommitment would return (including
// ErrManifestCommitmentUnverifiable for a memory-bearing manifest).
func CommittedMemoryFreeRoot(manifest []byte) ([32]byte, bool, error) {
	var none [32]byte
	if err := CheckManifestCommitment(manifest); err != nil {
		return none, false, err
	}
	d, err := committedDimensions(manifest)
	if err != nil || d == nil {
		return none, false, err
	}
	class, err := canon.ClassifyMemoryRoot(d.trailer, d.models, d.tools, d.cMax)
	if err != nil {
		return none, false, fmt.Errorf("%w: recompute: %w", ErrManifestCommitmentMismatch, err)
	}
	if class == canon.MemoryFreeRInitV1 {
		return canon.EmptyMemoryRoot(), true, nil
	}
	return none, true, nil // MemoryFreeLegacyZero, the only other class CheckManifestCommitment accepts
}

// manifestDimensions is what committedDimensions reads from a committed
// manifest: its trailer, the three public fields_root dimensions it
// declares, and whether it declares memory.
type manifestDimensions struct {
	trailer        canon.CommitTrailer
	models, tools  []string
	cMax           uint64
	declaresMemory bool
}

// committedDimensions parses a canonical manifest's trailer and declared
// fields.
//
// Input: the manifest bytes. Output: nil, nil when the manifest commits no
// fields_root (no magic line, or konareef-toml/v1); the dimensions; or an
// error wrapping ErrManifestVersionUnsupported,
// ErrManifestCommitmentUnreadable or ErrManifestCommitmentMismatch, as
// CheckManifestCommitment documents.
func committedDimensions(manifest []byte) (*manifestDimensions, error) {
	committed, err := ManifestFieldsRoot(manifest)
	if err != nil {
		return nil, err
	}
	if committed == nil {
		return nil, nil
	}
	trailer, err := canon.ParseCommitTrailer(manifest)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrManifestCommitmentUnreadable, err)
	}
	spec, meta, err := pod.ParseWithMeta(manifest)
	if err != nil {
		return nil, fmt.Errorf("%w: parse: %w", ErrManifestCommitmentMismatch, err)
	}

	var models []string
	if spec.Model != nil {
		id, err := canon.ModelID(spec.Model.Provider, spec.Model.Name)
		if err != nil {
			return nil, fmt.Errorf("%w: [model]: %w", ErrManifestCommitmentMismatch, err)
		}
		models = []string{id}
	}
	if !meta.IsDefined("budget", "max_sats") || spec.Budget.MaxSats < 0 {
		return nil, fmt.Errorf("%w: a committed manifest must declare a non-negative [budget].max_sats", ErrManifestCommitmentMismatch)
	}
	version, _ := canon.VersionIdentifier(manifest)
	sources, grants := pod.CommitToolInputs(*spec)
	tools, err := canon.CommittedTools(version, sources, grants)
	if err != nil {
		return nil, fmt.Errorf("%w: declared_tools: %w", ErrManifestCommitmentMismatch, err)
	}
	return &manifestDimensions{
		trailer: trailer, models: models, tools: tools, cMax: uint64(spec.Budget.MaxSats),
		declaresMemory: spec.Context != nil && len(spec.Context.Memory) > 0,
	}, nil
}
