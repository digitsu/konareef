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
// root without the salt holder's memory evidence (konareef-rinit/v1 §6.2),
// so a caller without that evidence refuses the manifest instead of
// trusting the trailer. Memory-bearing publish is disabled in every build
// today (MEM-03), so no genuine manifest reaches this.
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
	committed, err := ManifestFieldsRoot(manifest)
	if err != nil {
		return err
	}
	if committed == nil {
		return nil
	}
	trailer, err := canon.ParseCommitTrailer(manifest)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrManifestCommitmentUnreadable, err)
	}
	spec, meta, err := pod.ParseWithMeta(manifest)
	if err != nil {
		return fmt.Errorf("%w: parse: %w", ErrManifestCommitmentMismatch, err)
	}

	var models []string
	if spec.Model != nil {
		id, err := canon.ModelID(spec.Model.Provider, spec.Model.Name)
		if err != nil {
			return fmt.Errorf("%w: [model]: %w", ErrManifestCommitmentMismatch, err)
		}
		models = []string{id}
	}
	if !meta.IsDefined("budget", "max_sats") || spec.Budget.MaxSats < 0 {
		return fmt.Errorf("%w: a committed manifest must declare a non-negative [budget].max_sats", ErrManifestCommitmentMismatch)
	}
	cMax := uint64(spec.Budget.MaxSats)
	version, _ := canon.VersionIdentifier(manifest)
	sources, grants := pod.CommitToolInputs(*spec)
	tools, err := canon.CommittedTools(version, sources, grants)
	if err != nil {
		return fmt.Errorf("%w: declared_tools: %w", ErrManifestCommitmentMismatch, err)
	}

	class, err := canon.ClassifyMemoryRoot(trailer, models, tools, cMax)
	if err != nil {
		return fmt.Errorf("%w: recompute: %w", ErrManifestCommitmentMismatch, err)
	}
	declaresMemory := spec.Context != nil && len(spec.Context.Memory) > 0
	switch {
	case !declaresMemory && (class == canon.MemoryFreeRInitV1 || class == canon.MemoryFreeLegacyZero):
		return nil
	case declaresMemory && class == canon.NotMemoryFree:
		return ErrManifestCommitmentUnverifiable
	default:
		return fmt.Errorf("%w: recomputed from models=%q tools=%q c_max=%d (memory declared: %v), committed %x",
			ErrManifestCommitmentMismatch, models, tools, cMax, declaresMemory, trailer.FieldsRoot)
	}
}
