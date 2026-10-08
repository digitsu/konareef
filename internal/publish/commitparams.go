// Copyright 2026 Jerry David Chan, Konareef.ai
// SPDX-License-Identifier: Apache-2.0

// commitparams.go — derives the four konareef-toml/v2 publish-time
// values (spec §4) from a parsed pod manifest.
//
// canon performs no resolution of its own (R-V2.9, internal/canon/commit.go):
// canon.CanonicalizeV2 takes a canon.CommitParams it is handed and commits
// it verbatim. DeriveCommitParams is where those four values come FROM —
// the manifest-sourcing rules and every policy refusal that a manifest can
// trigger before it ever reaches the canonicalizer. canon.FieldsRoot
// separately enforces the structural constraints on the resulting lists
// (over-cap, duplicate, empty, non-UTF-8) — this file does not re-check
// those; it only decides what those lists and scalars ARE.
package publish

import (
	"fmt"

	"github.com/BurntSushi/toml"
	"golang.org/x/text/unicode/norm"

	"github.com/digitsu/konareef/internal/canon"
	"github.com/digitsu/konareef/internal/pod"
)

// DeriveCommitParams turns a parsed manifest into the four values the
// canonicalizer commits (spec §4).
//
// Input: the parsed spec and the toml.MetaData from the SAME decode — the
// metadata is how [budget] presence is known. Output: canon.CommitParams,
// or a coded *canon.Error naming the exact §7 rejection.
//
// meta.IsDefined is load-bearing: Budget.MaxSats is an int with
// omitempty, so an absent [budget] and max_sats = 0 are identical in the
// struct. Committing 0 for an absent budget is the failure spec §4.3
// exists to prevent — containment would tell a buyer the pod cannot
// spend, while the server's 200,000-sat ceiling in fact applies.
func DeriveCommitParams(spec *pod.Spec, meta toml.MetaData) (canon.CommitParams, error) {
	p, _, err := deriveCommitParams(spec, meta, nil)
	return p, err
}

// DeriveCommitParamsWithMemory is DeriveCommitParams for a publish that
// may carry initial memory.
//
// Inputs: as DeriveCommitParams, plus mem — the pod directory, sealed
// disclosure policy and lineage salt the memory-bearing path reads (nil
// for a memory-free pod). Output: the four committed values plus the
// r_init_scheme marker, or the coded refusal. A memory-bearing pod is
// refused with COMMIT_MEMORY_RESOLUTION_UNAVAILABLE in every build until
// the konareef-rinit/v1 rollout reaches phase 4 (memoryroot.go).
func DeriveCommitParamsWithMemory(spec *pod.Spec, meta toml.MetaData, mem *MemoryCommitInput) (canon.CommitParams, error) {
	p, _, err := deriveCommitParams(spec, meta, mem)
	return p, err
}

// deriveCommitParams is the shared body of the two exported entry
// points. Besides the params it returns the memory resolution: the
// [_files] entries a memory-bearing r_init was computed over, so Prepare
// can check that the canonical output commits the same bytes, and the
// cells Prepare builds the signed leaf table from.
func deriveCommitParams(spec *pod.Spec, meta toml.MetaData, mem *MemoryCommitInput) (canon.CommitParams, memoryResolution, error) {
	var p canon.CommitParams

	// The "<provider>/<name>" rule (spec §4.1, R-V2.5) lives in
	// canon.ModelID, not here, because two OTHER Go sites derive the same
	// identifier — internal/install.LoadManifestParams (the witness the
	// circuit checks against this commitment) and
	// internal/commission.ModelIDs (the envelope a containment check
	// decides on). They disagreed with this one until 2026-09-21; a shared
	// helper is what stops that recurring.
	if spec.Model != nil {
		id, err := canon.ModelID(spec.Model.Provider, spec.Model.Name)
		if err != nil {
			return p, memoryResolution{}, err
		}
		p.Models = []string{id}
	}

	// The declared_tools inputs come from pod.CommitToolInputs, the same
	// reader install.LoadManifestParams and commission.FromManifest use.
	// Brokered MCP grants ride along in BrokerGrants: CanonicalizeV3
	// commits their ids beside the sources (konareef-toml/v3), and
	// CanonicalizeV2 refuses them rather than leaving them uncommitted.
	sources, grants := pod.CommitToolInputs(*spec)
	for _, source := range sources {
		if norm.NFC.String(source) != source {
			return p, memoryResolution{}, canon.NewError(canon.ErrCommitNonNFCID,
				fmt.Sprintf("tool source %q is not NFC-normalized; "+
					"the commitment would hash SHA256(raw) while reef-core records SHA256(NFC)", source))
		}
	}
	if len(sources) > 0 {
		p.Tools = sources
	}
	p.BrokerGrants = grants

	// D4 (tool-policy semantics ADR): an explicit tools_allowed = []
	// declares "this pod uses no tools", which contradicts a non-empty
	// [[context.tools]]. meta.IsDefined is load-bearing here for the same
	// reason it is for [budget] above — an omitted tools_allowed and an
	// explicit [] both decode to len(spec.Directive.ToolsAllowed) == 0, so
	// only the metadata can tell "no directive policy stated" apart from
	// "policy is empty". p.Tools is already the full declared (S1) set at
	// this point, and every entry has already passed the NFC check above.
	if spec.Directive != nil && meta.IsDefined("directive", "tools_allowed") &&
		len(spec.Directive.ToolsAllowed) == 0 && len(p.Tools) > 0 {
		return p, memoryResolution{}, canon.NewError(canon.ErrCommitToolAuthorityContradiction,
			"[directive].tools_allowed is explicitly empty ([]), which declares this pod uses no "+
				"tools, but [[context.tools]] commits tools; publish with a non-empty tools_allowed, "+
				"or with [[context.tools]] empty too")
	}

	if err := checkToolAuthorityCommitted(spec); err != nil {
		return p, memoryResolution{}, err
	}

	if !meta.IsDefined("budget", "max_sats") {
		return p, memoryResolution{}, canon.NewError(canon.ErrCommitBudgetRequired,
			"a v2 publish requires [budget].max_sats; there is no default")
	}
	if spec.Budget.MaxSats < 0 {
		return p, memoryResolution{}, canon.NewError(canon.ErrCommitBudgetRequired,
			"[budget].max_sats must not be negative")
	}
	p.CMax = uint64(spec.Budget.MaxSats)

	// r_init and its derivation marker (konareef-rinit/v1 spec §5, §7.1).
	// A memory-free pod commits E20 — the Poseidon empty-tree root the
	// circuit proves for empty memory (D1-A) — with the r_init_scheme
	// marker (D2-A). This replaced the provisional zero that publish
	// committed from konareef !106 (2026-09-21): a zero root can never be
	// proved (MEM-01 §4, confirmed with the real prover). A memory-bearing
	// pod is resolved by resolveMemoryRInit, which refuses unless the
	// phase-3 gate is on and every source is supported (memoryroot.go).
	res, err := resolveMemoryRInit(spec, mem)
	if err != nil {
		return p, memoryResolution{}, err
	}
	p.RInit = res.rInit
	p.RInitScheme = res.scheme
	return p, res, nil
}

// checkToolAuthorityCommitted refuses a manifest whose [directive].
// tools_allowed or tools_denied breaks one of the byte-exact tool-policy
// rules the tool-policy semantics ADR settles for v2 publish
// (docs/design/tool-policy-semantics-adr.md, decisions D3 and D5):
//
//   - a tools_allowed name absent from [[context.tools]] (spec §7.1,
//     R-V2.14): `COMMIT_TOOL_AUTHORITY_UNCOMMITTED`.
//   - a non-NFC tools_allowed or tools_denied name (D5, the same rule the
//     loop above already applies to a declared source): `COMMIT_NON_NFC_ID`.
//   - a name in both tools_allowed and tools_denied (D5): the new
//     `COMMIT_TOOL_DENY_OVERLAP`.
//
// A tools_denied name absent from [[context.tools]] and not overlapping
// tools_allowed is NOT refused here — under the accepted declaration-only
// contract (decision D1 = Option B) that is an authoring-time finding only
// (`pod validate`'s "tools-denied-unknown" warning), not a publish
// rejection.
//
// pod.CheckToolPolicy is the single shared implementation of these byte
// comparisons; internal/commission.ValidateToolAuthorityCommitted calls the
// same function for check/sign/verify, per decision D3. This function's
// job is only to map CheckToolPolicy's findings to the coded *canon.Error
// this package's callers expect — the two used to disagree here (v2
// publish refused a manifest commission accepted; fixture TP-02), and
// decision D3 is what settled that they should not.
//
// context.tools NFC problems cannot reach this function: the loop in
// DeriveCommitParams above already walks every declared source and returns
// COMMIT_NON_NFC_ID before this is ever called, so by construction every
// name pod.CheckToolPolicy would report as Field ToolPolicyFieldDeclared
// has already passed.
func checkToolAuthorityCommitted(spec *pod.Spec) error {
	if spec.Directive == nil {
		return nil
	}
	for _, problem := range pod.CheckToolPolicy(*spec) {
		switch {
		case problem.Field == pod.ToolPolicyFieldAllowed && problem.Code == pod.ToolPolicyNonNFC:
			return canon.NewError(canon.ErrCommitNonNFCID,
				fmt.Sprintf("[directive].tools_allowed names %q, which is not NFC-normalized; "+
					"the commitment would hash SHA256(raw) while reef-core records SHA256(NFC)", problem.Name))
		case problem.Field == pod.ToolPolicyFieldAllowed && problem.Code == pod.ToolPolicyUncommitted:
			return canon.NewError(canon.ErrCommitToolAuthorityUncommitted,
				fmt.Sprintf("[directive].tools_allowed names %q, which has no matching [[context.tools]] entry; "+
					"tools_allowed does not reach fields_root, so an uncommitted name would grant runtime "+
					"authority the commitment does not cover", problem.Name))
		case problem.Field == pod.ToolPolicyFieldDenied && problem.Code == pod.ToolPolicyNonNFC:
			return canon.NewError(canon.ErrCommitNonNFCID,
				fmt.Sprintf("[directive].tools_denied names %q, which is not NFC-normalized", problem.Name))
		case problem.Field == pod.ToolPolicyFieldDenied && problem.Code == pod.ToolPolicyDenyOverlap:
			return canon.NewError(canon.ErrCommitToolDenyOverlap,
				fmt.Sprintf("%q is named in both tools_allowed and tools_denied; deny wins, so declaring "+
					"both is refused as an authoring mistake rather than silently resolved", problem.Name))
		}
	}
	return nil
}
