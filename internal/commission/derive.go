// Copyright 2026 Jerry David Chan, Konareef.ai
// SPDX-License-Identifier: Apache-2.0

// Package commission builds and signs konareef commissions, and derives
// the envelope a published pod manifest declares.
package commission

import (
	"errors"
	"fmt"

	"github.com/digitsu/konareef/internal/canon"
	"github.com/digitsu/konareef/internal/envelope"
	"github.com/digitsu/konareef/internal/pod"
)

// ModelIDs returns the model identifiers a spec declares, normalised. A
// spec with no [model] table declares no models.
//
// The identifier is "<provider>/<name>" — [model].provider and
// [model].name joined by a single "/", both REQUIRED — per
// docs/reference/konareef-toml-v2-spec.md §4.1 (R-V2.5). The join is not
// performed here: it is canon.ModelID, so that all THREE Go derivations of
// this field share one implementation.
//
//	internal/publish.DeriveCommitParams  — emits the id into the
//	                                       [_commit].fields_root a publish
//	                                       commits.
//	internal/install.LoadManifestParams  — emits the id into
//	                                       feeder.ManifestParams, which
//	                                       feeds the circuit witness.
//	this function                        — emits the id into the commission
//	                                       envelope a containment check
//	                                       decides on.
//
// The three must not diverge. Until 2026-09-21 they did: spec §4.1
// overturned the shipped `[model].name` form, publish adopted
// "<provider>/<name>", and these other two were left on the bare name. A
// --zk publish of a pod with a [model] therefore committed models_root
// over "openai/gpt-4o" while the prove side computed it over "gpt-4o" —
// the publish SUCCEEDED, burned a pod_hash, and the proof then failed at
// prove time. On this side the same divergence decides containment on a
// model identifier the commitment does not cover, which is the fail-open
// §4.3 rejects for c_max.
//
// A [model] that names only one of the two parts is an error rather than
// "no models declared": the pod schema requires both (spec_v0_1.schema.json
// makes provider and name required with minLength 1), so the shape cannot
// come from a valid manifest, and silently dropping the dimension would
// let containment report a pod contained over a model it does not name.
func ModelIDs(s pod.Spec) ([]string, error) {
	if s.Model == nil {
		return nil, nil
	}
	id, err := canon.ModelID(s.Model.Provider, s.Model.Name)
	if err != nil {
		return nil, err
	}
	return envelope.Normalise([]string{id}), nil
}

// ToolIDs returns the tool names a spec declares, normalised. The source
// is [[context.tools]].source, NOT [directive].tools_allowed.
//
// [directive].tools_allowed is read nowhere else in this codebase (checked
// by grep across all non-test .go files) and is not the circuit's
// allowlist: docs/design/pod-manifest-split.md §6 states "the circuit's
// declared-tools allowlist reads tool names from the head" and shows that
// allowlist as [[context.tools]] entries, and
// internal/install.LoadManifestParams builds feeder.ManifestParams.Tools
// from exactly spec.Context.Tools[].Source. tools_allowed and
// tools_denied are directive fields that no runtime enforces today:
// reef-core parses them and reads them nowhere (spec R-V2.14). Whether
// they become a runtime narrowing policy is an open owner decision, see
// docs/design/tool-policy-semantics-adr.md. Either way they are not the
// set FromSpec must match against a committed fields_root.
func ToolIDs(s pod.Spec) []string {
	if s.Context == nil {
		return nil
	}
	sources := make([]string, 0, len(s.Context.Tools))
	for _, t := range s.Context.Tools {
		sources = append(sources, t.Source)
	}
	return envelope.Normalise(sources)
}

// ErrToolAuthorityNotCommitted means a manifest declares runtime tool
// authority ONLY through [directive].tools_allowed, with no
// [[context.tools]] entries to carry it.
//
// Such a manifest cannot participate in commission containment. Its
// tools_allowed list states the tools the pod means to use (no runtime
// enforces that list today; see docs/design/tool-policy-semantics-adr.md),
// and a runtime may still expose tools to it, but the derivation that feeds
// the circuit (internal/install.LoadManifestParams) reads only
// [[context.tools]], so that authority never reaches fields_root. Deriving
// an envelope anyway would produce an empty Tools dimension, and a
// containment check over it would report the pod "contained" while the pod
// holds tool authority the envelope does not represent. That is a fail-open,
// so the manifest is refused instead.
//
// Refusing is deliberately NOT the same as teaching ToolIDs to read
// tools_allowed. Changing what feeds fields_root would redefine the
// committed tool set of every already-published pod, which is a
// circuit-level decision. Refusal changes only which manifests may be
// commissioned, and it fails closed.
var ErrToolAuthorityNotCommitted = errors.New(
	"manifest declares tool authority only in [directive].tools_allowed, which the manifest commitment does not cover: declare each tool as a [[context.tools]] entry so the tool set reaches fields_root")

// ErrToolNameNotNFC means a declared ([[context.tools]].source) or allowed
// ([directive].tools_allowed) tool name is not NFC-normalized.
//
// v2 publish has always refused a non-NFC declared source outright
// (COMMIT_NON_NFC_ID), but commission derivation skipped the check
// entirely until the tool-policy semantics ADR's fixture TP-08 named the
// gap: a manifest whose [[context.tools]] source was itself non-NFC still
// derived a usable envelope here, so a byte-exact containment check
// downstream (envelope.Contains, what a buyer's commission actually
// relies on) could compare two different Unicode encodings of what a
// human reads as the same tool name and get a false answer either way.
// Decision D5 applies the one NFC rule to every tool-name field, so this
// error closes that gap rather than leaving it commission-only.
var ErrToolNameNotNFC = errors.New("tool name is not NFC-normalized")

// ValidateToolAuthorityCommitted reports whether every route by which s
// declares tool authority is one the manifest commitment covers, per the
// tool-policy semantics ADR's decisions D3 and D5
// (docs/design/tool-policy-semantics-adr.md):
//
//   - D5: every declared ([[context.tools]].source) and allowed
//     ([directive].tools_allowed) name must be NFC-normalized
//     (ErrToolNameNotNFC) — see that error's doc comment.
//   - D3: every allowed name must have a byte-exact match in declared
//     (ErrToolAuthorityNotCommitted). This is the per-name rule
//     internal/publish/commitparams.go's checkToolAuthorityCommitted
//     already applied to v2 publish (spec R-V2.14); decision D3 extends it
//     to commission draft/check/sign/verify, superseding the coarser
//     "tools_allowed non-empty AND context.tools entirely empty" shape
//     decision 2026-08-31 shipped (TP-02, TP-07 and TP-11 all changed from
//     accepted to refused when this landed — see the fixture file).
//
// A manifest that declares no tools_allowed at all is accepted: it claims
// no tool authority through that route. [directive].tools_denied is not
// read here — commission containment has no deny-list dimension; adding
// one would be the fifth envelope dimension the work item forbids. Its
// own rules (overlap with tools_allowed, an unknown referent) are a
// pod validate / v2 publish concern (internal/pod/toolpolicy.go,
// commitparams.go).
//
// pod.CheckToolPolicy is the single shared implementation both this
// function and checkToolAuthorityCommitted call — see toolpolicy.go's
// header for why the two rules used to drift (fixture TP-02) and must not
// again.
//
// FromSpec calls this, so every verb that derives an envelope — draft,
// check, verify — refuses the same manifests. Do not inline the condition
// into a verb; that is how check and sign drifted apart twice already (see
// signable.go's header).
func ValidateToolAuthorityCommitted(s pod.Spec) error {
	for _, problem := range pod.CheckToolPolicy(s) {
		if problem.Field == pod.ToolPolicyFieldDenied {
			continue
		}
		switch problem.Code {
		case pod.ToolPolicyNonNFC:
			return fmt.Errorf("%w: %q (%s)", ErrToolNameNotNFC, problem.Name, problem.Field)
		case pod.ToolPolicyUncommitted:
			return fmt.Errorf("%w (tools_allowed names %q, absent from [[context.tools]])", ErrToolAuthorityNotCommitted, problem.Name)
		}
	}
	return nil
}

// FromManifest derives the envelope a canonical manifest declares. It is
// FromSpec with the Tools dimension taken from the manifest's committed
// declared_tools list rather than from [[context.tools]] alone.
//
// Inputs: the manifest bytes (canonical, or an author pod.toml with no
// magic line) and the spec decoded from those same bytes. Output: the
// envelope, or FromSpec's errors, or the coded canon.CommittedTools /
// canon.DeclaredToolsV3 refusal, or the coded MAGIC_NEAR_MISS refusal
// (canon.CheckMagicLine) for a near-miss magic line.
//
// For v1, v2 and magic-less bytes the result equals FromSpec(s): those
// versions commit [[context.tools]] only. For konareef-toml/v3 the Tools
// dimension also holds every brokered MCP tool id "<mcp_name>.<tool>",
// because v3 commits them (MCP-Z00 §10.2, D3 option A). Containment then
// decides on the same set the circuit's tools_root covers, so a buyer's
// commission that omits a brokered tool is reported as not containing the
// pod, instead of passing while the pod holds tool authority the envelope
// does not name.
func FromManifest(manifest []byte, s pod.Spec) (envelope.Envelope, error) {
	// A near-miss magic line has no version token, so the tools below
	// would be derived as v1 and leave out the brokered ids a v3 body
	// grants (KR-MAGIC). Every caller validates the binding first, which
	// refuses it too; this keeps the function safe on its own.
	if err := canon.CheckMagicLine(manifest); err != nil {
		return envelope.Envelope{}, err
	}
	e, err := FromSpec(s)
	if err != nil {
		return envelope.Envelope{}, err
	}
	version, _ := canon.VersionIdentifier(manifest)
	sources, grants := pod.CommitToolInputs(s)
	tools, err := canon.CommittedTools(version, sources, grants)
	if err != nil {
		return envelope.Envelope{}, err
	}
	e.Tools = envelope.Normalise(tools)
	return e, nil
}

// FromSpec derives the envelope a published manifest declares.
//
// Three dimensions are derived: models, tools, and the spend cap. The
// memory-scope dimension is NOT derived and is left absent (LabelsSet
// false, Labels empty), because the pod manifest has no provenance-label
// vocabulary to read: pod.ContextMemory carries only Kind, Snapshot, Path,
// URL and Content, none of which is a label. Inventing a proxy vocabulary
// from those fields would report coverage that does not exist; see spec
// section 4.2.
//
// Labels are attribution-only (owner decision 2026-10-08, DATA-00): the
// buyer's labels are bound in h_commission and never enforced. A salted
// `r_init` over bytes does not prove labels, provenance or subsequent
// information flow.
//
// ModelsSet, ToolsSet and CMaxSet are all true in the returned envelope,
// even when the corresponding manifest table is absent and the derived
// value is therefore empty/zero: absence of a [model], [context], or
// [budget] table is itself a declaration ("no models", "no tools", "no
// spend"), not a missing dimension. This matters downstream: a buyer's
// proposal seeded from this envelope must pass envelope.ValidateAsCommission,
// which refuses any omitted (Set == false) dimension.
//
// Returns an error if the declared budget is negative, which no valid
// manifest carries and which would otherwise wrap into a huge uint64;
// ErrToolAuthorityNotCommitted if the manifest declares tool authority only
// through a route the commitment does not cover — see
// ValidateToolAuthorityCommitted; or a coded COMMIT_MODEL_PROVIDER_MISSING
// canon.Error if the [model] table names only one of provider and name
// (see ModelIDs).
func FromSpec(s pod.Spec) (envelope.Envelope, error) {
	if err := ValidateToolAuthorityCommitted(s); err != nil {
		return envelope.Envelope{}, err
	}
	models, err := ModelIDs(s)
	if err != nil {
		return envelope.Envelope{}, err
	}
	var cMax uint64
	if s.Budget != nil {
		if s.Budget.MaxSats < 0 {
			return envelope.Envelope{}, fmt.Errorf("manifest declares negative budget %d", s.Budget.MaxSats)
		}
		cMax = uint64(s.Budget.MaxSats)
	}
	return envelope.Envelope{
		Models:    models,
		Tools:     ToolIDs(s),
		CMax:      cMax,
		ModelsSet: true,
		ToolsSet:  true,
		CMaxSet:   true,
		// LabelsSet deliberately false: not derived, see the doc comment.
	}, nil
}
