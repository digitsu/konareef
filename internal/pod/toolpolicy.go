// Copyright 2026 Jerry David Chan, Konareef.ai
// SPDX-License-Identifier: Apache-2.0

// toolpolicy.go — the shared, pure relation checks between
// [[context.tools]].source (declared, S1) and the two [directive] lists,
// tools_allowed (S3) and tools_denied (S4), that the tool-policy semantics
// ADR settles (docs/design/tool-policy-semantics-adr.md, TA-00 konareef#18
// / TA-01 konareef#19, decisions D3 and D5).
//
// CheckToolPolicy is the ONE place these byte-exact rules live. Before this
// file, v2 publish (internal/publish/commitparams.go,
// checkToolAuthorityCommitted) and commission draft/check/sign/verify
// (internal/commission/derive.go, ValidateToolAuthorityCommitted) each
// implemented their own idea of "is tools_allowed committed", and they
// disagreed on a manifest that named an uncommitted tool (fixture TP-02):
// v2 publish refused it, commission accepted it. Decision D3 makes the two
// rules the same rule, so this file is where both packages get it from —
// see commitparams.go's and derive.go's doc comments for how each maps
// these results to its own error type.
//
// Presence — whether [directive].tools_allowed was omitted or set to an
// explicit `[]` — is deliberately NOT decided here (see decision D4). That
// rule needs toml.MetaData, which only internal/publish.DeriveCommitParams
// receives (commission.FromSpec takes a bare pod.Spec); it lives entirely
// in commitparams.go.
package pod

import "golang.org/x/text/unicode/norm"

// ToolPolicyIssueCode names one of the tool-policy problems CheckToolPolicy
// detects. Stable for callers to dispatch on; do not string-match Field or
// Name for control flow.
type ToolPolicyIssueCode string

const (
	// ToolPolicyNonNFC means the name is not NFC-normalized (ADR D5:
	// "Refuse non-NFC in S3 and S4 ... then compare bytes. Never rewrite
	// author bytes."). It is checked FIRST for every name, including a
	// declared ([[context.tools]]) source: a name that fails this check is
	// not additionally evaluated against ToolPolicyUncommitted,
	// ToolPolicyDenyOverlap or ToolPolicyDenyUnknown below, because a byte
	// comparison against an unnormalized name would report a false
	// "uncommitted" or "unknown" verdict for what a human reads as the
	// same name (fixture TP-07).
	ToolPolicyNonNFC ToolPolicyIssueCode = "non_nfc"
	// ToolPolicyUncommitted means the name (from tools_allowed) has no
	// byte-exact match in declared. This is the per-name rule spec
	// R-V2.14 already applied to v2 publish; decision D3 extends it to
	// commission check/sign/verify.
	ToolPolicyUncommitted ToolPolicyIssueCode = "uncommitted"
	// ToolPolicyDenyOverlap means the name appears in both tools_allowed
	// and tools_denied. Decision D5: deny wins, but naming a tool in both
	// lists is an authoring mistake, refused rather than silently
	// resolved.
	ToolPolicyDenyOverlap ToolPolicyIssueCode = "deny_overlap"
	// ToolPolicyDenyUnknown means the name (from tools_denied) has no
	// byte-exact match in declared. Under the accepted Option B
	// (declaration-only; ADR decision D1), this is an authoring-time
	// finding only — no refusal follows it anywhere.
	ToolPolicyDenyUnknown ToolPolicyIssueCode = "deny_unknown"
)

// ToolPolicyField names which manifest field a ToolPolicyIssue concerns.
type ToolPolicyField string

const (
	ToolPolicyFieldDeclared ToolPolicyField = "context.tools"
	ToolPolicyFieldAllowed  ToolPolicyField = "tools_allowed"
	ToolPolicyFieldDenied   ToolPolicyField = "tools_denied"
)

// ToolPolicyIssue is one problem CheckToolPolicy found.
type ToolPolicyIssue struct {
	Code  ToolPolicyIssueCode
	Field ToolPolicyField
	Name  string
}

// DeclaredToolSources returns [[context.tools]].source in manifest order,
// or nil when [context] is absent or declares no tools. Every rule in this
// file compares tools_allowed and tools_denied against this set.
func DeclaredToolSources(spec Spec) []string {
	if spec.Context == nil {
		return nil
	}
	if len(spec.Context.Tools) == 0 {
		return nil
	}
	sources := make([]string, 0, len(spec.Context.Tools))
	for _, tool := range spec.Context.Tools {
		sources = append(sources, tool.Source)
	}
	return sources
}

// isNFC reports whether name is already NFC-normalized — i.e. whether
// applying NFC would change no byte of it.
func isNFC(name string) bool {
	return norm.NFC.String(name) == name
}

// CheckToolPolicy applies the D3/D5 byte-exact relations between declared
// ([[context.tools]].source), allowed ([directive].tools_allowed) and
// denied ([directive].tools_denied) to spec, and returns every problem
// found. Comparisons are byte-exact throughout: no case-folding (D5 is
// case-sensitive) and no Unicode normalization of author bytes (a
// non-NFC name is reported, never silently rewritten).
//
// Order: every declared source is checked for NFC first (a v2 publish
// already refuses a non-NFC declared source unconditionally — see
// commitparams.go's own loop — so a caller that reaches this rule with an
// already-NFC-checked declared set will simply see no ToolPolicyNonNFC
// issue with Field ToolPolicyFieldDeclared). Then each allowed name, in
// manifest order: NFC first, then committed-membership. Then each denied
// name, in manifest order: NFC first, then overlap-with-allowed, then
// unknown-referent. A nil Directive is treated as an empty allowed and
// denied list — CheckToolPolicy never needs Directive itself, only the
// three name slices, so it accepts a spec with no [directive] table and
// simply reports the declared-side NFC problems, if any.
func CheckToolPolicy(spec Spec) []ToolPolicyIssue {
	declared := DeclaredToolSources(spec)
	var allowed, denied []string
	if spec.Directive != nil {
		allowed = spec.Directive.ToolsAllowed
		denied = spec.Directive.ToolsDenied
	}

	var issues []ToolPolicyIssue

	declaredSet := make(map[string]bool, len(declared))
	for _, name := range declared {
		declaredSet[name] = true
		if !isNFC(name) {
			issues = append(issues, ToolPolicyIssue{Code: ToolPolicyNonNFC, Field: ToolPolicyFieldDeclared, Name: name})
		}
	}

	allowedSet := make(map[string]bool, len(allowed))
	for _, name := range allowed {
		if !isNFC(name) {
			issues = append(issues, ToolPolicyIssue{Code: ToolPolicyNonNFC, Field: ToolPolicyFieldAllowed, Name: name})
			continue
		}
		allowedSet[name] = true
		if !declaredSet[name] {
			issues = append(issues, ToolPolicyIssue{Code: ToolPolicyUncommitted, Field: ToolPolicyFieldAllowed, Name: name})
		}
	}

	for _, name := range denied {
		if !isNFC(name) {
			issues = append(issues, ToolPolicyIssue{Code: ToolPolicyNonNFC, Field: ToolPolicyFieldDenied, Name: name})
			continue
		}
		if allowedSet[name] {
			issues = append(issues, ToolPolicyIssue{Code: ToolPolicyDenyOverlap, Field: ToolPolicyFieldDenied, Name: name})
			continue
		}
		if !declaredSet[name] {
			issues = append(issues, ToolPolicyIssue{Code: ToolPolicyDenyUnknown, Field: ToolPolicyFieldDenied, Name: name})
		}
	}

	return issues
}
