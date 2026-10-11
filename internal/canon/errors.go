// Copyright 2026 Jerry David Chan, Konareef.ai
// SPDX-License-Identifier: Apache-2.0

// errors.go — fatal canonicalization failures.
//
// Every canonicalizer rejection is fatal: no partial output is ever
// produced. An Error carries a stable, machine-readable Code (the
// strings frozen in konareef-toml/v1 spec §7) plus a human-readable
// Message that callers may surface but MUST NOT pattern-match on —
// only Code is contractually stable.
package canon

import "errors"

// Error is a fatal canonicalization failure.
//
// Code is one of the constants below — a stable identifier safe for
// machine dispatch and golden-vector expected.error files. Message is
// a human-readable elaboration and may change between releases.
type Error struct {
	Code    string
	Message string
}

// Error renders the failure as "CODE: message", or just "CODE" when no
// message is attached.
func (e *Error) Error() string {
	if e.Message == "" {
		return e.Code
	}
	return e.Code + ": " + e.Message
}

// Error codes — stable strings, konareef-toml/v1 spec §7. These MUST
// NOT change once the spec is locked; a verifier in any language keys
// off these exact bytes.
const (
	ErrEncodingNotUTF8         = "ENCODING_NOT_UTF8"
	ErrEncodingBOMPresent      = "ENCODING_BOM_PRESENT"
	ErrWrongVersion            = "WRONG_VERSION"
	ErrTOMLParseError          = "TOML_PARSE_ERROR"
	ErrFloatNaNForbidden       = "FLOAT_NAN_FORBIDDEN"
	ErrFloatInfForbidden       = "FLOAT_INF_FORBIDDEN"
	ErrFloatOutOfRange         = "FLOAT_OUT_OF_RANGE"
	ErrFloatSubnormalForbidden = "FLOAT_SUBNORMAL_FORBIDDEN"
	ErrReservedKeyFiles        = "RESERVED_KEY_FILES"
	ErrReservedKeyUnderscore   = "RESERVED_KEY_UNDERSCORE_PREFIX"
	ErrDatetimeNotUTC          = "DATETIME_NOT_UTC"
	ErrDatetimeDateOnly        = "DATETIME_DATE_ONLY"
	ErrTimeOnly                = "TIME_ONLY"
	ErrKeyInvalidChar          = "KEY_INVALID_CHAR"
	ErrFileNotReadable         = "FILE_NOT_READABLE"
	ErrSymlinkForbidden        = "SYMLINK_FORBIDDEN"
	ErrPathInvalid             = "PATH_INVALID"
	ErrPodSizeExceeded         = "POD_SIZE_EXCEEDED"
	ErrNonRegularFile          = "NON_REGULAR_FILE_FORBIDDEN"

	// ErrArrayOfInlineTables rejects an array whose elements are inline
	// tables (`key = [{a=1}, {b=2}]`). Spec §11 implementation found
	// this TOML construct has no defined canonical form — R11 expands
	// inline tables into `[table]` headers, but an array *element*
	// cannot become a table header. Rather than invent an ambiguous
	// form, v1 rejects it. konareef pod schemas never produce it; all
	// repeating structures use array-of-tables (`[[...]]`).
	ErrArrayOfInlineTables = "ARRAY_OF_INLINE_TABLES_FORBIDDEN"

	// konareef-toml/v2 §7. Same contract as the v1 codes above: these
	// exact bytes are what a verifier in any language keys off.
	ErrReservedKeyCommit              = "RESERVED_KEY_COMMIT"
	ErrCommitDuplicateEntry           = "COMMIT_DUPLICATE_ENTRY"
	ErrCommitOverCap                  = "COMMIT_OVER_CAP"
	ErrCommitNonCanonicalRInit        = "COMMIT_NONCANONICAL_RINIT"
	ErrCommitBudgetRequired           = "COMMIT_BUDGET_REQUIRED"
	ErrCommitModelProviderMissing     = "COMMIT_MODEL_PROVIDER_MISSING"
	ErrCommitToolAuthorityUncommitted = "COMMIT_TOOL_AUTHORITY_UNCOMMITTED"
	ErrCommitEmptyID                  = "COMMIT_EMPTY_ID"
	ErrCommitInvalidUTF8ID            = "COMMIT_INVALID_UTF8_ID"
	ErrCommitNonNFCID                 = "COMMIT_NON_NFC_ID"

	// Not in spec §7: added by the 2026-09-19 design, which scopes v2 to
	// memory-free pods until the r_init companion spec lands.
	ErrCommitMemoryResolutionUnavailable = "COMMIT_MEMORY_RESOLUTION_UNAVAILABLE"

	// Not in spec §7: added by the konareef-rinit/v1 spec (MEM-00 D2-A,
	// docs/reference/konareef-memory-root-v1-spec.md §9). A `[_commit]`
	// trailer names an r_init derivation this build does not support. PS-1
	// refuses the same trailer with reason rinit_scheme_unknown.
	ErrCommitRInitSchemeUnknown = "COMMIT_RINIT_SCHEME_UNKNOWN"

	// Not in spec §7: added under the tool-policy semantics ADR
	// (docs/design/tool-policy-semantics-adr.md, TA-00 konareef#18 / TA-01
	// konareef#19, decisions D3-D5). Both extend the existing
	// COMMIT_TOOL_AUTHORITY_UNCOMMITTED / COMMIT_NON_NFC_ID family to two
	// shapes those codes do not name:
	//   - a manifest whose [directive].tools_allowed is explicitly `[]`
	//     ("this pod uses no tools") beside a non-empty [[context.tools]]
	//     (decision D4 — presence distinguishes an omitted key from an
	//     explicit empty one, and the two contradict);
	//   - a name present in both tools_allowed and tools_denied (decision
	//     D5 — deny wins, but declaring both is an authoring mistake,
	//     refused rather than silently resolved).
	ErrCommitToolAuthorityContradiction = "COMMIT_TOOL_AUTHORITY_CONTRADICTION"
	ErrCommitToolDenyOverlap            = "COMMIT_TOOL_DENY_OVERLAP"

	// Not in spec §7: added by konareef-toml/v3 (docs/reference/
	// konareef-toml-v3-spec.md; MCP-Z00 §10, decision D3 option A), which
	// commits brokered MCP tool ids in declared_tools.
	//   - COMMIT_TOOL_ID_COLLISION: a [[context.tools]].source equals a
	//     broker id "<mcp_name>.<tool>". Two authorities would share one
	//     leaf, so the manifest is refused rather than deduplicated.
	//   - COMMIT_BROKER_TOOL_ID_INVALID: an mcp_name or mcp_tools entry is
	//     outside the pod schema's ASCII pattern, so its id has no single
	//     canonical byte form.
	//   - COMMIT_BROKER_GRANTS_REQUIRE_V3: a v2 emit was asked to commit
	//     brokered grants. v2 commits only [[context.tools]], so the grants
	//     would be silently left out of fields_root.
	//   - COMMIT_SEALED_GRANT_ZK_UNSUPPORTED: a --zk publish of a closed pod
	//     that carries a brokered grant. Refused until the sealed-grant
	//     carrier (MCP-C00) is approved (MCP-Z00 §10.5, D8).
	ErrCommitToolIDCollision          = "COMMIT_TOOL_ID_COLLISION"
	ErrCommitBrokerToolIDInvalid      = "COMMIT_BROKER_TOOL_ID_INVALID"
	ErrCommitBrokerGrantsRequireV3    = "COMMIT_BROKER_GRANTS_REQUIRE_V3"
	ErrCommitSealedGrantZKUnsupported = "COMMIT_SEALED_GRANT_ZK_UNSUPPORTED"
	// COMMIT_V3_REQUIRES_BROKER_GRANT: a v3 emit or read of a manifest with
	// no brokered grant. Its root would equal the v2 root, so the same pod
	// would have two valid encodings; such a pod is v2.
	ErrCommitV3RequiresBrokerGrant = "COMMIT_V3_REQUIRES_BROKER_GRANT"

	// Not in spec §7: added by KR-MAGIC (konareef#29). The first line
	// claims a konareef-toml magic line (it normalizes to
	// `#!konareef-toml` after dropping every byte that is not visible
	// ASCII and folding case) but is not exactly the v1, v2 or v3 magic
	// line. See CheckMagicLine. paygate-zk PS-1 refuses the same bytes as
	// commit_trailer_malformed.
	ErrMagicNearMiss = "MAGIC_NEAR_MISS"

	// The two RECANONICALIZE_* codes that briefly lived here went with
	// canon.Recanonicalize on 2026-09-21. They were the only codes in this
	// file outside spec §7, and they existed for one function that no
	// production path ever called. The read-back sites that remain
	// (CanonicalizeLike, ParseCommitFieldsRoot) report only §7 codes, so
	// this set is closed to the spec again.
)

// newErr constructs a fatal canon.Error.
func newErr(code, message string) *Error {
	return &Error{Code: code, Message: message}
}

// NewError constructs a fatal canon.Error. It is the exported form of
// newErr, for callers outside this package (e.g. internal/publish) that
// need to build a coded *canon.Error using one of the constants above —
// most commonly the v2 §7 codes for a manifest-sourcing refusal that
// canon itself has no way to detect (COMMIT_MODEL_PROVIDER_MISSING,
// COMMIT_NON_NFC_ID, COMMIT_BUDGET_REQUIRED,
// COMMIT_TOOL_AUTHORITY_UNCOMMITTED).
func NewError(code, message string) *Error {
	return newErr(code, message)
}

// Code extracts the stable error code from err. It returns "" when err
// is nil or is not a *canon.Error — letting callers branch on the
// canonicalizer's documented failure modes without string matching.
func Code(err error) string {
	var e *Error
	if errors.As(err, &e) {
		return e.Code
	}
	return ""
}

// Warning is a non-fatal advisory raised during canonicalization.
// Unlike an Error it never aborts the process: canonical output is
// still produced and the pod_hash is unaffected. Warnings surface only
// through CanonicalizeWithWarnings; the spec-mandated Canonicalize
// discards them.
type Warning struct {
	Code    string
	Message string
}

// WarnPodSizeLarge is raised when the total pod size exceeds the R15
// advisory threshold (100 KiB) while staying within the 1 MiB hard
// cap. It flags a pod that is unusually heavy — a likely sign of
// accidentally vendored content — without rejecting it.
const WarnPodSizeLarge = "pod-size-large"
