// Copyright 2026 Jerry David Chan, Konareef.ai
// SPDX-License-Identifier: Apache-2.0

// commit.go — the konareef-toml/v2 and v3 emitters.
//
// v2 output is v1 output with the magic line swapped from
// `#!konareef-toml/v1` to `#!konareef-toml/v2`, plus one computed
// `[_commit]` trailer appended after `[_files]`. This file produces
// that trailer (CommitTrailerBytes, CommitSectionBytes) and the full v2
// document (CanonicalizeV2). Both reuse canonicalBody (canon.go) for the
// version-independent author-tree + `[_files]` core, so v1 output is
// never touched by this file.
//
// The trailer has two forms (konareef-toml/v2 spec §1, amended by the
// konareef-rinit/v1 spec D2-A):
//
//	[_commit]
//	fields_root = "poseidon:<64 hex>"                  legacy: no marker
//
//	[_commit]
//	fields_root = "poseidon:<64 hex>"
//	r_init_scheme = "konareef-rinit/v1"               every new memory-free --zk publish
//	r_init_scheme = "konareef-rinit/v2"               a memory-bearing --zk publish
//
// "Marker absent" means the r_init inside fields_root was derived before
// konareef-rinit/v1 (in practice: the provisional zero). The marker is
// computed by the publish flow and never hand-authored.
//
// konareef-toml/v3 (CanonicalizeV3) is v2 with the `#!konareef-toml/v3`
// magic line and the v3 declared_tools set: the [[context.tools]] sources
// plus every brokered MCP tool id (declaredtools.go). The trailer grammar
// and the fields_root construction are the same.
package canon

import (
	"bytes"
	"encoding/hex"
)

// RInitSchemeV1 is the r_init derivation of a memory-free publish
// (konareef-rinit/v1 spec §5, D2-A). Its memory-free root is E20.
const RInitSchemeV1 = "konareef-rinit/v1"

// RInitSchemeV2 is the r_init derivation of a memory-bearing publish
// (docs/reference/konareef-rinit-v2-spec.md R-M29): the salt-free payload
// and the key_tag index. Its memory-free root is also E20, but a
// memory-free publish keeps RInitSchemeV1 so no memory-free manifest
// changes.
const RInitSchemeV2 = "konareef-rinit/v2"

// supportedRInitSchemes lists the r_init_scheme values this build emits or
// accepts in a `[_commit]` trailer, for error text. Any other value is
// refused with COMMIT_RINIT_SCHEME_UNKNOWN.
const supportedRInitSchemes = RInitSchemeV1 + ", " + RInitSchemeV2

// knownRInitScheme reports whether scheme is RInitSchemeV1 or RInitSchemeV2.
func knownRInitScheme(scheme string) bool {
	return scheme == RInitSchemeV1 || scheme == RInitSchemeV2
}

// CommitParams carries the four publish-time values FieldsRoot commits
// into the `[_commit]` trailer's fields_root, plus the derivation marker
// written beside it. canon performs no resolution of its own (R-V2.9):
// every value here is supplied by the caller.
type CommitParams struct {
	Models []string // "<provider>/<name>"
	Tools  []string // context.tools[].source, already NFC
	CMax   uint64   // budget.max_sats
	RInit  [32]byte // resolved memory root
	// RInitScheme names the derivation that produced RInit. It is
	// RInitSchemeV1 for a memory-free publish and RInitSchemeV2 for a
	// memory-bearing one; "" writes the legacy trailer with no marker, and
	// exists only so tests can reproduce manifests that were published
	// before the marker. Any other value is refused.
	RInitScheme string
	// BrokerGrants are the brokered MCP grants ([[network.gateway]] with
	// protocol = "mcp") in manifest order. CanonicalizeV3 commits their
	// tool ids beside Tools (DeclaredToolsV3). CanonicalizeV2 refuses a
	// non-empty list with COMMIT_BROKER_GRANTS_REQUIRE_V3, because v2
	// cannot commit them and would silently leave them out.
	BrokerGrants []BrokerGrant
}

// CommitTrailer is the parsed (or to-be-emitted) content of a `[_commit]`
// trailer: the committed fields_root and the optional r_init_scheme
// marker. RInitScheme is "" when the trailer carries no marker (a legacy
// manifest), and RInitSchemeV1 or RInitSchemeV2 otherwise.
type CommitTrailer struct {
	FieldsRoot  [32]byte
	RInitScheme string
}

// CommitSectionBytes renders the legacy `[_commit]` trailer for root, with
// no r_init_scheme marker. It is CommitTrailerBytes with an empty scheme.
//
// The section is appended to serialized output rather than inserted into
// the AST: the AST path must keep rejecting `_`-prefixed sections, which is
// what stops a publisher hand-authoring a commitment (RESERVED_KEY_COMMIT).
func CommitSectionBytes(root [32]byte) []byte {
	return CommitTrailerBytes(CommitTrailer{FieldsRoot: root})
}

// CommitTrailerBytes renders the `[_commit]` trailer for t in canonical
// form.
//
// Input: a trailer whose RInitScheme is "" or a known scheme (callers check
// the scheme first; see checkRInitScheme). Output: the trailer bytes —
// fields_root first, then r_init_scheme when present, each line ending in
// "\n". The key order is fixed so that a trailer round-trips through
// ParseCommitTrailer and CommitTrailerBytes to identical bytes, which is
// what install's CanonicalizeLike relies on to reproduce pod_hash.
func CommitTrailerBytes(t CommitTrailer) []byte {
	out := "[_commit]\nfields_root = \"" +
		commitFieldsRootPrefix + hex.EncodeToString(t.FieldsRoot[:]) + "\"\n"
	if t.RInitScheme != "" {
		out += "r_init_scheme = \"" + t.RInitScheme + "\"\n"
	}
	return []byte(out)
}

// checkRInitScheme returns nil for "" (legacy, no marker), RInitSchemeV1
// and RInitSchemeV2, and a coded COMMIT_RINIT_SCHEME_UNKNOWN error for any
// other value. The message never echoes the value, because the value may
// come from an untrusted manifest.
func checkRInitScheme(scheme string) error {
	if scheme == "" || knownRInitScheme(scheme) {
		return nil
	}
	return newErr(ErrCommitRInitSchemeUnknown,
		"[_commit] r_init_scheme names a derivation this build does not support; supported: "+supportedRInitSchemes)
}

// CanonicalizeV2 emits complete konareef-toml/v2 bytes, [_commit] included,
// in one call. A two-phase surface was rejected by spec §5.1: its
// intermediate carries the v2 magic line without a trailer, so it looks
// complete and hashes wrong.
//
// Input: the author's pod.toml bytes, the pod directory (for [_files]), and
// the four publish-time values plus the r_init_scheme marker. Output:
// canonical v2 bytes, or a coded *Error (COMMIT_RINIT_SCHEME_UNKNOWN for a
// scheme other than "", RInitSchemeV1 or RInitSchemeV2). canon performs no resolution of
// its own (R-V2.9).
//
// A non-empty p.BrokerGrants is refused with COMMIT_BROKER_GRANTS_REQUIRE_V3:
// the v2 declared_tools set is [[context.tools]] only, so those grants
// would reach the pod at run time with no commitment covering them. The
// v2 output bytes for every other input are unchanged by konareef-toml/v3.
func CanonicalizeV2(input []byte, dir string, p CommitParams) ([]byte, error) {
	if len(p.BrokerGrants) > 0 {
		return nil, newErr(ErrCommitBrokerGrantsRequireV3,
			"konareef-toml/v2 cannot commit brokered MCP tool ids; emit konareef-toml/v3 for a pod with an mcp grant")
	}
	return canonicalizeCommitted(input, dir, p, magicHeaderV2, p.Tools)
}

// CanonicalizeV3 emits complete konareef-toml/v3 bytes, [_commit]
// included, in one call.
//
// Input: as CanonicalizeV2. p.Tools holds the [[context.tools]] sources and
// p.BrokerGrants the brokered MCP grants; the committed declared_tools is
// DeclaredToolsV3(p.Tools, p.BrokerGrants), derived here so that no caller
// can hand v3 a list derived some other way. Output: canonical v3 bytes,
// or a coded *Error — every DeclaredToolsV3 refusal
// (COMMIT_TOOL_ID_COLLISION, COMMIT_OVER_CAP, COMMIT_BROKER_TOOL_ID_INVALID,
// COMMIT_DUPLICATE_ENTRY, ...), COMMIT_V3_REQUIRES_BROKER_GRANT when
// p.BrokerGrants is empty (such a pod is v2), and every CanonicalizeV2
// refusal except the grant refusal.
func CanonicalizeV3(input []byte, dir string, p CommitParams) ([]byte, error) {
	tools, err := CommittedTools("v3", p.Tools, p.BrokerGrants)
	if err != nil {
		return nil, err
	}
	return canonicalizeCommitted(input, dir, p, magicHeaderV3, tools)
}

// canonicalizeCommitted is the shared body of CanonicalizeV2 and
// CanonicalizeV3.
//
// Inputs: the author's pod.toml bytes, the pod directory, the commit
// params, the magic line to write, and the declared_tools list to commit
// (the version-specific part). Output: magic line, author tree, [_files],
// then the [_commit] trailer over FieldsRoot(p.Models, tools, p.CMax,
// p.RInit); or a coded *Error.
func canonicalizeCommitted(input []byte, dir string, p CommitParams, header string, tools []string) ([]byte, error) {
	if err := checkRInitScheme(p.RInitScheme); err != nil {
		return nil, err
	}
	root, err := FieldsRoot(p.Models, tools, p.CMax, p.RInit)
	if err != nil {
		return nil, err
	}
	body, _, err := canonicalBody(input, dir)
	if err != nil {
		return nil, err
	}
	var out bytes.Buffer
	out.WriteString(header)
	out.Write(body)
	out.Write(CommitTrailerBytes(CommitTrailer{FieldsRoot: root, RInitScheme: p.RInitScheme}))
	return out.Bytes(), nil
}
