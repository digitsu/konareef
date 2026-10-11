// Copyright 2026 Jerry David Chan, Konareef.ai
// SPDX-License-Identifier: Apache-2.0

// custody_root_xcheck.go — the custody TOOL_LOG_ROOT cross-check of the
// v2 verifier (konareef#37, D7-XCHK; paygate-zk MCP-Z00 §9.5 D7).
//
// A broker-priced run (a konareef-toml/v3 manifest) ends in a v4 or v5
// custody record whose `TOOL_LOG_ROOT:` line is the server's SHA-256
// custody root over the stored tool-log records. A Type-C bundle
// discloses the tool-log records it proves (T_log_records). This check
// recomputes the custody root over those records, in disclosed order, and
// refuses the bundle when it differs from the link's TOOL_LOG_ROOT. It
// closes the splice in which an under-priced proof and its own records are
// placed under the unchanged custody link of a served bundle.
//
// It is not a boundary on its own. In bundle-only verification the custody
// chain is not anchored (custody.go), so a sender who rewrites
// TOOL_LOG_ROOT and re-hashes the link still passes it. Only reef-core
// ingest, a check against reef-core's stored custody record, or a verified
// chain-head anchor (reef-core#76) binds the link to the server.
//
// The SHA-256 custody root and the Poseidon t_root (checkTLogRoot) are
// different trees over the same records. They are never compared with
// each other.
//
// Precondition: a Type-C disclosure with witness_disclosure, and a
// disclosed manifest that opens with the exact konareef-toml/v3 magic line
// (a near miss is refused elsewhere, by ErrManifestMagicNearMiss). Any
// other bundle (a v1 or v2 manifest, Type D) verifies exactly as before.
//
// Under the precondition the check fails closed (review C-1). The chain
// must end in exactly one custody record, selected by label AND content
// (brokerPricedCustodyLink): the tail link has proof_type "custody", no
// other link claims custody, and the tail's data passes the custody blob
// rules as a v4 or v5 record. Anything else is refused with
// ErrCustodyLinkUnbound. The proof_type label is not covered by the link
// hash, so selecting on the label alone let a relabelled or appended link
// skip the check, even under a verified chain-head anchor.
//
// A record that fails the custody blob rules is refused here with
// ErrCustodyLinkUnbound. assessCustodyV2 then also reports it as
// ErrCustodyRecordInvalid, on VerifyV2 and on the live path
// (VerifyV2Production) alike (LIVE-CUSTODY, konareef#38).
//
// Public surface: ErrCustodyToolLogRootMismatch, ErrCustodyLinkUnbound (errors.go).
package verify

import (
	"bytes"
	"fmt"
	"strings"

	"github.com/digitsu/konareef/internal/canon"
)

// custodyToolLogRootMismatchMsg is the fixed divergence message of
// ErrCustodyToolLogRootMismatch.
const custodyToolLogRootMismatchMsg = "disclosed T_log records do not reproduce the custody TOOL_LOG_ROOT"

// brokerPricedManifestVersion is the manifest version whose tool-log
// records are broker-priced, so that the custody record's TOOL_LOG_ROOT
// is the root of the same records the bundle discloses.
const brokerPricedManifestVersion = "v3"

// isBrokerPricedManifest reports whether manifest opens with the exact
// konareef-toml/v3 magic line.
//
// Input: the disclosed manifest bytes. Output: true only for an exact v3
// magic line; false for v1, v2, an unsupported version or a near miss.
func isBrokerPricedManifest(manifest []byte) bool {
	if canon.CheckMagicLine(manifest) != nil {
		return false
	}
	version, ok := canon.VersionIdentifier(manifest)
	return ok && version == brokerPricedManifestVersion
}

// claimsCustody reports whether a link is a custody record by label or by
// content: its proof_type is "custody", or the FIRST line of its data is
// the custody version line (`CUSTODY_PROOF:`), compared case-insensitively
// after removing a leading BOM and surrounding white space. The label is
// not covered by the link hash, so a link is never taken to be
// non-custody on its label alone (review C-1).
//
// Only the first line is read (re-review N-2). reef-core writes the version
// line first and ParseCustodyBlob requires it there; a later line can come
// from an interpolated value (for example TASK_ID or POD_ID) and must not
// turn an honest link into a second custody record.
//
// The content test is a best-effort guard, not the boundary (re-review
// N-1). The boundary is the tail: its data must pass ParseCustodyBlob
// (which also refuses a blob with a blank or disguised first line), and on
// an anchored chain the tail cannot change. A sender who can re-hash links
// can already do more (the documented 5b class).
//
// Input: the link. Output: true for a custody record by either test.
func claimsCustody(link *ChainLinkV2) bool {
	if link.ProofType == "custody" {
		return true
	}
	first, _, _ := strings.Cut(string(link.Data), "\n")
	first = strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(first), "\ufeff"))
	return len(first) >= len(custodyVersionPrefix) &&
		strings.EqualFold(first[:len(custodyVersionPrefix)], custodyVersionPrefix)
}

// brokerPricedCustodyLink returns the custody record that a broker-priced
// (konareef-toml/v3) Type-C bundle must end in, or a description of why it
// has none.
//
// The chain must end in exactly one custody record: the tail link has
// proof_type "custody", no other link claims custody by label or content
// (claimsCustody), and the tail's data passes the custody blob rules
// (ParseCustodyBlob) as a v4 or v5 record, so it has one TOOL_LOG_ROOT.
// reef-core serves exactly this shape: Bundle.V2.pack walks the chain back
// from the custody row, custody is written as v4 or v5 with TOOL_LOG_ROOT,
// and a run with an MCP grant takes one task. The link hash is checked by
// checkTypeCLinkHashes (ErrChainBroken), not here.
//
// Input: b, the decoded bundle. Output: the parsed claim, or "" and a
// non-empty reason.
func brokerPricedCustodyLink(b *BundleV2) (CustodyClaim, string) {
	if len(b.Chain) == 0 {
		return CustodyClaim{}, "the chain has no custody link"
	}
	claims := 0
	for i := range b.Chain {
		if claimsCustody(&b.Chain[i]) {
			claims++
		}
	}
	tail := &b.Chain[len(b.Chain)-1]
	switch {
	case claims > 1:
		return CustodyClaim{}, fmt.Sprintf("the chain has %d custody records (by proof_type or content), want 1", claims)
	case tail.ProofType != "custody":
		return CustodyClaim{}, fmt.Sprintf("the chain tail has proof_type %q, want \"custody\"", tail.ProofType)
	}
	claim, err := ParseCustodyBlob(string(tail.Data))
	if err != nil {
		return CustodyClaim{}, fmt.Sprintf("the custody record fails the custody rules (%s)", CustodyRuleCode(err))
	}
	if claim.Version != CustodyV4 && claim.Version != CustodyV5 {
		return CustodyClaim{}, fmt.Sprintf("the chain tail is a %s custody record with no TOOL_LOG_ROOT, want v4 or v5", claim.Version)
	}
	return claim, ""
}

// checkCustodyToolLogRoot runs the custody TOOL_LOG_ROOT cross-check for a
// broker-priced Type-C bundle (the precondition in the file header).
//
// Inputs: b, the decoded bundle; v, its verdict; r, its result.
// Output: true when the precondition does not hold, or when the chain ends
// in one v4/v5 custody link whose TOOL_LOG_ROOT the disclosed records
// reproduce. Otherwise false, with v.CommitmentsValid=false and one
// divergence: ErrCustodyLinkUnbound naming the shape problem when there is
// no such link, or ErrCustodyToolLogRootMismatch when the roots differ.
func checkCustodyToolLogRoot(b *BundleV2, v *Verdict, r *ResultV2) bool {
	if b.Disclosure != "C" || b.WitnessDisclosure == nil || !isBrokerPricedManifest(b.Manifest) {
		return true
	}
	claim, reason := brokerPricedCustodyLink(b)
	if reason != "" {
		r.diverge(ErrCustodyLinkUnbound, "broker-priced (konareef-toml/v3) bundle: "+reason+
			"; the disclosed T_log records cannot be checked against a custody TOOL_LOG_ROOT")
		v.CommitmentsValid = false
		return false
	}
	computed := CustodyToolLogRoot(b.WitnessDisclosure.TLogRecords)
	if bytes.Equal(computed[:], claim.ToolLogRoot) {
		return true
	}
	r.diverge(ErrCustodyToolLogRootMismatch, custodyToolLogRootMismatchMsg)
	v.CommitmentsValid = false
	return false
}
