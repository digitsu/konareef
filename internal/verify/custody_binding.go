// Copyright 2026 Jerry David Chan, Konareef.ai
// SPDX-License-Identifier: Apache-2.0

// custody_binding.go — what a v2 verdict's custody fields are bound to
// (konareef#37, D7-XCHK).
//
// A bundle carries its own custody record: the custody link's data, with
// TOTAL_SATS (the total behind ResultV2.CTotalChecked) and TOOL_LOG_ROOT.
// Bundle-only verification checks that this record is consistent with the
// bundle, not that it is the server's record: anyone can build a
// consistent chain (custody.go). ResultV2.CustodyBinding says which of
// these a verdict's custody fields are:
//
//   - CustodyBindingBundleClaim: the bundle's own claims. The default, and
//     the value of every bundle-only result without a verified anchor.
//   - CustodyBindingChainAnchored: a passing Type-C bundle whose chain-head
//     anchor verified (reef-core#76). The anchor attests the chain head,
//     and the head is the bound custody link, so the custody record is the
//     one the attested node wrote. It is still not a check against
//     reef-core's stored custody row.
//   - CustodyBindingServerChecked: checked against reef-core's stored
//     custody record (AssessCustodyRecord with the stored columns). No
//     verify path does that today, so no result carries this value yet.
//
// Scope: the binding covers the custody link's own fields (TOTAL_SATS,
// TOOL_LOG_ROOT, the broker marker), not the disclosed T_log records.
// Whether the records reproduce TOOL_LOG_ROOT is a separate check
// (custody_root_xcheck.go), and it runs only for a konareef-toml/v3
// manifest. So "chain-anchored" on a v2-manifest bundle says that the
// node wrote the custody link; it says nothing about the records next to
// it.
//
// Public surface: CustodyBinding and its constants, ResultV2.CTotalLabel.
package verify

// CustodyBinding says what a v2 verdict's custody fields are bound to.
type CustodyBinding string

// The custody bindings. The values are stable output strings.
const (
	CustodyBindingBundleClaim   CustodyBinding = "bundle-claim"
	CustodyBindingChainAnchored CustodyBinding = "chain-anchored"
	CustodyBindingServerChecked CustodyBinding = "server-checked"
)

// custodyBindingV2 returns the custody binding of a verified bundle.
//
// Inputs: b, the decoded bundle; r, its result after every check ran.
// Output: CustodyBindingChainAnchored only for a Type-C bundle that
// passed, whose chain-head anchor verified and that has a bound custody
// link (boundCustodyLinkV2); otherwise CustodyBindingBundleClaim.
func custodyBindingV2(b *BundleV2, r *ResultV2) CustodyBinding {
	if b.Disclosure == "C" && r.OK && r.V2Verdict != nil && r.V2Verdict.ChainHeadAnchored &&
		boundCustodyLinkV2(b) != nil {
		return CustodyBindingChainAnchored
	}
	return CustodyBindingBundleClaim
}

// CTotalLabel returns one line of display text for the c check
// (CTotalChecked) that names what the custody total is bound to.
//
// Input: the result. Output: the text. It never says more than the
// binding supports: an unknown or empty binding reads as a bundle claim.
func (r *ResultV2) CTotalLabel() string {
	if !r.CTotalChecked {
		return "c not checked against a custody total"
	}
	switch r.CustodyBinding {
	case CustodyBindingServerChecked:
		return "c equals the custody total of reef-core's stored custody record (server-checked)"
	case CustodyBindingChainAnchored:
		return "c equals the custody total of the anchored chain head " +
			"(written by the attested node; not checked against reef-core's stored custody record)"
	default:
		return "c equals the bundle's stated custody total (unanchored claim)"
	}
}
