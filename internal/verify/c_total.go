// Copyright 2026 Jerry David Chan, Konareef.ai
// SPDX-License-Identifier: Apache-2.0

// c_total.go — the custody total that the Rust verifier binds the proven
// cost to (paygate-zk MCP-Z00 §7, owner decision O1 option B).
//
// The circuit accumulates the run's cost `c` in the fold lane Z_C_ACC. The
// circuit alone accepts a double charge (`c = total + Σ sats`), because
// `Σ sats ≤ c` still holds. The Rust `verify` binary refuses it when the
// envelope carries `custody_total_sats`: the proven final Z_C_ACC must equal
// that total and the genesis lane must be zero. This file supplies the
// total from the bundle and names the refusal.
//
// Where the total comes from: the `TOTAL_SATS:` line of the bundle's custody
// link. The link is used only when assessCustodyV2 would also read it:
// exactly one custody link, at the tail, with data, and a link hash that
// recomputes from that data. Otherwise there is no total to use and the
// check is not run (ResultV2.CTotalChecked stays false). A Type-D bundle
// carries no link data, so its `c` is never checked here.
//
// What a pass means: in bundle-only verification the total is as
// unanchored as the custody record itself (see custody.go: anyone can
// build a consistent chain). CTotalChecked=true says the proof's `c`
// equals the TOTAL_SATS this bundle states, and ResultV2.CustodyBinding
// ("bundle-claim") and ResultV2.CTotalLabel say so to a reader
// (custody_binding.go, konareef#37). When the bundle's chain head
// anchor also verified (Type C), the custody link is the one the attested
// node wrote, and ResultV2.CTotalAnchored reports the check as anchored
// (reef-core#76). Without that, an anchored check must take the total
// from the stored custody row (reef-core) and pass it to the same Rust
// check.
//
// Public surface:
//
//   - ErrCTotalMismatch (errors.go) — the divergence code
//   - CustodyTotalSats — reads the total from a custody blob
//   - custodyTotalSatsV2 — reads the total of the bound custody link
//   - boundCustodyLinkV2 — selects the bound custody link of a v2 bundle
package verify

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// cTotalRejectCodeLine is the stderr line the Rust `verify` binary prints
// when check_c_total refuses (paygate-zk `src/bin/verify.rs`). Matched as a
// whole line, never as a substring of free text.
const cTotalRejectCodeLine = "verify: reject_code=ERR_C_TOTAL_MISMATCH"

// cTotalCheckedLine is the stderr line the Rust `verify` binary prints on
// an accept when the envelope carried custody_total_sats. A binary built
// before that field existed ignores it and never prints this line, so an
// accept without it must not count as a checked `c`.
const cTotalCheckedLine = "verify: c_total=checked"

// podStepScheduleCheckedLine is the stderr line the Rust `verify` binary
// prints on every accept once it checks the pod-step schedule
// (z0[Z_STEP_INDEX] == 0 and final == 1) for every envelope (paygate-zk!68,
// VHASH review M1). A binary built before that check never prints it, and
// it would accept a non-genesis v1 fold, so an accept without the line is
// refused (VHASH versioning review M-2).
const podStepScheduleCheckedLine = "verify: pod_step_schedule=checked"

// zStepIndexLane is the index of the step-counter lane in z0
// (paygate-zk circuit.rs Z_STEP_INDEX). A genuine fold starts it at zero.
const zStepIndexLane = 20

const totalSatsPrefix = "TOTAL_SATS:"

// totalSatsLine is the only accepted shape: a decimal with no sign, no
// leading zeros (reef-core writes Integer.to_string/1) and no spaces.
var totalSatsLine = regexp.MustCompile(`^TOTAL_SATS: (0|[1-9][0-9]*)$`)

// CustodyTotalSats reads the custody total from a custody blob.
//
// Input: data, the custody commitment's `data` blob (newline-separated
// `KEY: value` lines, as hashed into the chain).
// Output: the total, or an error wrapping ErrCTotalMismatch when the blob
// has no `TOTAL_SATS:` line, more than one, or a value that is not a
// canonical decimal that fits in a uint64. A verifier that has a bound
// custody record and cannot read its total must refuse, not skip.
func CustodyTotalSats(data string) (uint64, error) {
	var found []string
	for _, line := range strings.Split(data, "\n") {
		if strings.HasPrefix(line, totalSatsPrefix) {
			found = append(found, line)
		}
	}
	switch len(found) {
	case 0:
		return 0, fmt.Errorf("%w: custody record has no TOTAL_SATS line", ErrCTotalMismatch)
	case 1:
	default:
		return 0, fmt.Errorf("%w: custody record has %d TOTAL_SATS lines", ErrCTotalMismatch, len(found))
	}
	m := totalSatsLine.FindStringSubmatch(found[0])
	if m == nil {
		return 0, fmt.Errorf("%w: custody TOTAL_SATS is not a canonical decimal", ErrCTotalMismatch)
	}
	total, err := strconv.ParseUint(m[1], 10, 64)
	if err != nil {
		return 0, fmt.Errorf("%w: custody TOTAL_SATS does not fit in 64 bits", ErrCTotalMismatch)
	}
	return total, nil
}

// custodyTotalSatsV2 returns the custody total of a v2 bundle for the Rust
// verifier's `custody_total_sats`.
//
// The custody link is selected with the same rules as assessCustodyV2:
// exactly one custody link, it is the chain tail, it carries data, and its
// hash recomputes as SHA-256(prev_hash || data || timestamp).
//
// Input: b, the decoded bundle.
// Output:
//   - (&total, nil) when the link is bound and its TOTAL_SATS is readable;
//   - (nil, nil) when no bound custody link exists (Type-D, several custody
//     links, a non-custody tail, or a hash that does not recompute): the
//     `c` check is not run;
//   - (nil, err wrapping ErrCTotalMismatch) when the link is bound but its
//     TOTAL_SATS is missing, repeated or malformed: the caller must refuse.
func custodyTotalSatsV2(b *BundleV2) (*uint64, error) {
	link := boundCustodyLinkV2(b)
	if link == nil {
		return nil, nil
	}
	total, err := CustodyTotalSats(string(link.Data))
	if err != nil {
		return nil, err
	}
	return &total, nil
}

// boundCustodyLinkV2 returns the custody link of a v2 bundle when it is
// bound: exactly one custody link, at the tail, with data, and a hash
// that recomputes as SHA-256(prev_hash || data || timestamp). Otherwise
// it returns nil. assessCustodyV2, custodyTotalSatsV2 and
// checkCustodyLaneBinding select the same link with this rule.
//
// Input: b, the decoded bundle. Output: the link or nil.
func boundCustodyLinkV2(b *BundleV2) *ChainLinkV2 {
	if len(b.Chain) == 0 {
		return nil
	}
	custodyLinks := 0
	for i := range b.Chain {
		if b.Chain[i].ProofType == "custody" {
			custodyLinks++
		}
	}
	link := &b.Chain[len(b.Chain)-1]
	if custodyLinks != 1 || link.ProofType != "custody" || len(link.Data) == 0 {
		return nil
	}
	got := ComputeChainHash(hex.EncodeToString(link.PrevHash), string(link.Data), link.Timestamp)
	if len(link.Hash) != 32 || !bytes.Equal(got[:], link.Hash) {
		return nil
	}
	return link
}

// hasCTotalRejectLine reports whether the Rust verifier's stderr carries
// the ERR_C_TOTAL_MISMATCH reject-code line.
//
// Input: stderr, the captured stderr bytes. Output: true only when one
// whole line (trailing CR tolerated) equals cTotalRejectCodeLine.
func hasCTotalRejectLine(stderr []byte) bool {
	return hasStderrLine(stderr, cTotalRejectCodeLine)
}

// hasStderrLine reports whether want is one whole line of stderr (a
// trailing CR is tolerated). Input: stderr bytes and the line. Output:
// true on an exact line match, never on a substring.
func hasStderrLine(stderr []byte, want string) bool {
	for _, line := range strings.Split(string(stderr), "\n") {
		if strings.TrimSuffix(line, "\r") == want {
			return true
		}
	}
	return false
}
