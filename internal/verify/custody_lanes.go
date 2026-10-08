// Copyright 2026 Jerry David Chan, Konareef.ai
// SPDX-License-Identifier: Apache-2.0

// custody_lanes.go — the Type-C custody-to-proof check (reef-core#76
// decision A8).
//
// reef-core writes the custody record lines
//
//	TASK_HASH: sha256:<hex of SHA-256(P)>
//	RESULT_HASH: sha256:<hex of SHA-256(R)>
//
// for the same P and R it discloses to the prover, so in a genuine
// Type-C bundle they equal the proof's h_p and h_r lanes. Checking that
// ties the custody chain to this proof: a genuine chain from one run
// cannot be attached to the proof of another run. It is useful with or
// without a chain-head anchor.
package verify

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"regexp"
	"strings"
)

// custodyHashLine matches one "KEY: sha256:<64 lowercase hex>" line.
var custodyHashLine = regexp.MustCompile(`^([A-Z_]+): sha256:([0-9a-f]{64})$`)

// CustodyLaneHash reads the digest of the single line KEY: sha256:<hex>
// from a custody blob.
// Inputs: data, the custody blob; key, for example "TASK_HASH".
// Output: the 32 bytes, or an error when the line is absent, repeated or
// not canonical lowercase hex.
func CustodyLaneHash(data, key string) ([]byte, error) {
	var found [][]byte
	for _, line := range strings.Split(data, "\n") {
		if !strings.HasPrefix(line, key+":") {
			continue
		}
		m := custodyHashLine.FindStringSubmatch(line)
		if m == nil || m[1] != key {
			return nil, fmt.Errorf("custody %s line is not canonical", key)
		}
		b, _ := hex.DecodeString(m[2])
		found = append(found, b)
	}
	if len(found) != 1 {
		return nil, fmt.Errorf("custody record has %d %s lines, want 1", len(found), key)
	}
	return found[0], nil
}

// checkCustodyLaneBinding compares the bound custody record's TASK_HASH
// and RESULT_HASH with the h_p and h_r lanes. It runs for Type C only.
// Without a bound custody link (see boundCustodyLinkV2) there is nothing
// to compare and it adds nothing; the link-hash and custody checks report
// that case.
//
// Inputs: b, the decoded bundle; v; r.
// Output: true when the lanes agree or no bound link exists. Otherwise
// false, with an ErrCustodyLaneMismatch divergence per fault and
// v.CommitmentsValid=false.
func checkCustodyLaneBinding(b *BundleV2, v *Verdict, r *ResultV2) bool {
	link := boundCustodyLinkV2(b)
	if link == nil {
		return true
	}
	ok := true
	for _, pair := range []struct{ key, lane string }{{"TASK_HASH", "h_p"}, {"RESULT_HASH", "h_r"}} {
		stated, err := CustodyLaneHash(string(link.Data), pair.key)
		if err != nil {
			r.diverge(ErrCustodyLaneMismatch, err.Error())
			ok = false
			continue
		}
		lane, err := extractPublicInputStrict(b.SpartanCompressResult, pair.lane, 32)
		if err != nil {
			// checkTypeCWitnessHashes already reports an unreadable lane.
			ok = false
			continue
		}
		if !bytes.Equal(stated, lane) {
			r.diverge(ErrCustodyLaneMismatch, fmt.Sprintf("custody %s != %s (public input)", pair.key, pair.lane))
			ok = false
		}
	}
	if !ok {
		v.CommitmentsValid = false
	}
	return ok
}
