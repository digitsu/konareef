// Copyright 2026 Jerry David Chan, Konareef.ai
// SPDX-License-Identifier: Apache-2.0

// custody_lanes_test.go — tests for checkCustodyLaneBinding (reef-core#76
// decision A8): a Type-C custody record must state the proof's h_p and
// h_r as its TASK_HASH and RESULT_HASH.
package verify

import (
	"encoding/hex"
	"errors"
	"strings"
	"testing"
)

// rewriteCustody replaces the custody tail's data with edit(data) and
// recomputes its hash, so only the lane binding can object.
func rewriteCustody(edit func(string) string) func(b *BundleV2) {
	return func(b *BundleV2) {
		tail := &b.Chain[len(b.Chain)-1]
		tail.Data = []byte(edit(string(tail.Data)))
		h := ComputeChainHash(hex.EncodeToString(tail.PrevHash), string(tail.Data), tail.Timestamp)
		tail.Hash = h[:]
	}
}

// requireLaneMismatch asserts the bundle failed with
// ErrCustodyLaneMismatch and CommitmentsValid=false.
func requireLaneMismatch(t *testing.T, r *ResultV2, want string) {
	t.Helper()
	if r.OK || r.V2Verdict.CommitmentsValid {
		t.Fatalf("OK=%v CommitmentsValid=%v", r.OK, r.V2Verdict.CommitmentsValid)
	}
	for _, d := range r.Divergences {
		if errors.Is(d.Err, ErrCustodyLaneMismatch) && strings.Contains(d.Msg, want) {
			return
		}
	}
	t.Fatalf("no ErrCustodyLaneMismatch naming %q: %v", want, divergenceStrings(r))
}

func TestCustodyLanes_GenuineRecordPasses(t *testing.T) {
	r := verifyTypeCWithLinkMutation(t, nil)
	if !r.OK || !r.V2Verdict.CommitmentsValid {
		t.Fatalf("genuine custody lanes refused: %v", divergenceStrings(r))
	}
}

func TestCustodyLanes_TaskHashDiffers(t *testing.T) {
	r := verifyTypeCWithLinkMutation(t, rewriteCustody(func(d string) string {
		i := strings.Index(d, "TASK_HASH: sha256:") + len("TASK_HASH: sha256:")
		return d[:i] + strings.Repeat("0", 64) + d[i+64:]
	}))
	requireLaneMismatch(t, r, "TASK_HASH != h_p")
}

func TestCustodyLanes_ResultHashDiffers(t *testing.T) {
	r := verifyTypeCWithLinkMutation(t, rewriteCustody(func(d string) string {
		i := strings.Index(d, "RESULT_HASH: sha256:") + len("RESULT_HASH: sha256:")
		return d[:i] + strings.Repeat("f", 64) + d[i+64:]
	}))
	requireLaneMismatch(t, r, "RESULT_HASH != h_r")
}

func TestCustodyLanes_MissingOrRepeatedLine(t *testing.T) {
	missing := verifyTypeCWithLinkMutation(t, rewriteCustody(func(d string) string {
		var keep []string
		for _, line := range strings.Split(d, "\n") {
			if !strings.HasPrefix(line, "TASK_HASH:") {
				keep = append(keep, line)
			}
		}
		return strings.Join(keep, "\n")
	}))
	requireLaneMismatch(t, missing, "0 TASK_HASH lines")

	repeated := verifyTypeCWithLinkMutation(t, rewriteCustody(func(d string) string {
		for _, line := range strings.Split(d, "\n") {
			if strings.HasPrefix(line, "RESULT_HASH:") {
				return d + "\n" + line
			}
		}
		return d
	}))
	requireLaneMismatch(t, repeated, "2 RESULT_HASH lines")

	upper := verifyTypeCWithLinkMutation(t, rewriteCustody(func(d string) string {
		i := strings.Index(d, "TASK_HASH: sha256:") + len("TASK_HASH: sha256:")
		return d[:i] + strings.ToUpper(d[i:i+64]) + d[i+64:]
	}))
	requireLaneMismatch(t, upper, "not canonical")
}

func TestCustodyLaneHash(t *testing.T) {
	h := strings.Repeat("ab", 32)
	got, err := CustodyLaneHash("CUSTODY_PROOF: v3\nTASK_HASH: sha256:"+h+"\n", "TASK_HASH")
	if err != nil || hex.EncodeToString(got) != h {
		t.Fatalf("%x %v", got, err)
	}
	if _, err := CustodyLaneHash("TASK_HASH: sha256:"+h+" \n", "TASK_HASH"); err == nil {
		t.Fatal("trailing space accepted")
	}
}
