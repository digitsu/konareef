// Copyright 2026 Jerry David Chan, Konareef.ai
// SPDX-License-Identifier: Apache-2.0

// run_outcome_test.go — tests for the run_outcome link reader
// (konareef#41): parsing, the label text, and Verify on a bundle whose
// run_outcome is absent, completed, failed or unreadable.

package verify

import (
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
)

// bundleWithRunOutcome returns buildValidBundle with a run_outcome link
// carrying outcomeData inserted before the custody link. The custody
// link is re-chained, so the bundle still verifies.
//
// Input: outcomeData, the run_outcome link's data. Output: the bundle.
func bundleWithRunOutcome(outcomeData string) *Bundle {
	b := buildValidBundle()
	snapshot := b.Chain[1]
	custody := b.Chain[2]

	outcomeTS := "2026-05-23T14:01:30.000000Z"
	outcomeHash := ComputeChainHash(snapshot.Hash, outcomeData, outcomeTS)
	outcomeHex := hex.EncodeToString(outcomeHash[:])
	outcome := ChainLink{ProofType: "run_outcome", Hash: outcomeHex, PrevHash: &snapshot.Hash,
		Data: outcomeData, Timestamp: outcomeTS}

	custodyHash := ComputeChainHash(outcomeHex, custody.Data, custody.Timestamp)
	custody.Hash = hex.EncodeToString(custodyHash[:])
	custody.PrevHash = &outcomeHex

	b.Chain = []ChainLink{b.Chain[0], snapshot, outcome, custody}
	return b
}

func TestParseRunOutcome(t *testing.T) {
	failed := ParseRunOutcome("RUN_OUTCOME: v1\n" +
		`{"deliverable_states":[],"exit_code":1,"run_status":"failed","stop_reason":"runtime_error"}`)
	if failed.Reason != "" || failed.Status != "failed" || failed.StopReason != "runtime_error" ||
		failed.ExitCode == nil || *failed.ExitCode != 1 {
		t.Fatalf("failed outcome parsed wrong: %+v", failed)
	}
	if failed.Completed() {
		t.Error("a failed run must not be Completed")
	}

	for name, data := range map[string]string{
		"no prefix":     `{"run_status":"completed"}`,
		"bad json":      "RUN_OUTCOME: v1\nnot json",
		"no run_status": "RUN_OUTCOME: v1\n{}",
		"non-int exit":  "RUN_OUTCOME: v1\n" + `{"run_status":"completed","exit_code":"0"}`,
		"empty":         "",
	} {
		o := ParseRunOutcome(data)
		if o.Reason != RunOutcomeUnreadable || o.Completed() {
			t.Errorf("%s: want unreadable and not completed, got %+v", name, o)
		}
	}
}

func TestRunOutcomeLabel(t *testing.T) {
	var absent *RunOutcome
	if absent.Completed() {
		t.Error("nil outcome must not be Completed")
	}
	if got := absent.Label(); !strings.Contains(got, "not recorded") {
		t.Errorf("absent label = %q", got)
	}
	completed := ParseRunOutcome("RUN_OUTCOME: v1\n" + `{"run_status":"completed","exit_code":0}`)
	if got := completed.Label(); got != "completed (exit_code=0)" {
		t.Errorf("completed label = %q", got)
	}
	failed := ParseRunOutcome("RUN_OUTCOME: v1\n" + `{"run_status":"failed","stop_reason":"runtime_error","exit_code":1}`)
	if got := failed.Label(); !strings.Contains(got, "failed (stop_reason=runtime_error, exit_code=1)") ||
		!strings.Contains(got, "NOT a completed run") {
		t.Errorf("failed label = %q", got)
	}
	if got := ParseRunOutcome("junk").Label(); !strings.Contains(got, "NOT a completed run") {
		t.Errorf("unreadable label = %q", got)
	}
}

// TestVerifyRunOutcome covers absent, completed, failed and unreadable
// run_outcome links. The integrity verdict is OK in every case.
func TestVerifyRunOutcome(t *testing.T) {
	cases := []struct {
		name          string
		bundle        *Bundle
		wantRecorded  bool
		wantCompleted bool
		wantStatus    string
	}{
		{"absent", buildValidBundle(), false, false, ""},
		{"completed", bundleWithRunOutcome("RUN_OUTCOME: v1\n" + `{"run_status":"completed","exit_code":0}`), true, true, "completed"},
		{"failed", bundleWithRunOutcome("RUN_OUTCOME: v1\n" + `{"run_status":"failed","stop_reason":"runtime_error","exit_code":1}`), true, false, "failed"},
		{"unreadable", bundleWithRunOutcome("garbage"), true, false, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := Verify(c.bundle)
			if !r.OK {
				t.Fatalf("integrity verdict must stay OK, divergences: %v", r.Divergences)
			}
			if (r.RunOutcome != nil) != c.wantRecorded {
				t.Fatalf("RunOutcome recorded = %v, want %v", r.RunOutcome != nil, c.wantRecorded)
			}
			if r.RunOutcome.Completed() != c.wantCompleted {
				t.Errorf("Completed = %v, want %v", r.RunOutcome.Completed(), c.wantCompleted)
			}
			if c.wantRecorded && r.RunOutcome.Status != c.wantStatus {
				t.Errorf("Status = %q, want %q", r.RunOutcome.Status, c.wantStatus)
			}
			doc := RunOutcomeJSON(r.RunOutcome)
			if doc["recorded"] != c.wantRecorded || doc["completed"] != c.wantCompleted {
				t.Errorf("json doc wrong: %v", doc)
			}
		})
	}
}

func TestRunOutcomeV2(t *testing.T) {
	b := &BundleV2{Disclosure: "C", Chain: []ChainLinkV2{
		{ProofType: "structured_bundle"},
		{ProofType: "run_outcome", Data: []byte("RUN_OUTCOME: v1\n" + `{"run_status":"failed"}`)},
		{ProofType: "custody"},
	}}
	if o := runOutcomeV2(b); o == nil || o.Status != "failed" || o.Completed() {
		t.Errorf("v2 failed outcome wrong: %+v", o)
	}
	typeD := &BundleV2{Disclosure: "D", Chain: []ChainLinkV2{{ProofType: "run_outcome"}, {ProofType: "custody"}}}
	if o := runOutcomeV2(typeD); o == nil || o.Reason != RunOutcomeNotDisclosed || o.FailsClosed() {
		t.Errorf("Type-D outcome must be not disclosed and must not fail closed: %+v", o)
	}
	if o := runOutcomeV2(&BundleV2{Disclosure: "C", Chain: []ChainLinkV2{{ProofType: "custody"}}}); o != nil {
		t.Errorf("absent outcome must be nil, got %+v", o)
	}
}

// TestRunOutcomeNotTrustedWhenBundleFails checks that a bundle that
// failed verification never reports a completed run: a tampered
// run_outcome link, and a structurally broken bundle that has a link.
func TestRunOutcomeNotTrustedWhenBundleFails(t *testing.T) {
	completed := "RUN_OUTCOME: v1\n" + `{"run_status":"completed","exit_code":0}`

	tampered := bundleWithRunOutcome(completed)
	tampered.Chain[2].Data = "RUN_OUTCOME: v1\n" + `{"run_status":"completed","exit_code":0,"x":1}`
	broken := bundleWithRunOutcome(completed)
	broken.Chain[0].ProofType = "custody" // structure check fails early

	for name, b := range map[string]*Bundle{"tampered": tampered, "broken structure": broken} {
		r := Verify(b)
		if r.OK {
			t.Fatalf("%s: bundle must fail verification", name)
		}
		o := TrustRunOutcome(r.RunOutcome, r.OK)
		if o.Completed() || o.Reason != RunOutcomeUntrusted || o.FailsClosed() {
			t.Errorf("%s: want untrusted (exit 1 not 3), got %+v", name, o)
		}
		if got := o.Label(); !strings.Contains(got, "not trusted") || strings.Contains(got, "not recorded") {
			t.Errorf("%s: label = %q", name, got)
		}
		doc := RunOutcomeJSON(o)
		if doc["completed"] != false || doc["trusted"] != false {
			t.Errorf("%s: json = %v", name, doc)
		}
	}
}

// TestRunOutcomeAmbiguous checks that two run_outcome links, or one that
// is not directly before custody, fail closed even when the first says
// completed.
func TestRunOutcomeAmbiguous(t *testing.T) {
	two := &Bundle{Chain: []ChainLink{
		{ProofType: "structured_bundle"},
		{ProofType: "run_outcome", Data: "RUN_OUTCOME: v1\n" + `{"run_status":"completed"}`},
		{ProofType: "run_outcome", Data: "RUN_OUTCOME: v1\n" + `{"run_status":"failed"}`},
		{ProofType: "custody"},
	}}
	misplaced := &Bundle{Chain: []ChainLink{
		{ProofType: "structured_bundle"},
		{ProofType: "run_outcome", Data: "RUN_OUTCOME: v1\n" + `{"run_status":"completed"}`},
		{ProofType: "openbrain_snapshot"},
		{ProofType: "custody"},
	}}
	for name, b := range map[string]*Bundle{"two links": two, "misplaced": misplaced} {
		o := runOutcomeV1(b)
		if o == nil || o.Reason != RunOutcomeAmbiguous || o.Completed() || !o.FailsClosed() {
			t.Errorf("%s: want ambiguous and fail closed, got %+v", name, o)
		}
	}
}

// TestRunOutcomeFailsClosed pins the exit-code-3 rule.
func TestRunOutcomeFailsClosed(t *testing.T) {
	var missing *RunOutcome
	if !missing.FailsClosed() {
		t.Error("missing outcome must fail closed")
	}
	if ParseRunOutcome("RUN_OUTCOME: v1\n" + `{"run_status":"completed"}`).FailsClosed() {
		t.Error("completed must not fail closed")
	}
	for _, data := range []string{"RUN_OUTCOME: v1\n" + `{"run_status":"failed"}`, "junk"} {
		if !ParseRunOutcome(data).FailsClosed() {
			t.Errorf("%q must fail closed", data)
		}
	}
}

// TestRunOutcomeLabelSanitizesBundleStrings checks that an ESC sequence,
// a newline and an over-long value cannot reach the terminal, while the
// JSON field stays the exact string (encoding/json escapes it).
func TestRunOutcomeLabelSanitizesBundleStrings(t *testing.T) {
	hostile := "oops\x1b[2J\x1b]0;pwned\x07\nRun outcome: completed\r" + strings.Repeat("A", 500)
	o := ParseRunOutcome("RUN_OUTCOME: v1\n" + `{"run_status":"failed","stop_reason":` + jsonString(hostile) + `}`)
	if o.StopReason != hostile {
		t.Fatalf("parse must keep the raw string")
	}
	label := o.Label()
	for _, r := range label {
		if r < 0x20 || r == 0x7f {
			t.Fatalf("label holds control rune %U: %q", r, label)
		}
	}
	if strings.Contains(label, "\n") || len([]rune(label)) > 200 {
		t.Errorf("label not bounded or has a newline: %q", label)
	}
	statusHostile := ParseRunOutcome("RUN_OUTCOME: v1\n" + `{"run_status":"\u001b[31mred"}`)
	if strings.ContainsRune(statusHostile.Label(), 0x1b) {
		t.Errorf("run_status escape reached the label: %q", statusHostile.Label())
	}
	raw, err := json.Marshal(RunOutcomeJSON(o))
	if err != nil || strings.ContainsAny(string(raw), "\x1b\n") {
		t.Errorf("JSON output must escape control characters: %v %q", err, raw)
	}
}

func jsonString(s string) string {
	raw, _ := json.Marshal(s)
	return string(raw)
}
