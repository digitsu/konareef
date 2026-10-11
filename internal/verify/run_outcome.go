// Copyright 2026 Jerry David Chan, Konareef.ai
// SPDX-License-Identifier: Apache-2.0

// run_outcome.go — reads the run_outcome link of a bundle chain
// (konareef#41, reef-core#98).
//
// Since reef-core#98 a failed run that settled at least one LLM call
// also gets a custody proof. The chain then reads
// `... → run_outcome (failed) → custody`. A custody proof alone is not
// a completed run, so verify must show what the run_outcome link says.
//
// The run_outcome link carries `RUN_OUTCOME: v1\n` and a JSON body with
// run_status, stop_reason and exit_code. This file only reads it. The
// outcome never changes the integrity verdict (Result.OK): a failed-run
// custody proof is a valid proof of the money that was settled. The
// outcome is trusted only when the bundle verified (TrustRunOutcome).
// `konareef verify` maps it to exit code 3 (FailsClosed), apart from
// code 1 for an integrity failure.

package verify

import (
	"encoding/json"
	"fmt"
	"strings"
	"unicode"
	"unicode/utf8"
)

// runOutcomePrefix is the first line of a run_outcome link's data.
const runOutcomePrefix = "RUN_OUTCOME: v1\n"

// RunOutcomeProofType is the proof_type of the run outcome link.
const RunOutcomeProofType = "run_outcome"

// Reasons a RunOutcome is not a readable record (RunOutcome.Reason).
const (
	// RunOutcomeUnreadable: the link data is not a `RUN_OUTCOME: v1`
	// record with a string run_status.
	RunOutcomeUnreadable = "unreadable"
	// RunOutcomeAmbiguous: the chain has more than one run_outcome link,
	// or the one link is not immediately before custody.
	RunOutcomeAmbiguous = "ambiguous"
	// RunOutcomeNotDisclosed: the bundle type carries no link data (v2
	// Type-D), so the outcome cannot be read from it.
	RunOutcomeNotDisclosed = "not_disclosed"
	// RunOutcomeUntrusted: the bundle failed verification, so nothing in
	// its chain, the run_outcome link included, can be trusted.
	RunOutcomeUntrusted = "untrusted"
)

// maxDisplayRunes bounds a bundle-supplied string in terminal output.
const maxDisplayRunes = 64

// RunOutcome is the run outcome of a bundle chain. A nil *RunOutcome
// means the chain has no run_outcome link (and the bundle verified).
//
// Reason is empty for a readable record. Otherwise it is one of the
// RunOutcome* reasons above, and Status, StopReason and ExitCode are
// empty. StopReason and ExitCode are also empty/nil when a readable
// record leaves them out.
type RunOutcome struct {
	Reason     string `json:"reason,omitempty"`
	Status     string `json:"run_status,omitempty"`
	StopReason string `json:"stop_reason,omitempty"`
	ExitCode   *int   `json:"exit_code,omitempty"`
}

// ParseRunOutcome parses the data of a run_outcome link.
//
// Input: data, the link's data field. Output: the outcome; never nil.
// Data that is not a `RUN_OUTCOME: v1` record with a string run_status
// gives an outcome with Reason RunOutcomeUnreadable (fail closed: it is
// never read as completed).
func ParseRunOutcome(data string) *RunOutcome {
	body, ok := strings.CutPrefix(data, runOutcomePrefix)
	if !ok {
		return &RunOutcome{Reason: RunOutcomeUnreadable}
	}
	var record struct {
		RunStatus  *string `json:"run_status"`
		StopReason *string `json:"stop_reason"`
		ExitCode   *int    `json:"exit_code"`
	}
	if err := json.Unmarshal([]byte(body), &record); err != nil || record.RunStatus == nil {
		return &RunOutcome{Reason: RunOutcomeUnreadable}
	}
	out := &RunOutcome{Status: *record.RunStatus, ExitCode: record.ExitCode}
	if record.StopReason != nil {
		out.StopReason = *record.StopReason
	}
	return out
}

// Completed reports whether the run completed: the outcome is readable
// and its run_status is "completed". Nil, unreadable, ambiguous,
// undisclosed, untrusted and every other status are not a completed run.
func (o *RunOutcome) Completed() bool {
	return o != nil && o.Reason == "" && o.Status == "completed"
}

// FailsClosed reports whether `konareef verify` exits with code 3 for a
// bundle that verified: the run is failed, its outcome is missing,
// ambiguous or unreadable. It is false for a completed run, for a
// bundle type that cannot carry the outcome, and for an untrusted
// bundle (that one already exits 1).
func (o *RunOutcome) FailsClosed() bool {
	if o == nil {
		return true
	}
	if o.Reason == RunOutcomeNotDisclosed || o.Reason == RunOutcomeUntrusted {
		return false
	}
	return !o.Completed()
}

// sanitizeDisplay makes a bundle-supplied string safe to print to a
// terminal: every control or non-printable rune (ESC, newline, DEL, C1
// controls, bidi and format characters) becomes "?", and the result is
// cut to maxDisplayRunes runes.
//
// Input: s, any string. Output: the safe string.
func sanitizeDisplay(s string) string {
	var out []rune
	for _, r := range s {
		if len(out) == maxDisplayRunes {
			out = append(out, '…')
			break
		}
		if r == utf8.RuneError || !unicode.IsPrint(r) {
			r = '?'
		}
		out = append(out, r)
	}
	return string(out)
}

// Label returns the display text for the outcome. Bundle-supplied
// strings are sanitized. A run that did not complete says so in words,
// with stop_reason and exit_code when the record has them.
//
// Input: the receiver, which may be nil. Output: one line of text.
func (o *RunOutcome) Label() string {
	switch {
	case o == nil:
		return "not recorded (no run_outcome link in the chain)"
	case o.Reason == RunOutcomeUntrusted:
		return "not trusted (bundle failed verification)"
	case o.Reason == RunOutcomeNotDisclosed:
		return "outcome not disclosed in this bundle type"
	case o.Reason == RunOutcomeAmbiguous:
		return "ambiguous run_outcome links - NOT a completed run"
	case o.Reason != "":
		return "unreadable run_outcome link - NOT a completed run"
	}
	var details []string
	if o.StopReason != "" {
		details = append(details, "stop_reason="+sanitizeDisplay(o.StopReason))
	}
	if o.ExitCode != nil {
		details = append(details, fmt.Sprintf("exit_code=%d", *o.ExitCode))
	}
	suffix := ""
	if len(details) > 0 {
		suffix = " (" + strings.Join(details, ", ") + ")"
	}
	if o.Completed() {
		return "completed" + suffix
	}
	return sanitizeDisplay(o.Status) + suffix + " - NOT a completed run"
}

// TrustRunOutcome applies the verification verdict to an outcome: when
// the bundle did not verify, the outcome is untrusted, whatever the
// chain says (a failed bundle may hold a tampered link, or no readable
// one at all).
//
// Input: o, the outcome found in the chain (may be nil); verified, the
// integrity verdict. Output: o when verified, else an untrusted outcome.
func TrustRunOutcome(o *RunOutcome, verified bool) *RunOutcome {
	if verified {
		return o
	}
	return &RunOutcome{Reason: RunOutcomeUntrusted}
}

// pickRunOutcome reads the run outcome from the proof types and link
// data of a chain, oldest first. Fail closed: more than one run_outcome
// link, or one that is not immediately before the last (custody) link,
// is ambiguous.
//
// Input: types and data, parallel slices for the chain's links.
// Output: the outcome, or nil when there is no run_outcome link.
func pickRunOutcome(types []string, data func(i int) string) *RunOutcome {
	found := -1
	for i, proofType := range types {
		if proofType != RunOutcomeProofType {
			continue
		}
		if found >= 0 {
			return &RunOutcome{Reason: RunOutcomeAmbiguous}
		}
		found = i
	}
	switch {
	case found < 0:
		return nil
	case found != len(types)-2:
		return &RunOutcome{Reason: RunOutcomeAmbiguous}
	}
	return ParseRunOutcome(data(found))
}

// runOutcomeV1 reads the run outcome of a v1 bundle chain.
//
// Input: b, the bundle. Output: the outcome, or nil when the chain has
// no run_outcome link.
func runOutcomeV1(b *Bundle) *RunOutcome {
	types := make([]string, len(b.Chain))
	for i := range b.Chain {
		types[i] = b.Chain[i].ProofType
	}
	return pickRunOutcome(types, func(i int) string { return b.Chain[i].Data })
}

// runOutcomeV2 reads the run outcome of a v2 bundle chain. A Type-D
// bundle carries no link data, so its outcome is not disclosed.
//
// Input: b, the bundle. Output: the outcome, or nil when a Type-C chain
// has no run_outcome link.
func runOutcomeV2(b *BundleV2) *RunOutcome {
	if b.Disclosure == "D" {
		return &RunOutcome{Reason: RunOutcomeNotDisclosed}
	}
	types := make([]string, len(b.Chain))
	for i := range b.Chain {
		types[i] = b.Chain[i].ProofType
	}
	return pickRunOutcome(types, func(i int) string { return string(b.Chain[i].Data) })
}

// RunOutcomeJSON renders the outcome for `konareef verify --json`.
//
// Input: o, which may be nil. Output: a map with "recorded" (a
// run_outcome link was read), "trusted" (the bundle verified),
// "completed", "label" (sanitized text) and, for a readable record,
// "run_status", "stop_reason" and "exit_code" as the bundle states them
// (JSON-encoded strings). "reason" names why a record is unreadable,
// ambiguous, not disclosed or untrusted.
func RunOutcomeJSON(o *RunOutcome) map[string]any {
	untrusted := o != nil && o.Reason == RunOutcomeUntrusted
	doc := map[string]any{
		"recorded":  o != nil && o.Reason != RunOutcomeUntrusted && o.Reason != RunOutcomeNotDisclosed,
		"trusted":   !untrusted,
		"completed": o.Completed(),
		"label":     o.Label(),
	}
	if o != nil && o.Reason != "" {
		doc["reason"] = o.Reason
	}
	if o != nil && o.Reason == "" {
		doc["run_status"] = o.Status
		if o.StopReason != "" {
			doc["stop_reason"] = o.StopReason
		}
		if o.ExitCode != nil {
			doc["exit_code"] = *o.ExitCode
		}
	}
	return doc
}
