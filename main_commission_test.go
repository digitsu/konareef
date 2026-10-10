// Copyright 2026 Jerry David Chan, Konareef.ai
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"strings"
	"testing"

	"github.com/digitsu/konareef/internal/commission"
	"github.com/digitsu/konareef/internal/envelope"
)

func TestFormatContainmentReport_Contained(t *testing.T) {
	res := envelope.Result{OK: true}
	out := formatContainmentReport(res)
	if !strings.Contains(out, "contained") {
		t.Fatalf("got %q", out)
	}
}

func TestFormatContainmentReport_NamesEveryFailure(t *testing.T) {
	res := envelope.Result{Failures: []envelope.Failure{
		{Dimension: "tools", Detail: "manifest declares [web_fetch], not permitted by commission"},
		{Dimension: "spend", Detail: "manifest cap 9000 sats exceeds commission cap 100 sats"},
	}}
	out := formatContainmentReport(res)
	for _, want := range []string{"tools", "web_fetch", "spend", "9000"} {
		if !strings.Contains(out, want) {
			t.Errorf("report missing %q:\n%s", want, out)
		}
	}
}

// The memory-scope dimension is not derived from a manifest, so the report
// must say it is unchecked rather than imply it passed.
func TestFormatContainmentReport_SaysLabelsAreUnchecked(t *testing.T) {
	out := formatContainmentReport(envelope.Result{OK: true})
	if !strings.Contains(out, "memory scope: not checked") {
		t.Fatalf("report must disclose that memory scope is unchecked:\n%s", out)
	}
}

// TestProposalRoundTripsThroughTOML checks that a fully-stated proposal
// survives a marshalProposal -> unmarshalProposal round trip.
//
// envelope.Equal is FLAG-BLIND: it compares Models/Tools/Labels/CMax only
// and does not look at ModelsSet/ToolsSet/LabelsSet/CMaxSet at all (see
// internal/envelope/meet.go). A bug that round-trips the four flag bits
// wrong — e.g. losing CMaxSet, or collapsing "stated but empty" into
// "omitted" — is therefore INVISIBLE to an Equal-only assertion. This test
// adds explicit flag checks after the Equal check for exactly that reason;
// see TestProposalRoundTripsThroughTOML_StatedEmptySurvives and its
// siblings below for the cases Equal structurally cannot catch.
//
// CMaxSet: true is added here (the brief's literal test omitted it, along
// with the CMaxSet field itself predating the brief). Without it this
// proposal states CMax: 4200 while flagging the dimension unstated, which
// is a nonsensical input on the write side, not something worth locking in.
func TestProposalRoundTripsThroughTOML(t *testing.T) {
	p := commission.Proposal{
		Envelope: envelope.Envelope{
			Models: []string{"anthropic/claude-sonnet-5"}, ModelsSet: true,
			Tools: []string{"fs_read"}, ToolsSet: true,
			Labels: []string{"public"}, LabelsSet: true,
			CMax: 4200, CMaxSet: true,
		},
		Binding: commission.Binding{PodRef: "dave/mybot@0.1.0", HManifest: [32]byte{7, 7, 7}},
		Prose:   "Summarise the weekly reports.",
	}
	raw, err := marshalProposal(p)
	if err != nil {
		t.Fatal(err)
	}
	got, err := unmarshalProposal(raw)
	if err != nil {
		t.Fatal(err)
	}
	if !got.Envelope.Equal(p.Envelope) || got.Prose != p.Prose {
		t.Fatalf("proposal did not survive TOML round trip:\n got %+v\nwant %+v", got, p)
	}
	if got.Envelope.ModelsSet != true || got.Envelope.ToolsSet != true ||
		got.Envelope.LabelsSet != true || got.Envelope.CMaxSet != true {
		t.Fatalf("presence flags did not survive TOML round trip: got %+v", got.Envelope)
	}
	if got.Binding != p.Binding {
		t.Fatalf("binding did not survive TOML round trip: got %+v want %+v", got.Binding, p.Binding)
	}
}

// TestProposalRoundTripsThroughTOML_HManifestSurvives isolates the
// Binding.HManifest wiring: proposalFile.HManifest was declared but never
// populated or read by either marshalProposal or unmarshalProposal, so a
// proposal's pinned manifest hash was silently dropped on every save
// (it always came back the zero [32]byte, regardless of what was signed
// in). This matters because a later task pins a manifest hash through
// exactly this file's draft -> sign path.
func TestProposalRoundTripsThroughTOML_HManifestSurvives(t *testing.T) {
	var want [32]byte
	for i := range want {
		want[i] = byte(i + 1)
	}
	p := commission.Proposal{
		Binding: commission.Binding{PodRef: "dave/mybot@0.1.0", HManifest: want},
	}
	raw, err := marshalProposal(p)
	if err != nil {
		t.Fatal(err)
	}
	got, err := unmarshalProposal(raw)
	if err != nil {
		t.Fatal(err)
	}
	if got.Binding.HManifest != want {
		t.Fatalf("HManifest did not survive TOML round trip:\nTOML:\n%s\ngot %x\nwant %x", raw, got.Binding.HManifest, want)
	}
}

// TestUnmarshalProposal_AbsentHManifestIsZeroValue checks that a hand-edited
// or freshly-created file with no h_manifest key at all is accepted (a
// draft may not have a pod pinned yet) and decodes to the zero [32]byte,
// rather than being rejected as malformed. marshalProposal's own output
// always includes h_manifest (see its doc comment), so this exercises a
// file this package did not itself write.
func TestUnmarshalProposal_AbsentHManifestIsZeroValue(t *testing.T) {
	raw := []byte("pod_ref = \"dave/mybot@0.1.0\"\n")
	got, err := unmarshalProposal(raw)
	if err != nil {
		t.Fatalf("an absent h_manifest should be accepted, got error: %v", err)
	}
	if got.Binding.HManifest != ([32]byte{}) {
		t.Fatalf("absent h_manifest should decode to the zero value, got %x", got.Binding.HManifest)
	}
}

// TestUnmarshalProposal_RejectsMalformedHManifest checks the other side of
// that distinction: unlike an absent h_manifest, a PRESENT h_manifest that
// isn't exactly 64 hex characters must be rejected outright, not silently
// zeroed or truncated. Silently zeroing it would be indistinguishable from
// "no pin at all" to a caller -- exactly the bug this validation exists to
// prevent (see unmarshalProposal's doc comment).
func TestUnmarshalProposal_RejectsMalformedHManifest(t *testing.T) {
	cases := []struct {
		name      string
		hManifest string
	}{
		{"too_short", "0707"},
		{"too_long", strings.Repeat("0", 66)},
		{"non_hex", "zz" + strings.Repeat("0", 62)},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			raw := []byte("pod_ref = \"dave/mybot@0.1.0\"\nh_manifest = \"" + c.hManifest + "\"\n")
			if _, err := unmarshalProposal(raw); err == nil {
				t.Fatalf("want error for malformed h_manifest %q", c.hManifest)
			}
		})
	}
}

// TestProposalRoundTripsThroughTOML_PresenceByDimension checks, for each of
// the four presence-flagged dimensions independently, that BOTH directions
// of the stated/omitted distinction survive a marshalProposal ->
// unmarshalProposal round trip:
//
//   - "stated at its minimal value" (an empty set, or a zero spend cap)
//     must come back stated (fail-CLOSED bug if it doesn't: a buyer's
//     deliberate restriction is silently discarded).
//   - "never mentioned" must come back unstated (fail-OPEN bug if it
//     doesn't: an omitted dimension — which envelope.ValidateAsCommission
//     must refuse — is laundered into a validly-stated one, e.g. an unset
//     spend cap becoming a valid zero-spend commission).
//
// These two bugs fail in OPPOSITE directions, so a single combined
// assertion (or testing only one direction) can hide one of them. Each
// dimension gets its own pair of subtests for exactly that reason; see the
// task-8-report.md fix-round-2 section for the before/after proof this
// discriminates against the pre-fix code.
func TestProposalRoundTripsThroughTOML_PresenceByDimension(t *testing.T) {
	type dimension struct {
		name   string
		stated func(envelope.Envelope) envelope.Envelope // returns e with this dimension stated at its minimal value
		isSet  func(envelope.Envelope) bool
	}
	dims := []dimension{
		{
			name:   "models",
			stated: func(e envelope.Envelope) envelope.Envelope { e.Models, e.ModelsSet = []string{}, true; return e },
			isSet:  func(e envelope.Envelope) bool { return e.ModelsSet },
		},
		{
			name:   "tools",
			stated: func(e envelope.Envelope) envelope.Envelope { e.Tools, e.ToolsSet = []string{}, true; return e },
			isSet:  func(e envelope.Envelope) bool { return e.ToolsSet },
		},
		{
			name:   "labels",
			stated: func(e envelope.Envelope) envelope.Envelope { e.Labels, e.LabelsSet = []string{}, true; return e },
			isSet:  func(e envelope.Envelope) bool { return e.LabelsSet },
		},
		{
			name:   "c_max_sats",
			stated: func(e envelope.Envelope) envelope.Envelope { e.CMax, e.CMaxSet = 0, true; return e },
			isSet:  func(e envelope.Envelope) bool { return e.CMaxSet },
		},
	}

	roundTrip := func(t *testing.T, e envelope.Envelope) envelope.Envelope {
		t.Helper()
		p := commission.Proposal{Envelope: e, Binding: commission.Binding{PodRef: "dave/mybot@0.1.0"}}
		raw, err := marshalProposal(p)
		if err != nil {
			t.Fatal(err)
		}
		got, err := unmarshalProposal(raw)
		if err != nil {
			t.Fatalf("%v\nTOML:\n%s", err, raw)
		}
		return got.Envelope
	}

	for _, d := range dims {
		t.Run(d.name+"/stated_minimal_stays_stated", func(t *testing.T) {
			got := roundTrip(t, d.stated(envelope.Envelope{}))
			if !d.isSet(got) {
				t.Fatalf("dimension %q stated at its minimal value came back omitted (fail-closed): got %+v", d.name, got)
			}
		})
		t.Run(d.name+"/omitted_stays_omitted", func(t *testing.T) {
			got := roundTrip(t, envelope.Envelope{})
			if d.isSet(got) {
				t.Fatalf("dimension %q, never stated, came back stated (fail-open): got %+v", d.name, got)
			}
		})
	}
}

// TestProposalRoundTripsThroughTOML_StatedEmptySurvives locks in the fix
// for a real defect: marshalProposal used to encode Models/Tools/Labels as
// plain (non-pointer) TOML fields. BurntSushi/toml has no way to tell "the
// field holds an empty slice" from "the field was never touched" for a
// plain field, so a dimension stated but deliberately empty — e.g.
// Tools: []string{}, ToolsSet: true, meaning "may call no tools" — wrote
// NO `tools` key at all, identically to a dimension that was never
// mentioned. unmarshalProposal then read both cases back as omitted
// (ToolsSet == false), silently discarding the buyer's restriction.
//
// This test is the discriminator: it FAILS against the old marshalProposal
// (the *Set flags come back false) and PASSES once marshalProposal emits
// an explicit `dimension = []` / `c_max_sats = 0` key for anything stated,
// using pointer fields the way internal/commission/rar's detail type does.
// See the task-8-report.md fix-round section for both runs.
func TestProposalRoundTripsThroughTOML_StatedEmptySurvives(t *testing.T) {
	p := commission.Proposal{
		Envelope: envelope.Envelope{
			Models: []string{}, ModelsSet: true,
			Tools: []string{}, ToolsSet: true,
			Labels: []string{}, LabelsSet: true,
			CMax: 0, CMaxSet: true,
		},
		Binding: commission.Binding{PodRef: "dave/mybot@0.1.0"},
	}
	raw, err := marshalProposal(p)
	if err != nil {
		t.Fatal(err)
	}
	got, err := unmarshalProposal(raw)
	if err != nil {
		t.Fatal(err)
	}
	if !got.Envelope.ModelsSet {
		t.Errorf("stated-but-empty models came back omitted (ModelsSet=false)\nTOML:\n%s", raw)
	}
	if !got.Envelope.ToolsSet {
		t.Errorf("stated-but-empty tools came back omitted (ToolsSet=false)\nTOML:\n%s", raw)
	}
	if !got.Envelope.LabelsSet {
		t.Errorf("stated-but-empty labels came back omitted (LabelsSet=false)\nTOML:\n%s", raw)
	}
	if !got.Envelope.CMaxSet {
		t.Errorf("stated zero spend came back omitted (CMaxSet=false)\nTOML:\n%s", raw)
	}
	if len(got.Envelope.Models) != 0 || len(got.Envelope.Tools) != 0 || len(got.Envelope.Labels) != 0 {
		t.Errorf("stated-but-empty dimensions should stay empty, got %+v", got.Envelope)
	}
}

// TestProposalRoundTripsThroughTOML_OmittedStaysOmitted is the mirror of
// the test above: a proposal that never states a dimension must come back
// with that dimension's presence flag false, not laundered into "stated".
func TestProposalRoundTripsThroughTOML_OmittedStaysOmitted(t *testing.T) {
	p := commission.Proposal{
		Envelope: envelope.Envelope{},
		Binding:  commission.Binding{PodRef: "dave/mybot@0.1.0"},
	}
	raw, err := marshalProposal(p)
	if err != nil {
		t.Fatal(err)
	}
	got, err := unmarshalProposal(raw)
	if err != nil {
		t.Fatal(err)
	}
	if got.Envelope.ModelsSet || got.Envelope.ToolsSet || got.Envelope.LabelsSet || got.Envelope.CMaxSet {
		t.Fatalf("an omitted dimension came back stated:\nTOML:\n%s\ngot %+v", raw, got.Envelope)
	}
}

// TestProposalRoundTripsThroughTOML_StatedZeroSpendSurvives isolates the
// zero-spend case specifically, because it is the over-correction trap
// that bit the internal/commission/rar fix: a naive fix might drop a
// pointer field under `omitempty`-like reasoning when the pointee is the
// zero value. proposalFile's CMaxSats field carries no such tag; presence
// is decided solely by whether the pointer itself is nil.
func TestProposalRoundTripsThroughTOML_StatedZeroSpendSurvives(t *testing.T) {
	p := commission.Proposal{
		Envelope: envelope.Envelope{CMax: 0, CMaxSet: true},
		Binding:  commission.Binding{PodRef: "dave/mybot@0.1.0"},
	}
	raw, err := marshalProposal(p)
	if err != nil {
		t.Fatal(err)
	}
	got, err := unmarshalProposal(raw)
	if err != nil {
		t.Fatal(err)
	}
	if !got.Envelope.CMaxSet {
		t.Fatalf("stated zero spend came back unstated:\nTOML:\n%s", raw)
	}
	if got.Envelope.CMax != 0 {
		t.Fatalf("stated zero spend came back as %d", got.Envelope.CMax)
	}
}

// TestAnnotateDraftLabels_InsertsAboveTheKeyAndStillParses covers the draft
// annotation in-process, so the CLI test does not have to carry the whole
// burden. The comment must land immediately above the key it explains, and
// must not change what unmarshalProposal reads back — a TOML comment is
// ignored by the decoder, but only if it is placed as one.
func TestAnnotateDraftLabels_InsertsAboveTheKeyAndStillParses(t *testing.T) {
	p := commission.Proposal{
		Envelope: envelope.Envelope{
			Models: []string{"claude-sonnet-5"}, ModelsSet: true,
			Tools: []string{"fs_read"}, ToolsSet: true,
			Labels: []string{}, LabelsSet: true,
			CMax: 4200, CMaxSet: true,
		},
		Binding: commission.Binding{PodRef: "dave/mybot@0.1.0", HManifest: [32]byte{9}},
	}
	raw, err := marshalProposal(p)
	if err != nil {
		t.Fatal(err)
	}
	annotated := string(annotateDraftLabels(raw))

	lines := strings.Split(annotated, "\n")
	keyLine := -1
	for i, line := range lines {
		if strings.HasPrefix(strings.TrimSpace(line), "labels =") {
			keyLine = i
			break
		}
	}
	if keyLine < 1 {
		t.Fatalf("expected a labels key with at least one line above it:\n%s", annotated)
	}
	if !strings.HasPrefix(strings.TrimSpace(lines[keyLine-1]), "#") {
		t.Fatalf("the line above the labels key must be the comment:\n%s", annotated)
	}

	got, err := unmarshalProposal([]byte(annotated))
	if err != nil {
		t.Fatalf("annotated draft must still parse: %v\n%s", err, annotated)
	}
	if !got.Envelope.LabelsSet || len(got.Envelope.Labels) != 0 {
		t.Fatalf("annotation changed what the file states: got %+v", got.Envelope)
	}
	if err := got.Envelope.ValidateAsCommission(); err != nil {
		t.Fatalf("an annotated draft must be signable, got %v", err)
	}
}

// The annotation must be inert on input it does not recognise, and must not
// attach itself to a different key that merely starts with the same letters.
func TestAnnotateDraftLabels_LeavesUnrelatedInputAlone(t *testing.T) {
	for _, tc := range []struct {
		name string
		in   string
	}{
		{"no labels key", "pod_ref = \"dave/mybot@0.1.0\"\ntools = []\n"},
		{"a different key with the same prefix", "labels_denied = [\"secret\"]\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := string(annotateDraftLabels([]byte(tc.in))); got != tc.in {
				t.Fatalf("input was modified:\n got:\n%s\nwant:\n%s", got, tc.in)
			}
		})
	}
}
