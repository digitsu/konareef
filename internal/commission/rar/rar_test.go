// Copyright 2026 Jerry David Chan, Konareef.ai
// SPDX-License-Identifier: Apache-2.0

package rar

import (
	"strings"
	"testing"

	"github.com/digitsu/konareef/internal/commission"
	"github.com/digitsu/konareef/internal/envelope"
)

func TestRoundTrip(t *testing.T) {
	e := envelope.Envelope{
		Models: []string{"anthropic/claude-sonnet-5"}, ModelsSet: true,
		Tools: []string{"fs_read", "web_fetch"}, ToolsSet: true,
		Labels: []string{"public"}, LabelsSet: true,
		CMax: 4200, CMaxSet: true,
	}
	b := commission.Binding{PodRef: "dave/mybot@0.1.0", HManifest: [32]byte{7, 7, 7}}

	raw, err := Render(e, b)
	if err != nil {
		t.Fatal(err)
	}
	got, gotB, err := Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	// envelope.Equal ignores the presence flags entirely (it compares only
	// the sets and CMax), so on its own it cannot catch a bug where a flag
	// comes back wrong -- e.g. an omitted dimension laundered into a
	// stated one. Assert the flags explicitly alongside it. See
	// TestParse_CannotLaunderOmittedDimension and
	// TestRoundTrip_PresenceFlags for the cases Equal alone would miss.
	if !got.Equal(e) {
		t.Fatalf("envelope did not survive the round trip:\n got %+v\nwant %+v", got, e)
	}
	if got.ModelsSet != e.ModelsSet || got.ToolsSet != e.ToolsSet ||
		got.LabelsSet != e.LabelsSet || got.CMaxSet != e.CMaxSet {
		t.Fatalf("presence flags did not survive the round trip:\n got %+v\nwant %+v", got, e)
	}
	if gotB != b {
		t.Fatalf("binding did not survive: got %+v want %+v", gotB, b)
	}
}

// TestParse_CannotLaunderOmittedDimension is the discriminating case from
// fix round 1: Models is left omitted (ModelsSet: false) while every other
// dimension is stated, so bad is invalid per envelope.ValidateAsCommission
// -- an omitted dimension must be refused, not defaulted (spec section
// 4.5). A Render/Parse round trip must not be able to turn that omission
// into a stated dimension: the wire format has no business supplying
// presence information the sender never provided. If Parse ever goes back
// to setting every flag unconditionally, this test is what catches it.
func TestParse_CannotLaunderOmittedDimension(t *testing.T) {
	bad := envelope.Envelope{
		Models: nil, ModelsSet: false, // omitted: must not survive the trip as "stated"
		Tools: []string{"fs_read"}, ToolsSet: true,
		Labels: []string{"public"}, LabelsSet: true,
		CMax: 4200, CMaxSet: true,
	}
	b := commission.Binding{PodRef: "dave/mybot@0.1.0", HManifest: [32]byte{7}}

	if err := bad.ValidateAsCommission(); err == nil {
		t.Fatal("test setup broken: bad must already be invalid before any round trip")
	}

	raw, err := Render(bad, b)
	if err != nil {
		t.Fatal(err)
	}
	got, _, err := Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	if err := got.ValidateAsCommission(); err == nil {
		t.Fatal("round trip laundered an invalid (omitted-dimension) envelope into a valid one")
	}
}

// TestRoundTrip_PresenceFlags is table-driven over all four dimensions,
// covering both directions of the JSON key-presence encoding: a dimension
// stated but left empty (or, for spend, stated as zero) versus a dimension
// never stated at all. Each case starts from a fully-stated base envelope
// and flips exactly one dimension, so a bug confined to one flag can't
// hide behind the other three being handled correctly.
func TestRoundTrip_PresenceFlags(t *testing.T) {
	base := envelope.Envelope{
		Models: []string{"anthropic/claude-sonnet-5"}, ModelsSet: true,
		Tools: []string{"fs_read"}, ToolsSet: true,
		Labels: []string{"public"}, LabelsSet: true,
		CMax: 4200, CMaxSet: true,
	}
	b := commission.Binding{PodRef: "dave/mybot@0.1.0", HManifest: [32]byte{7}}

	cases := []struct {
		name   string
		mutate func(e *envelope.Envelope)
		check  func(t *testing.T, got envelope.Envelope)
	}{
		{"models stated-empty", func(e *envelope.Envelope) { e.Models, e.ModelsSet = nil, true },
			func(t *testing.T, got envelope.Envelope) {
				if !got.ModelsSet || len(got.Models) != 0 {
					t.Fatalf("want ModelsSet=true, empty set; got %+v", got)
				}
			}},
		{"models omitted", func(e *envelope.Envelope) { e.Models, e.ModelsSet = nil, false },
			func(t *testing.T, got envelope.Envelope) {
				if got.ModelsSet {
					t.Fatalf("want ModelsSet=false; got %+v", got)
				}
			}},
		{"tools stated-empty", func(e *envelope.Envelope) { e.Tools, e.ToolsSet = nil, true },
			func(t *testing.T, got envelope.Envelope) {
				if !got.ToolsSet || len(got.Tools) != 0 {
					t.Fatalf("want ToolsSet=true, empty set; got %+v", got)
				}
			}},
		{"tools omitted", func(e *envelope.Envelope) { e.Tools, e.ToolsSet = nil, false },
			func(t *testing.T, got envelope.Envelope) {
				if got.ToolsSet {
					t.Fatalf("want ToolsSet=false; got %+v", got)
				}
			}},
		{"labels stated-empty", func(e *envelope.Envelope) { e.Labels, e.LabelsSet = nil, true },
			func(t *testing.T, got envelope.Envelope) {
				if !got.LabelsSet || len(got.Labels) != 0 {
					t.Fatalf("want LabelsSet=true, empty set; got %+v", got)
				}
			}},
		{"labels omitted", func(e *envelope.Envelope) { e.Labels, e.LabelsSet = nil, false },
			func(t *testing.T, got envelope.Envelope) {
				if got.LabelsSet {
					t.Fatalf("want LabelsSet=false; got %+v", got)
				}
			}},
		{"c_max stated-zero", func(e *envelope.Envelope) { e.CMax, e.CMaxSet = 0, true },
			func(t *testing.T, got envelope.Envelope) {
				if !got.CMaxSet || got.CMax != 0 {
					t.Fatalf("want CMaxSet=true, CMax=0; got %+v", got)
				}
			}},
		{"c_max omitted", func(e *envelope.Envelope) { e.CMax, e.CMaxSet = 0, false },
			func(t *testing.T, got envelope.Envelope) {
				if got.CMaxSet {
					t.Fatalf("want CMaxSet=false; got %+v", got)
				}
			}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e := base
			tc.mutate(&e)

			raw, err := Render(e, b)
			if err != nil {
				t.Fatal(err)
			}
			got, _, err := Parse(raw)
			if err != nil {
				t.Fatal(err)
			}
			tc.check(t, got)
		})
	}
}

func TestParse_RejectsUnknownType(t *testing.T) {
	if _, _, err := Parse([]byte(`[{"type":"payment_initiation"}]`)); err == nil {
		t.Fatal("want error for a non-konareef authorization_details type")
	}
}

func TestParse_RejectsEmptyArray(t *testing.T) {
	if _, _, err := Parse([]byte(`[]`)); err == nil {
		t.Fatal("want error for an authorization_details array with zero entries")
	}
}

func TestParse_RejectsMultipleEntries(t *testing.T) {
	raw := []byte(`[
		{"type":"https://konareef.ai/authz/commission/v1","h_manifest":"` + zeroHex + `"},
		{"type":"https://konareef.ai/authz/commission/v1","h_manifest":"` + zeroHex + `"}
	]`)
	if _, _, err := Parse(raw); err == nil {
		t.Fatal("want error for an authorization_details array with more than one entry")
	}
}

func TestParse_RejectsShortHManifest(t *testing.T) {
	raw := []byte(`[{"type":"https://konareef.ai/authz/commission/v1","h_manifest":"0707"}]`)
	if _, _, err := Parse(raw); err == nil {
		t.Fatal("want error for an h_manifest that is not 64 hex characters")
	}
}

func TestParse_RejectsNonHexHManifest(t *testing.T) {
	raw := []byte(`[{"type":"https://konareef.ai/authz/commission/v1","h_manifest":"` +
		"zz" + zeroHex[2:] + `"}]`)
	if _, _, err := Parse(raw); err == nil {
		t.Fatal("want error for an h_manifest containing non-hex characters")
	}
}

// zeroHex is 64 hex characters (32 bytes) of zeroes, a validly-shaped
// h_manifest value for tests that don't care about its content.
var zeroHex = strings.Repeat("0", 64)
