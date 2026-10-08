// Copyright 2026 Jerry David Chan, Konareef.ai
// SPDX-License-Identifier: Apache-2.0

package envelope

import (
	"errors"
	"strings"
	"testing"
)

// completeEnvelope returns an envelope that states all four dimensions at
// non-empty, non-zero values, for a case to knock exactly one flag down
// from without also emptying that dimension's value.
func completeEnvelope() Envelope {
	return Envelope{
		Models: []string{"m"}, ModelsSet: true,
		Tools: []string{"t"}, ToolsSet: true,
		Labels: []string{"l"}, LabelsSet: true,
		CMax: 1, CMaxSet: true,
	}
}

// clearFlag names one presence flag and gives the tables below a way to
// knock it down while leaving the other three, and every value, intact.
type clearFlag struct {
	name  string
	clear func(*Envelope)
}

var clearFlags = []clearFlag{
	{"models", func(e *Envelope) { e.ModelsSet = false }},
	{"tools", func(e *Envelope) { e.ToolsSet = false }},
	{"labels", func(e *Envelope) { e.LabelsSet = false }},
	{"c_max_sats", func(e *Envelope) { e.CMaxSet = false }},
}

// TestValidateAsCommission_RejectsAbsentDimensions is the empty-value half
// of the contract: a dimension neither stated nor carrying a value must be
// refused.
func TestValidateAsCommission_RejectsAbsentDimensions(t *testing.T) {
	cases := map[string]Envelope{
		"no models": {Tools: []string{"t"}, ToolsSet: true, Labels: []string{"l"}, LabelsSet: true, CMax: 1, CMaxSet: true},
		"no tools":  {Models: []string{"m"}, ModelsSet: true, Labels: []string{"l"}, LabelsSet: true, CMax: 1, CMaxSet: true},
		"no labels": {Models: []string{"m"}, ModelsSet: true, Tools: []string{"t"}, ToolsSet: true, CMax: 1, CMaxSet: true},
		"zero cmax": {Models: []string{"m"}, ModelsSet: true, Tools: []string{"t"}, ToolsSet: true, Labels: []string{"l"}, LabelsSet: true},
	}
	for name, e := range cases {
		if err := e.ValidateAsCommission(); !errors.Is(err, ErrDimensionAbsent) {
			t.Errorf("%s: want ErrDimensionAbsent, got %v", name, err)
		}
	}
}

// TestValidateAsCommission_RejectsUnstatedDimensionCarryingAValue is the
// DISCRIMINATING case, and the reason the check is on the flag alone.
//
// The condition used to be `len(e.Models) == 0 && !e.ModelsSet`: a refusal
// only when the dimension was BOTH empty AND unstated. Every input above
// satisfies both halves, so the whole table stayed green against that
// conjunction. This one does not: it knocks exactly one flag down while
// leaving that dimension's value non-empty (or, for spend, non-zero), which
// is precisely the shape the old condition let through.
//
// That shape is not hypothetical. A decoder that reads values and presence
// from different sources — unmarshalProposal reads values from the decoded
// struct and presence from toml metadata, rar.Parse from JSON key presence
// — can produce it from a file, and internal/commission.Sign relies on this
// method as its only envelope gate. A commission whose tools were never
// stated would have been signable purely because some tool name survived in
// the decoded slice, which is the fail-open the presence flags exist to stop.
func TestValidateAsCommission_RejectsUnstatedDimensionCarryingAValue(t *testing.T) {
	for _, f := range clearFlags {
		t.Run(f.name, func(t *testing.T) {
			e := completeEnvelope()
			f.clear(&e)
			if err := e.ValidateAsCommission(); !errors.Is(err, ErrDimensionAbsent) {
				t.Fatalf("dimension %q carries a value but was never stated; want ErrDimensionAbsent, got %v (envelope %+v)",
					f.name, err, e)
			}
		})
	}
}

func TestValidateAsCommission_AcceptsComplete(t *testing.T) {
	e := completeEnvelope()
	if err := e.ValidateAsCommission(); err != nil {
		t.Fatalf("want nil, got %v", err)
	}
}

// The refusal must name which dimension was omitted. Without it a buyer
// staring at a four-key file is told only that one of the four is missing.
func TestValidateAsCommission_NamesTheOmittedDimension(t *testing.T) {
	for _, f := range clearFlags {
		t.Run(f.name, func(t *testing.T) {
			e := completeEnvelope()
			f.clear(&e)
			err := e.ValidateAsCommission()
			if err == nil {
				t.Fatalf("want a refusal for omitted %q", f.name)
			}
			if !strings.Contains(err.Error(), f.name) {
				t.Fatalf("refusal for omitted %q does not name it: %q", f.name, err)
			}
		})
	}
}

// An explicitly empty tool set is a real, restrictive statement — "this pod
// may call nothing" — and must be distinguishable from an absent one.
func TestValidateAsCommission_ExplicitEmptyToolSetIsAllowed(t *testing.T) {
	e := completeEnvelope()
	e.Tools = []string{}
	if err := e.ValidateAsCommission(); err != nil {
		t.Fatalf("explicit empty tool set must be allowed, got %v", err)
	}
}

// An explicitly zero spend cap is a real, restrictive statement — "this pod
// may spend nothing" — and must be distinguishable from an absent one.
func TestValidateAsCommission_ExplicitZeroSpendIsAllowed(t *testing.T) {
	e := completeEnvelope()
	e.CMax = 0
	if err := e.ValidateAsCommission(); err != nil {
		t.Fatalf("explicit zero spend must be allowed, got %v", err)
	}
}
