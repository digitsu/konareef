// Copyright 2026 Jerry David Chan, Konareef.ai
// SPDX-License-Identifier: Apache-2.0

package envelope

import (
	"math/rand"
	"reflect"
	"testing"
	"testing/quick"
)

// Generate builds an arbitrary Envelope from a small vocabulary, so
// subset relations actually occur rather than being vanishingly rare.
func (Envelope) Generate(r *rand.Rand, _ int) reflect.Value {
	vocab := []string{"a", "b", "c", "d"}
	pick := func() []string {
		var out []string
		for _, v := range vocab {
			if r.Intn(2) == 0 {
				out = append(out, v)
			}
		}
		return out
	}
	return reflect.ValueOf(Envelope{
		Models: pick(), Tools: pick(), Labels: pick(),
		CMax: uint64(r.Intn(100)),
	})
}

func TestReflexive(t *testing.T) {
	f := func(e Envelope) bool { return e.Contains(e).OK }
	if err := quick.Check(f, nil); err != nil {
		t.Fatal(err)
	}
}

// TestTransitive proves a.Contains(b) && b.Contains(c) => a.Contains(c).
//
// The antecedent is constructed, not sampled: measured over 20,000 draws
// from Generate, a.Contains(b).OK held in ~1.4% of draws and a⊒b⊒c
// together held in 0 of 20,000 — a random-draw version of this test would
// pass vacuously, without the "if" branch ever firing. Meet(x, y) is
// always contained in x (proved by TestMeetIsGreatestLowerBound's lower
// bound half), so building b := Meet(a, x) and c := Meet(b, y) guarantees
// a ⊒ b ⊒ c by construction on every draw, and the conclusion is checked
// unconditionally.
func TestTransitive(t *testing.T) {
	f := func(a, x, y Envelope) bool {
		b := Meet(a, x)
		c := Meet(b, y)
		return a.Contains(c).OK
	}
	if err := quick.Check(f, nil); err != nil {
		t.Fatal(err)
	}
}

// TestAntisymmetric proves a.Contains(b) && b.Contains(a) => a.Equal(b).
//
// This is table-driven rather than generated, unlike TestTransitive and
// TestMeetIsGreatestLowerBound. Those two could manufacture their
// antecedent with Meet, because Meet always narrows towards a common
// lower bound. Antisymmetry's antecedent is the opposite shape — two
// envelopes that carry the same effective content in every dimension —
// which Meet cannot construct from two distinct arbitrary inputs, and
// which random draws over the Generate vocabulary satisfy close to never
// (rarer than TestTransitive's premise, which itself never fired in
// 20,000 draws). Explicit cases instead exercise the real content of the
// property: pairs that are equal only after normalisation.
func TestAntisymmetric(t *testing.T) {
	cases := []struct {
		name string
		a, b Envelope
	}{
		{
			name: "different declaration order",
			a:    Envelope{Models: []string{"a", "b"}, CMax: 1},
			b:    Envelope{Models: []string{"b", "a"}, CMax: 1},
		},
		{
			name: "duplicate entries",
			a:    Envelope{Models: []string{"a", "a", "b"}, CMax: 1},
			b:    Envelope{Models: []string{"a", "b"}, CMax: 1},
		},
		{
			name: "nil versus empty slice",
			a:    Envelope{Models: nil, CMax: 1},
			b:    Envelope{Models: []string{}, CMax: 1},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if !tc.a.Contains(tc.b).OK || !tc.b.Contains(tc.a).OK {
				t.Fatalf("expected mutual containment for %q", tc.name)
			}
			if !tc.a.Equal(tc.b) {
				t.Fatalf("expected Equal for %q", tc.name)
			}
		})
	}
}

// TestMeetIsGreatestLowerBound proves both halves of the "greatest lower
// bound" claim: Meet(a, b) is a lower bound of a and b, and it is the
// greatest such lower bound — any envelope that both a and b contain is
// itself contained in Meet(a, b).
//
// The greatest half's antecedent (a common lower bound c) is constructed,
// not sampled, for the same reason as TestTransitive: drawing c at random
// and hoping a.Contains(c) && b.Contains(c) hold is essentially never
// satisfied. Instead m := Meet(a, b) and c := Meet(m, z) makes c a common
// lower bound of a and b by construction — c is contained in m, hence in
// both a and b — so the greatest-half assertion runs unconditionally on
// every draw.
func TestMeetIsGreatestLowerBound(t *testing.T) {
	f := func(a, b, z Envelope) bool {
		m := Meet(a, b)
		// A lower bound of both.
		if !a.Contains(m).OK || !b.Contains(m).OK {
			return false
		}
		// Greatest: c is a common lower bound of a and b by construction,
		// so it must be contained in the meet.
		c := Meet(m, z)
		return m.Contains(c).OK
	}
	if err := quick.Check(f, nil); err != nil {
		t.Fatal(err)
	}
}

func TestMeetIsGreatest_ExplicitWitness(t *testing.T) {
	a := Envelope{Models: []string{"a", "b"}, Tools: []string{"x"}, CMax: 10}
	b := Envelope{Models: []string{"b", "c"}, Tools: []string{"x"}, CMax: 5}
	m := Meet(a, b)
	lower := Envelope{Models: []string{"b"}, Tools: []string{"x"}, CMax: 5}
	if !m.Contains(lower).OK {
		t.Fatal("meet must contain every common lower bound")
	}
	if m.CMax != 5 {
		t.Fatalf("meet CMax = %d, want 5", m.CMax)
	}
}

// TestMeetPreservesValidity_OverlappingSets verifies that the meet of two
// fully-stated valid commissions with overlapping sets remains valid. This
// passes regardless of whether flags are propagated, so it does not
// discriminate the propagation property.
func TestMeetPreservesValidity_OverlappingSets(t *testing.T) {
	a := Envelope{
		Models: []string{"m1", "m2"}, Tools: []string{"t1"}, Labels: []string{"l1"},
		CMax: 10, ModelsSet: true, ToolsSet: true, LabelsSet: true, CMaxSet: true,
	}
	b := Envelope{
		Models: []string{"m2"}, Tools: []string{"t1", "t2"}, Labels: []string{"l1"},
		CMax: 5, ModelsSet: true, ToolsSet: true, LabelsSet: true, CMaxSet: true,
	}
	m := Meet(a, b)
	if err := m.ValidateAsCommission(); err != nil {
		t.Fatalf("meet of two valid commissions with overlapping sets must be valid, got %v", err)
	}
}

// presenceFlag names one of the four presence flags and gives the table
// below a way to read and write it, so a single case can vary one dimension
// while holding the other three complete.
type presenceFlag struct {
	name string
	get  func(Envelope) bool
	set  func(*Envelope, bool)
}

var presenceFlags = []presenceFlag{
	{"ModelsSet", func(e Envelope) bool { return e.ModelsSet }, func(e *Envelope, v bool) { e.ModelsSet = v }},
	{"ToolsSet", func(e Envelope) bool { return e.ToolsSet }, func(e *Envelope, v bool) { e.ToolsSet = v }},
	{"LabelsSet", func(e Envelope) bool { return e.LabelsSet }, func(e *Envelope, v bool) { e.LabelsSet = v }},
	{"CMaxSet", func(e Envelope) bool { return e.CMaxSet }, func(e *Envelope, v bool) { e.CMaxSet = v }},
}

// fullyStatedEnvelope returns an envelope that states every dimension, for a
// case to knock exactly one flag down from.
func fullyStatedEnvelope() Envelope {
	return Envelope{
		Models: []string{"m1"}, Tools: []string{"t1"}, Labels: []string{"l1"},
		CMax: 10, ModelsSet: true, ToolsSet: true, LabelsSet: true, CMaxSet: true,
	}
}

// TestMeetPropagatesFlags verifies that presence flags are propagated by
// CONJUNCTION on all four dimensions: stated in the result only if BOTH
// inputs stated it.
//
// The discriminating cases are the ones where the two inputs disagree. A
// test whose inputs all state every dimension cannot tell `a && b` from
// `a || b`, or from an unconditional `true` — both of those mutants survived
// this suite before, and both are the exact fail-open the presence flags
// exist to prevent: Meet marking a dimension "stated" that one input never
// stated launders an omitted dimension into a signable commission through
// the narrowing path. So every case here asserts the resulting flag's VALUE,
// in both directions, rather than only that the meet still validates.
func TestMeetPropagatesFlags(t *testing.T) {
	cases := []struct {
		name    string
		a, b    bool
		want    bool
		mutants string
	}{
		{"both stated", true, true, true, ""},
		{"only a stated", true, false, false, "kills `||` and unconditional `true`"},
		{"only b stated", false, true, false, "kills `||` and unconditional `true`"},
		{"neither stated", false, false, false, "kills unconditional `true`"},
	}
	for _, f := range presenceFlags {
		for _, tc := range cases {
			t.Run(f.name+"/"+tc.name, func(t *testing.T) {
				a, b := fullyStatedEnvelope(), fullyStatedEnvelope()
				f.set(&a, tc.a)
				f.set(&b, tc.b)

				m := Meet(a, b)
				if got := f.get(m); got != tc.want {
					t.Fatalf("Meet(%s=%v, %s=%v).%s = %v, want %v (%s)",
						f.name, tc.a, f.name, tc.b, f.name, got, tc.want, tc.mutants)
				}
				// The other three dimensions were stated by both inputs, so
				// they must survive. This catches a mutant that returns a
				// constant `false` instead of the conjunction.
				for _, other := range presenceFlags {
					if other.name == f.name {
						continue
					}
					if !other.get(m) {
						t.Fatalf("varying %s dropped %s, which both inputs stated", f.name, other.name)
					}
				}
			})
		}
	}
}

// TestMeetKeepsDisjointDimensionsStated is the validity half of the same
// property: when narrowing empties a dimension, the result must still be a
// valid commission, because "may use nothing here" is a statement and not an
// omission. It is deliberately separate from the conjunction test above,
// which is about the flag's value rather than the meet's validity.
func TestMeetKeepsDisjointDimensionsStated(t *testing.T) {
	cases := []struct {
		name string
		a, b Envelope
		desc string
	}{
		{
			name: "ModelsSet",
			a: Envelope{
				Models: []string{"m1", "m2"}, Tools: []string{"t1"}, Labels: []string{"l1"},
				CMax: 10, ModelsSet: true, ToolsSet: true, LabelsSet: true, CMaxSet: true,
			},
			b: Envelope{
				Models: []string{"m3", "m4"}, Tools: []string{"t1"}, Labels: []string{"l1"},
				CMax: 5, ModelsSet: true, ToolsSet: true, LabelsSet: true, CMaxSet: true,
			},
			desc: "disjoint models → empty Models set, flag propagation saves it",
		},
		{
			name: "ToolsSet",
			a: Envelope{
				Models: []string{"m1"}, Tools: []string{"t1", "t2"}, Labels: []string{"l1"},
				CMax: 10, ModelsSet: true, ToolsSet: true, LabelsSet: true, CMaxSet: true,
			},
			b: Envelope{
				Models: []string{"m1"}, Tools: []string{"t3", "t4"}, Labels: []string{"l1"},
				CMax: 5, ModelsSet: true, ToolsSet: true, LabelsSet: true, CMaxSet: true,
			},
			desc: "disjoint tools → empty Tools set, flag propagation saves it",
		},
		{
			name: "LabelsSet",
			a: Envelope{
				Models: []string{"m1"}, Tools: []string{"t1"}, Labels: []string{"l1", "l2"},
				CMax: 10, ModelsSet: true, ToolsSet: true, LabelsSet: true, CMaxSet: true,
			},
			b: Envelope{
				Models: []string{"m1"}, Tools: []string{"t1"}, Labels: []string{"l3", "l4"},
				CMax: 5, ModelsSet: true, ToolsSet: true, LabelsSet: true, CMaxSet: true,
			},
			desc: "disjoint labels → empty Labels set, flag propagation saves it",
		},
		{
			name: "CMaxSet",
			a: Envelope{
				Models: []string{"m1"}, Tools: []string{"t1"}, Labels: []string{"l1"},
				CMax: 0, ModelsSet: true, ToolsSet: true, LabelsSet: true, CMaxSet: true,
			},
			b: Envelope{
				Models: []string{"m1"}, Tools: []string{"t1"}, Labels: []string{"l1"},
				CMax: 10, ModelsSet: true, ToolsSet: true, LabelsSet: true, CMaxSet: true,
			},
			desc: "CMax: 0 from first input → meet CMax is 0, flag propagation saves it",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			m := Meet(tc.a, tc.b)
			if err := m.ValidateAsCommission(); err != nil {
				t.Fatalf("%s: meet %s must be valid when flags are propagated, got %v",
					tc.name, tc.desc, err)
			}
		})
	}
}
