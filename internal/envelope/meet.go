// Copyright 2026 Jerry David Chan, Konareef.ai
// SPDX-License-Identifier: Apache-2.0

package envelope

// Meet returns the greatest lower bound of a and b: the widest envelope
// contained in both. Refinement — narrowing a commission — is exactly this
// operation, which makes monotone narrowing a property of the algebra
// rather than a convention a caller must remember. Presence flags are
// propagated by conjunction: a dimension is stated in the result only if
// both inputs stated it.
func Meet(a, b Envelope) Envelope {
	cMax := a.CMax
	if b.CMax < cMax {
		cMax = b.CMax
	}
	return Envelope{
		Models:    intersect(a.Models, b.Models),
		Tools:     intersect(a.Tools, b.Tools),
		Labels:    intersect(a.Labels, b.Labels),
		CMax:      cMax,
		ModelsSet: a.ModelsSet && b.ModelsSet,
		ToolsSet:  a.ToolsSet && b.ToolsSet,
		LabelsSet: a.LabelsSet && b.LabelsSet,
		CMaxSet:   a.CMaxSet && b.CMaxSet,
	}
}

// intersect returns the normalised set intersection of a and b.
func intersect(a, b []string) []string {
	in := make(map[string]struct{}, len(b))
	for _, v := range b {
		in[v] = struct{}{}
	}
	var out []string
	for _, v := range Normalise(a) {
		if _, ok := in[v]; ok {
			out = append(out, v)
		}
	}
	return out
}

// Equal reports whether two envelopes are the same after normalisation.
func (e Envelope) Equal(o Envelope) bool {
	return e.CMax == o.CMax &&
		sameSet(e.Models, o.Models) &&
		sameSet(e.Tools, o.Tools) &&
		sameSet(e.Labels, o.Labels)
}

// sameSet compares two string sets by their normalised forms.
func sameSet(a, b []string) bool {
	na, nb := Normalise(a), Normalise(b)
	if len(na) != len(nb) {
		return false
	}
	for i := range na {
		if na[i] != nb[i] {
			return false
		}
	}
	return true
}
