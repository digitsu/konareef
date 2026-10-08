// Copyright 2026 Jerry David Chan, Konareef.ai
// SPDX-License-Identifier: Apache-2.0

// Package envelope defines the constraint dimensions of a konareef
// commission and the containment relation over them.
//
// Each dimension is a partially ordered set; an Envelope is their product,
// ordered pointwise. A run is admissible when the manifest envelope is
// contained in the commission envelope. The package is pure: no I/O, no
// crypto, no serialisation, so containment is decidable by unit test alone.
package envelope

import (
	"fmt"
	"sort"
)

// Envelope is a set of constraints. As a commission it states what a buyer
// permits; as a manifest envelope it states what a pod declares.
//
// Labels is the memory-scope dimension. It is ATTRIBUTION-ONLY (owner
// decision 2026-10-08, DATA-00): the buyer's labels are bound in h_commission
// and never enforced. IT IS NOT PROOF-BOUND. A salted r_init over bytes does
// not prove labels, provenance or subsequent information flow. Nothing may
// document or report this dimension as proof coverage.
type Envelope struct {
	Models []string
	Tools  []string
	Labels []string
	CMax   uint64
	// ModelsSet, ToolsSet, LabelsSet and CMaxSet record that a dimension was
	// stated explicitly, so an intentionally empty set ("may call no tools") or
	// zero value (e.g. "may spend nothing") is distinguishable from an omitted
	// one. An omitted dimension is refused; see ValidateAsCommission.
	ModelsSet bool
	ToolsSet  bool
	LabelsSet bool
	CMaxSet   bool
}

// Failure names one dimension that broke containment and why.
type Failure struct {
	Dimension string
	Detail    string
}

// Result is the outcome of a containment check. It always carries full
// detail; deciding how much of it to disclose is the caller's policy, not
// this package's.
type Result struct {
	OK       bool
	Failures []Failure
}

// Normalise returns s sorted and deduplicated, matching the canonical set
// representation used by internal/canon/fieldsroot.go.
func Normalise(s []string) []string {
	if len(s) == 0 {
		return nil
	}
	cp := append([]string(nil), s...)
	sort.Strings(cp)
	out := cp[:0]
	for i, v := range cp {
		if i == 0 || v != cp[i-1] {
			out = append(out, v)
		}
	}
	return out
}

// subsetFailures returns a Failure for each element of inner absent from outer.
func subsetFailures(dimension string, outer, inner []string) []Failure {
	permitted := make(map[string]struct{}, len(outer))
	for _, v := range outer {
		permitted[v] = struct{}{}
	}
	var missing []string
	for _, v := range Normalise(inner) {
		if _, ok := permitted[v]; !ok {
			missing = append(missing, v)
		}
	}
	if len(missing) == 0 {
		return nil
	}
	return []Failure{{
		Dimension: dimension,
		Detail:    fmt.Sprintf("manifest declares %v, not permitted by commission", missing),
	}}
}

// Contains reports whether inner (a manifest envelope) fits inside e (a
// commission envelope). It checks every dimension and reports all failures
// rather than stopping at the first.
func (e Envelope) Contains(inner Envelope) Result {
	var fs []Failure
	fs = append(fs, subsetFailures("models", Normalise(e.Models), inner.Models)...)
	fs = append(fs, subsetFailures("tools", Normalise(e.Tools), inner.Tools)...)
	fs = append(fs, subsetFailures("labels", Normalise(e.Labels), inner.Labels)...)
	if inner.CMax > e.CMax {
		fs = append(fs, Failure{
			Dimension: "spend",
			Detail:    fmt.Sprintf("manifest cap %d sats exceeds commission cap %d sats", inner.CMax, e.CMax),
		})
	}
	return Result{OK: len(fs) == 0, Failures: fs}
}
