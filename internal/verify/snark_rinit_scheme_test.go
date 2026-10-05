// Copyright 2026 Jerry David Chan, Konareef.ai
// SPDX-License-Identifier: Apache-2.0

// snark_rinit_scheme_test.go — the verifier accepts the konareef-rinit/v1
// r_init_scheme marker in [_commit] (MEM-00 D2-A, MEM-03 konareef#26).
// Every manifest konareef publishes since MEM-03 carries the marker, so a
// verifier that still refused every key but fields_root would reject every
// new manifest. The unmarked (legacy) trailer keeps verifying (control), and
// an unknown scheme is refused as a fields_root parse divergence.
package verify

import "testing"

// TestSnarkPhase_V2FieldsRoot_AcceptsRInitSchemeMarker: marked trailer
// verifies OK with all three R-V2.23 links agreeing.
func TestSnarkPhase_V2FieldsRoot_AcceptsRInitSchemeMarker(t *testing.T) {
	fr := v2FieldsRoot(t)
	for name, extra := range map[string]string{
		"legacy, no marker": "",
		"marker":            "r_init_scheme = \"konareef-rinit/v1\"\n",
	} {
		bundle := buildV2FieldsRootBundleTrailer(t, fr, fr[:], true, false, extra)
		r := VerifyV2(bundle, WithAcceptingVerifierForTests())
		if !r.OK {
			t.Fatalf("%s: verification rejected a consistent bundle:\n%v", name, divergenceStrings(r))
		}
	}
}

// TestSnarkPhase_V2FieldsRoot_RefusesUnknownRInitScheme: a trailer naming
// a derivation this build does not know is a fields_root divergence, even
// when every link would otherwise agree.
func TestSnarkPhase_V2FieldsRoot_RefusesUnknownRInitScheme(t *testing.T) {
	fr := v2FieldsRoot(t)
	bundle := buildV2FieldsRootBundleTrailer(t, fr, fr[:], true, false, "r_init_scheme = \"konareef-rinit/v2\"\n")
	r := VerifyV2(bundle, WithAcceptingVerifierForTests())
	assertFieldsRootRejected(t, r)
}
