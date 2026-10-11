// Copyright 2026 Jerry David Chan, Konareef.ai
// SPDX-License-Identifier: Apache-2.0

// snark_v3fieldsroot_test.go — the CL-5(a) fields_root bindings apply to a
// konareef-toml/v3 manifest exactly as to v2 (MCP-Z03, konareef#15). Before
// the gate learned v3, a `#!konareef-toml/v3` Type-C bundle skipped every
// binding below, so a prover could attest any fields_root for it.
package verify

import (
	"testing"

	"github.com/digitsu/konareef/internal/canon"
)

// v3Magic is the manifest magic line these tests disclose.
const v3Magic = "#!konareef-toml/v3\n"

// TestSnarkPhase_V3FieldsRoot_Accepts is the control: a consistent v3
// Type-C bundle verifies.
func TestSnarkPhase_V3FieldsRoot_Accepts(t *testing.T) {
	fr := v3FieldsRoot(t)
	bundle := buildFieldsRootBundle(t, v3Magic, fr, fr[:], true, false, "r_init_scheme = \"konareef-rinit/v1\"\n")
	r := VerifyV2(bundle, WithAcceptingVerifierForTests())
	if !r.OK {
		t.Fatalf("expected accept; got divergences:\n%v", divergenceStrings(r))
	}
	if r.V2Verdict == nil || !r.V2Verdict.CommitmentsValid {
		t.Error("CommitmentsValid=false on a consistent v3 fields_root bundle")
	}
}

// TestSnarkPhase_V3FieldsRoot_GenesisMismatch: the proof's genesis lane
// differs from the v3 [_commit].fields_root → ErrFieldsRootMismatch.
func TestSnarkPhase_V3FieldsRoot_GenesisMismatch(t *testing.T) {
	fr := v3FieldsRoot(t)
	var other [32]byte
	for i := range other {
		other[i] = 0xFF
	}
	bundle := buildFieldsRootBundle(t, v3Magic, fr, other[:], true, false, "")
	assertFieldsRootRejected(t, VerifyV2(bundle, WithAcceptingVerifierForTests()))
}

// TestSnarkPhase_V3FieldsRoot_CommitMissing: a v3 manifest with no
// [_commit] trailer is refused, not read as a v1 manifest with nothing to
// bind.
func TestSnarkPhase_V3FieldsRoot_CommitMissing(t *testing.T) {
	fr := v3FieldsRoot(t)
	bundle := buildFieldsRootBundle(t, v3Magic, fr, fr[:], true, true, "")
	assertFieldsRootRejected(t, VerifyV2(bundle, WithAcceptingVerifierForTests()))
}

// TestSnarkPhase_V3FieldsRoot_Z0Required: the mandatory-z0 gate that
// shares the CL-5(a) scope also fires for v3.
func TestSnarkPhase_V3FieldsRoot_Z0Required(t *testing.T) {
	fr := v3FieldsRoot(t)
	bundle := buildFieldsRootBundle(t, v3Magic, fr, fr[:], true, false, "")
	decoded, err := decodeBundleV2(bundle)
	if err != nil {
		t.Fatal(err)
	}
	decoded.SpartanCompressResult.Z0 = nil
	r := VerifyV2(reencodeBundleV2(t, decoded), WithAcceptingVerifierForTests())
	if r.OK {
		t.Fatal("a v3 Type-C bundle without z0 was accepted")
	}
}

// TestSnarkPhase_V3NearMissMagicFailsClosed: a first line that starts with
// the v3 prefix but is not exactly the v3 magic is refused with
// ErrManifestMagicNearMiss before the gated branch reads its trailer
// (KR-MAGIC; snark_magic_near_miss_test.go covers the other near misses).
func TestSnarkPhase_V3NearMissMagicFailsClosed(t *testing.T) {
	fr := v3FieldsRoot(t)
	bundle := buildFieldsRootBundle(t, "#!konareef-toml/v3evil\n", fr, fr[:], true, false, "")
	r := VerifyV2(bundle, WithAcceptingVerifierForTests())
	if r.OK || (r.V2Verdict != nil && r.V2Verdict.CommitmentsValid) {
		t.Fatal("a near-miss v3 magic line was accepted")
	}
	found := false
	for _, d := range r.Divergences {
		if d.Err == ErrManifestMagicNearMiss {
			found = true
		}
	}
	if !found {
		t.Errorf("expected an ErrManifestMagicNearMiss divergence; got %v", divergenceStrings(r))
	}
}

// TestSnarkPhase_UnsupportedManifestVersionRefused: a manifest whose magic
// line names a version this build does not implement is refused, not
// verified as though it were v1 with nothing to bind.
func TestSnarkPhase_UnsupportedManifestVersionRefused(t *testing.T) {
	fr := v3FieldsRoot(t)
	for _, magic := range []string{"#!konareef-toml/v4\n", "#!konareef-toml/v1x\n"} {
		bundle := buildFieldsRootBundle(t, magic, fr, fr[:], true, false, "")
		if r := VerifyV2(bundle, WithAcceptingVerifierForTests()); r.OK {
			t.Errorf("%q: a manifest of an unsupported version was accepted", magic)
		}
	}
}

// TestSnarkPhase_ExtraToolTrailerRefused is the MCP-Z03 review M1 case at
// the verifier: the trailer, the genesis lane and z0 all agree on a root
// that commits a tool (evil.x) the disclosed manifest never declares.
// Bindings (b) and (c) pass; only recomputing the root from the manifest
// refuses it. v2 and v3 are both covered; the Accepts tests are the
// controls.
func TestSnarkPhase_ExtraToolTrailerRefused(t *testing.T) {
	cases := map[string][]string{
		"#!konareef-toml/v2\n": {"evil.x"},
		v3Magic:                {"evil.x", "jira.search"},
	}
	for magic, tools := range cases {
		tainted, err := canon.FieldsRoot(nil, tools, 1000, canon.EmptyMemoryRoot())
		if err != nil {
			t.Fatal(err)
		}
		bundle := buildFieldsRootBundle(t, magic, tainted, tainted[:], true, false, "")
		r := VerifyV2(bundle, WithAcceptingVerifierForTests())
		if r.OK {
			t.Errorf("%q: an extra-tool trailer was accepted", magic)
			continue
		}
		assertFieldsRootRejected(t, r)
	}
}
