// Copyright 2026 Jerry David Chan, Konareef.ai
// SPDX-License-Identifier: Apache-2.0

// custody_binding_test.go — tests for ResultV2.CustodyBinding and
// ResultV2.CTotalLabel (konareef#37, D7-XCHK): bundle-only verification
// says that the custody fields are the bundle's own claim, and only a
// verified chain-head anchor raises that.
package verify

import (
	"path/filepath"
	"testing"
)

// TestCustodyBinding_BundleOnlyIsBundleClaim: every bundle-only result,
// passed or failed, on both entry points, reports "bundle-claim".
func TestCustodyBinding_BundleOnlyIsBundleClaim(t *testing.T) {
	honest := verifyV3Custody(t, setCustodyRoot("v4", disclosedRecords))
	spliced := verifyV3Custody(t, setCustodyRoot("v4", otherRecords))
	for name, r := range map[string]*ResultV2{
		"honest":      honest,
		"spliced":     spliced,
		"empty input": VerifyV2(nil, WithAcceptingVerifierForTests()),
		"v1 JSON":     VerifyV2([]byte("{}"), WithAcceptingVerifierForTests()),
	} {
		if r.CustodyBinding != CustodyBindingBundleClaim {
			t.Errorf("%s: CustodyBinding = %q, want %q", name, r.CustodyBinding, CustodyBindingBundleClaim)
		}
	}
	if !honest.OK {
		t.Fatalf("honest fixture refused: %v", divergenceStrings(honest))
	}

	out := filepath.Join(t.TempDir(), "env.json")
	t.Setenv(VerifyBinEnv, fakeVerifyBin(t, out,
		"verify: pod_step_schedule=checked\nverify: c_total=checked\nverify: ACCEPT\n", 0))
	prod := VerifyV2Production(reencodeBundleV2(t, v3CustodyBundle(t, setCustodyRoot("v4", disclosedRecords))), false)
	if !prod.OK || !prod.CTotalChecked || prod.CTotalAnchored || prod.CustodyBinding != CustodyBindingBundleClaim {
		t.Fatalf("production: OK=%v CTotalChecked=%v CTotalAnchored=%v CustodyBinding=%q",
			prod.OK, prod.CTotalChecked, prod.CTotalAnchored, prod.CustodyBinding)
	}
	if got, want := prod.CTotalLabel(), "c equals the bundle's stated custody total (unanchored claim)"; got != want {
		t.Fatalf("CTotalLabel = %q, want %q", got, want)
	}
	if empty := VerifyV2Production(nil, false); empty.CustodyBinding != CustodyBindingBundleClaim {
		t.Fatalf("production empty input: CustodyBinding = %q", empty.CustodyBinding)
	}
}

// TestCustodyBinding_AnchoredTypeC: a Type-C bundle whose chain-head
// anchor verified reports "chain-anchored", since the attested node wrote
// its custody link. A Type-D bundle, or one whose anchor is absent, stays
// "bundle-claim".
func TestCustodyBinding_AnchoredTypeC(t *testing.T) {
	c := newAnchorParts(t, "C").verify(t)
	if !c.OK || !c.V2Verdict.ChainHeadAnchored || c.CustodyBinding != CustodyBindingChainAnchored {
		t.Fatalf("anchored Type C: OK=%v anchored=%v CustodyBinding=%q %v",
			c.OK, c.V2Verdict.ChainHeadAnchored, c.CustodyBinding, divergenceStrings(c))
	}

	absent := newAnchorParts(t, "C")
	absent.wire = nil
	if r := absent.verify(t); !r.OK || r.CustodyBinding != CustodyBindingBundleClaim {
		t.Fatalf("no anchor: OK=%v CustodyBinding=%q", r.OK, r.CustodyBinding)
	}

	if r := newAnchorParts(t, "D").verify(t); r.CustodyBinding != CustodyBindingBundleClaim {
		t.Fatalf("Type D: CustodyBinding=%q, want bundle-claim", r.CustodyBinding)
	}
}

// TestCustodyToolLogRoot_AnchorDoesNotSkipTheCheck: an anchored v3 bundle
// with a v4 link still has its disclosed records checked. The honest one
// is chain-anchored; the spliced one is refused and is not anchored.
func TestCustodyToolLogRoot_AnchorDoesNotSkipTheCheck(t *testing.T) {
	honest := anchorPartsFor(t, v3CustodyBundle(t, setCustodyRoot("v4", disclosedRecords))).verify(t)
	if !honest.OK || honest.CustodyBinding != CustodyBindingChainAnchored {
		t.Fatalf("anchored honest v3/v4: OK=%v CustodyBinding=%q %v", honest.OK, honest.CustodyBinding, divergenceStrings(honest))
	}

	spliced := anchorPartsFor(t, v3CustodyBundle(t, setCustodyRoot("v4", otherRecords))).verify(t)
	if spliced.OK || countDiverged(spliced, ErrCustodyToolLogRootMismatch) != 1 {
		t.Fatalf("anchored spliced v3/v4: OK=%v %v", spliced.OK, divergenceStrings(spliced))
	}
	if spliced.V2Verdict.ChainHeadAnchored || spliced.CustodyBinding != CustodyBindingBundleClaim {
		t.Fatalf("refused bundle reads as anchored: anchored=%v CustodyBinding=%q",
			spliced.V2Verdict.ChainHeadAnchored, spliced.CustodyBinding)
	}
}

// TestCTotalLabel pins the display text of the c check for each binding.
func TestCTotalLabel(t *testing.T) {
	cases := []struct {
		checked bool
		binding CustodyBinding
		want    string
	}{
		{false, CustodyBindingBundleClaim, "c not checked against a custody total"},
		{false, CustodyBindingChainAnchored, "c not checked against a custody total"},
		{true, CustodyBindingBundleClaim, "c equals the bundle's stated custody total (unanchored claim)"},
		{true, CustodyBindingChainAnchored, "c equals the custody total of the anchored chain head " +
			"(written by the attested node; not checked against reef-core's stored custody record)"},
		{true, CustodyBindingServerChecked, "c equals the custody total of reef-core's stored custody record (server-checked)"},
		{true, "", "c equals the bundle's stated custody total (unanchored claim)"},
	}
	for _, c := range cases {
		r := &ResultV2{CTotalChecked: c.checked, CustodyBinding: c.binding}
		if got := r.CTotalLabel(); got != c.want {
			t.Errorf("checked=%v binding=%q: %q, want %q", c.checked, c.binding, got, c.want)
		}
	}
	// The values are stable output strings (JSON custody_binding, CLI).
	for b, want := range map[CustodyBinding]string{
		CustodyBindingBundleClaim:   "bundle-claim",
		CustodyBindingChainAnchored: "chain-anchored",
		CustodyBindingServerChecked: "server-checked",
	} {
		if string(b) != want {
			t.Errorf("binding value %q, want %q", b, want)
		}
	}
}
