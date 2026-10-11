// Copyright 2026 Jerry David Chan, Konareef.ai
// SPDX-License-Identifier: Apache-2.0

// main_verify_custody_binding_test.go — the `konareef verify` output for a
// konareef-bundle/v2 bundle names what its custody total is bound to
// (konareef#37, D7-XCHK): the text output never shows the c check as a
// bare "checked", and the JSON carries custody_binding.
package main

import (
	"bytes"
	"strings"
	"testing"

	"github.com/digitsu/konareef/internal/verify"
)

// TestVerifyV2Text_ShowsCustodyBinding checks the text output for a
// checked bundle-only total, an anchored total and an unchecked total.
func TestVerifyV2Text_ShowsCustodyBinding(t *testing.T) {
	cases := []struct {
		name string
		r    *verify.ResultV2
		want []string
	}{
		{"bundle claim", &verify.ResultV2{OK: true, CTotalChecked: true, CustodyBinding: verify.CustodyBindingBundleClaim},
			[]string{"Custody total: c equals the bundle's stated custody total (unanchored claim)\n",
				"Custody binding: bundle-claim\n"}},
		{"anchored", &verify.ResultV2{OK: true, CTotalChecked: true, CTotalAnchored: true, CustodyBinding: verify.CustodyBindingChainAnchored},
			[]string{"Custody total: c equals the custody total of the anchored chain head (written by the attested node; not checked against reef-core's stored custody record)\n",
				"Custody binding: chain-anchored\n"}},
		{"not checked", &verify.ResultV2{OK: false, CustodyBinding: verify.CustodyBindingBundleClaim},
			[]string{"Custody total: c not checked against a custody total\n", "Custody binding: bundle-claim\n"}},
	}
	for _, c := range cases {
		var buf bytes.Buffer
		writeVerifyV2Text(&buf, "b.cbor", "konareef-bundle/v2", "konareef-pod-step-v1", "C", c.r)
		out := buf.String()
		for _, w := range c.want {
			if !strings.Contains(out, w) {
				t.Errorf("%s: output lacks %q:\n%s", c.name, w, out)
			}
		}
		// Exactly one custody-total line, and it is the result's own label,
		// so the c check is never printed without its binding.
		var totals []string
		for _, line := range strings.Split(out, "\n") {
			if strings.HasPrefix(line, "Custody total: ") {
				totals = append(totals, line)
			}
		}
		if len(totals) != 1 || totals[0] != "Custody total: "+c.r.CTotalLabel() {
			t.Fatalf("%s: custody total lines %q, want exactly %q", c.name, totals, "Custody total: "+c.r.CTotalLabel())
		}
		if c.r.CTotalChecked && !strings.HasSuffix(totals[0], ")") {
			t.Errorf("%s: a checked total is printed without its binding qualifier: %q", c.name, totals[0])
		}
	}
}

// TestVerifyV2JSON_CarriesCustodyBinding checks the JSON keys next to
// c_total_checked.
func TestVerifyV2JSON_CarriesCustodyBinding(t *testing.T) {
	r := &verify.ResultV2{OK: true, CTotalChecked: true, CustodyBinding: verify.CustodyBindingBundleClaim}
	doc := verifyV2JSONDoc("b.cbor", "konareef-bundle/v2", "konareef-pod-step-v1", "C", r)
	if doc["c_total_checked"] != true || doc["custody_binding"] != "bundle-claim" ||
		doc["c_total_label"] != "c equals the bundle's stated custody total (unanchored claim)" {
		t.Fatalf("custody keys: c_total_checked=%v custody_binding=%v c_total_label=%v",
			doc["c_total_checked"], doc["custody_binding"], doc["c_total_label"])
	}
}
