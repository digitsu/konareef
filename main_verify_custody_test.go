// Copyright 2026 Jerry David Chan, Konareef.ai
// SPDX-License-Identifier: Apache-2.0

// main_verify_custody_test.go — the `konareef verify --json` custody
// object (MCP-K04). It must not put an unanchored bundle claim in the
// "version" and "mcp_broker" keys.
package main

import (
	"testing"

	"github.com/digitsu/konareef/internal/verify"
)

// TestCustodyJSONKeepsUnanchoredClaimsApart checks every assurance level:
// only a fully verified contained record fills "version" and
// "mcp_broker"; any other parsed claim is under "unanchored_claim".
func TestCustodyJSONKeepsUnanchoredClaimsApart(t *testing.T) {
	v5 := verify.CustodyClaim{Version: verify.CustodyV5, Marker: verify.BrokerMarkerContained}
	v4 := verify.CustodyClaim{Version: verify.CustodyV4, Marker: verify.BrokerMarkerProofIncomplete}
	cases := []struct {
		name        string
		a           verify.CustodyAssessment
		version     string
		marker      string
		unanchored  bool
		wantRefusal string
	}{
		{"contained", verify.CustodyAssessment{Assurance: verify.BrokerAssuranceContained, Claim: v5}, "v5", "contained", false, ""},
		{"unanchored v5", verify.CustodyAssessment{Assurance: verify.BrokerAssuranceContainedRootUnchecked, Claim: v5}, "", "", true, ""},
		{"proof_incomplete", verify.CustodyAssessment{Assurance: verify.BrokerAssuranceProofIncomplete, Claim: v4}, "", "", true, ""},
		{"not verified", verify.CustodyAssessment{Assurance: verify.BrokerAssuranceNotVerified}, "", "", false, ""},
		{"refused", verify.CustodyAssessment{Assurance: verify.BrokerAssuranceRefused, RuleErr: verify.ErrCustodyV5WithoutContained},
			"", "", false, "custody_v5_without_contained"},
	}
	for _, c := range cases {
		m := custodyJSON(c.a)
		if m["version"] != c.version || m["mcp_broker"] != c.marker {
			t.Errorf("%s: version=%v mcp_broker=%v, want %q %q", c.name, m["version"], m["mcp_broker"], c.version, c.marker)
		}
		if _, ok := m["unanchored_claim"]; ok != c.unanchored {
			t.Errorf("%s: unanchored_claim present = %v, want %v", c.name, ok, c.unanchored)
		}
		if m["refusal"] != c.wantRefusal {
			t.Errorf("%s: refusal = %v, want %q", c.name, m["refusal"], c.wantRefusal)
		}
		if m["assurance"] != string(c.a.Assurance) || m["label"] != c.a.Label() {
			t.Errorf("%s: assurance/label = %v / %v", c.name, m["assurance"], m["label"])
		}
	}
}
