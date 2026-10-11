// Copyright 2026 Jerry David Chan, Konareef.ai
// SPDX-License-Identifier: Apache-2.0

// llm_proof_totals_test.go — cross-repo check of reef-core P3-08 custody
// proof totals (K3-01, konareef#6).
//
// P3-08 changed where a custody run's `llm_sats` comes from (the proxy's
// settled rows, not the harness total) but not the custody blob format:
// TOTAL_SATS = llm_sats + egress_sats is still the one line the verifier
// binds the proof's `c` to (c_total.go). This test reads the proof_totals
// cases of the vendored P3-08 fixture and checks that:
//
//   - each case is self-consistent (c == total_sats == llm + egress, and
//     under custody llm_sats is the sum of settled rows and ignores the
//     harness total and released rows);
//   - the existing CustodyTotalSats reader returns expect.c for the
//     case's custody_line, so no new custody version or reader is needed.
//
// It adds no verifier code path: the signature, chain and `c` checks are
// unchanged.
package verify

import (
	"encoding/json"
	"os"
	"testing"
)

// llmProofTotalsFixture is the proof_totals part of the P3-08 fixture. Its
// bytes are pinned by internal/ws (llmFixtureSHA256).
type llmProofTotalsFixture struct {
	ProofTotals []struct {
		Name             string `json:"name"`
		LLMCustody       bool   `json:"llm_custody"`
		EgressSats       uint64 `json:"egress_sats"`
		HarnessTotalSats uint64 `json:"harness_total_sats"`
		ReleasedRows     int    `json:"released_rows"`
		SettledRows      []struct {
			Sats        uint64 `json:"sats"`
			SettleBasis string `json:"settle_basis"`
		} `json:"settled_rows"`
		Expect struct {
			C           uint64 `json:"c"`
			CustodyLine string `json:"custody_line"`
			LLMSats     uint64 `json:"llm_sats"`
			TotalSats   uint64 `json:"total_sats"`
		} `json:"expect"`
	} `json:"proof_totals"`
}

func TestLLMProofTotalsFixture(t *testing.T) {
	raw, err := os.ReadFile("../ws/testdata/p3_08/llm-billing-v1.json")
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	var fx llmProofTotalsFixture
	if err := json.Unmarshal(raw, &fx); err != nil {
		t.Fatalf("decode fixture: %v", err)
	}
	if len(fx.ProofTotals) != 5 {
		t.Fatalf("fixture has %d proof_totals cases, want 5", len(fx.ProofTotals))
	}

	for _, tc := range fx.ProofTotals {
		t.Run(tc.Name, func(t *testing.T) {
			wantLLM := tc.HarnessTotalSats
			if tc.LLMCustody {
				wantLLM = 0
				for _, row := range tc.SettledRows {
					wantLLM += row.Sats
				}
			}
			if tc.Expect.LLMSats != wantLLM {
				t.Errorf("llm_sats = %d, want %d (custody=%v)", tc.Expect.LLMSats, wantLLM, tc.LLMCustody)
			}
			if tc.Expect.TotalSats != tc.Expect.LLMSats+tc.EgressSats {
				t.Errorf("total_sats %d != llm %d + egress %d", tc.Expect.TotalSats, tc.Expect.LLMSats, tc.EgressSats)
			}
			if tc.Expect.C != tc.Expect.TotalSats {
				t.Errorf("c %d != total_sats %d", tc.Expect.C, tc.Expect.TotalSats)
			}

			// The custody line as it sits in a custody blob among other lines.
			blob := "TOOL_LOG_ROOT: 00\n" + tc.Expect.CustodyLine + "\nEND"
			got, err := CustodyTotalSats(blob)
			if err != nil {
				t.Fatalf("CustodyTotalSats(%q): %v", tc.Expect.CustodyLine, err)
			}
			if got != tc.Expect.C {
				t.Errorf("CustodyTotalSats = %d, want c = %d", got, tc.Expect.C)
			}
		})
	}
}
