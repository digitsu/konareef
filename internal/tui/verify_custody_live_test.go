// Copyright 2026 Jerry David Chan, Konareef.ai
// SPDX-License-Identifier: Apache-2.0

// internal/tui/verify_custody_live_test.go
//
// The verify view shows the custody assessment of the LIVE v2 path
// (LIVE-CUSTODY, konareef#38): a bundle with a refused custody record,
// verified with verify.VerifyV2Production, gets a failed custody row.
// Before that item the live path left the assessment unset, so the row
// was always informational.

package tui

import (
	"bytes"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/fxamacker/cbor/v2"

	"github.com/digitsu/konareef/internal/verify"
)

// TestOutcomeFromV2_LivePathRefusedCustodyIsAFailRow checks the custody
// row of a live-path result for a v5 record without `MCP_BROKER: contained`.
func TestOutcomeFromV2_LivePathRefusedCustodyIsAFailRow(t *testing.T) {
	data := strings.Join([]string{
		"CUSTODY_PROOF: v5",
		"TOOL_LOG_ROOT: sha256:" + strings.Repeat("ab", 32),
		"TOTAL_SATS: 1",
	}, "\n")
	prev := bytes.Repeat([]byte{0xab}, 32)
	timestamp := "2026-09-28T01:00:00.000000Z"
	hash := verify.ComputeChainHash(hex.EncodeToString(prev), data, timestamp)
	mode, err := cbor.CoreDetEncOptions().EncMode()
	if err != nil {
		t.Fatal(err)
	}
	raw, err := mode.Marshal(verify.BundleV2{
		Version: "konareef-bundle/v2", CircuitID: "konareef-pod-step-v1", Disclosure: "C",
		Chain: []verify.ChainLinkV2{{ProofType: "custody", Hash: hash[:], PrevHash: prev, Data: []byte(data), Timestamp: timestamp}},
	})
	if err != nil {
		t.Fatal(err)
	}

	r := verify.VerifyV2Production(raw, false)
	o := outcomeFromV2("b.cbor", "konareef-bundle/v2", "konareef-pod-step-v1", "C", r)
	if o.Custody != verify.BrokerAssuranceRefused {
		t.Fatalf("Custody = %q, want %q", o.Custody, verify.BrokerAssuranceRefused)
	}
	var row *checkLine
	for i := range o.Checks {
		if o.Checks[i].Label == custodyCheckLabel {
			row = &o.Checks[i]
		}
	}
	if row == nil || row.State != checkFail ||
		!strings.Contains(row.Detail, "custody_v5_without_contained") {
		t.Fatalf("custody row = %+v, want a fail row naming custody_v5_without_contained", row)
	}
}
