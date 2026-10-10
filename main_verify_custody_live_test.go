// Copyright 2026 Jerry David Chan, Konareef.ai
// SPDX-License-Identifier: Apache-2.0

// main_verify_custody_live_test.go — `konareef verify` shows the custody
// assessment of the LIVE v2 path (LIVE-CUSTODY, konareef#38). Before that
// item, verify.VerifyV2Production left ResultV2.Custody as the zero value,
// so the text and JSON output never showed a refused custody record.
package main

import (
	"bytes"
	"encoding/hex"
	"errors"
	"strings"
	"testing"

	"github.com/fxamacker/cbor/v2"

	"github.com/digitsu/konareef/internal/verify"
)

// liveCustodyRefusedBundle returns CBOR bytes for a Type-C bundle whose
// only link is a bound custody link (its hash recomputes from its data)
// with a v5 record that has no `MCP_BROKER: contained` line. The bundle
// fails other checks too; only its custody assessment is under test.
func liveCustodyRefusedBundle(t *testing.T) []byte {
	t.Helper()
	data := strings.Join([]string{
		"CUSTODY_PROOF: v5",
		"TOOL_LOG_ROOT: sha256:" + strings.Repeat("ab", 32),
		"TOTAL_SATS: 1",
	}, "\n")
	prev := bytes.Repeat([]byte{0xab}, 32)
	timestamp := "2026-09-28T01:00:00.000000Z"
	hash := verify.ComputeChainHash(hex.EncodeToString(prev), data, timestamp)
	raw, err := cbor.CoreDetEncOptions().EncMode()
	if err != nil {
		t.Fatal(err)
	}
	enc, err := raw.Marshal(verify.BundleV2{
		Version: "konareef-bundle/v2", CircuitID: "konareef-pod-step-v1", Disclosure: "C",
		Chain: []verify.ChainLinkV2{{ProofType: "custody", Hash: hash[:], PrevHash: prev, Data: []byte(data), Timestamp: timestamp}},
	})
	if err != nil {
		t.Fatal(err)
	}
	return enc
}

// TestVerifyV2Live_ShowsRefusedCustody runs a bundle with a refused custody
// record through verify.VerifyV2Production and checks the text output, the
// JSON document and the divergence list.
func TestVerifyV2Live_ShowsRefusedCustody(t *testing.T) {
	r := verify.VerifyV2Production(liveCustodyRefusedBundle(t), false)
	if r.OK {
		t.Fatal("a refused custody record verified OK on the live path")
	}

	var buf bytes.Buffer
	writeVerifyV2Text(&buf, "b.cbor", "konareef-bundle/v2", "konareef-pod-step-v1", "C", r)
	wantText := "MCP broker (server custody): custody record refused (custody_v5_without_contained); no broker assurance"
	if !strings.Contains(buf.String(), wantText) {
		t.Errorf("text output lacks %q:\n%s", wantText, buf.String())
	}

	doc := verifyV2JSONDoc("b.cbor", "konareef-bundle/v2", "konareef-pod-step-v1", "C", r)
	custody, _ := doc["custody"].(map[string]any)
	if custody["assurance"] != "refused" || custody["refusal"] != "custody_v5_without_contained" {
		t.Errorf("JSON custody = %v, want assurance refused with refusal custody_v5_without_contained", custody)
	}
	refused := false
	for _, d := range r.Divergences {
		refused = refused || errors.Is(d.Err, verify.ErrCustodyRecordInvalid)
	}
	if !refused {
		t.Errorf("no ERR_CUSTODY_RECORD_INVALID divergence: %v", doc["divergences"])
	}
}
