// Copyright 2026 Jerry David Chan, Konareef.ai
// SPDX-License-Identifier: Apache-2.0

// custody_test.go — self-contained tests of the custody-record rules, the
// SHA-256 custody root and the broker assurance display (MCP-K04). The
// cross-repo fixture test is custody_fixtures_test.go.
package verify

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/digitsu/konareef/internal/poseidon"
	"github.com/digitsu/konareef/internal/tlog"
)

// testCustodyRecords returns three encoded tool-log records with distinct,
// non-zero prices, so a price change or a SHA/Poseidon mix-up is visible.
func testCustodyRecords(t *testing.T) [][]byte {
	t.Helper()
	ts := time.Date(2026, 9, 27, 1, 0, 0, 0, time.UTC)
	rows := []tlog.Row{
		{ToolID: "jira.get_issue", ArgsHash: sha256.Sum256([]byte("a0")), ResultHash: sha256.Sum256([]byte("r0")), TS: ts, Sats: 250},
		{ToolID: "bash", ArgsHash: sha256.Sum256([]byte("a1")), ResultHash: sha256.Sum256([]byte("r1")), TS: ts.Add(time.Second), Sats: 7},
		{ToolID: "jira.search_issues", ArgsHash: sha256.Sum256([]byte("a2")), ResultHash: sha256.Sum256([]byte("r2")), TS: ts.Add(2 * time.Second), Sats: 1},
	}
	out := make([][]byte, len(rows))
	for i, r := range rows {
		out[i] = tlog.RecordBytes(r)
	}
	return out
}

// custodyBlob builds a custody blob in the reef-core layout. root is
// written as a TOOL_LOG_ROOT line when non-nil; marker is appended as the
// last line when non-empty.
func custodyBlob(version string, root []byte, marker string) string {
	lines := []string{
		"CUSTODY_PROOF: " + version,
		"CUSTOMER_KEY: [REDACTED]",
		"TASK_HASH: sha256:" + strings.Repeat("11", 32),
		"RESULT_HASH: sha256:" + strings.Repeat("22", 32),
		"TOOLS_USED: jira.get_issue, bash",
	}
	if root != nil {
		lines = append(lines, "TOOL_LOG_ROOT: sha256:"+hex.EncodeToString(root))
	}
	lines = append(lines, "TOTAL_SATS: 258", "AGENT_KEY: agent-k04-test")
	if marker != "" {
		lines = append(lines, "MCP_BROKER: "+marker)
	}
	return strings.Join(lines, "\n")
}

// columnsFor returns stored columns that match records.
func columnsFor(records [][]byte) CustodyColumns {
	root := CustodyToolLogRoot(records)
	return CustodyColumns{
		ToolLogRecords: bytes.Join(records, nil), RecordsPresent: true,
		ToolLogRoot: root[:], RootPresent: true,
	}
}

func TestCustodyRootDiffersFromPoseidonRoot(t *testing.T) {
	records := testCustodyRecords(t)
	sha := CustodyToolLogRoot(records)
	pos, err := poseidon.Default().TRoot(records)
	if err != nil {
		t.Fatalf("poseidon TRoot: %v", err)
	}
	if sha == pos {
		t.Fatal("SHA-256 custody root equals the Poseidon t_root; the two must never coincide")
	}

	// A blob that carries the Poseidon root as its TOOL_LOG_ROOT is refused,
	// whichever column value it is paired with.
	blob := custodyBlob("v5", pos[:], "contained")
	cols := columnsFor(records)
	if _, err := CheckCustodyRecord(blob, cols); !errors.Is(err, ErrToolLogRootMismatch) {
		t.Fatalf("Poseidon root in the blob: err = %v, want tool_log_root_mismatch", err)
	}
	cols.ToolLogRoot = pos[:]
	if _, err := CheckCustodyRecord(custodyBlob("v5", sha[:], "contained"), cols); !errors.Is(err, ErrToolLogRootMismatch) {
		t.Fatalf("Poseidon root in the column: err = %v, want tool_log_root_mismatch", err)
	}
}

func TestCustodyRootBindsPrices(t *testing.T) {
	records := testCustodyRecords(t)
	root := CustodyToolLogRoot(records)
	blob := custodyBlob("v5", root[:], "contained")
	cols := columnsFor(records)
	if _, err := CheckCustodyRecord(blob, cols); err != nil {
		t.Fatalf("control: %v", err)
	}

	// Change the last byte of record 0's sats (250 -> 251) in the stored
	// records only.
	altered := bytes.Clone(cols.ToolLogRecords)
	altered[custodyRecordSize-1]++
	cols.ToolLogRecords = altered
	if _, err := CheckCustodyRecord(blob, cols); !errors.Is(err, ErrToolLogRootMismatch) {
		t.Fatalf("altered price: err = %v, want tool_log_root_mismatch", err)
	}
}

func TestCustodyRootKnownShapes(t *testing.T) {
	z := sha256.Sum256([]byte{0x00, 0x00})
	empty := CustodyToolLogRoot(nil)
	want := sha256.Sum256(append([]byte{0x03, 0x00}, z[:]...))
	if empty != want {
		t.Fatalf("empty root = %x, want SHA-256(0x03 || 0x00 || Z) = %x", empty, want)
	}
	if got := custodyULEB128(300); !bytes.Equal(got, []byte{0xac, 0x02}) {
		t.Fatalf("ULEB128(300) = %x, want ac02", got)
	}
	if _, err := SplitCustodyToolLogRecords(make([]byte, custodyRecordSize+1)); !errors.Is(err, ErrToolLogRecordsNotMultiple) {
		t.Fatalf("partial record: err = %v, want not_a_record_multiple", err)
	}
}

func TestCustodyNullColumnsAreRefusedNotLegacy(t *testing.T) {
	records := testCustodyRecords(t)
	root := CustodyToolLogRoot(records)
	for _, version := range []string{"v4", "v5"} {
		marker := ""
		if version == "v5" {
			marker = "contained"
		}
		blob := custodyBlob(version, root[:], marker)
		if _, err := CheckCustodyRecord(blob, CustodyColumns{}); !errors.Is(err, ErrToolLogRecordsMissing) {
			t.Errorf("%s with NULL records: err = %v, want tool_log_records_missing", version, err)
		}
		cols := columnsFor(records)
		cols.RootPresent, cols.ToolLogRoot = false, nil
		if _, err := CheckCustodyRecord(blob, cols); !errors.Is(err, ErrToolLogRootMismatch) {
			t.Errorf("%s with NULL root column: err = %v, want tool_log_root_mismatch", version, err)
		}
		// Removing the root line does not turn the record into a v3 record.
		if _, err := ParseCustodyBlob(custodyBlob(version, nil, marker)); !errors.Is(err, ErrToolLogRootMissing) {
			t.Errorf("%s without a root line: err = %v, want tool_log_root_missing", version, err)
		}
	}
}

func TestCustodyBlobRulesEdgeCases(t *testing.T) {
	root := bytes.Repeat([]byte{0xab}, 32)
	v4 := custodyBlob("v4", root, "")
	cases := []struct {
		name string
		data string
		want error
	}{
		{"empty", "", ErrCustodyVersionMissing},
		{"no space after colon", strings.Replace(v4, "CUSTODY_PROOF: v4", "CUSTODY_PROOF:v4", 1), ErrCustodyVersionUnknown},
		{"version smuggled later", v4 + "\nTOOLS_USED_EXTRA\nCUSTODY_PROOF: v5", ErrCustodyVersionMultipleLines},
		{"marker trailing space", v4 + "\nMCP_BROKER: proof_incomplete ", ErrMCPBrokerLineUnknown},
		{"marker CR", v4 + "\nMCP_BROKER: proof_incomplete\r", ErrMCPBrokerLineUnknown},
		{"root uppercase hex", strings.Replace(v4, hex.EncodeToString(root), strings.ToUpper(hex.EncodeToString(root)), 1), ErrToolLogRootMalformed},
		{"root odd hex", strings.Replace(v4, hex.EncodeToString(root), "abc", 1), ErrToolLogRootUndecodable},
		{"two roots", v4 + "\nTOOL_LOG_ROOT: sha256:" + hex.EncodeToString(root), ErrToolLogRootMultipleLines},
		{"v3 malformed root", custodyBlob("v3", nil, "") + "\nTOOL_LOG_ROOT: nope", ErrToolLogRootMalformed},
	}
	for _, c := range cases {
		if _, err := ParseCustodyBlob(c.data); !errors.Is(err, c.want) {
			t.Errorf("%s: err = %v, want %v", c.name, err, c.want)
		}
	}
}

// custodyTestBundle replaces the custody data of the standard valid test
// bundle with data and recomputes the custody link hash.
func custodyTestBundle(data string) *Bundle {
	b := buildValidBundle()
	link := &b.Chain[len(b.Chain)-1]
	link.Data = data
	h := ComputeChainHash(*link.PrevHash, link.Data, link.Timestamp)
	link.Hash = hex.EncodeToString(h[:])
	return b
}

func TestVerifyBundleCustodyAssurance(t *testing.T) {
	root := CustodyToolLogRoot(testCustodyRecords(t))
	cases := []struct {
		name string
		data string
		ok   bool
		want BrokerAssurance
	}{
		{"legacy v3", custodyBlob("v3", nil, ""), true, BrokerAssuranceNoMarker},
		{"v3 proof_incomplete", custodyBlob("v3", nil, "proof_incomplete"), true, BrokerAssuranceProofIncomplete},
		{"v4 no grant", custodyBlob("v4", root[:], ""), true, BrokerAssuranceNoMarker},
		{"v4 proof_incomplete", custodyBlob("v4", root[:], "proof_incomplete"), true, BrokerAssuranceProofIncomplete},
		// A bundle has no stored records, so v5 is never shown as contained.
		{"v5 contained", custodyBlob("v5", root[:], "contained"), true, BrokerAssuranceContainedRootUnchecked},
		{"v5 without marker", custodyBlob("v5", root[:], ""), false, BrokerAssuranceRefused},
		{"v5 proof_incomplete", custodyBlob("v5", root[:], "proof_incomplete"), false, BrokerAssuranceRefused},
		{"v4 contained", custodyBlob("v4", root[:], "contained"), false, BrokerAssuranceRefused},
		{"v4 missing root", custodyBlob("v4", nil, ""), false, BrokerAssuranceRefused},
		{"unknown version", custodyBlob("v6", root[:], "contained"), false, BrokerAssuranceRefused},
	}
	for _, c := range cases {
		r := Verify(custodyTestBundle(c.data))
		if r.OK != c.ok {
			t.Errorf("%s: OK = %v, want %v (divergences %v)", c.name, r.OK, c.ok, r.Divergences)
		}
		if r.Custody.Assurance != c.want {
			t.Errorf("%s: assurance = %s, want %s", c.name, r.Custody.Assurance, c.want)
		}
		if !c.ok && !containsAny(r.Divergences, "custody commitment: ") {
			t.Errorf("%s: no custody-rule divergence in %v", c.name, r.Divergences)
		}
	}
}

func TestVerifyBundleUpgradedV4IsNotContained(t *testing.T) {
	root := CustodyToolLogRoot(testCustodyRecords(t))
	b := custodyTestBundle(custodyBlob("v4", root[:], "proof_incomplete"))
	if r := Verify(b); !r.OK {
		t.Fatalf("control v4 bundle rejected: %v", r.Divergences)
	}

	// Rewrite the valid v4 record as v5 + contained without re-hashing.
	link := &b.Chain[len(b.Chain)-1]
	link.Data = custodyBlob("v5", root[:], "contained")
	r := Verify(b)
	if r.OK {
		t.Fatal("a v4 record rewritten as v5 passed")
	}
	if r.Custody.Assurance != BrokerAssuranceNotVerified {
		t.Fatalf("assurance = %s, want not_verified", r.Custody.Assurance)
	}
}

func TestVerifyBundleShortRootShowsNoClaim(t *testing.T) {
	// A one-byte root passes the blob rules, as in reef-core, but can never
	// match a recomputed root, so no claim is shown for it.
	r := Verify(custodyTestBundle(custodyBlob("v5", []byte{0x00}, "contained")))
	if !r.OK || r.Custody.Assurance != BrokerAssuranceNotVerified {
		t.Fatalf("OK = %v, assurance = %s; want true, not_verified", r.OK, r.Custody.Assurance)
	}
}

func TestVerifySanitizedBundleShowsNoBrokerClaim(t *testing.T) {
	root := CustodyToolLogRoot(testCustodyRecords(t))
	b := custodyTestBundle(custodyBlob("v5", root[:], "contained"))
	f := false
	b.Verifiable = &f
	if r := Verify(b); r.Custody.Assurance != BrokerAssuranceNotVerified {
		t.Fatalf("sanitized bundle assurance = %s, want not_verified", r.Custody.Assurance)
	}
}

func TestVerifyStructureFailureShowsNoBrokerClaim(t *testing.T) {
	b := custodyTestBundle(custodyBlob("v3", nil, ""))
	b.Chain = b.Chain[:2]
	r := Verify(b)
	if r.OK || r.Custody.Assurance != BrokerAssuranceNotVerified {
		t.Fatalf("OK = %v, assurance = %s; want false, not_verified", r.OK, r.Custody.Assurance)
	}
}

// v2CustodyBundle returns a v2 bundle whose only link is a custody link
// with data; hashOK selects whether the link hash recomputes from it.
func v2CustodyBundle(data string, hashOK bool) *BundleV2 {
	prev := bytes.Repeat([]byte{0xab}, 32)
	ts := "2026-09-27T01:00:00.000000Z"
	h := ComputeChainHash(hex.EncodeToString(prev), data, ts)
	if !hashOK {
		h[0] ^= 0xff
	}
	return &BundleV2{Chain: []ChainLinkV2{{
		ProofType: "custody", Hash: h[:], PrevHash: prev, Data: []byte(data), Timestamp: ts,
	}}}
}

// twoCustodyLinks returns a v2 chain with a bound custody link followed
// by a second custody link.
func twoCustodyLinks(data string) *BundleV2 {
	b := v2CustodyBundle(data, true)
	b.Chain = append(b.Chain, b.Chain[0])
	return b
}

// custodyNotAtTail returns a v2 chain whose bound custody link is followed
// by another link type.
func custodyNotAtTail(data string) *BundleV2 {
	b := v2CustodyBundle(data, true)
	b.Chain = append(b.Chain, ChainLinkV2{ProofType: "capture_commitment", Hash: bytes.Repeat([]byte{1}, 32)})
	return b
}

func TestAssessCustodyV2(t *testing.T) {
	root := CustodyToolLogRoot(testCustodyRecords(t))
	v5 := custodyBlob("v5", root[:], "contained")
	bad := custodyBlob("v5", root[:], "")

	cases := []struct {
		name      string
		b         *BundleV2
		ok        bool
		want      BrokerAssurance
		divergent bool
	}{
		{"bound v5, bundle ok", v2CustodyBundle(v5, true), true, BrokerAssuranceContainedRootUnchecked, false},
		{"bound v5, bundle failed", v2CustodyBundle(v5, true), false, BrokerAssuranceNotVerified, false},
		{"unbound v5", v2CustodyBundle(v5, false), true, BrokerAssuranceNotVerified, false},
		{"bound malformed", v2CustodyBundle(bad, true), true, BrokerAssuranceRefused, true},
		{"unbound malformed", v2CustodyBundle(bad, false), true, BrokerAssuranceNotVerified, false},
		{"type D, no data", &BundleV2{Chain: []ChainLinkV2{{ProofType: "custody", Scrubbed: true}}}, true, BrokerAssuranceNotVerified, false},
		{"two custody links", twoCustodyLinks(v5), true, BrokerAssuranceNotVerified, false},
		{"custody not at tail", custodyNotAtTail(v5), true, BrokerAssuranceNotVerified, false},
		{"short root", v2CustodyBundle(custodyBlob("v5", []byte{0x00}, "contained"), true), true, BrokerAssuranceNotVerified, false},
	}
	for _, c := range cases {
		r := &ResultV2{OK: c.ok, V2Verdict: &Verdict{CommitmentsValid: true}}
		a := assessCustodyV2(c.b, r)
		if a.Assurance != c.want {
			t.Errorf("%s: assurance = %s, want %s", c.name, a.Assurance, c.want)
		}
		gotDiv := false
		for _, d := range r.Divergences {
			if errors.Is(d.Err, ErrCustodyRecordInvalid) {
				gotDiv = true
			}
		}
		if gotDiv != c.divergent {
			t.Errorf("%s: custody divergence = %v, want %v", c.name, gotDiv, c.divergent)
		}
		if c.divergent && (r.OK || r.V2Verdict.CommitmentsValid) {
			t.Errorf("%s: OK = %v, CommitmentsValid = %v; want both false", c.name, r.OK, r.V2Verdict.CommitmentsValid)
		}
	}
}

// TestBrokerAssuranceLabels pins the display text of every level. Only the
// fully verified contained level states that calls were brokered, and it
// says that it is server custody and not a ZK spend guarantee.
func TestBrokerAssuranceLabels(t *testing.T) {
	want := map[BrokerAssurance]string{
		BrokerAssuranceContained: "MCP calls to granted upstream authorities were brokered and recorded, " +
			"under accepted containment (server custody record; not a ZK spend guarantee)",
		BrokerAssuranceContainedRootUnchecked: "unanchored claim of contained MCP brokering (v5): the bundle does not " +
			"anchor this record and does not carry its tool-log records, so the tool-log root was not recomputed; not verified",
		BrokerAssuranceProofIncomplete: "MCP broker proof incomplete: this record does not show that MCP calls were contained",
		BrokerAssuranceNoMarker: "no MCP broker marker: this record makes no broker claim " +
			"(a missing marker does not show that a firewall was installed)",
		BrokerAssuranceRefused:     "custody record refused; no broker assurance",
		BrokerAssuranceNotVerified: "custody record not verified; no broker assurance",
	}
	for level, text := range want {
		got := BrokerAssuranceLabel(level)
		if got != text {
			t.Errorf("%s: label = %q, want %q", level, got, text)
		}
		if level != BrokerAssuranceContained && strings.Contains(got, "were brokered") {
			t.Errorf("%s: label claims brokering: %q", level, got)
		}
	}
	if got := BrokerAssuranceLabel("unknown"); got != want[BrokerAssuranceNotVerified] {
		t.Errorf("unknown level label = %q, want the not-verified label", got)
	}
	refused := CustodyAssessment{Assurance: BrokerAssuranceRefused, RuleErr: ErrCustodyV5WithoutContained}
	if got := refused.Label(); got != "custody record refused (custody_v5_without_contained); no broker assurance" {
		t.Errorf("refused label = %q", got)
	}
}
