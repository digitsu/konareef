// Copyright 2026 Jerry David Chan, Konareef.ai
// SPDX-License-Identifier: Apache-2.0

// custody_root_xcheck_test.go — tests for checkCustodyToolLogRoot
// (konareef#37, D7-XCHK): a Type-C bundle with a konareef-toml/v3 manifest
// and a bound v4 or v5 custody link must disclose T_log records whose
// SHA-256 custody root is the link's TOOL_LOG_ROOT. Bundles outside that
// precondition verify exactly as before.
package verify

import (
	"encoding/hex"
	"errors"
	"path/filepath"
	"strings"
	"testing"
)

// v3RInitLine is the extra [_commit] line of the accepted v3 fixture
// (TestSnarkPhase_V3FieldsRoot_Accepts).
const v3RInitLine = "r_init_scheme = \"konareef-rinit/v1\"\n"

// setCustodyRoot returns an edit that makes the custody tail a record of
// the given version (v3, v4 or v5) and re-hashes the link. For v4 and v5
// it writes TOOL_LOG_ROOT = root(records) of the records that rootOf
// returns for the bundle; v5 also gets `MCP_BROKER: contained`. Only the
// root check can then object to the bundle.
//
// Inputs: version; rootOf, which picks the records to hash (nil for v3).
// Output: the bundle edit.
func setCustodyRoot(version string, rootOf func(b *BundleV2) [][]byte) func(b *BundleV2) {
	return func(b *BundleV2) {
		tail := &b.Chain[len(b.Chain)-1]
		var keep []string
		for _, line := range strings.Split(string(tail.Data), "\n") {
			if strings.HasPrefix(line, "CUSTODY_PROOF:") || strings.HasPrefix(line, "TOOL_LOG_ROOT:") ||
				strings.HasPrefix(line, "MCP_BROKER:") {
				continue
			}
			keep = append(keep, line)
		}
		lines := []string{"CUSTODY_PROOF: " + version}
		lines = append(lines, keep...)
		if rootOf != nil {
			root := CustodyToolLogRoot(rootOf(b))
			lines = append(lines, "TOOL_LOG_ROOT: sha256:"+hex.EncodeToString(root[:]))
		}
		if version == "v5" {
			lines = append(lines, "MCP_BROKER: contained")
		}
		tail.Data = []byte(strings.Join(lines, "\n"))
		h := ComputeChainHash(hex.EncodeToString(tail.PrevHash), string(tail.Data), tail.Timestamp)
		tail.Hash = h[:]
	}
}

// disclosedRecords returns the bundle's own disclosed T_log records: the
// honest root input.
func disclosedRecords(b *BundleV2) [][]byte { return b.WitnessDisclosure.TLogRecords }

// otherRecords returns the disclosed records with one byte of the first
// record flipped. Its custody root is what a link carries when the
// disclosed records were spliced in under it (MCP-Z04 case 5a).
func otherRecords(b *BundleV2) [][]byte {
	out := make([][]byte, len(b.WitnessDisclosure.TLogRecords))
	for i, rec := range b.WitnessDisclosure.TLogRecords {
		out[i] = append([]byte(nil), rec...)
	}
	out[0][len(out[0])-1] ^= 0x01
	return out
}

// v3CustodyBundle builds the accepted konareef-toml/v3 Type-C fixture and
// applies edit to its decoded form. Output: the decoded bundle.
func v3CustodyBundle(t *testing.T, edit func(b *BundleV2)) *BundleV2 {
	t.Helper()
	fr := v3FieldsRoot(t)
	b, err := decodeBundleV2(buildFieldsRootBundle(t, v3Magic, fr, fr[:], true, false, v3RInitLine))
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if edit != nil {
		edit(b)
	}
	return b
}

// verifyV3Custody verifies the v3 fixture after edit with the accepting
// SNARK stub.
func verifyV3Custody(t *testing.T, edit func(b *BundleV2)) *ResultV2 {
	t.Helper()
	return VerifyV2(reencodeBundleV2(t, v3CustodyBundle(t, edit)), WithAcceptingVerifierForTests())
}

// countDiverged returns how many divergences of r wrap want.
func countDiverged(r *ResultV2, want error) int {
	n := 0
	for _, d := range r.Divergences {
		if errors.Is(d.Err, want) {
			n++
		}
	}
	return n
}

// requireRootMismatch asserts that r is refused with exactly one
// ErrCustodyToolLogRootMismatch, its fixed message, CommitmentsValid=false,
// and no other divergence.
func requireRootMismatch(t *testing.T, r *ResultV2) {
	t.Helper()
	if r.OK {
		t.Fatalf("ACCEPTED (OK=true): disclosed records that do not reproduce TOOL_LOG_ROOT must be refused")
	}
	if n := countDiverged(r, ErrCustodyToolLogRootMismatch); n != 1 || len(r.Divergences) != 1 {
		t.Fatalf("want exactly one ErrCustodyToolLogRootMismatch, got: %v", divergenceStrings(r))
	}
	if msg := r.Divergences[0].Msg; msg != custodyToolLogRootMismatchMsg {
		t.Fatalf("message %q, want %q", msg, custodyToolLogRootMismatchMsg)
	}
	if r.V2Verdict.CommitmentsValid {
		t.Fatal("CommitmentsValid=true after a TOOL_LOG_ROOT mismatch")
	}
	if !r.V2Verdict.ProofValid {
		t.Fatal("ProofValid=false: the refusal must come from the custody root check")
	}
}

// TestCustodyToolLogRoot_SplicedRecordsRefused is the D7 case (MCP-Z04
// 5a): a v3 manifest, a bound v4 or v5 link with an unchanged
// TOOL_LOG_ROOT, and disclosed records that do not reproduce it.
func TestCustodyToolLogRoot_SplicedRecordsRefused(t *testing.T) {
	for _, version := range []string{"v4", "v5"} {
		t.Run(version, func(t *testing.T) {
			requireRootMismatch(t, verifyV3Custody(t, setCustodyRoot(version, otherRecords)))
		})
	}
}

// TestCustodyToolLogRoot_HonestRecordsVerify is the control: the same
// bundles with the root of the disclosed records verify.
func TestCustodyToolLogRoot_HonestRecordsVerify(t *testing.T) {
	for _, version := range []string{"v4", "v5"} {
		t.Run(version, func(t *testing.T) {
			r := verifyV3Custody(t, setCustodyRoot(version, disclosedRecords))
			if !r.OK || !r.V2Verdict.CommitmentsValid {
				t.Fatalf("honest %s custody root refused: %v", version, divergenceStrings(r))
			}
		})
	}
}

// TestCustodyToolLogRoot_OutsidePreconditionUnchanged pins the
// precondition rule: a konareef-toml/v2 manifest is not broker-priced, so
// its bundles verify exactly as they did before the check existed, even
// where the link states a root the disclosed records do not reproduce, or
// where the tail link is relabelled.
func TestCustodyToolLogRoot_OutsidePreconditionUnchanged(t *testing.T) {
	fr := v2FieldsRoot(t)
	v2Manifest := func(edit func(b *BundleV2)) *ResultV2 {
		return VerifyV2(buildV2Z0FieldsRootBundle(t, fr, fr[:], fr[:], edit), WithAcceptingVerifierForTests())
	}
	for name, r := range map[string]*ResultV2{
		"v2 manifest, v4 link, other root": v2Manifest(setCustodyRoot("v4", otherRecords)),
		"v2 manifest, v3 link":             v2Manifest(setCustodyRoot("v3", nil)),
	} {
		if n := countDiverged(r, ErrCustodyToolLogRootMismatch) + countDiverged(r, ErrCustodyLinkUnbound); n != 0 {
			t.Errorf("%s: root check ran outside its precondition: %v", name, divergenceStrings(r))
		}
		if !r.OK {
			t.Errorf("%s: refused, want verified as before: %v", name, divergenceStrings(r))
		}
	}
	relabelled := v2Manifest(func(b *BundleV2) {
		setCustodyRoot("v4", otherRecords)(b)
		b.Chain[len(b.Chain)-1].ProofType = "task"
	})
	if n := countDiverged(relabelled, ErrCustodyLinkUnbound) + countDiverged(relabelled, ErrCustodyToolLogRootMismatch); n != 0 {
		t.Errorf("v2 manifest, relabelled tail: root check ran outside its precondition: %v", divergenceStrings(relabelled))
	}
}

// requireLinkUnbound asserts that r is refused with exactly one
// ErrCustodyLinkUnbound whose message contains want, with
// CommitmentsValid=false, and that the refusal does not read as anchored.
func requireLinkUnbound(t *testing.T, r *ResultV2, want string) {
	t.Helper()
	if r.OK {
		t.Fatalf("ACCEPTED (OK=true): a v3-manifest bundle without one bound v4/v5 custody link must be refused")
	}
	if n := countDiverged(r, ErrCustodyLinkUnbound); n != 1 {
		t.Fatalf("want exactly one ErrCustodyLinkUnbound, got: %v", divergenceStrings(r))
	}
	found := false
	for _, d := range r.Divergences {
		if errors.Is(d.Err, ErrCustodyLinkUnbound) && strings.Contains(d.Msg, want) {
			found = true
		}
	}
	if !found {
		t.Fatalf("no ErrCustodyLinkUnbound message contains %q: %v", want, divergenceStrings(r))
	}
	if r.V2Verdict.CommitmentsValid {
		t.Fatal("CommitmentsValid=true after a custody link shape refusal")
	}
	if r.V2Verdict.ChainHeadAnchored || r.CustodyBinding != CustodyBindingBundleClaim {
		t.Fatalf("refused bundle reads as anchored: anchored=%v CustodyBinding=%q",
			r.V2Verdict.ChainHeadAnchored, r.CustodyBinding)
	}
}

// relabelTail returns an edit that sets the tail link's proof_type. The
// link hash does not cover proof_type, so no hash changes (review C-1, A1).
func relabelTail(label string) func(b *BundleV2) {
	return func(b *BundleV2) { b.Chain[len(b.Chain)-1].ProofType = label }
}

// appendLink returns an edit that appends a link with the given label and
// data after the current tail, chained to it and with a hash that
// recomputes (review C-1, A2 and A3).
func appendLink(label, data string) func(b *BundleV2) {
	return func(b *BundleV2) {
		tail := b.Chain[len(b.Chain)-1]
		l := tail
		l.ProofType = label
		l.PrevHash = append([]byte(nil), tail.Hash...)
		l.Data = []byte(data)
		h := ComputeChainHash(hex.EncodeToString(l.PrevHash), data, l.Timestamp)
		l.Hash = h[:]
		b.Chain = append(b.Chain, l)
	}
}

// insertBeforeTail returns an edit that puts a link with the given label
// and data in front of the tail, re-chains the tail to it and re-hashes the
// tail, so every link hash recomputes.
func insertBeforeTail(label, data string) func(b *BundleV2) {
	return func(b *BundleV2) {
		tail := b.Chain[len(b.Chain)-1]
		l := tail
		l.ProofType = label
		l.Data = []byte(data)
		h := ComputeChainHash(hex.EncodeToString(l.PrevHash), data, l.Timestamp)
		l.Hash = h[:]
		tail.PrevHash = append([]byte(nil), l.Hash...)
		th := ComputeChainHash(hex.EncodeToString(tail.PrevHash), string(tail.Data), tail.Timestamp)
		tail.Hash = th[:]
		b.Chain = append(b.Chain[:len(b.Chain)-1], l, tail)
	}
}

// chainEdits applies edits in order.
func chainEdits(edits ...func(b *BundleV2)) func(b *BundleV2) {
	return func(b *BundleV2) {
		for _, e := range edits {
			e(b)
		}
	}
}

// custodyLookingData is a v4 custody blob, for a link whose label says it
// is not custody.
const custodyLookingData = "CUSTODY_PROOF: v4\nTOOL_LOG_ROOT: sha256:" +
	"0000000000000000000000000000000000000000000000000000000000000000\nTOTAL_SATS: 1"

// TestCustodyToolLogRoot_LinkShapeBypassesRefused is review C-1: the
// spliced bundle (records that do not reproduce the link's root) with one
// edit that moves the link out of the old selection rule. Every variant
// must be refused with ErrCustodyLinkUnbound.
func TestCustodyToolLogRoot_LinkShapeBypassesRefused(t *testing.T) {
	spliced := setCustodyRoot("v4", otherRecords)
	cases := []struct {
		name string
		edit func(b *BundleV2)
		want string
	}{
		{"A1 tail relabelled task", chainEdits(spliced, relabelTail("task")), `proof_type "task"`},
		{"A1 tail relabelled Custody", chainEdits(spliced, relabelTail("Custody")), `proof_type "Custody"`},
		{"A2 non-custody link appended", chainEdits(spliced, appendLink("task", "NOTE: appended")), `proof_type "task"`},
		{"A3 second custody link appended", chainEdits(spliced, appendLink("custody", custodyLookingData)), "2 custody records"},
		{"custody data under a non-custody label", chainEdits(spliced, insertBeforeTail("task", custodyLookingData)), "2 custody records"},
		{"v3 custody record", setCustodyRoot("v3", nil), "v3 custody record"},
		{"record fails a custody rule", func(b *BundleV2) {
			setCustodyRoot("v5", disclosedRecords)(b)
			rewriteCustody(func(d string) string { return strings.Replace(d, "\nMCP_BROKER: contained", "", 1) })(b)
		}, "custody_v5_without_contained"},
		{"tail record with a leading blank line", chainEdits(spliced,
			rewriteCustody(func(d string) string { return "\n" + d })), "custody_version_multiple_lines"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			requireLinkUnbound(t, verifyV3Custody(t, c.edit), c.want)
		})
	}
}

// TestCustodyToolLogRoot_NonCustodyLinkBeforeTailVerifies is the control
// for the content rule: a non-custody link in front of an honest custody
// tail verifies.
func TestCustodyToolLogRoot_NonCustodyLinkBeforeTailVerifies(t *testing.T) {
	r := verifyV3Custody(t, chainEdits(setCustodyRoot("v4", disclosedRecords),
		insertBeforeTail("capture_commitment", "CAPTURE_ROOT: sha256:00\nCAPTURE_COUNT: 1")))
	if !r.OK {
		t.Fatalf("non-custody link before an honest custody tail refused: %v", divergenceStrings(r))
	}
}

// TestCustodyToolLogRoot_LaterCustodyLineIsNotACustodyRecord (re-review
// N-2): the content test reads only the first line of a link's data, where
// reef-core writes the version line. A non-custody link whose later line
// happens to read `CUSTODY_PROOF: v4` (for example through an interpolated
// id) does not refuse an honest bundle.
func TestCustodyToolLogRoot_LaterCustodyLineIsNotACustodyRecord(t *testing.T) {
	r := verifyV3Custody(t, chainEdits(setCustodyRoot("v4", disclosedRecords),
		insertBeforeTail("capture_commitment", "CAPTURE_COMMITMENT: v1\nTASK_ID: x\nCUSTODY_PROOF: v4")))
	if !r.OK {
		t.Fatalf("a later CUSTODY_PROOF line in a non-custody link refused an honest bundle: %v", divergenceStrings(r))
	}
}

// TestCustodyToolLogRoot_DisguisedVersionLineCounts (re-review N-1): a
// non-custody link whose first line is the custody version line in another
// case, or after a BOM or white space, still counts as a custody record.
func TestCustodyToolLogRoot_DisguisedVersionLineCounts(t *testing.T) {
	for name, first := range map[string]string{
		"lower case":    "custody_proof: v4",
		"leading space": "  CUSTODY_PROOF: v4",
		"BOM":           "\ufeffCUSTODY_PROOF: v4",
		"tab and CR":    "\tCUSTODY_PROOF: v4\r",
	} {
		t.Run(name, func(t *testing.T) {
			r := verifyV3Custody(t, chainEdits(setCustodyRoot("v4", otherRecords),
				insertBeforeTail("task", first+"\nTOTAL_SATS: 1")))
			requireLinkUnbound(t, r, "2 custody records")
		})
	}
}

// TestCustodyToolLogRoot_RelabelledAnchoredTailRefused is review C-1 on an
// anchored chain: relabelling the tail changes no hash, so the anchor
// still checks out; the bundle must be refused all the same, and must not
// read as anchored.
func TestCustodyToolLogRoot_RelabelledAnchoredTailRefused(t *testing.T) {
	p := anchorPartsFor(t, v3CustodyBundle(t, setCustodyRoot("v4", otherRecords)))
	relabelTail("task")(p.bundle)
	requireLinkUnbound(t, p.verify(t), `proof_type "task"`)
}

// TestCustodyToolLogRoot_RootEdgeCases covers review M-3: an empty
// disclosed record list and a TOOL_LOG_ROOT that is not 32 bytes are both
// refused as a mismatch.
func TestCustodyToolLogRoot_RootEdgeCases(t *testing.T) {
	empty := verifyV3Custody(t, func(b *BundleV2) {
		setCustodyRoot("v4", disclosedRecords)(b)
		b.WitnessDisclosure.TLogRecords = nil
	})
	if empty.OK || countDiverged(empty, ErrCustodyToolLogRootMismatch) != 1 {
		t.Fatalf("empty T_log_records: OK=%v %v", empty.OK, divergenceStrings(empty))
	}
	short := verifyV3Custody(t, func(b *BundleV2) {
		setCustodyRoot("v4", disclosedRecords)(b)
		rewriteCustody(func(d string) string {
			i := strings.Index(d, "TOOL_LOG_ROOT: sha256:") + len("TOOL_LOG_ROOT: sha256:")
			return d[:i] + "abcd" + d[i+64:]
		})(b)
	})
	requireRootMismatch(t, short)
}

// TestCustodyToolLogRoot_TypeDUnchanged: the Type-D parity bundle carries
// no link data and no records, so the check never runs.
func TestCustodyToolLogRoot_TypeDUnchanged(t *testing.T) {
	r := VerifyV2(loadParityEnvelopeStripped(t, "parity-v2-typed.cbor"), WithAcceptingVerifierForTests())
	if n := countDiverged(r, ErrCustodyToolLogRootMismatch); n != 0 {
		t.Fatalf("root check ran on Type D: %v", divergenceStrings(r))
	}
}

// TestCustodyToolLogRoot_ProductionPath runs the check through
// VerifyV2Production (the path `konareef verify` and MCP-Z04 use) with a
// fake Rust binary that confirms the c check. The honest bundle passes
// with CTotalChecked; the spliced one is refused and CTotalChecked stays
// false.
func TestCustodyToolLogRoot_ProductionPath(t *testing.T) {
	out := filepath.Join(t.TempDir(), "env.json")
	t.Setenv(VerifyBinEnv, fakeVerifyBin(t, out,
		"verify: pod_step_schedule=checked\nverify: c_total=checked\nverify: ACCEPT\n", 0))

	honest := VerifyV2Production(reencodeBundleV2(t, v3CustodyBundle(t, setCustodyRoot("v4", disclosedRecords))), false)
	if !honest.OK || !honest.CTotalChecked {
		t.Fatalf("honest: OK=%v CTotalChecked=%v %v", honest.OK, honest.CTotalChecked, divergenceStrings(honest))
	}

	spliced := VerifyV2Production(reencodeBundleV2(t, v3CustodyBundle(t, setCustodyRoot("v4", otherRecords))), false)
	requireRootMismatch(t, spliced)
	if spliced.CTotalChecked {
		t.Fatal("CTotalChecked=true on a refused bundle")
	}
}
