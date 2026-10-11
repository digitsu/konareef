// Copyright 2026 Jerry David Chan, Konareef.ai
// SPDX-License-Identifier: Apache-2.0

// custody_live_path_test.go — tests that the custody-record rules
// (assessCustodyV2) apply on the LIVE v2 verify path,
// VerifyV2ProductionWithAnchor (LIVE-CUSTODY, konareef#38). Before that
// item, only VerifyV2 (the test and reference path) called
// assessCustodyV2, so a bound custody link with a malformed record
// verified OK=true on the path that `konareef verify`, the TUI, the
// verdict server and replay use.
//
// The fixtures reuse the D7-XCHK builders (custody_root_xcheck_test.go):
// a Type-C bundle whose custody tail is rewritten and re-hashed, so the
// link hash still recomputes and the custody rules alone can object.
package verify

import (
	"encoding/hex"
	"errors"
	"path/filepath"
	"strings"
	"testing"
)

// custodyLiveFakeBin points the production verifier at a fake Rust binary
// that accepts the proof and confirms the c check, so a refusal in these
// tests can only come from the Go-side checks.
func custodyLiveFakeBin(t *testing.T) {
	t.Helper()
	out := filepath.Join(t.TempDir(), "env.json")
	t.Setenv(VerifyBinEnv, fakeVerifyBin(t, out,
		"verify: pod_step_schedule=checked\nverify: c_total=checked\nverify: ACCEPT\n", 0))
}

// editCustodyLines returns a bundle edit that rewrites the lines of the
// custody tail with mutate and re-hashes the link, so the link stays bound
// (its hash recomputes from its data).
//
// Input: mutate, which takes the tail's lines and returns the new lines.
// Output: the bundle edit.
func editCustodyLines(mutate func(lines []string) []string) func(b *BundleV2) {
	return func(b *BundleV2) {
		tail := &b.Chain[len(b.Chain)-1]
		tail.Data = []byte(strings.Join(mutate(strings.Split(string(tail.Data), "\n")), "\n"))
		h := ComputeChainHash(hex.EncodeToString(tail.PrevHash), string(tail.Data), tail.Timestamp)
		tail.Hash = h[:]
	}
}

// dropLinesWithPrefix removes every line that starts with prefix.
func dropLinesWithPrefix(prefix string) func(lines []string) []string {
	return func(lines []string) []string {
		var keep []string
		for _, line := range lines {
			if !strings.HasPrefix(line, prefix) {
				keep = append(keep, line)
			}
		}
		return keep
	}
}

// duplicateLinesWithPrefix repeats every line that starts with prefix.
func duplicateLinesWithPrefix(prefix string) func(lines []string) []string {
	return func(lines []string) []string {
		var out []string
		for _, line := range lines {
			out = append(out, line)
			if strings.HasPrefix(line, prefix) {
				out = append(out, line)
			}
		}
		return out
	}
}

// v2ManifestCustodyBundle builds the konareef-toml/v2 Type-C fixture and
// applies edit to it. A v2 manifest is outside the D7-XCHK precondition,
// so on this bundle only the custody rules can refuse a malformed record.
//
// Input: edit, applied to the decoded bundle (may be nil).
// Output: the decoded bundle.
func v2ManifestCustodyBundle(t *testing.T, edit func(b *BundleV2)) *BundleV2 {
	t.Helper()
	fr := v2FieldsRoot(t)
	b, err := decodeBundleV2(buildV2FieldsRootBundle(t, fr, fr[:], true, false))
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if edit != nil {
		edit(b)
	}
	return b
}

// TestVerifyV2Production_BoundCustodyRuleFailureRefused is the LIVE-CUSTODY
// acceptance test: a bound custody blob that fails a custody rule is
// refused with ErrCustodyRecordInvalid on the production path.
func TestVerifyV2Production_BoundCustodyRuleFailureRefused(t *testing.T) {
	custodyLiveFakeBin(t)
	v5 := setCustodyRoot("v5", disclosedRecords)

	cases := []struct {
		name string
		edit func(b *BundleV2)
	}{
		{"v5 without MCP_BROKER: contained", chainEdits(v5, editCustodyLines(dropLinesWithPrefix("MCP_BROKER:")))},
		{"two TOOL_LOG_ROOT lines", chainEdits(v5, editCustodyLines(duplicateLinesWithPrefix("TOOL_LOG_ROOT:")))},
		{"v4 without TOOL_LOG_ROOT", chainEdits(setCustodyRoot("v4", disclosedRecords), editCustodyLines(dropLinesWithPrefix("TOOL_LOG_ROOT:")))},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := VerifyV2Production(reencodeBundleV2(t, v2ManifestCustodyBundle(t, c.edit)), false)
			if r.OK {
				t.Fatalf("ACCEPTED (OK=true): a bound custody record that fails a rule must be refused")
			}
			if n := countDiverged(r, ErrCustodyRecordInvalid); n != 1 {
				t.Fatalf("want exactly one ErrCustodyRecordInvalid, got %d: %v", n, divergenceStrings(r))
			}
			if r.V2Verdict.CommitmentsValid {
				t.Error("CommitmentsValid=true after a custody-rule refusal")
			}
			if r.Custody.Assurance != BrokerAssuranceRefused {
				t.Errorf("Custody.Assurance = %q, want %q", r.Custody.Assurance, BrokerAssuranceRefused)
			}
			if r.CTotalChecked || r.CTotalAnchored {
				t.Errorf("CTotalChecked=%v CTotalAnchored=%v on a refused bundle", r.CTotalChecked, r.CTotalAnchored)
			}
		})
	}
}

// TestVerifyV2Production_HonestCustodyShowsBrokerAssurance: an honest v5
// contained record verifies on the live path and reports its broker
// assurance (the CLI and the TUI display r.Custody). The level is the
// unanchored one: a bundle-only check does not anchor the record.
func TestVerifyV2Production_HonestCustodyShowsBrokerAssurance(t *testing.T) {
	custodyLiveFakeBin(t)
	r := VerifyV2Production(reencodeBundleV2(t,
		v2ManifestCustodyBundle(t, setCustodyRoot("v5", disclosedRecords))), false)
	if !r.OK {
		t.Fatalf("honest v5 refused: %v", divergenceStrings(r))
	}
	if r.Custody.Assurance != BrokerAssuranceContainedRootUnchecked {
		t.Fatalf("Custody.Assurance = %q, want %q", r.Custody.Assurance, BrokerAssuranceContainedRootUnchecked)
	}
	if r.Custody.Claim.Version != CustodyV5 || r.Custody.Claim.Marker == "" {
		t.Errorf("Custody.Claim = %+v, want a v5 claim with its marker", r.Custody.Claim)
	}
	if got := r.Custody.Label(); got != BrokerAssuranceLabel(BrokerAssuranceContainedRootUnchecked) {
		t.Errorf("Custody.Label() = %q", got)
	}
}

// TestVerifyV2Production_CustodyParityWithVerifyV2 pins that the reference
// path and the live path report the same custody assessment, and the same
// custody-rule divergence, for the same bundle. The fixtures cover both
// manifest versions (so D7-XCHK's refusals compose with the custody rules)
// and every custody-rule failure the tests above use.
func TestVerifyV2Production_CustodyParityWithVerifyV2(t *testing.T) {
	custodyLiveFakeBin(t)
	v5 := setCustodyRoot("v5", disclosedRecords)
	noMarker := chainEdits(v5, editCustodyLines(dropLinesWithPrefix("MCP_BROKER:")))
	twoRoots := chainEdits(v5, editCustodyLines(duplicateLinesWithPrefix("TOOL_LOG_ROOT:")))

	cases := []struct {
		name   string
		bundle func(t *testing.T) *BundleV2
	}{
		{"v2 manifest, fixture v3 record", func(t *testing.T) *BundleV2 { return v2ManifestCustodyBundle(t, nil) }},
		{"v2 manifest, v4", func(t *testing.T) *BundleV2 {
			return v2ManifestCustodyBundle(t, setCustodyRoot("v4", disclosedRecords))
		}},
		{"v2 manifest, v5 contained", func(t *testing.T) *BundleV2 { return v2ManifestCustodyBundle(t, v5) }},
		{"v2 manifest, v5 no marker", func(t *testing.T) *BundleV2 { return v2ManifestCustodyBundle(t, noMarker) }},
		{"v2 manifest, two roots", func(t *testing.T) *BundleV2 { return v2ManifestCustodyBundle(t, twoRoots) }},
		{"v3 manifest, v4 honest", func(t *testing.T) *BundleV2 {
			return v3CustodyBundle(t, setCustodyRoot("v4", disclosedRecords))
		}},
		{"v3 manifest, v5 honest", func(t *testing.T) *BundleV2 { return v3CustodyBundle(t, v5) }},
		{"v3 manifest, v5 no marker", func(t *testing.T) *BundleV2 { return v3CustodyBundle(t, noMarker) }},
		{"v3 manifest, spliced records", func(t *testing.T) *BundleV2 {
			return v3CustodyBundle(t, setCustodyRoot("v4", otherRecords))
		}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			raw := reencodeBundleV2(t, c.bundle(t))
			ref := VerifyV2(raw, WithAcceptingVerifierForTests())
			live := VerifyV2Production(raw, false)

			if ref.Custody.Assurance != live.Custody.Assurance ||
				ref.Custody.Claim.Version != live.Custody.Claim.Version ||
				ref.Custody.Claim.Marker != live.Custody.Claim.Marker ||
				CustodyRuleCode(ref.Custody.RuleErr) != CustodyRuleCode(live.Custody.RuleErr) {
				t.Errorf("Custody differs: VerifyV2 %+v, production %+v", ref.Custody, live.Custody)
			}
			for _, want := range []error{ErrCustodyRecordInvalid, ErrCustodyToolLogRootMismatch, ErrCustodyLinkUnbound} {
				if a, b := countDiverged(ref, want), countDiverged(live, want); a != b {
					t.Errorf("%v: VerifyV2 reports %d, production %d (%v vs %v)",
						want, a, b, divergenceStrings(ref), divergenceStrings(live))
				}
			}
			if ref.OK != live.OK {
				t.Errorf("OK differs: VerifyV2 %v, production %v (%v vs %v)",
					ref.OK, live.OK, divergenceStrings(ref), divergenceStrings(live))
			}
		})
	}
}

// TestVerifyV2Production_CustodyRefusalComposesWithRootCheck: a v3-manifest
// bundle whose custody record fails a rule is refused by both checks, in
// the same order as VerifyV2: D7-XCHK's ErrCustodyLinkUnbound first (it
// runs in the commitment phase), then ErrCustodyRecordInvalid. Each stays
// a separate divergence, and the bundle is refused either way.
func TestVerifyV2Production_CustodyRefusalComposesWithRootCheck(t *testing.T) {
	custodyLiveFakeBin(t)
	edit := chainEdits(setCustodyRoot("v5", disclosedRecords), editCustodyLines(dropLinesWithPrefix("MCP_BROKER:")))
	r := VerifyV2Production(reencodeBundleV2(t, v3CustodyBundle(t, edit)), false)
	if r.OK {
		t.Fatal("ACCEPTED (OK=true)")
	}
	unbound, invalid := -1, -1
	for i, d := range r.Divergences {
		switch {
		case errors.Is(d.Err, ErrCustodyLinkUnbound):
			unbound = i
		case errors.Is(d.Err, ErrCustodyRecordInvalid):
			invalid = i
		}
	}
	if unbound < 0 || invalid < 0 || unbound > invalid {
		t.Fatalf("want ErrCustodyLinkUnbound before ErrCustodyRecordInvalid, got: %v", divergenceStrings(r))
	}
}
