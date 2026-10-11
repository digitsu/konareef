// Copyright 2026 Jerry David Chan, Konareef.ai
// SPDX-License-Identifier: Apache-2.0

// Package verify — tests for the custody-total binding of the proven cost
// (paygate-zk MCP-Z00 §7, owner decision O1 option B; c_total.go).
//
// The Rust verifier makes the check. These tests cover this side of it:
// reading TOTAL_SATS from a bound custody link, sending it as
// custody_total_sats, and turning the Rust reject-code line into
// ErrCTotalMismatch. A fake `verify` binary (a shell script) stands in for
// the Rust binary, so the tests run without the Rust toolchain. The
// real-binary run is TestCTotal_RealBinary, gated on two env vars.
package verify

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/fxamacker/cbor/v2"
)

// o1CustodyBlob is a v3 custody blob with the given TOTAL_SATS line(s).
func o1CustodyBlob(totalLines ...string) string {
	lines := []string{
		"CUSTODY_PROOF: v3",
		"CUSTOMER_KEY: fixture-customer",
		"ITERATIONS: 1",
	}
	lines = append(lines, totalLines...)
	lines = append(lines, "AGENT_KEY: agent-o1")
	return strings.Join(lines, "\n")
}

// boundCustodyLink returns a custody link whose hash recomputes from data.
func boundCustodyLink(data string) ChainLinkV2 {
	prev := make([]byte, 32)
	prev[0] = 0xAB
	ts := "2026-09-25T00:00:00Z"
	h := ComputeChainHash(hex.EncodeToString(prev), data, ts)
	return ChainLinkV2{ProofType: "custody", Hash: h[:], PrevHash: prev, Data: []byte(data), Timestamp: ts}
}

func TestCustodyTotalSats_ReadsTheCanonicalLine(t *testing.T) {
	for _, tc := range []struct {
		line string
		want uint64
	}{
		{"TOTAL_SATS: 1281", 1281},
		{"TOTAL_SATS: 0", 0},
		{"TOTAL_SATS: 18446744073709551615", ^uint64(0)},
	} {
		got, err := CustodyTotalSats(o1CustodyBlob(tc.line))
		if err != nil || got != tc.want {
			t.Errorf("%q: got (%d, %v), want (%d, nil)", tc.line, got, err, tc.want)
		}
	}
}

func TestCustodyTotalSats_RefusesMissingRepeatedOrMalformed(t *testing.T) {
	cases := map[string]string{
		"missing":      o1CustodyBlob(),
		"repeated":     o1CustodyBlob("TOTAL_SATS: 1", "TOTAL_SATS: 1"),
		"empty":        o1CustodyBlob("TOTAL_SATS: "),
		"negative":     o1CustodyBlob("TOTAL_SATS: -1"),
		"leading zero": o1CustodyBlob("TOTAL_SATS: 01"),
		"plus sign":    o1CustodyBlob("TOTAL_SATS: +1"),
		"fraction":     o1CustodyBlob("TOTAL_SATS: 1.5"),
		"two spaces":   o1CustodyBlob("TOTAL_SATS:  1"),
		"trailing sp":  o1CustodyBlob("TOTAL_SATS: 1 "),
		"overflow":     o1CustodyBlob("TOTAL_SATS: 18446744073709551616"),
	}
	for name, blob := range cases {
		if _, err := CustodyTotalSats(blob); !errors.Is(err, ErrCTotalMismatch) {
			t.Errorf("%s: err=%v, want ErrCTotalMismatch", name, err)
		}
	}
}

func TestCustodyTotalSatsV2_UsesOnlyABoundTailCustodyLink(t *testing.T) {
	bound := boundCustodyLink(o1CustodyBlob("TOTAL_SATS: 1281"))

	b := &BundleV2{Chain: []ChainLinkV2{{ProofType: "structured_bundle", Hash: make([]byte, 32)}, bound}}
	got, err := custodyTotalSatsV2(b)
	if err != nil || got == nil || *got != 1281 {
		t.Fatalf("bound link: got (%v, %v), want (1281, nil)", got, err)
	}

	typeD := bound
	typeD.Data = nil
	broken := bound
	broken.Hash = append([]byte(nil), bound.Hash...)
	broken.Hash[0] ^= 0xFF
	notTail := []ChainLinkV2{bound, {ProofType: "run_outcome", Hash: make([]byte, 32)}}

	for name, chain := range map[string][]ChainLinkV2{
		"empty chain":        nil,
		"type-D (no data)":   {typeD},
		"hash not bound":     {broken},
		"two custody links":  {bound, bound},
		"custody not tail":   notTail,
		"non-custody single": {{ProofType: "structured_bundle", Hash: make([]byte, 32)}},
	} {
		got, err := custodyTotalSatsV2(&BundleV2{Chain: chain})
		if got != nil || err != nil {
			t.Errorf("%s: got (%v, %v), want (nil, nil): no check", name, got, err)
		}
	}

	// Bound, but the total is unreadable: refuse, never skip.
	bad := boundCustodyLink(o1CustodyBlob("TOTAL_SATS: 1", "TOTAL_SATS: 2"))
	if _, err := custodyTotalSatsV2(&BundleV2{Chain: []ChainLinkV2{bad}}); !errors.Is(err, ErrCTotalMismatch) {
		t.Errorf("bound unreadable total: err=%v, want ErrCTotalMismatch", err)
	}
}

func TestHasCTotalRejectLine_MatchesWholeLinesOnly(t *testing.T) {
	yes := []string{
		"verify: REJECT — ERR_C_TOTAL_MISMATCH: x\nverify: reject_code=ERR_C_TOTAL_MISMATCH\n",
		"verify: reject_code=ERR_C_TOTAL_MISMATCH\r\n",
	}
	no := []string{
		"",
		"verify: REJECT — ERR_C_TOTAL_MISMATCH: final_zi[Z_C_ACC] != custody_total_sats\n",
		"x verify: reject_code=ERR_C_TOTAL_MISMATCH\n",
		"verify: reject_code=ERR_C_TOTAL_MISMATCHED\n",
	}
	for _, s := range yes {
		if !hasCTotalRejectLine([]byte(s)) {
			t.Errorf("want match: %q", s)
		}
	}
	for _, s := range no {
		if hasCTotalRejectLine([]byte(s)) {
			t.Errorf("want no match: %q", s)
		}
	}
}

// fakeVerifyBin writes a shell script that copies its envelope argument to
// outPath, prints stderr, and exits with exitCode. It skips on Windows.
func fakeVerifyBin(t *testing.T, outPath, stderr string, exitCode int) string {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("fake verify binary is a POSIX shell script")
	}
	script := fmt.Sprintf("#!/bin/sh\ncp \"$1\" %q\nprintf '%%b' %q >&2\nexit %d\n",
		outPath, stderr, exitCode)
	path := filepath.Join(t.TempDir(), "verify")
	if err := os.WriteFile(path, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	return path
}

// sentEnvelope reads the envelope the fake binary copied.
func sentEnvelope(t *testing.T, outPath string) map[string]json.RawMessage {
	t.Helper()
	raw, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatalf("fake binary did not receive an envelope: %v", err)
	}
	var env map[string]json.RawMessage
	if err := json.Unmarshal(raw, &env); err != nil {
		t.Fatal(err)
	}
	return env
}

// o1Scr is a carrier with a well-formed 736-byte z0.
func o1Scr() SpartanCompressResult {
	return SpartanCompressResult{
		SpartanSnark: []byte{1}, FirstStepPublicInputs: make([]byte, 298),
		LastStepPublicInputs: make([]byte, 298), VkeyHash: make([]byte, 32),
		CircuitID: "konareef-pod-step-v1", Z0: make([]byte, z0LaneCount*z0LaneWidth),
	}
}

func TestSubprocessVerifier_SendsTheTotalAndNamesTheRefusal(t *testing.T) {
	b := &BundleV2{SpartanCompressResult: o1Scr(),
		Chain: []ChainLinkV2{boundCustodyLink(o1CustodyBlob("TOTAL_SATS: 1281"))}}
	out := filepath.Join(t.TempDir(), "env.json")

	// Genuine match: the Rust side accepts and confirms the c check.
	v := newSubprocessVerifier(b, fakeVerifyBin(t, out, "verify: pod_step_schedule=checked\nverify: c_total=checked\nverify: ACCEPT\n", 0))
	ok, err := v.Verify(b.SpartanCompressResult.SpartanSnark, nil, nil, nil)
	if !ok || err != nil {
		t.Fatalf("accept: got (%v, %v)", ok, err)
	}
	if got := string(sentEnvelope(t, out)["custody_total_sats"]); got != "1281" {
		t.Fatalf("custody_total_sats sent = %q, want 1281", got)
	}

	// Mismatch: the Rust side refuses with the reject-code line.
	v = newSubprocessVerifier(b, fakeVerifyBin(t, out,
		"verify: REJECT — ERR_C_TOTAL_MISMATCH: final_zi[Z_C_ACC] != custody_total_sats\n"+
			"verify: reject_code=ERR_C_TOTAL_MISMATCH\n", 1))
	ok, err = v.Verify(nil, nil, nil, nil)
	if ok || !errors.Is(err, ErrCTotalMismatch) {
		t.Fatalf("mismatch: got (%v, %v), want (false, ErrCTotalMismatch)", ok, err)
	}

	// A binary built before custody_total_sats ignores it and accepts with
	// no confirmation line: fail closed.
	v = newSubprocessVerifier(b, fakeVerifyBin(t, out, "verify: pod_step_schedule=checked\nverify: ACCEPT\n", 0))
	ok, err = v.Verify(nil, nil, nil, nil)
	if ok || !errors.Is(err, ErrCTotalMismatch) {
		t.Fatalf("unconfirmed accept: got (%v, %v), want (false, ErrCTotalMismatch)", ok, err)
	}

	// Any other reject stays a plain reject.
	v = newSubprocessVerifier(b, fakeVerifyBin(t, out, "verify: REJECT — bad snark\n", 1))
	ok, err = v.Verify(nil, nil, nil, nil)
	if ok || err != nil {
		t.Fatalf("plain reject: got (%v, %v), want (false, nil)", ok, err)
	}
}

func TestSubprocessVerifier_NoBoundTotalSendsNoField(t *testing.T) {
	typeD := boundCustodyLink(o1CustodyBlob("TOTAL_SATS: 1281"))
	typeD.Data = nil
	b := &BundleV2{SpartanCompressResult: o1Scr(), Chain: []ChainLinkV2{typeD}}
	out := filepath.Join(t.TempDir(), "env.json")

	v := newSubprocessVerifier(b, fakeVerifyBin(t, out, "verify: pod_step_schedule=checked\n", 0))
	if ok, err := v.Verify(nil, nil, nil, nil); !ok || err != nil {
		t.Fatalf("got (%v, %v)", ok, err)
	}
	if _, present := sentEnvelope(t, out)["custody_total_sats"]; present {
		t.Fatal("custody_total_sats sent for a bundle with no bound custody total")
	}
}

func TestSubprocessVerifier_UnreadableTotalRefusesWithoutSpawning(t *testing.T) {
	b := &BundleV2{SpartanCompressResult: o1Scr(),
		Chain: []ChainLinkV2{boundCustodyLink(o1CustodyBlob("TOTAL_SATS: 01"))}}
	out := filepath.Join(t.TempDir(), "env.json")

	v := newSubprocessVerifier(b, fakeVerifyBin(t, out, "", 0))
	ok, err := v.Verify(nil, nil, nil, nil)
	if ok || !errors.Is(err, ErrCTotalMismatch) {
		t.Fatalf("got (%v, %v), want (false, ErrCTotalMismatch)", ok, err)
	}
	if _, statErr := os.Stat(out); !os.IsNotExist(statErr) {
		t.Fatal("the verify binary ran although the custody total was unreadable")
	}
}

// cTotalStub is a SpartanVerifier that returns a fixed result.
type cTotalStub struct {
	ok  bool
	err error
}

func (s cTotalStub) Verify(_, _, _, _ []byte) (bool, error) { return s.ok, s.err }

func TestSnarkPhase_CTotalMismatchIsItsOwnDivergence(t *testing.T) {
	b := bundleWithValidPublisherSig(t)
	r := &ResultV2{OK: true}
	verifySnarkPhase(b, VerifyOptions{Spartan: cTotalStub{false,
		fmt.Errorf("%w: proven c != custody TOTAL_SATS", ErrCTotalMismatch)}}, r)

	assertDiverged(t, r, ErrCTotalMismatch)
	if r.V2Verdict.ProofValid {
		t.Error("ProofValid=true after a c-total refusal")
	}
	for _, d := range r.Divergences {
		if errors.Is(d.Err, ErrProofRejected) {
			t.Errorf("c-total refusal also reported as a bare ERR_PROOF_REJECTED: %s", d.Msg)
		}
	}
}

// productionBundle is bundleWithValidPublisherSig with a bound custody
// link carrying TOTAL_SATS, CBOR-encoded for VerifyV2Production.
func productionBundle(t *testing.T, totalLine string) []byte {
	t.Helper()
	b := bundleWithValidPublisherSig(t)
	b.SpartanCompressResult.Z0 = make([]byte, z0LaneCount*z0LaneWidth)
	b.Chain = []ChainLinkV2{boundCustodyLink(o1CustodyBlob(totalLine))}
	enc, err := cbor.CoreDetEncOptions().EncMode()
	if err != nil {
		t.Fatal(err)
	}
	raw, err := enc.Marshal(b)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestVerifyV2Production_CTotalChecked(t *testing.T) {
	out := filepath.Join(t.TempDir(), "env.json")

	t.Setenv(VerifyBinEnv, fakeVerifyBin(t, out, "verify: pod_step_schedule=checked\nverify: c_total=checked\nverify: ACCEPT\n", 0))
	r := VerifyV2Production(productionBundle(t, "TOTAL_SATS: 1281"), false)
	// The proof is valid, but this synthetic bundle fails other checks (a
	// Type-D bundle carrying link data), so the flag must stay false.
	if !r.V2Verdict.ProofValid || r.OK || r.CTotalChecked {
		t.Fatalf("accept: ProofValid=%v OK=%v CTotalChecked=%v divergences=%v",
			r.V2Verdict.ProofValid, r.OK, r.CTotalChecked, divergenceStrings(r))
	}
	if got := string(sentEnvelope(t, out)["custody_total_sats"]); got != "1281" {
		t.Fatalf("custody_total_sats sent = %q, want 1281", got)
	}

	t.Setenv(VerifyBinEnv, fakeVerifyBin(t, out, "verify: reject_code=ERR_C_TOTAL_MISMATCH\n", 1))
	r = VerifyV2Production(productionBundle(t, "TOTAL_SATS: 1281"), false)
	assertDiverged(t, r, ErrCTotalMismatch)
	if r.CTotalChecked || r.V2Verdict.ProofValid {
		t.Errorf("mismatch: CTotalChecked=%v ProofValid=%v, want both false",
			r.CTotalChecked, r.V2Verdict.ProofValid)
	}
}

func TestCTotalChecked_OnlyForAConfirmedPassingBundle(t *testing.T) {
	total := uint64(1281)
	withTotal := VerifyOptions{Spartan: subprocessVerifier{custodyTotal: &total}}
	noTotal := VerifyOptions{Spartan: subprocessVerifier{}}
	stub := VerifyOptions{Spartan: cTotalStub{ok: true}}
	pass := func(ok, proof bool) *ResultV2 {
		return &ResultV2{OK: ok, V2Verdict: &Verdict{ProofValid: proof}}
	}

	if !cTotalChecked(withTotal, pass(true, true)) {
		t.Error("passing bundle with a confirmed total: want true")
	}
	for name, tc := range map[string]struct {
		opts VerifyOptions
		r    *ResultV2
	}{
		"bundle failed another check": {withTotal, pass(false, true)},
		"proof invalid":               {withTotal, pass(false, false)},
		"no custody total":            {noTotal, pass(true, true)},
		"not the real verifier":       {stub, pass(true, true)},
		"no verdict":                  {withTotal, &ResultV2{OK: true}},
	} {
		if cTotalChecked(tc.opts, tc.r) {
			t.Errorf("%s: want false", name)
		}
	}
}

// TestCTotal_RealBinary runs the REAL Rust `verify` binary on a genuine
// envelope written by paygate-zk's real-prover test, with the envelope's
// custody total set to c, c+1 and c-1. It skips unless
// KONAREEF_VERIFY_BIN and KONAREEF_O1_ENVELOPE (a VerifyEnvelope JSON
// file with custody_total_sats = c) are set.
//
// Since paygate-zk#13 (VHASH-FU) the paygate-zk test writes one envelope
// per pod-step circuit id: run it with KONAREEF_O1_ENVELOPE_OUT=<dir>, then
// run this test once with each of <dir>/o1-envelope-konareef-pod-step-v1.json
// and <dir>/o1-envelope-konareef-pod-step-v1.1.json.
func TestCTotal_RealBinary(t *testing.T) {
	bin, envPath := os.Getenv(VerifyBinEnv), os.Getenv("KONAREEF_O1_ENVELOPE")
	if bin == "" || envPath == "" {
		t.Skipf("%s and KONAREEF_O1_ENVELOPE unset — skipping real-binary c-total run", VerifyBinEnv)
	}
	raw, err := os.ReadFile(envPath)
	if err != nil {
		t.Fatal(err)
	}
	var env struct {
		SnarkInts        []int   `json:"snark"`
		VkeyInts         []int   `json:"vkey"`
		FirstInts        []int   `json:"first_step"`
		LastInts         []int   `json:"last_step"`
		VkeyHashInts     []int   `json:"vkey_hash"`
		CircuitID        string  `json:"circuit_id"`
		Z0Lanes          [][]int `json:"z0_lanes"`
		CustodyTotalSats *uint64 `json:"custody_total_sats"`
	}
	if err := json.Unmarshal(raw, &env); err != nil {
		t.Fatal(err)
	}
	if env.CustodyTotalSats == nil || *env.CustodyTotalSats == 0 {
		t.Fatal("envelope must carry a positive custody_total_sats (the proof's c)")
	}
	toBytes := func(xs []int) []byte {
		out := make([]byte, len(xs))
		for i, x := range xs {
			out[i] = byte(x)
		}
		return out
	}
	var z0 []byte
	for _, lane := range env.Z0Lanes {
		z0 = append(z0, toBytes(lane)...)
	}
	c := *env.CustodyTotalSats
	verifier := func(total uint64) subprocessVerifier {
		return subprocessVerifier{
			binPath: bin, timeout: 0, vkey: toBytes(env.VkeyInts), custodyTotal: &total,
			scr: SpartanCompressResult{VkeyHash: toBytes(env.VkeyHashInts), CircuitID: env.CircuitID, Z0: z0},
		}
	}
	run := func(total uint64) (bool, error) {
		return verifier(total).Verify(toBytes(env.SnarkInts), toBytes(env.FirstInts),
			toBytes(env.LastInts), toBytes(env.VkeyInts))
	}

	if ok, err := run(c); !ok || err != nil {
		t.Fatalf("c == custody total: got (%v, %v), want accept", ok, err)
	}
	for name, total := range map[string]uint64{"custody c+1": c + 1, "custody c-1": c - 1} {
		if ok, err := run(total); ok || !errors.Is(err, ErrCTotalMismatch) {
			t.Errorf("%s: got (%v, %v), want (false, ErrCTotalMismatch)", name, ok, err)
		}
	}
}

// TestSubprocessVerifier_RequiresTheScheduleLine covers VHASH versioning
// review M-2: a stale `verify` binary (built before paygate-zk!68) accepts
// without printing the pod-step schedule line, and that accept is refused,
// with or without a custody total. The current binary's line is accepted.
func TestSubprocessVerifier_RequiresTheScheduleLine(t *testing.T) {
	noTotal := &BundleV2{SpartanCompressResult: o1Scr()}
	withTotal := &BundleV2{SpartanCompressResult: o1Scr(),
		Chain: []ChainLinkV2{boundCustodyLink(o1CustodyBlob("TOTAL_SATS: 1281"))}}
	out := filepath.Join(t.TempDir(), "env.json")
	for name, b := range map[string]*BundleV2{"no total": noTotal, "with total": withTotal} {
		stale := newSubprocessVerifier(b, fakeVerifyBin(t, out, "verify: c_total=checked\nverify: ACCEPT\n", 0))
		if ok, err := stale.Verify(nil, nil, nil, nil); ok || !errors.Is(err, ErrProofRejected) {
			t.Errorf("%s: stale binary: got (%v, %v), want (false, ErrProofRejected)", name, ok, err)
		}
		current := newSubprocessVerifier(b, fakeVerifyBin(t, out,
			"verify: pod_step_schedule=checked\nverify: c_total=checked\nverify: ACCEPT\n", 0))
		if ok, err := current.Verify(nil, nil, nil, nil); !ok || err != nil {
			t.Errorf("%s: current binary: got (%v, %v), want accept", name, ok, err)
		}
	}
}

// TestSubprocessVerifier_RefusesNonGenesisZ0WithoutSpawning covers the Go
// defense-in-depth half of M-2: a z0 whose step_index lane is not zero is
// refused before the binary runs, even by a binary that would accept.
func TestSubprocessVerifier_RefusesNonGenesisZ0WithoutSpawning(t *testing.T) {
	scr := o1Scr()
	scr.Z0[zStepIndexLane*z0LaneWidth] = 1 // step_index = 1 (LE)
	b := &BundleV2{SpartanCompressResult: scr}
	out := filepath.Join(t.TempDir(), "env.json")
	v := newSubprocessVerifier(b, fakeVerifyBin(t, out,
		"verify: pod_step_schedule=checked\nverify: ACCEPT\n", 0))
	if ok, err := v.Verify(nil, nil, nil, nil); ok || !errors.Is(err, ErrProofRejected) {
		t.Fatalf("got (%v, %v), want (false, ErrProofRejected)", ok, err)
	}
	if _, statErr := os.Stat(out); !os.IsNotExist(statErr) {
		t.Fatal("the verify binary ran although z0 step_index was not zero")
	}
}
