// Copyright 2026 Jerry David Chan, Konareef.ai
// SPDX-License-Identifier: Apache-2.0

// replay_test.go — the genuine replay, the tamper cases, the proof cases
// and the display strings of the commission replay (IB-07).

package replay

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/digitsu/konareef/internal/canon"
	"github.com/digitsu/konareef/internal/commission"
)

// TestReplayGenuineControl replays the A01 control: the genuine signed
// commission, the pinned manifest and the receipt reef-core writes. The
// verdict is admission_replayed, and each dimension carries exactly the
// status the evidence supports.
func TestReplayGenuineControl(t *testing.T) {
	v := loadVectors(t)
	ev, _ := genuineEvidence(t, v, "A01")
	rep := Replay(ev)

	if rep.Verdict != VerdictAdmissionReplayed {
		t.Fatalf("verdict = %s, want %s; failed=%v\nchecks=%+v", rep.Verdict, VerdictAdmissionReplayed, failedChecks(rep), rep.Checks)
	}
	if got, want := rep.HCommission, v.caseByID(t, "A01").Expect.HCommission; got != want {
		t.Fatalf("h_commission = %s, want the fixture's %s", got, want)
	}
	for _, c := range rep.Checks {
		if c.Outcome != CheckPass && c.Outcome != CheckNotApplicable {
			t.Errorf("check %s = %s (%s), want pass", c.ID, c.Outcome, c.Reason)
		}
	}
	want := map[string]struct {
		status Status
		basis  []string
	}{
		"signature":         {StatusVerified, []string{"buyer_attested"}},
		"run_binding":       {StatusUnverified, []string{"server_asserted"}},
		"manifest_binding":  {StatusVerified, []string{"admission_checked"}},
		"models":            {StatusVerified, []string{"buyer_attested", "admission_checked"}},
		"tools":             {StatusVerified, []string{"buyer_attested", "admission_checked_declared_only"}},
		"spend":             {StatusVerified, []string{"buyer_attested", "admission_checked", "server_asserted"}},
		"labels":            {StatusUnverified, []string{"buyer_attested", "not_evaluated"}},
		"memory":            {StatusVerified, []string{"admission_checked"}},
		"effective_runtime": {StatusUnverified, []string{"server_asserted"}},
		"proof":             {StatusUnverified, nil},
		"inputs":            {StatusUnverified, []string{"not_buyer_signed"}},
	}
	if len(rep.Dimensions) != len(want) {
		t.Fatalf("%d dimensions, want %d", len(rep.Dimensions), len(want))
	}
	for _, d := range rep.Dimensions {
		w, ok := want[d.Name]
		if !ok {
			t.Fatalf("unexpected dimension %s", d.Name)
		}
		if d.Status != w.status || !slices.Equal(d.Basis, w.basis) {
			t.Errorf("%s = %s %v, want %s %v (%s)", d.Name, d.Status, d.Basis, w.status, w.basis, d.Reason)
		}
		if d.Reason == "" {
			t.Errorf("%s has no reason", d.Name)
		}
	}
	if r := dimensionOf(t, rep, "run_binding").Reason; !strings.Contains(r, "server-asserted") {
		t.Errorf("run_binding reason %q does not say server-asserted", r)
	}
	if ExitCode(rep.Verdict) != 0 {
		t.Errorf("exit code %d, want 0", ExitCode(rep.Verdict))
	}
}

// TestReplayAcceptsResponseBody accepts the 201 response body, which
// carries the receipt under "receipt", as well as the bare receipt.
func TestReplayAcceptsResponseBody(t *testing.T) {
	v := loadVectors(t)
	ev, rec := genuineEvidence(t, v, "A01")
	body, err := json.Marshal(map[string]any{"agent_id": "agent-1", "pod_id": "pod-1", "receipt": rec})
	if err != nil {
		t.Fatal(err)
	}
	ev.Receipt = body
	if rep := Replay(ev); rep.Verdict != VerdictAdmissionReplayed {
		t.Fatalf("verdict = %s, want admission_replayed; failed=%v", rep.Verdict, failedChecks(rep))
	}
}

// TestReplayEveryAdmittedFixtureCase replays every case the fixture admits
// (the reef-core IB-04/IB-05 parity set), including the legacy zero root
// (A03), the explicit zero cap (A04), the uint64 cap (A05), the priced pod
// (A06) and the mirrored handle (P05, P06).
func TestReplayEveryAdmittedFixtureCase(t *testing.T) {
	v := loadVectors(t)
	n := 0
	for _, c := range v.Cases {
		if c.Expect.Verdict != "admit" {
			continue
		}
		n++
		t.Run(c.ID, func(t *testing.T) {
			ev, _ := genuineEvidence(t, v, c.ID)
			rep := Replay(ev)
			if rep.Verdict != VerdictAdmissionReplayed {
				t.Fatalf("verdict = %s; failed=%v; checks=%+v", rep.Verdict, failedChecks(rep), rep.Checks)
			}
			if c.Expect.MemoryClass == memoryClassLegacy {
				if r := dimensionOf(t, rep, "memory").Reason; !strings.Contains(r, "not proof-eligible") {
					t.Errorf("legacy memory reason %q does not say not proof-eligible", r)
				}
			}
		})
	}
	if n < 8 {
		t.Fatalf("only %d admitted cases; the fixture has at least 8", n)
	}
}

// replayVisibleCodes are the refusal codes whose cause is in the evidence
// the replay reads. The other refusals depend on the request, the wire
// encoding or server state (keys, rows, revocation), which the buyer's
// artifact does not carry.
var replayVisibleCodes = map[string]bool{
	"commission_signature_invalid":              true,
	"commission_invalid":                        true,
	"commission_binding_mismatch":               true,
	"commission_manifest_version_unsupported":   true,
	"commission_manifest_commitment_unreadable": true,
	"commission_memory_unsupported":             true,
	"commission_sealed_grants_unsupported":      true,
	"commission_model_undeclared":               true,
	"commission_budget_undeclared":              true,
	"commission_tool_policy_invalid":            true,
	"commission_manifest_invalid":               true,
	"commission_fields_root_unpinned":           true,
	"commission_fields_root_mismatch":           true,
	"commission_fields_root_unrecognized":       true,
	"commission_not_contained":                  true,
	"commission_noncanonical":                   true,
}

// TestReplayRefusedFixtureCasesNeverReplayAsAdmitted forges an admission
// receipt for every fixture case the server refuses for a reason in the
// evidence, and checks that the replay reports a contradiction. A receipt
// can say anything; the replay must not believe an admission the contract
// refuses.
func TestReplayRefusedFixtureCasesNeverReplayAsAdmitted(t *testing.T) {
	v := loadVectors(t)
	n := 0
	for _, c := range v.Cases {
		if c.Expect.Verdict != "refuse" || !replayVisibleCodes[c.Expect.Code] {
			continue
		}
		com, err := decodeWire(c.WireHex)
		if err != nil {
			// A wire-level defect (noncanonical bytes, unknown keys): the
			// buyer's artifact cannot carry it. The signature check covers
			// the re-encoded bytes instead (see the S cases).
			continue
		}
		n++
		t.Run(c.ID, func(t *testing.T) {
			manifest, _ := v.manifestByRef(com.Proposal().Binding.PodRef)
			// The forged receipt claims what an admission would: the
			// manifest's true derivation when it has one (so only the
			// refused rule differs), else the commission's own envelope.
			p := com.Proposal()
			c.Expect.DerivedModels, c.Expect.DerivedTools, c.Expect.DerivedCMax = p.Envelope.Models, p.Envelope.Tools, p.Envelope.CMax
			c.Expect.MemoryClass = memoryClassRInitV1
			if d, err := deriveEnvelope(manifest); err == nil {
				c.Expect.DerivedModels, c.Expect.DerivedTools, c.Expect.DerivedCMax = d.models, d.tools, d.cMax
				c.Expect.AuthorFeeSats, c.Expect.MemoryClass = d.authorFee, d.class
			}
			c.Expect.Dimensions = expectedDimensions(c.Expect.MemoryClass)
			rec := receiptFor(t, com, c)
			rep := Replay(Evidence{Commission: &com, Receipt: rec.bytes(t), Manifest: manifest})
			if rep.Verdict != VerdictContradicted {
				t.Fatalf("%s (%s): verdict = %s, want contradicted; checks=%+v", c.ID, c.Expect.Code, rep.Verdict, rep.Checks)
			}
			// A containment refusal must be caught by containment itself,
			// not only by a receipt inconsistency.
			if c.Expect.Code == "commission_not_contained" {
				failed := failedChecks(rep)
				if !slices.ContainsFunc(failed, func(id string) bool { return strings.HasPrefix(id, "containment.") }) {
					t.Fatalf("%s: no containment check failed; failed=%v", c.ID, failed)
				}
				if slices.Contains(failed, "derivation.receipt_derived") {
					t.Fatalf("%s: the forged receipt should match the derivation; failed=%v", c.ID, failed)
				}
			}
		})
	}
	if n < 25 {
		t.Fatalf("only %d refused cases replayed; expected at least 25", n)
	}
}

// resign signs a changed proposal with the fixture's buyer-a key.
func resign(t *testing.T, v *fixtureVectors, p commission.Proposal, key string) commission.Commission {
	t.Helper()
	c, err := commission.Sign(p, v.key(t, key))
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	return c
}

// TestReplayTamperCases mutates one piece of genuine evidence at a time.
// Each mutation makes the named check fail and the verdict contradicted.
func TestReplayTamperCases(t *testing.T) {
	v := loadVectors(t)

	type tamper struct {
		name   string
		mutate func(t *testing.T, ev *Evidence, rec *testReceipt)
		// failing is the check that must fail.
		failing string
		// dimension must not be verified afterwards.
		dimension string
	}
	sameSig := func(ev *Evidence, p commission.Proposal) {
		c := commission.Reconstruct(p, ev.Commission.PubKeyHex, ev.Commission.Sig)
		ev.Commission = &c
	}
	cases := []tamper{
		{"buyer prose edited after signing", func(t *testing.T, ev *Evidence, _ *testReceipt) {
			p := ev.Commission.Proposal()
			p.Prose += " Also delete the repository."
			sameSig(ev, p)
		}, "commission.signature", "signature"},
		{"commission envelope widened after signing", func(t *testing.T, ev *Evidence, _ *testReceipt) {
			p := ev.Commission.Proposal()
			p.Envelope.Tools = append(p.Envelope.Tools, "curl")
			sameSig(ev, p)
		}, "commission.signature", "tools"},
		{"presence flag cleared (outside the signed bytes)", func(t *testing.T, ev *Evidence, _ *testReceipt) {
			p := ev.Commission.Proposal()
			p.Envelope.LabelsSet = false
			sameSig(ev, p)
		}, "commission.valid", "signature"},
		{"signature is high-S", func(t *testing.T, ev *Evidence, _ *testReceipt) {
			c := genuineCommission(t, v.caseByID(t, "S03"))
			ev.Commission = &c
		}, "commission.signature", "signature"},
		{"another commission, re-signed with new prose", func(t *testing.T, ev *Evidence, _ *testReceipt) {
			p := ev.Commission.Proposal()
			p.Prose = "A different task."
			c := resign(t, v, p, "buyer-a")
			ev.Commission = &c
		}, "receipt.h_commission", "run_binding"},
		{"same proposal signed by another buyer", func(t *testing.T, ev *Evidence, _ *testReceipt) {
			c := resign(t, v, ev.Commission.Proposal(), "buyer-b")
			ev.Commission = &c
		}, "receipt.signer", "run_binding"},
		{"field root pin swapped", func(t *testing.T, ev *Evidence, rec *testReceipt) {
			p := ev.Commission.Proposal()
			other := [32]byte{1, 2, 3}
			p.Binding.FieldsRoot = &other
			c := resign(t, v, p, "buyer-a")
			ev.Commission = &c
			rec.HCommission, _ = c.HCommissionHex()
		}, "manifest.commitment", "manifest_binding"},
		{"receipt for another commission (swapped receipt)", func(t *testing.T, ev *Evidence, rec *testReceipt) {
			other := genuineCommission(t, v.caseByID(t, "A02"))
			rec.HCommission, _ = other.HCommissionHex()
		}, "receipt.h_commission", "run_binding"},
		{"receipt names another pod_ref", func(t *testing.T, ev *Evidence, rec *testReceipt) {
			rec.PodRef = "mallory/admit-fixture@1.0.0"
		}, "receipt.pod_ref", "run_binding"},
		{"receipt names another pod_hash", func(t *testing.T, ev *Evidence, rec *testReceipt) {
			rec.PodHash = strings.Repeat("ab", 32)
		}, "receipt.pod_hash", "manifest_binding"},
		{"receipt fields_root swapped", func(t *testing.T, ev *Evidence, rec *testReceipt) {
			rec.FieldsRoot = strings.Repeat("00", 32)
		}, "derivation.fields_root", "models"},
		{"receipt memory class upgraded", func(t *testing.T, ev *Evidence, rec *testReceipt) {
			rec.MemoryClass = memoryClassLegacy
		}, "derivation.memory_class", "memory"},
		{"receipt derived model changed", func(t *testing.T, ev *Evidence, rec *testReceipt) {
			rec.Derived["models"] = []string{"anthropic/claude-opus-4-1"}
		}, "derivation.receipt_derived", "models"},
		{"receipt derived tools narrowed", func(t *testing.T, ev *Evidence, rec *testReceipt) {
			rec.Derived["tools"] = []string{"bash"}
		}, "derivation.receipt_derived", "tools"},
		{"receipt derived model listed twice", func(t *testing.T, ev *Evidence, rec *testReceipt) {
			rec.Derived["models"] = []string{"anthropic/claude-sonnet-4-5", "anthropic/claude-sonnet-4-5"}
		}, "derivation.receipt_derived", "models"},
		{"receipt derived tools duplicated", func(t *testing.T, ev *Evidence, rec *testReceipt) {
			rec.Derived["tools"] = []string{"bash", "bash", "ripgrep"}
		}, "derivation.receipt_derived", "tools"},
		{"receipt derived cap changed", func(t *testing.T, ev *Evidence, rec *testReceipt) {
			rec.Derived["c_max_sats"] = 100
		}, "derivation.receipt_derived", "spend"},
		{"receipt overclaims labels", func(t *testing.T, ev *Evidence, rec *testReceipt) {
			rec.Dimensions["labels"] = "admission_checked"
		}, "receipt.dimensions", "labels"},
		{"receipt overclaims tools as runtime enforced", func(t *testing.T, ev *Evidence, rec *testReceipt) {
			rec.Dimensions["tools"] = "runtime_enforced"
		}, "receipt.dimensions", "tools"},
		{"receipt adds an unknown dimension claim", func(t *testing.T, ev *Evidence, rec *testReceipt) {
			rec.Dimensions["outcome"] = "circuit_verified"
		}, "receipt.dimensions", "models"},
		{"receipt claims a signature it does not carry", func(t *testing.T, ev *Evidence, rec *testReceipt) {
			rec.Authenticity = "server_signed"
		}, "receipt.authenticity", "run_binding"},
		{"receipt claims signed inputs", func(t *testing.T, ev *Evidence, rec *testReceipt) {
			rec.Inputs = "buyer_signed"
		}, "receipt.inputs", "run_binding"},
		{"receipt unknown contract", func(t *testing.T, ev *Evidence, rec *testReceipt) {
			rec.AssuranceMode = "full/v2"
		}, "receipt.contract", "run_binding"},
		{"receipt unknown run state", func(t *testing.T, ev *Evidence, rec *testReceipt) {
			rec.RunState = "finished_and_proven"
		}, "receipt.run_state", "run_binding"},
		{"receipt effective model outside the commission", func(t *testing.T, ev *Evidence, rec *testReceipt) {
			rec.Effective["model_id"] = "anthropic/claude-opus-4-1"
		}, "effective.model", "effective_runtime"},
		{"receipt effective budget over the cap", func(t *testing.T, ev *Evidence, rec *testReceipt) {
			rec.Effective["budget_sats"] = 1_000_000
		}, "effective.budget", "effective_runtime"},
		{"receipt says fees are unbounded", func(t *testing.T, ev *Evidence, rec *testReceipt) {
			rec.Fees["bounded_by_commission"] = false
		}, "derivation.fees", "spend"},
		{"receipt ZK fee pushes spend over the cap", func(t *testing.T, ev *Evidence, rec *testReceipt) {
			rec.Fees["zk_fee_sats"] = 1
		}, "containment.spend_total", "spend"},
		{"manifest swapped for another published pod", func(t *testing.T, ev *Evidence, _ *testReceipt) {
			ev.Manifest = v.manifestByName(t, "mf-legacy")
		}, "manifest.hash", "manifest_binding"},
		{"manifest bytes edited (tool added)", func(t *testing.T, ev *Evidence, _ *testReceipt) {
			ev.Manifest = bytes.Replace(ev.Manifest, []byte(`source = "bash"`), []byte(`source = "bash"`+"\n[[context.tools]]\nsource = \"curl\""), 1)
		}, "manifest.hash", "tools"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ev, rec := genuineEvidence(t, v, "A01")
			tc.mutate(t, &ev, rec)
			ev.Receipt = rec.bytes(t)
			rep := Replay(ev)
			if rep.Verdict != VerdictContradicted {
				t.Fatalf("verdict = %s, want contradicted; checks=%+v", rep.Verdict, rep.Checks)
			}
			if got := checkOutcome(rep, tc.failing); got != CheckFail {
				t.Fatalf("check %s = %q, want fail; failed=%v", tc.failing, got, failedChecks(rep))
			}
			if d := dimensionOf(t, rep, tc.dimension); d.Status == StatusVerified {
				t.Fatalf("dimension %s is still verified: %s", tc.dimension, d.Reason)
			}
			if ExitCode(rep.Verdict) != 4 {
				t.Fatalf("exit code %d, want 4", ExitCode(rep.Verdict))
			}
		})
	}
}

// TestReplayMissingEvidence removes or corrupts one piece of evidence at a
// time. Missing evidence gives "incomplete", never a pass and never a
// crash.
func TestReplayMissingEvidence(t *testing.T) {
	v := loadVectors(t)
	cases := []struct {
		name   string
		mutate func(ev *Evidence)
		want   Verdict
	}{
		{"no commission", func(ev *Evidence) { ev.Commission, ev.CommissionProblem = nil, "read c.cbor: no such file" }, VerdictIncomplete},
		{"no receipt", func(ev *Evidence) { ev.Receipt = nil }, VerdictIncomplete},
		{"no manifest", func(ev *Evidence) { ev.Manifest = nil }, VerdictIncomplete},
		{"receipt is not JSON", func(ev *Evidence) { ev.Receipt = []byte("\x00\xff not json") }, VerdictIncomplete},
		{"receipt is JSON null", func(ev *Evidence) { ev.Receipt = []byte("null") }, VerdictIncomplete},
		{"receipt is an empty object", func(ev *Evidence) { ev.Receipt = []byte("{}") }, VerdictIncomplete},
		{"response with a null receipt", func(ev *Evidence) { ev.Receipt = []byte(`{"receipt":null}`) }, VerdictIncomplete},
		{"receipt with a negative cap (malformed)", func(ev *Evidence) {
			ev.Receipt = bytes.Replace(ev.Receipt, []byte(`"c_max_sats":2500`), []byte(`"c_max_sats":-1`), 1)
		}, VerdictContradicted},
		{"receipt with a string cap (malformed)", func(ev *Evidence) {
			ev.Receipt = bytes.Replace(ev.Receipt, []byte(`"c_max_sats":2500`), []byte(`"c_max_sats":"2500"`), 1)
		}, VerdictContradicted},
		{"receipt with a duplicate key", func(ev *Evidence) {
			ev.Receipt = bytes.Replace(ev.Receipt, []byte(`"run_state":"started"`), []byte(`"run_state":"launch_failed","run_state":"started"`), 1)
		}, VerdictContradicted},
		{"receipt with a case-folded duplicate key", func(ev *Evidence) {
			ev.Receipt = bytes.Replace(ev.Receipt, []byte(`"run_state":"started"`), []byte(`"run_state":"launch_failed","RUN_STATE":"started"`), 1)
		}, VerdictContradicted},
		{"receipt with a Unicode-folded key", func(ev *Evidence) {
			ev.Receipt = bytes.Replace(ev.Receipt, []byte(`"inputs":`), []byte("\"input\u017f\":"), 1)
		}, VerdictContradicted},
		{"receipt for a claimed run", func(ev *Evidence) {
			ev.Receipt = bytes.Replace(ev.Receipt, []byte(`"run_state":"started"`), []byte(`"run_state":"claimed"`), 1)
		}, VerdictIncomplete},
		{"receipt for a released claim", func(ev *Evidence) {
			ev.Receipt = bytes.Replace(ev.Receipt, []byte(`"run_state":"started"`), []byte(`"run_state":"released"`), 1)
		}, VerdictIncomplete},
		{"empty manifest", func(ev *Evidence) { ev.Manifest = []byte{} }, VerdictContradicted},
		{"nothing at all", func(ev *Evidence) { *ev = Evidence{} }, VerdictIncomplete},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ev, _ := genuineEvidence(t, v, "A01")
			tc.mutate(&ev)
			rep := Replay(ev)
			if rep.Verdict != tc.want {
				t.Fatalf("verdict = %s, want %s; checks=%+v", rep.Verdict, tc.want, rep.Checks)
			}
			for _, d := range rep.Dimensions {
				if d.Status == StatusVerified && d.Name != "signature" && d.Name != "manifest_binding" {
					t.Errorf("dimension %s is verified with incomplete evidence: %s", d.Name, d.Reason)
				}
			}
			if ExitCode(rep.Verdict) == 0 {
				t.Fatalf("exit code 0 for %s", rep.Verdict)
			}
		})
	}
}

// TestReplayLaunchFailed replays a receipt whose run never launched: the
// admission replays, the run dimensions do not apply, and a proof offered
// for it supports nothing.
func TestReplayLaunchFailed(t *testing.T) {
	v := loadVectors(t)
	ev, rec := genuineEvidence(t, v, "A01")
	rec.RunState = runStateLaunchFail
	ev.Receipt = rec.bytes(t)
	ev.Proof = []byte{0xa0}
	ev.VerifyProof = func([]byte) ProofCheck {
		t.Fatal("a proof for a run that never launched was verified")
		return ProofCheck{}
	}
	rep := Replay(ev)
	if rep.Verdict != VerdictNotLaunched {
		t.Fatalf("verdict = %s, want %s; failed=%v", rep.Verdict, VerdictNotLaunched, failedChecks(rep))
	}
	for _, name := range []string{"run_binding", "effective_runtime", "proof"} {
		if d := dimensionOf(t, rep, name); d.Status != StatusNotApplicable {
			t.Errorf("%s = %s, want not_applicable", name, d.Status)
		}
	}
	if ExitCode(rep.Verdict) != 5 {
		t.Fatalf("exit code %d, want 5", ExitCode(rep.Verdict))
	}
}

// genuineProof is a proof check that passed, over the given manifest.
func genuineProof(manifest []byte, genesis []byte, disclosure string) ProofVerifier {
	return func([]byte) ProofCheck {
		return ProofCheck{OK: true, Bundle: &BundleFacts{Disclosure: disclosure, Manifest: manifest, GenesisFieldsRoot: genesis}}
	}
}

// trailerOf returns the fields_root the fixture case's binding pins.
func trailerOf(ev Evidence) []byte {
	fr := ev.Commission.Proposal().Binding.FieldsRoot
	return fr[:]
}

// TestReplayWithProof covers the proof dimension: a verified Type-C proof
// over the pinned manifest adds circuit_verified to models, tools and
// spend, and still leaves the run binding server-asserted. Every weaker or
// mismatched proof leaves the proof unverified or contradicts.
func TestReplayWithProof(t *testing.T) {
	v := loadVectors(t)

	t.Run("verified Type-C proof over the pinned manifest", func(t *testing.T) {
		ev, _ := genuineEvidence(t, v, "A01")
		ev.Proof = []byte{0xa0}
		ev.VerifyProof = genuineProof(ev.Manifest, trailerOf(ev), "C")
		rep := Replay(ev)
		if rep.Verdict != VerdictProofVerified {
			t.Fatalf("verdict = %s; failed=%v; checks=%+v", rep.Verdict, failedChecks(rep), rep.Checks)
		}
		for _, name := range []string{"models", "tools", "spend"} {
			d := dimensionOf(t, rep, name)
			if d.Status != StatusVerified || !slices.Contains(d.Basis, "circuit_verified") {
				t.Errorf("%s = %s %v, want verified with circuit_verified", name, d.Status, d.Basis)
			}
			if !strings.Contains(d.Reason, "not bound to this receipt") {
				t.Errorf("%s reason %q does not state that the proof is not bound to the run", name, d.Reason)
			}
		}
		if d := dimensionOf(t, rep, "run_binding"); d.Status != StatusUnverified {
			t.Fatalf("run_binding = %s with a proof; the proof names no run", d.Status)
		}
		if d := dimensionOf(t, rep, "tools"); !strings.Contains(d.Reason, "no runtime restricts") {
			t.Errorf("tools reason %q drops the declaration-only limit", d.Reason)
		}
	})

	weaker := []struct {
		name     string
		id       string
		verifier func(ev Evidence) ProofVerifier
		want     Verdict
		check    string
		outcome  CheckOutcome
	}{
		{"no SNARK verifier configured", "A01", func(ev Evidence) ProofVerifier {
			return func([]byte) ProofCheck {
				return ProofCheck{VerifierMissing: true, Bundle: &BundleFacts{Disclosure: "C", Manifest: ev.Manifest, GenesisFieldsRoot: trailerOf(ev)}}
			}
		}, VerdictAdmissionReplayed, "proof.snark", CheckMissing},
		{"Type-D proof", "A01", func(ev Evidence) ProofVerifier { return genuineProof(ev.Manifest, trailerOf(ev), "D") },
			VerdictAdmissionReplayed, "proof.disclosure", CheckMissing},
		{"legacy zero root is not proof-eligible", "A03", func(ev Evidence) ProofVerifier { return genuineProof(ev.Manifest, trailerOf(ev), "C") },
			VerdictAdmissionReplayed, "proof.memory_eligible", CheckMissing},
		{"swapped proof of another pod", "A01", func(ev Evidence) ProofVerifier {
			return genuineProof(v.manifestByName(t, "mf-priced"), trailerOf(ev), "C")
		}, VerdictContradicted, "proof.manifest", CheckFail},
		{"proof genesis fields_root differs", "A01", func(ev Evidence) ProofVerifier {
			return genuineProof(ev.Manifest, bytes.Repeat([]byte{7}, 32), "C")
		}, VerdictContradicted, "proof.fields_root", CheckFail},
		{"proof fails verification", "A01", func(ev Evidence) ProofVerifier {
			return func([]byte) ProofCheck {
				return ProofCheck{Divergences: []string{"spartan verify err=<nil> ok=false"}, Bundle: &BundleFacts{Disclosure: "C", Manifest: ev.Manifest, GenesisFieldsRoot: trailerOf(ev)}}
			}
		}, VerdictContradicted, "proof.snark", CheckFail},
		{"proof is not a bundle", "A01", func(Evidence) ProofVerifier {
			return func([]byte) ProofCheck { return ProofCheck{DecodeErr: errors.New("ERR_MALFORMED_CBOR")} }
		}, VerdictContradicted, "proof.snark", CheckFail},
	}
	for _, tc := range weaker {
		t.Run(tc.name, func(t *testing.T) {
			ev, _ := genuineEvidence(t, v, tc.id)
			ev.Proof = []byte{0xa0}
			ev.VerifyProof = tc.verifier(ev)
			rep := Replay(ev)
			if rep.Verdict != tc.want {
				t.Fatalf("verdict = %s, want %s; checks=%+v", rep.Verdict, tc.want, rep.Checks)
			}
			if got := checkOutcome(rep, tc.check); got != tc.outcome {
				t.Fatalf("check %s = %s, want %s", tc.check, got, tc.outcome)
			}
			if d := dimensionOf(t, rep, "proof"); d.Status == StatusVerified {
				t.Fatalf("proof verified: %s", d.Reason)
			}
			for _, name := range []string{"models", "tools", "spend"} {
				if slices.Contains(dimensionOf(t, rep, name).Basis, "circuit_verified") {
					t.Fatalf("%s claims circuit_verified", name)
				}
			}
		})
	}
}

// TestReplayArchivedProofFixture runs the production proof path on the
// archived Type-C parity bundle (internal/verify/testdata). The production
// verifier refuses it (it proves another manifest, and no SNARK verifier is
// configured), and the replay's own comparison also finds another manifest,
// so the verdict is a contradiction and no dimension gains
// circuit_verified.
func TestReplayArchivedProofFixture(t *testing.T) {
	t.Setenv("KONAREEF_VERIFY_BIN", "")
	v := loadVectors(t)
	bundle, err := os.ReadFile(filepath.Join("..", "verify", "testdata", "parity-v2-typec.cbor"))
	if err != nil {
		t.Fatal(err)
	}
	ev, _ := genuineEvidence(t, v, "A01")
	ev.Proof = bundle
	rep := Replay(ev)
	if got := checkOutcome(rep, "proof.snark"); got != CheckFail {
		t.Fatalf("proof.snark = %s, want fail; checks=%+v", got, rep.Checks)
	}
	for _, c := range rep.Checks {
		if c.ID == "proof.snark" && !strings.Contains(c.Reason, "no Spartan verifier wired") {
			t.Fatalf("proof.snark reason %q does not name the missing SNARK verifier", c.Reason)
		}
	}
	if got := checkOutcome(rep, "proof.manifest"); got != CheckFail {
		t.Fatalf("proof.manifest = %s, want fail: the archived bundle proves another manifest", got)
	}
	if rep.Verdict != VerdictContradicted {
		t.Fatalf("verdict = %s, want contradicted", rep.Verdict)
	}
}

// TestHeadlines pins the display string of every verdict. None of them
// says the commission was fulfilled or proven, and each weaker verdict
// states what is missing.
func TestHeadlines(t *testing.T) {
	want := map[Verdict]string{
		VerdictContradicted: "CONTRADICTED: the evidence does not agree. Do not rely on this commission-to-run record.",
		VerdictIncomplete:   "INCOMPLETE: some evidence is missing or unreadable. Only the dimensions marked verified hold.",
		VerdictNotLaunched:  "ADMISSION REPLAYED, NO RUN: the admission checks reproduce offline, and the receipt says the commission was consumed without launching a run.",
		VerdictAdmissionReplayed: "ADMISSION REPLAYED: the admission checks reproduce offline. The run-to-commission link is server-asserted, " +
			"and nothing about the run's actions is proven.",
		VerdictProofVerified: "ADMISSION REPLAYED, PROOF VERIFIED: the admission checks reproduce offline, and a verified proof covers the recorded " +
			"steps of a run of this exact manifest. The proof is not bound to this receipt's run, and the run-to-commission link is server-asserted.",
	}
	for verdict, text := range want {
		if got := Headline(verdict); got != text {
			t.Errorf("Headline(%s) = %q, want %q", verdict, got, text)
		}
		lower := strings.ToLower(Headline(verdict))
		for _, overclaim := range []string{"fulfil", "proven commission", "guarantee", "enforced"} {
			if strings.Contains(lower, overclaim) {
				t.Errorf("Headline(%s) contains %q", verdict, overclaim)
			}
		}
	}
	if got := Headline("fully_proven"); !strings.HasPrefix(got, "CONTRADICTED") {
		t.Errorf("an unknown verdict displays as %q, want a CONTRADICTED line", got)
	}
	codes := map[Verdict]int{VerdictProofVerified: 0, VerdictAdmissionReplayed: 0, VerdictNotLaunched: 5, VerdictIncomplete: 3, VerdictContradicted: 4, "unknown": 4}
	for verdict, code := range codes {
		if got := ExitCode(verdict); got != code {
			t.Errorf("ExitCode(%s) = %d, want %d", verdict, got, code)
		}
	}
}

// TestRenderTextByLevel checks the text rendering of each assurance level:
// the headline, the status of the run binding, and the fixed limits.
func TestRenderTextByLevel(t *testing.T) {
	v := loadVectors(t)
	build := map[Verdict]func() Evidence{
		VerdictAdmissionReplayed: func() Evidence { ev, _ := genuineEvidence(t, v, "A01"); return ev },
		VerdictProofVerified: func() Evidence {
			ev, _ := genuineEvidence(t, v, "A01")
			ev.Proof = []byte{0xa0}
			ev.VerifyProof = genuineProof(ev.Manifest, trailerOf(ev), "C")
			return ev
		},
		VerdictNotLaunched: func() Evidence {
			ev, rec := genuineEvidence(t, v, "A01")
			rec.RunState = runStateLaunchFail
			ev.Receipt = rec.bytes(t)
			return ev
		},
		VerdictIncomplete: func() Evidence { ev, _ := genuineEvidence(t, v, "A01"); ev.Manifest = nil; return ev },
		VerdictContradicted: func() Evidence {
			ev, rec := genuineEvidence(t, v, "A01")
			rec.PodRef = "mallory/x@1"
			ev.Receipt = rec.bytes(t)
			return ev
		},
	}
	for verdict, mk := range build {
		t.Run(string(verdict), func(t *testing.T) {
			rep := Replay(mk())
			if rep.Verdict != verdict {
				t.Fatalf("verdict = %s, want %s", rep.Verdict, verdict)
			}
			var out bytes.Buffer
			RenderText(&out, rep, false)
			text := out.String()
			for _, want := range []string{"verdict:   " + string(verdict), Headline(verdict), "run_binding", "Limits",
				"No result of this command means that the commission was fulfilled."} {
				if !strings.Contains(text, want) {
					t.Errorf("text lacks %q:\n%s", want, text)
				}
			}
			if verdict != VerdictNotLaunched && !strings.Contains(text, "run_binding        unverified") {
				t.Errorf("run_binding is not shown as unverified:\n%s", text)
			}
			var js bytes.Buffer
			if err := RenderJSON(&js, rep); err != nil {
				t.Fatal(err)
			}
			var decoded Report
			if err := json.Unmarshal(js.Bytes(), &decoded); err != nil {
				t.Fatalf("JSON does not decode: %v", err)
			}
			if decoded.Verdict != verdict || decoded.Format != ReportFormat {
				t.Fatalf("JSON verdict %s format %s", decoded.Verdict, decoded.Format)
			}
		})
	}
}

// TestReportIsTerminalSafe puts terminal control sequences into every
// server- and manifest-controlled string the report can carry. Neither
// rendering prints a raw control character.
func TestReportIsTerminalSafe(t *testing.T) {
	v := loadVectors(t)
	ev, rec := genuineEvidence(t, v, "A01")
	evil := "\x1b[2J\x1b]0;owned\x07\u009b31m\r"
	rec.ReceiptID = "rid" + evil
	rec.PodRef = "pod" + evil
	rec.Authenticity = "api" + evil
	rec.Dimensions["labels"] = "x" + evil
	rec.Effective["model_id"] = "m" + evil
	ev.Receipt = rec.bytes(t)
	ev.ManifestProblem = "unused" + evil
	rep := Replay(ev)
	if rep.Verdict != VerdictContradicted {
		t.Fatalf("verdict = %s", rep.Verdict)
	}
	var text, js bytes.Buffer
	RenderText(&text, rep, true)
	if err := RenderJSON(&js, rep); err != nil {
		t.Fatal(err)
	}
	for name, out := range map[string]string{"text": text.String(), "json": js.String()} {
		if strings.ContainsAny(out, "\x1b\x07\r\u009b") {
			t.Fatalf("%s output carries a raw control character:\n%q", name, out)
		}
		if !strings.Contains(out, `\x1b`) {
			t.Fatalf("%s output does not show the escaped sequence", name)
		}
	}
}

// TestReportNeverCarriesProse checks that the commission prose appears in
// neither rendering, for a genuine and for a contradicted replay.
func TestReportNeverCarriesProse(t *testing.T) {
	v := loadVectors(t)
	ev, rec := genuineEvidence(t, v, "A01")
	prose := ev.Commission.Proposal().Prose
	if prose == "" {
		t.Fatal("fixture prose is empty")
	}
	for _, mutate := range []func(){func() {}, func() { rec.PodRef = "x/y@1"; ev.Receipt = rec.bytes(t) }} {
		mutate()
		rep := Replay(ev)
		var text, js bytes.Buffer
		RenderText(&text, rep, true)
		_ = RenderJSON(&js, rep)
		for _, out := range []string{text.String(), js.String()} {
			if strings.Contains(out, prose) {
				t.Fatalf("the report discloses the commission prose (verdict %s)", rep.Verdict)
			}
		}
	}
}

// TestReplayNeverPanicsOnHostileBytes feeds malformed receipts, manifests
// and proofs. Every one degrades the verdict; none panics.
func TestReplayNeverPanicsOnHostileBytes(t *testing.T) {
	v := loadVectors(t)
	inputs := [][]byte{nil, {}, []byte("{"), []byte(`{"receipt":{"derived":{"models":7}}}`), bytes.Repeat([]byte{0xff}, 64),
		[]byte("#!konareef-toml/v2\n[_commit]\nfields_root = \"poseidon:zz\"\n"), []byte("#!konareef-toml/v2\n[[[\n")}
	for i, in := range inputs {
		ev, _ := genuineEvidence(t, v, "A01")
		ev.Receipt, ev.Manifest, ev.Proof = in, in, in
		if in == nil {
			ev.Proof = nil
		}
		ev.VerifyProof = ProductionProofVerifier
		rep := Replay(ev)
		if rep == nil || rep.Verdict == VerdictAdmissionReplayed || rep.Verdict == VerdictProofVerified {
			t.Fatalf("input %d: verdict %v", i, rep)
		}
	}
	// A verifier that panics is caught and reported.
	ev, _ := genuineEvidence(t, v, "A01")
	ev.Proof = []byte{0xa0}
	ev.VerifyProof = func([]byte) ProofCheck { panic("boom") }
	if rep := Replay(ev); rep.Verdict != VerdictContradicted || checkOutcome(rep, "replay.internal") != CheckFail {
		t.Fatalf("a panicking verifier gave verdict %s", rep.Verdict)
	}
}

// TestReceiptHexIsCaseInsensitive accepts upper-case hex in the receipt:
// the comparison is on bytes, not on text.
func TestReceiptHexIsCaseInsensitive(t *testing.T) {
	v := loadVectors(t)
	ev, rec := genuineEvidence(t, v, "A01")
	rec.HCommission = strings.ToUpper(rec.HCommission)
	rec.PodHash = strings.ToUpper(rec.PodHash)
	ev.Receipt = rec.bytes(t)
	if rep := Replay(ev); rep.Verdict != VerdictAdmissionReplayed {
		t.Fatalf("verdict = %s; failed=%v", rep.Verdict, failedChecks(rep))
	}
	if _, err := hex.DecodeString(rec.HCommission); err != nil {
		t.Fatal(err)
	}
}

// resignForManifest signs the A01 envelope for a changed manifest, pinning
// its hash and trailer, and returns evidence with a receipt that matches.
// models, when set, replaces the commission's and the receipt's models.
func resignForManifest(t *testing.T, v *fixtureVectors, manifest []byte, models []string) Evidence {
	t.Helper()
	c := v.caseByID(t, "A01")
	p := genuineCommission(t, c).Proposal()
	p.Binding.HManifest = sha256.Sum256(manifest)
	if fr, err := canon.ParseCommitFieldsRoot(manifest); err == nil {
		p.Binding.FieldsRoot = &fr
	}
	if models != nil {
		p.Envelope.Models = models
		c.Expect.DerivedModels = models
	}
	com := resign(t, v, p, "buyer-a")
	rec := receiptFor(t, com, c)
	return Evidence{Commission: &com, Receipt: rec.bytes(t), Manifest: manifest}
}

// withRecomputedTrailer replaces the manifest's fields_root with the one
// its declared fields give under E20.
func withRecomputedTrailer(t *testing.T, manifest []byte, models []string) []byte {
	t.Helper()
	root, err := canon.FieldsRoot(models, []string{"bash", "ripgrep"}, 2500, canon.EmptyMemoryRoot())
	if err != nil {
		t.Fatal(err)
	}
	i := bytes.Index(manifest, []byte("\n[_commit]\n"))
	return append(append([]byte{}, manifest[:i]...), fmt.Sprintf("\n[_commit]\nfields_root = \"poseidon:%x\"\n", root)...)
}

// TestReplayServerParity replays manifests that reef-core's admission
// refuses (security review M1). With a re-signed commission and a matching
// receipt, each one must be a contradiction, never admission_replayed.
func TestReplayServerParity(t *testing.T) {
	v := loadVectors(t)
	ok := v.manifestByName(t, "mf-ok")
	trailerAt := bytes.Index(ok, []byte("\n[_commit]\n"))
	commitLine := string(ok[trailerAt:])
	insertBeforeCommit := func(extra string) []byte {
		return append(append(append([]byte{}, ok[:trailerAt+1]...), extra...), ok[trailerAt+1:]...)
	}
	cases := []struct {
		name     string
		manifest []byte
		models   []string
	}{
		{"blank line after the trailer", append(append([]byte{}, ok...), '\n'), nil},
		{"no final LF", ok[:len(ok)-1], nil},
		{"trailing spaces after fields_root", append(append([]byte{}, ok[:len(ok)-1]...), "  \n"...), nil},
		{"spaced trailer assignment", append(append([]byte{}, ok[:trailerAt]...), strings.Replace(commitLine, "fields_root = ", "fields_root   =   ", 1)...), nil},
		{"r_init_scheme in the trailer", append(append([]byte{}, ok...), "r_init_scheme = \"konareef-rinit/v1\"\n"...), nil},
		{"provider containing a slash", withRecomputedTrailer(t,
			bytes.Replace(ok, []byte(`provider = "anthropic"`), []byte(`provider = "anthropic/x"`), 1),
			[]string{"anthropic/x/claude-sonnet-4-5"}), []string{"anthropic/x/claude-sonnet-4-5"}},
		{"NFD name in tools_denied", bytes.Replace(ok, []byte("template = \"./prompts/system.md\"\n"),
			[]byte("template = \"./prompts/system.md\"\ntools_denied = [\"café\"]\n"), 1), nil},
		{"table after [_files]", insertBeforeCommit("[evil]\nx = 1\n"), nil},
		{"sub-table after [_files]", insertBeforeCommit("[runtime.x]\ny = 2\n"), nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if bytes.Equal(tc.manifest, ok) {
				t.Fatal("the mutation did not change the manifest")
			}
			rep := Replay(resignForManifest(t, v, tc.manifest, tc.models))
			if rep.Verdict != VerdictContradicted {
				t.Fatalf("verdict = %s, want contradicted; checks=%+v", rep.Verdict, rep.Checks)
			}
		})
	}
	// Control: the unchanged manifest, re-signed the same way, replays.
	if rep := Replay(resignForManifest(t, v, ok, nil)); rep.Verdict != VerdictAdmissionReplayed {
		t.Fatalf("control verdict = %s; failed=%v", rep.Verdict, failedChecks(rep))
	}
}
