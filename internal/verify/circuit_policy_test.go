// Copyright 2026 Jerry David Chan, Konareef.ai
// SPDX-License-Identifier: Apache-2.0

// circuit_policy_test.go — tests for the VHASH-M1 circuit policy
// (paygate-zk#14): the bundle's circuit_id must equal the publisher's
// pinned id and a vkey_anchor's circuit_id, and konareef-pod-step-v1 is
// refused once the verifier clock passes the configured cutoff.

package verify

import (
	"encoding/hex"
	"testing"
	"time"

	"github.com/digitsu/konareef/internal/vkeystore"
	"github.com/fxamacker/cbor/v2"
)

// runVerifyWithPolicy verifies b with the accepting Spartan stub and the
// given circuit policy. Output: the result.
func runVerifyWithPolicy(t *testing.T, b *BundleV2, p CircuitPolicy) *ResultV2 {
	t.Helper()
	enc, err := cbor.CoreDetEncOptions().EncMode()
	if err != nil {
		t.Fatalf("enc mode: %v", err)
	}
	raw, err := enc.Marshal(b)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	opts := WithAcceptingVerifierForTests()
	opts.Circuit = p
	return VerifyV2(raw, opts)
}

// v1_1Bundle returns the valid-signature bundle relabelled to v1.1 with
// the pinned v1.1 vkey_hash.
func v1_1Bundle(t *testing.T) *BundleV2 {
	t.Helper()
	pin, _ := vkeystore.KnownVkeySha256For(vkeystore.CircuitIDPodStepV1_1)
	pinBytes, _ := hex.DecodeString(pin)
	return withCircuit(t, vkeystore.CircuitIDPodStepV1_1, pinBytes)
}

// fixedNow returns a clock that always reads ts.
func fixedNow(ts string) func() time.Time {
	at, _ := time.Parse(time.RFC3339, ts)
	return func() time.Time { return at }
}

// TestCircuitPolicy_PublisherPinRefusesV1Downgrade is review finding M-1:
// a v1 bundle for a pod whose publisher pinned v1.1 must not verify.
func TestCircuitPolicy_PublisherPinRefusesV1Downgrade(t *testing.T) {
	b := withCircuit(t, vkeystore.CircuitIDPodStepV1, make([]byte, 32))
	r := runVerifyWithPolicy(t, b, CircuitPolicy{PublisherCircuitID: vkeystore.CircuitIDPodStepV1_1})
	assertDiverged(t, r, ErrCircuitIDMismatch)
	if r.OK {
		t.Fatal("a v1 bundle passed against a v1.1 publisher pin")
	}
}

// TestCircuitPolicy_PublisherPinMatchPasses checks that a matching pin
// adds no divergence.
func TestCircuitPolicy_PublisherPinMatchPasses(t *testing.T) {
	r := runVerifyWithPolicy(t, v1_1Bundle(t), CircuitPolicy{PublisherCircuitID: vkeystore.CircuitIDPodStepV1_1})
	if hasDivergence(r, ErrCircuitIDMismatch) || hasDivergence(r, ErrCircuitRetired) {
		t.Fatalf("matching pin diverged: %v", divergenceStrings(r))
	}
}

// TestCircuitPolicy_VkeyAnchorCircuitMismatch checks that a vkey_anchor
// naming another circuit is refused, and one naming the same circuit is not.
func TestCircuitPolicy_VkeyAnchorCircuitMismatch(t *testing.T) {
	b := withCircuit(t, vkeystore.CircuitIDPodStepV1, make([]byte, 32))
	b.VkeyAnchor = map[string]any{"circuit_id": vkeystore.CircuitIDPodStepV1_1}
	assertDiverged(t, runVerifyWithPolicy(t, b, CircuitPolicy{}), ErrCircuitIDMismatch)

	b.VkeyAnchor = map[string]any{"circuit_id": vkeystore.CircuitIDPodStepV1}
	if r := runVerifyWithPolicy(t, b, CircuitPolicy{}); hasDivergence(r, ErrCircuitIDMismatch) {
		t.Fatalf("matching vkey_anchor circuit_id diverged: %v", divergenceStrings(r))
	}

	b.VkeyAnchor = map[string]any{"circuit_id": 7}
	assertDiverged(t, runVerifyWithPolicy(t, b, CircuitPolicy{}), ErrCircuitIDMismatch)
}

// TestCircuitPolicy_V1RefusedAfterCutoff checks the enforceable end of v1:
// after the cutoff the verifier refuses every v1 bundle, before it v1 is
// still accepted, and v1.1 is never affected.
func TestCircuitPolicy_V1RefusedAfterCutoff(t *testing.T) {
	cutoff, _ := time.Parse(time.RFC3339, "2026-12-01T00:00:00Z")
	v1 := withCircuit(t, vkeystore.CircuitIDPodStepV1, make([]byte, 32))

	after := CircuitPolicy{V1Cutoff: cutoff, Now: fixedNow("2026-12-01T00:00:01Z")}
	r := runVerifyWithPolicy(t, v1, after)
	assertDiverged(t, r, ErrCircuitRetired)
	if r.OK {
		t.Fatal("a v1 bundle passed after the cutoff")
	}

	before := CircuitPolicy{V1Cutoff: cutoff, Now: fixedNow("2026-12-01T00:00:00Z")}
	if r := runVerifyWithPolicy(t, v1, before); hasDivergence(r, ErrCircuitRetired) {
		t.Fatalf("v1 refused at the cutoff: %v", divergenceStrings(r))
	}

	if r := runVerifyWithPolicy(t, v1_1Bundle(t), after); hasDivergence(r, ErrCircuitRetired) {
		t.Fatalf("v1.1 refused by the v1 cutoff: %v", divergenceStrings(r))
	}
}

// TestCircuitPolicy_ZeroValueKeepsCurrentBehaviour checks that the zero
// policy adds no divergence to either id.
func TestCircuitPolicy_ZeroValueKeepsCurrentBehaviour(t *testing.T) {
	for _, b := range []*BundleV2{withCircuit(t, vkeystore.CircuitIDPodStepV1, make([]byte, 32)), v1_1Bundle(t)} {
		r := runVerifyWithPolicy(t, b, CircuitPolicy{})
		if hasDivergence(r, ErrCircuitIDMismatch) || hasDivergence(r, ErrCircuitRetired) {
			t.Fatalf("%s: zero policy diverged: %v", b.CircuitID, divergenceStrings(r))
		}
	}
}

// TestCircuitPolicyFromEnv checks the production configuration: the
// publisher pin and cutoff come from the environment, the build default
// applies when the cutoff variable is unset, and a bad cutoff is an error.
func TestCircuitPolicyFromEnv(t *testing.T) {
	t.Setenv(PublisherCircuitIDEnv, vkeystore.CircuitIDPodStepV1_1)
	t.Setenv(PodStepV1CutoffEnv, "2026-12-01T00:00:00Z")
	p, err := CircuitPolicyFromEnv()
	if err != nil {
		t.Fatalf("CircuitPolicyFromEnv: %v", err)
	}
	if p.PublisherCircuitID != vkeystore.CircuitIDPodStepV1_1 || p.V1Cutoff.Format(time.RFC3339) != "2026-12-01T00:00:00Z" {
		t.Fatalf("policy = %+v", p)
	}

	t.Setenv(PodStepV1CutoffEnv, "")
	old := DefaultPodStepV1Cutoff
	DefaultPodStepV1Cutoff = "2027-01-01T00:00:00Z"
	t.Cleanup(func() { DefaultPodStepV1Cutoff = old })
	if p, err = CircuitPolicyFromEnv(); err != nil || p.V1Cutoff.Format(time.RFC3339) != "2027-01-01T00:00:00Z" {
		t.Fatalf("build default not applied: %+v err=%v", p, err)
	}

	t.Setenv(PublisherCircuitIDEnv, "not-a-circuit")
	if _, err = CircuitPolicyFromEnv(); err == nil {
		t.Fatal("unsupported publisher circuit id accepted")
	}

	t.Setenv(PublisherCircuitIDEnv, "")
	t.Setenv(PodStepV1CutoffEnv, "next tuesday")
	if _, err = CircuitPolicyFromEnv(); err == nil {
		t.Fatal("unparseable cutoff accepted")
	}
}

// TestVerifyV2Production_BadCircuitPolicyFailsClosed checks that the live
// path refuses a bundle when the circuit policy cannot be read, rather than
// verifying with the check switched off.
func TestVerifyV2Production_BadCircuitPolicyFailsClosed(t *testing.T) {
	t.Setenv(PodStepV1CutoffEnv, "next tuesday")
	enc, _ := cbor.CoreDetEncOptions().EncMode()
	raw, err := enc.Marshal(v1_1Bundle(t))
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	r := VerifyV2Production(raw, false)
	assertDiverged(t, r, ErrCircuitPolicyInvalid)
}
