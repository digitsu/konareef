// Copyright 2026 Jerry David Chan, Konareef.ai
// SPDX-License-Identifier: Apache-2.0

package verify

import (
	"encoding/hex"
	"errors"
	"testing"

	"github.com/digitsu/konareef/internal/vkeystore"
)

// hasDivergence reports whether r carries a divergence wrapping want.
func hasDivergence(r *ResultV2, want error) bool {
	for _, d := range r.Divergences {
		if errors.Is(d.Err, want) {
			return true
		}
	}
	return false
}

// withCircuit returns the valid-signature bundle relabelled to circuit id
// (top level and inner) with the given vkey_hash.
func withCircuit(t *testing.T, id string, vkeyHash []byte) *BundleV2 {
	t.Helper()
	b := bundleWithValidPublisherSig(t)
	b.CircuitID = id
	b.SpartanCompressResult.CircuitID = id
	b.SpartanCompressResult.VkeyHash = vkeyHash
	return b
}

// TestCircuitIDs_V1AndV1_1Accepted checks the VHASH migration gate
// (paygate-zk#12, O2-A): both pod-step ids pass the circuit gate and reach
// the later checks (Check 4 sets SignatureValid). v1 keeps its pre-VHASH
// behaviour: no vkey pin check at the gate.
func TestCircuitIDs_V1AndV1_1Accepted(t *testing.T) {
	pin, _ := vkeystore.KnownVkeySha256For(vkeystore.CircuitIDPodStepV1_1)
	pinBytes, _ := hex.DecodeString(pin)
	for _, tc := range []struct {
		id       string
		vkeyHash []byte
	}{
		{vkeystore.CircuitIDPodStepV1, make([]byte, 32)},
		{vkeystore.CircuitIDPodStepV1_1, pinBytes},
	} {
		v, r := runVerify(t, withCircuit(t, tc.id, tc.vkeyHash))
		if hasDivergence(r, ErrUnsupportedCircuit) || hasDivergence(r, ErrVkeyMismatch) {
			t.Errorf("%s: refused at the circuit gate: %v", tc.id, divergenceStrings(r))
		}
		if !v.SignatureValid {
			t.Errorf("%s: later checks did not run (SignatureValid=false)", tc.id)
		}
	}
}

// TestCircuitIDs_V1_1WrongVkeyHashDiverges checks that a v1.1 bundle whose
// vkey_hash is not the pinned v1.1 vkey (here: the v1 pin) is refused.
func TestCircuitIDs_V1_1WrongVkeyHashDiverges(t *testing.T) {
	v1Pin, _ := vkeystore.KnownVkeySha256For(vkeystore.CircuitIDPodStepV1)
	v1PinBytes, _ := hex.DecodeString(v1Pin)
	_, r := runVerify(t, withCircuit(t, vkeystore.CircuitIDPodStepV1_1, v1PinBytes))
	assertDiverged(t, r, ErrVkeyMismatch)
}

// TestCircuitIDs_UnknownIDsDiverge checks that ids outside the table are
// still refused with ErrUnsupportedCircuit.
func TestCircuitIDs_UnknownIDsDiverge(t *testing.T) {
	for _, id := range []string{"konareef-pod-step-v2", "konareef-pod-step-v0", "konareef-pod-step-v1.10"} {
		_, r := runVerify(t, withCircuit(t, id, make([]byte, 32)))
		assertDiverged(t, r, ErrUnsupportedCircuit)
	}
}

// TestCircuitIDs_V1_2 checks konareef-pod-step-v1.2 (CL-4-live,
// reef-core#84). While this build has no v1.2 vkey pin, a v1.2 bundle is
// refused at the circuit gate (fail closed). Once the pin is set, a v1.2
// bundle with the pinned vkey_hash passes the gate and reaches the later
// checks, and one with another vkey_hash (the v1.1 pin) is refused.
func TestCircuitIDs_V1_2(t *testing.T) {
	pin, ok := vkeystore.KnownVkeySha256For(vkeystore.CircuitIDPodStepV1_2)
	if !ok {
		_, r := runVerify(t, withCircuit(t, vkeystore.CircuitIDPodStepV1_2, make([]byte, 32)))
		assertDiverged(t, r, ErrUnsupportedCircuit)
		return
	}
	pinBytes, _ := hex.DecodeString(pin)
	v, r := runVerify(t, withCircuit(t, vkeystore.CircuitIDPodStepV1_2, pinBytes))
	if hasDivergence(r, ErrUnsupportedCircuit) || hasDivergence(r, ErrVkeyMismatch) || !v.SignatureValid {
		t.Errorf("v1.2 with its pinned vkey refused at the circuit gate: %v", divergenceStrings(r))
	}
	v11Pin, _ := vkeystore.KnownVkeySha256For(vkeystore.CircuitIDPodStepV1_1)
	v11PinBytes, _ := hex.DecodeString(v11Pin)
	_, r = runVerify(t, withCircuit(t, vkeystore.CircuitIDPodStepV1_2, v11PinBytes))
	assertDiverged(t, r, ErrVkeyMismatch)
}
