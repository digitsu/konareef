// Copyright 2026 Jerry David Chan, Konareef.ai
// SPDX-License-Identifier: Apache-2.0

package vkeystore

import "testing"

// TestKnownCircuits_BothPodStepIDsAccepted checks the VHASH migration table:
// v1, v1.1 and (once pinned) v1.2 are accepted with well-formed, distinct
// pins, and nothing else is.
func TestKnownCircuits_BothPodStepIDsAccepted(t *testing.T) {
	pins := map[string]bool{}
	for _, id := range SupportedCircuitIDs() {
		if !IsSupportedCircuitID(id) {
			t.Fatalf("%s not accepted", id)
		}
		if err := ValidateCircuitID(id); err != nil {
			t.Fatalf("%s is not a safe circuit id: %v", id, err)
		}
		pin, ok := KnownVkeySha256For(id)
		if !ok || ValidateVkeySha256(pin) != nil {
			t.Fatalf("%s pin %q invalid", id, pin)
		}
		pins[pin] = true
	}
	if len(pins) != len(SupportedCircuitIDs()) || len(pins) < 2 {
		t.Fatalf("every accepted id must have a distinct vkey pin")
	}
	for _, id := range []string{"", "konareef-pod-step-v0", "konareef-pod-step-v2", "konareef-pod-step-v1.10"} {
		if IsSupportedCircuitID(id) {
			t.Errorf("%q accepted, want refused", id)
		}
	}
}

// TestKnownCircuits_PodStepV1_2FailsClosedWithoutPin checks that
// konareef-pod-step-v1.2 is accepted exactly when its pin is set, and is
// then a pinned id in the fixed order after v1.1.
func TestKnownCircuits_PodStepV1_2FailsClosedWithoutPin(t *testing.T) {
	if !IsPinnedCircuitID(CircuitIDPodStepV1_2) || !IsPinnedCircuitID(CircuitIDPodStepV1_1) || IsPinnedCircuitID(CircuitIDPodStepV1) {
		t.Fatal("v1.1 and v1.2 are pinned ids; v1 is not")
	}
	ids := SupportedCircuitIDs()
	if podStepV1_2VkeySha256 == "" {
		if IsSupportedCircuitID(CircuitIDPodStepV1_2) || len(ids) != 2 {
			t.Fatalf("v1.2 must be refused while its pin is unset; supported = %v", ids)
		}
		return
	}
	if !IsSupportedCircuitID(CircuitIDPodStepV1_2) || ids[len(ids)-1] != CircuitIDPodStepV1_2 {
		t.Fatalf("v1.2 must be accepted, last, once pinned; supported = %v", ids)
	}
}

// TestKnownCircuits_PodStepV1_2PinIsSet checks the konareef-pod-step-v1.2
// pin (CL-4-live, reef-core#84): it is set, well formed, and equals the
// vkey_hash paygate-zk pins in param_drift_gate.rs (paygate-zk!74,
// e27a7b25). A change here must follow a paygate-zk re-pin.
func TestKnownCircuits_PodStepV1_2PinIsSet(t *testing.T) {
	if err := ValidateVkeySha256(podStepV1_2VkeySha256); err != nil {
		t.Fatalf("v1.2 pin is malformed: %v", err)
	}
	if podStepV1_2VkeySha256 != "bcffffbbbc61749b9b511333d476ada29f7d4246269ec544cc85a44fc1c04dc9" {
		t.Fatalf("v1.2 pin = %s, want the paygate-zk param_drift_gate value", podStepV1_2VkeySha256)
	}
	if pin, ok := KnownVkeySha256For(CircuitIDPodStepV1_2); !ok || pin != podStepV1_2VkeySha256 {
		t.Fatalf("v1.2 is not accepted with its pin: %q, %v", pin, ok)
	}
}
