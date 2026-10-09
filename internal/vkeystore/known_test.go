// Copyright 2026 Jerry David Chan, Konareef.ai
// SPDX-License-Identifier: Apache-2.0

package vkeystore

import "testing"

// TestKnownCircuits_BothPodStepIDsAccepted checks the VHASH migration table:
// v1 and v1.1 are accepted with well-formed, distinct pins, and nothing else is.
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
	if len(pins) != 2 {
		t.Fatalf("v1 and v1.1 must have distinct vkey pins")
	}
	for _, id := range []string{"", "konareef-pod-step-v0", "konareef-pod-step-v2", "konareef-pod-step-v1.10"} {
		if IsSupportedCircuitID(id) {
			t.Errorf("%q accepted, want refused", id)
		}
	}
}
