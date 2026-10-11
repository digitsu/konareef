// Copyright 2026 Jerry David Chan, Konareef.ai
// SPDX-License-Identifier: Apache-2.0

// known.go — the pod-step circuit ids this build accepts and the vkey pin
// of each (paygate-zk#12 VHASH, owner decisions O2-A and O4-A).
//
// paygate-zk serves these pod-step circuits during the VHASH migration:
//
//   - konareef-pod-step-v1: the pre-VHASH circuit. Its vkey is unchanged.
//   - konareef-pod-step-v1.1: binds the written memory value to its bytes and
//     makes the pod step genesis-only. It has its own vkey.
//   - konareef-pod-step-v1.2 (CL-4-live): the memory-bearing read circuit of
//     konareef-rinit/v2. It has its own vkey (paygate-zk!74).
//
// Deploy order (O5-A): konareef accepts both ids first, then PS-1 serves
// both, then publishers move to v1.1, then v1 proving retires. So this
// table lists both ids until v1 is retired.
//
// The pins are SHA-256(vkey) as lowercase hex, where vkey is the 32-byte
// little-endian pp.digest() that PS-1 serves. They match the Rust pins in
// paygate-zk crates/konareef-circuit/tests/param_drift_gate.rs
// (pod_step_vkeys_are_pinned).

package vkeystore

// CircuitIDPodStepV1 is the pre-VHASH pod-step circuit id.
const CircuitIDPodStepV1 = "konareef-pod-step-v1"

// CircuitIDPodStepV1_1 is the VHASH pod-step circuit id (paygate-zk#12).
const CircuitIDPodStepV1_1 = "konareef-pod-step-v1.1"

// CircuitIDPodStepV1_2 is the pod-step circuit id of a memory-bearing run
// (CL-4-live, reef-core#84; docs/reference/konareef-rinit-v2-spec.md
// R-M28): it binds value_hash_in to the 65-byte konareef-rinit/v2 payload
// and proves a read (r_out = r_in). A memory-free step stays on v1.1.
const CircuitIDPodStepV1_2 = "konareef-pod-step-v1.2"

// podStepV1_2VkeySha256 is the SHA-256(vkey) pin of konareef-pod-step-v1.2.
// It is the vkey_hash column of paygate-zk
// crates/konareef-circuit/tests/param_drift_gate.rs (pod_step_vkeys_are_pinned)
// at paygate-zk!74, head e27a7b25 (branch feat/cl4-pod-step-v1-2). The
// vkey itself is 252ca0b7317c053b0dc2ce81712b9c438b7f36881dbafd38555d3bc4648c3003.
// If the pin is empty, this build does not accept v1.2 (fail closed).
const podStepV1_2VkeySha256 = "bcffffbbbc61749b9b511333d476ada29f7d4246269ec544cc85a44fc1c04dc9"

// orderedCircuitIDs is every pod-step circuit id this build knows, in the
// fixed order SupportedCircuitIDs reports them.
var orderedCircuitIDs = []string{CircuitIDPodStepV1, CircuitIDPodStepV1_1, CircuitIDPodStepV1_2}

// knownVkeySha256 maps each accepted pod-step circuit id to the
// SHA-256(vkey) pin of the vkey paygate-zk serves for it. An id without a
// pin is not in the map, so it is not accepted.
var knownVkeySha256 = func() map[string]string {
	m := map[string]string{
		CircuitIDPodStepV1:   "0166012bb782673a0892d010b3716191eeb45372ee4854c799a5df80436426ce",
		CircuitIDPodStepV1_1: "eb065a0599b2bd29b260b194706d70c83d8405274920260070333dac4c2fc2e0",
	}
	if podStepV1_2VkeySha256 != "" {
		m[CircuitIDPodStepV1_2] = podStepV1_2VkeySha256
	}
	return m
}()

// IsSupportedCircuitID reports whether this build accepts a pod-step circuit id.
//
// Input: a circuit id. Output: true for konareef-pod-step-v1,
// konareef-pod-step-v1.1 and, once its vkey pin is set,
// konareef-pod-step-v1.2; false for anything else.
func IsSupportedCircuitID(id string) bool {
	_, ok := knownVkeySha256[id]
	return ok
}

// IsPinnedCircuitID reports whether the verifier must check a bundle's
// vkey_hash against this build's pin for id. v1 keeps its pre-VHASH
// behaviour (legacy artifacts carry other pins), so it is not pinned here.
//
// Input: a circuit id. Output: true for konareef-pod-step-v1.1 and
// konareef-pod-step-v1.2.
func IsPinnedCircuitID(id string) bool {
	return id == CircuitIDPodStepV1_1 || id == CircuitIDPodStepV1_2
}

// KnownVkeySha256For returns the SHA-256(vkey) pin of an accepted circuit id.
//
// Input: a circuit id. Output: the lowercase-hex pin and true, or "" and
// false for an id this build does not accept.
func KnownVkeySha256For(id string) (string, bool) {
	pin, ok := knownVkeySha256[id]
	return pin, ok
}

// SupportedCircuitIDs returns the accepted circuit ids in a fixed order (v1,
// v1.1, then v1.2 when its pin is set), for flag help and error text.
func SupportedCircuitIDs() []string {
	out := make([]string, 0, len(orderedCircuitIDs))
	for _, id := range orderedCircuitIDs {
		if IsSupportedCircuitID(id) {
			out = append(out, id)
		}
	}
	return out
}
