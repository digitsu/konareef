// Copyright 2026 Jerry David Chan, Konareef.ai
// SPDX-License-Identifier: Apache-2.0

// known.go — the pod-step circuit ids this build accepts and the vkey pin
// of each (paygate-zk#12 VHASH, owner decisions O2-A and O4-A).
//
// paygate-zk serves two pod-step circuits during the VHASH migration:
//
//   - konareef-pod-step-v1: the pre-VHASH circuit. Its vkey is unchanged.
//   - konareef-pod-step-v1.1: binds the written memory value to its bytes and
//     makes the pod step genesis-only. It has its own vkey.
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

// knownVkeySha256 maps each accepted pod-step circuit id to the
// SHA-256(vkey) pin of the vkey paygate-zk serves for it.
var knownVkeySha256 = map[string]string{
	CircuitIDPodStepV1:   "0166012bb782673a0892d010b3716191eeb45372ee4854c799a5df80436426ce",
	CircuitIDPodStepV1_1: "eb065a0599b2bd29b260b194706d70c83d8405274920260070333dac4c2fc2e0",
}

// IsSupportedCircuitID reports whether this build accepts a pod-step circuit id.
//
// Input: a circuit id. Output: true for konareef-pod-step-v1 and
// konareef-pod-step-v1.1; false for anything else.
func IsSupportedCircuitID(id string) bool {
	_, ok := knownVkeySha256[id]
	return ok
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
// then v1.1), for flag help and error text.
func SupportedCircuitIDs() []string {
	return []string{CircuitIDPodStepV1, CircuitIDPodStepV1_1}
}
