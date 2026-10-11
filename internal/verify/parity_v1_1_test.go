// Copyright 2026 Jerry David Chan, Konareef.ai
// SPDX-License-Identifier: Apache-2.0

// parity_v1_1_test.go — the Type-C parity artifact for the
// konareef-pod-step-v1.1 circuit (VHASH-FU, script-verify/paygate-zk#13).
//
// reef-core packs testdata/parity-v2-typec-v1_1.cbor with
// `ReefCore.BundleV2Fixture.insert_type_c!(circuit_id: "konareef-pod-step-v1.1")`
// (test/support/fixtures/bundle_v2/parity-v2-typec-v1_1.cbor there). It is
// the v1 Type-C parity bundle with three changes: the circuit id, the real
// v1.1 vkey, and its pinned vkey_hash. TestRegenerateParityTRoot then sets
// its Poseidon t_root, as for the v1 file. The proof bytes stay synthetic,
// so these tests use the accepting SNARK stub.

package verify

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"testing"

	"github.com/digitsu/konareef/internal/vkeystore"
	"github.com/fxamacker/cbor/v2"
)

// parityV1_1VkeyLEHex is the v1.1 vkey (pp.digest(), 32 bytes LE). It equals
// paygate-zk VKEY_V1_1_LE_HEX; SHA-256 of it is the vkeystore v1.1 pin.
const parityV1_1VkeyLEHex = "4bedb9d36ca9f4f7c176f1637acea80e60d714bfc5b80358fba1453fa766f302"

// TestParity_V2_RoundTrip_TypeC_V1_1 checks that the reef-core-packed v1.1
// Type-C bundle carries the pinned v1.1 vkey, passes the circuit gate, and
// otherwise gets the same verdict as the v1 Type-C parity bundle: Check 4
// fails closed on the synthetic pk_pub, and the chain policy passes.
func TestParity_V2_RoundTrip_TypeC_V1_1(t *testing.T) {
	raw := loadParityEnvelopeStripped(t, "parity-v2-typec-v1_1.cbor")
	b, err := decodeBundleV2(raw)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if b.CircuitID != vkeystore.CircuitIDPodStepV1_1 || b.SpartanCompressResult.CircuitID != vkeystore.CircuitIDPodStepV1_1 {
		t.Fatalf("circuit_id = %q / %q, want %q at both levels",
			b.CircuitID, b.SpartanCompressResult.CircuitID, vkeystore.CircuitIDPodStepV1_1)
	}
	if got := hex.EncodeToString(b.Vkey); got != parityV1_1VkeyLEHex {
		t.Errorf("vkey = %s, want the v1.1 vkey %s", got, parityV1_1VkeyLEHex)
	}
	pin, _ := vkeystore.KnownVkeySha256For(vkeystore.CircuitIDPodStepV1_1)
	vkeySum := sha256.Sum256(b.Vkey)
	if hex.EncodeToString(vkeySum[:]) != pin || hex.EncodeToString(b.SpartanCompressResult.VkeyHash) != pin {
		t.Errorf("SHA-256(vkey) = %x, vkey_hash = %x, want both = pin %s",
			vkeySum, b.SpartanCompressResult.VkeyHash, pin)
	}

	r := VerifyV2(raw, WithAcceptingVerifierForTests())
	if hasDivergence(r, ErrUnsupportedCircuit) || hasDivergence(r, ErrVkeyMismatch) {
		t.Errorf("v1.1 parity refused at the circuit gate: %v", divergenceStrings(r))
	}
	if r.OK {
		t.Errorf("v1.1 parity (no valid pk_pub) accepted; Check 4 fail-closed is broken")
	}
	if r.V2Verdict == nil {
		t.Fatal("v2 verdict missing")
	}
	if !signatureInvalidDiverged(r) {
		t.Errorf("expected ErrSignatureInvalid divergence; got: %v", divergenceStrings(r))
	}
	if !r.V2Verdict.ChainPolicyValid {
		t.Errorf("v1.1 parity chain refused: %v", divergenceStrings(r))
	}
}

// TestParity_V2_TypeC_V1_1_WrongVkeyHashDiverges checks that the v1.1
// parity bundle is refused with ErrVkeyMismatch when its vkey_hash is the
// v1 pin instead of the v1.1 pin.
func TestParity_V2_TypeC_V1_1_WrongVkeyHashDiverges(t *testing.T) {
	b, err := decodeBundleV2(loadParityEnvelopeStripped(t, "parity-v2-typec-v1_1.cbor"))
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	v1Pin, _ := vkeystore.KnownVkeySha256For(vkeystore.CircuitIDPodStepV1)
	v1PinBytes, _ := hex.DecodeString(v1Pin)
	if bytes.Equal(b.SpartanCompressResult.VkeyHash, v1PinBytes) {
		t.Fatal("fixture already carries the v1 pin; the test would prove nothing")
	}
	b.SpartanCompressResult.VkeyHash = v1PinBytes

	enc, err := cbor.CoreDetEncOptions().EncMode()
	if err != nil {
		t.Fatalf("enc mode: %v", err)
	}
	out, err := enc.Marshal(b)
	if err != nil {
		t.Fatalf("re-encode: %v", err)
	}
	assertDiverged(t, VerifyV2(out, WithAcceptingVerifierForTests()), ErrVkeyMismatch)
}
