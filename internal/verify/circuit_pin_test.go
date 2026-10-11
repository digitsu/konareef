// Copyright 2026 Jerry David Chan, Konareef.ai
// SPDX-License-Identifier: Apache-2.0

// circuit_pin_test.go — tests for the node-signed publisher circuit pin
// (circuit_pin.go, VHASH-ROLLOUT part 2): the recorded cross-repo vector,
// a valid pin, the refusals (tampered circuit id, wrong key, wrong domain,
// malformed map, missing pod_hash), the downgrade refusal, an untrusted
// key, an absent pin, and the precedence over KONAREEF_PUBLISHER_CIRCUIT_ID.
package verify

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/fxamacker/cbor/v2"

	"github.com/digitsu/konareef/internal/spv"
	"github.com/digitsu/konareef/internal/spv/spvtest"
	"github.com/digitsu/konareef/internal/vkeystore"
)

// circuitPinVector is the JSON shape of the recorded cross-repo vector.
// reef-core vendors a byte copy (test/support/fixtures/chain_head_anchor/)
// and checks that its Elixir code builds the same statement and pin map
// and verifies the same signatures.
type circuitPinVector struct {
	Comment     string `json:"comment"`
	IdentityKey string `json:"identity_key_hex"`
	Invoice     string `json:"invoice"`
	DerivedKey  string `json:"derived_key_hex"`
	PodHash     string `json:"pod_hash_hex"`
	CircuitID   string `json:"circuit_id"`
	Statement   string `json:"statement_hex"`
	Sig         string `json:"sig_der_hex"`
	PinCBOR     string `json:"circuit_pin_cbor_hex"`
	// WrongDomainSig is the same statement signed with the chain-head
	// anchor key (invoice "2-reef chain anchor-1"). Both repos must
	// refuse it as a pin.
	WrongDomainSig string `json:"wrong_domain_sig_der_hex"`
}

// circuitPinVectorPath is the recorded vector file.
var circuitPinVectorPath = filepath.Join("testdata", "anchor", "circuit-pin-vectors-v1.json")

// pinEncMode is the deterministic CBOR encoder the tests build pins with.
func pinEncMode(t *testing.T) cbor.EncMode {
	t.Helper()
	enc, err := cbor.CoreDetEncOptions().EncMode()
	if err != nil {
		t.Fatal(err)
	}
	return enc
}

// pinMap builds a circuit_pin wire map. Inputs: the circuit id, the
// identity key and the signature. Output: the CBOR bytes.
func pinMap(t *testing.T, circuitID string, identity, sig []byte) []byte {
	t.Helper()
	out, err := pinEncMode(t).Marshal(map[string]any{
		"circuit_id": circuitID, "identity_key": identity,
		"protocol": CircuitPinProtocol, "key_id": CircuitPinKeyID, "sig": sig,
	})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// signedPin returns a circuit_pin for podHash and circuitID, signed by key
// under invoice.
func signedPin(t *testing.T, key *secp256k1.PrivateKey, invoice string, podHash []byte, circuitID string) []byte {
	t.Helper()
	sig := spvtest.SignAnyone(key, invoice, CircuitPinStatement(podHash, circuitID))
	return pinMap(t, circuitID, key.PubKey().SerializeCompressed(), sig)
}

// testNodeKey is the identity key of the test node, the same key the
// chain-head anchor vector uses.
func testNodeKey() *secp256k1.PrivateKey { return spvtest.TestIdentityPrivateKey() }

// trustedTestKeys trusts only the test node key.
func trustedTestKeys() [][]byte {
	return [][]byte{testNodeKey().PubKey().SerializeCompressed()}
}

// pinnedBundle returns the valid-signature bundle on circuitID with the
// matching vkey_hash, a fixed 32-byte pod_hash, and pin as circuit_pin.
func pinnedBundle(t *testing.T, circuitID string, pin []byte) *BundleV2 {
	t.Helper()
	var b *BundleV2
	if circuitID == vkeystore.CircuitIDPodStepV1_1 {
		b = v1_1Bundle(t)
	} else {
		b = withCircuit(t, circuitID, make([]byte, 32))
	}
	if len(b.PodHash) != 32 {
		h := sha256.Sum256([]byte("circuit-pin test pod"))
		b.PodHash = h[:]
	}
	b.CircuitPin = pin
	return b
}

// runWithPin verifies b with the accepting Spartan stub, the given trusted
// keys and the given environment pin. Output: the result.
func runWithPin(t *testing.T, b *BundleV2, trustedKeys [][]byte, envPin string) *ResultV2 {
	t.Helper()
	raw, err := pinEncMode(t).Marshal(b)
	if err != nil {
		t.Fatal(err)
	}
	opts := WithAcceptingVerifierForTests()
	opts.Anchor.TrustedNodeKeys = trustedKeys
	opts.Circuit = CircuitPolicy{PublisherCircuitID: envPin}
	return VerifyV2(raw, opts)
}

// pinDivergence reports whether r carries a circuit pin or circuit id
// divergence.
func pinDivergence(r *ResultV2) bool {
	return hasDivergence(r, ErrCircuitIDMismatch) || hasDivergence(r, ErrCircuitPinInvalid) ||
		hasDivergence(r, ErrCircuitPinMalformed)
}

// buildCircuitPinVector computes the vector from its fixed inputs.
func buildCircuitPinVector(t *testing.T) circuitPinVector {
	t.Helper()
	key := testNodeKey()
	identity := key.PubKey().SerializeCompressed()
	derived, err := spv.DeriveAnyonePublicKey(identity, CircuitPinInvoice())
	if err != nil {
		t.Fatal(err)
	}
	pod := sha256.Sum256([]byte("circuit-pin vector pod"))
	circuitID := vkeystore.CircuitIDPodStepV1_1
	statement := CircuitPinStatement(pod[:], circuitID)
	sig := spvtest.SignAnyone(key, CircuitPinInvoice(), statement)
	return circuitPinVector{
		Comment:        "Synthetic node-signed circuit pin vector (VHASH-ROLLOUT, paygate-zk#14). The identity key is the test key SHA-256(\"konareef chain-head anchor test identity\"); never use it for anything else.",
		IdentityKey:    hex.EncodeToString(identity),
		Invoice:        CircuitPinInvoice(),
		DerivedKey:     hex.EncodeToString(derived),
		PodHash:        hex.EncodeToString(pod[:]),
		CircuitID:      circuitID,
		Statement:      hex.EncodeToString(statement),
		Sig:            hex.EncodeToString(sig),
		PinCBOR:        hex.EncodeToString(pinMap(t, circuitID, identity, sig)),
		WrongDomainSig: hex.EncodeToString(spvtest.SignAnyone(key, AnchorInvoice(), statement)),
	}
}

// TestCircuitPinVector_RecordedBytesMatch checks the recorded cross-repo
// vector. Regenerate with KONAREEF_REGEN_ANCHOR_VECTORS=1, then copy the
// file byte for byte to reef-core
// test/support/fixtures/chain_head_anchor/circuit-pin-vectors-v1.json:
// nothing detects drift between the two copies.
func TestCircuitPinVector_RecordedBytesMatch(t *testing.T) {
	want := buildCircuitPinVector(t)
	if os.Getenv("KONAREEF_REGEN_ANCHOR_VECTORS") == "1" {
		out, _ := json.MarshalIndent(want, "", "  ")
		if err := os.WriteFile(circuitPinVectorPath, append(out, '\n'), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	raw, err := os.ReadFile(circuitPinVectorPath)
	if err != nil {
		t.Fatalf("recorded vector missing (regenerate with KONAREEF_REGEN_ANCHOR_VECTORS=1): %v", err)
	}
	var got circuitPinVector
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Fatal("recorded vector differs from the computed one; regenerate and re-vendor into reef-core")
	}
	identity, _ := hex.DecodeString(got.IdentityKey)
	sig, _ := hex.DecodeString(got.Sig)
	statement, _ := hex.DecodeString(got.Statement)
	if err := verifyAnyoneSignature(identity, sig, statement, CircuitPinInvoice()); err != nil {
		t.Fatalf("recorded signature: %v", err)
	}
	wrong, _ := hex.DecodeString(got.WrongDomainSig)
	if verifyAnyoneSignature(identity, wrong, statement, CircuitPinInvoice()) == nil {
		t.Fatal("a chain-head-domain signature verified as a circuit pin")
	}
}

// TestCircuitPin_DomainsDiffer checks the domain separation constants:
// the pin and the chain-head anchor use different statement versions,
// protocols and so derived keys.
func TestCircuitPin_DomainsDiffer(t *testing.T) {
	if CircuitPinStatementVersion == AnchorStatementVersion || CircuitPinProtocol == AnchorProtocol ||
		CircuitPinInvoice() == AnchorInvoice() {
		t.Fatal("the circuit pin and the chain-head anchor share a domain")
	}
	if CircuitPinInvoice() != "2-konareef circuit pin-1" {
		t.Fatalf("invoice = %q", CircuitPinInvoice())
	}
}

// TestCircuitPin_ValidPinAccepted: a trusted pin on the bundle's circuit
// adds no divergence and reads as verified.
func TestCircuitPin_ValidPinAccepted(t *testing.T) {
	b := pinnedBundle(t, vkeystore.CircuitIDPodStepV1_1, nil)
	b.CircuitPin = signedPin(t, testNodeKey(), CircuitPinInvoice(), b.PodHash, vkeystore.CircuitIDPodStepV1_1)
	r := runWithPin(t, b, trustedTestKeys(), "")
	if pinDivergence(r) {
		t.Fatalf("valid pin diverged: %v", divergenceStrings(r))
	}
	pv := r.V2Verdict.CircuitPin
	if pv == nil || pv.Status != CircuitPinVerified || pv.CircuitID != vkeystore.CircuitIDPodStepV1_1 ||
		pv.AttributedTo != hex.EncodeToString(trustedTestKeys()[0]) {
		t.Fatalf("pin verdict = %+v", pv)
	}
}

// TestCircuitPin_DowngradeRefused: a v1 bundle that carries a trusted
// v1.1 pin is refused (the M-1 downgrade).
func TestCircuitPin_DowngradeRefused(t *testing.T) {
	b := pinnedBundle(t, vkeystore.CircuitIDPodStepV1, nil)
	b.CircuitPin = signedPin(t, testNodeKey(), CircuitPinInvoice(), b.PodHash, vkeystore.CircuitIDPodStepV1_1)
	r := runWithPin(t, b, trustedTestKeys(), "")
	assertDiverged(t, r, ErrCircuitIDMismatch)
}

// TestCircuitPin_TamperedCircuitIDRefused: a pin signed for v1.1 whose
// circuit_id was changed to v1 does not verify.
func TestCircuitPin_TamperedCircuitIDRefused(t *testing.T) {
	b := pinnedBundle(t, vkeystore.CircuitIDPodStepV1, nil)
	sig := spvtest.SignAnyone(testNodeKey(), CircuitPinInvoice(),
		CircuitPinStatement(b.PodHash, vkeystore.CircuitIDPodStepV1_1))
	b.CircuitPin = pinMap(t, vkeystore.CircuitIDPodStepV1, trustedTestKeys()[0], sig)
	assertDiverged(t, runWithPin(t, b, trustedTestKeys(), ""), ErrCircuitPinInvalid)
}

// TestCircuitPin_OtherPodRefused: a genuine pin of another pod does not
// verify against this bundle's pod_hash.
func TestCircuitPin_OtherPodRefused(t *testing.T) {
	b := pinnedBundle(t, vkeystore.CircuitIDPodStepV1_1, nil)
	other := sha256.Sum256([]byte("another pod"))
	b.CircuitPin = signedPin(t, testNodeKey(), CircuitPinInvoice(), other[:], vkeystore.CircuitIDPodStepV1_1)
	assertDiverged(t, runWithPin(t, b, trustedTestKeys(), ""), ErrCircuitPinInvalid)
}

// TestCircuitPin_WrongKeyRefused: a signature made by a key other than
// the identity key the pin names is refused, even when that identity key
// is trusted.
func TestCircuitPin_WrongKeyRefused(t *testing.T) {
	b := pinnedBundle(t, vkeystore.CircuitIDPodStepV1_1, nil)
	seed := sha256.Sum256([]byte("another signer"))
	other := secp256k1.PrivKeyFromBytes(seed[:])
	sig := spvtest.SignAnyone(other, CircuitPinInvoice(),
		CircuitPinStatement(b.PodHash, vkeystore.CircuitIDPodStepV1_1))
	b.CircuitPin = pinMap(t, vkeystore.CircuitIDPodStepV1_1, trustedTestKeys()[0], sig)
	assertDiverged(t, runWithPin(t, b, trustedTestKeys(), ""), ErrCircuitPinInvalid)
}

// TestCircuitPin_WrongDomainRefused: a signature made with the chain-head
// anchor key, or over a chain-head anchor statement, is not a pin; and a
// pin signature is not a chain-head attestation.
func TestCircuitPin_WrongDomainRefused(t *testing.T) {
	b := pinnedBundle(t, vkeystore.CircuitIDPodStepV1_1, nil)
	identity := trustedTestKeys()[0]

	// The pin statement, signed with the chain-head anchor key.
	b.CircuitPin = signedPin(t, testNodeKey(), AnchorInvoice(), b.PodHash, vkeystore.CircuitIDPodStepV1_1)
	assertDiverged(t, runWithPin(t, b, trustedTestKeys(), ""), ErrCircuitPinInvalid)

	// A chain-head anchor statement, signed with the pin key.
	anchorStmt := AnchorStatement(make([]byte, 32), 1, b.PodHash, b.SpartanCompressResult.VkeyHash,
		b.SpartanCompressResult.LastStepPublicInputs)
	b.CircuitPin = pinMap(t, vkeystore.CircuitIDPodStepV1_1, identity,
		spvtest.SignAnyone(testNodeKey(), CircuitPinInvoice(), anchorStmt))
	assertDiverged(t, runWithPin(t, b, trustedTestKeys(), ""), ErrCircuitPinInvalid)

	// The reverse: a pin signature does not verify as an anchor
	// attestation over the same bytes, or over an anchor statement.
	pinStmt := CircuitPinStatement(b.PodHash, vkeystore.CircuitIDPodStepV1_1)
	pinSig := spvtest.SignAnyone(testNodeKey(), CircuitPinInvoice(), pinStmt)
	if verifyAnchorSignature(identity, pinSig, pinStmt) == nil {
		t.Fatal("a circuit pin signature verified as a chain-head attestation")
	}
}

// TestCircuitPin_MalformedRefused: shape faults are refused with
// ERR_CIRCUIT_PIN_MALFORMED.
func TestCircuitPin_MalformedRefused(t *testing.T) {
	enc := pinEncMode(t)
	b := pinnedBundle(t, vkeystore.CircuitIDPodStepV1_1, nil)
	identity := trustedTestKeys()[0]
	sig := spvtest.SignAnyone(testNodeKey(), CircuitPinInvoice(),
		CircuitPinStatement(b.PodHash, vkeystore.CircuitIDPodStepV1_1))
	base := func() map[string]any {
		return map[string]any{
			"circuit_id": vkeystore.CircuitIDPodStepV1_1, "identity_key": identity,
			"protocol": CircuitPinProtocol, "key_id": CircuitPinKeyID, "sig": sig,
		}
	}
	for name, mutate := range map[string]func(m map[string]any){
		"unknown key":        func(m map[string]any) { m["extra"] = "x" },
		"missing sig":        func(m map[string]any) { delete(m, "sig") },
		"anchor protocol":    func(m map[string]any) { m["protocol"] = AnchorProtocol },
		"other key id":       func(m map[string]any) { m["key_id"] = "2" },
		"unsupported id":     func(m map[string]any) { m["circuit_id"] = "konareef-pod-step-v9" },
		"short identity key": func(m map[string]any) { m["identity_key"] = identity[:32] },
		"text sig":           func(m map[string]any) { m["sig"] = "not bytes" },
	} {
		m := base()
		mutate(m)
		raw, err := enc.Marshal(m)
		if err != nil {
			t.Fatal(err)
		}
		b.CircuitPin = raw
		r := runWithPin(t, b, trustedTestKeys(), "")
		if !hasDivergence(r, ErrCircuitPinMalformed) || r.OK {
			t.Errorf("%s: want ERR_CIRCUIT_PIN_MALFORMED, got %v", name, divergenceStrings(r))
		}
	}
	// Not a map at all.
	b.CircuitPin, _ = enc.Marshal("pin")
	assertDiverged(t, runWithPin(t, b, trustedTestKeys(), ""), ErrCircuitPinMalformed)
}

// TestCircuitPin_NoPodHashRefused: a pin cannot bind a bundle without a
// 32-byte pod_hash.
func TestCircuitPin_NoPodHashRefused(t *testing.T) {
	b := pinnedBundle(t, vkeystore.CircuitIDPodStepV1_1, nil)
	b.CircuitPin = signedPin(t, testNodeKey(), CircuitPinInvoice(), b.PodHash, vkeystore.CircuitIDPodStepV1_1)
	b.PodHash = nil
	assertDiverged(t, runWithPin(t, b, trustedTestKeys(), ""), ErrCircuitPinInvalid)
}

// TestCircuitPin_UntrustedKeyNotUsed: a valid pin from a key that is not
// trusted reads "unattributed" and is not used, so a v1 bundle with an
// untrusted v1.1 pin gets the result of a bundle without a pin.
func TestCircuitPin_UntrustedKeyNotUsed(t *testing.T) {
	b := pinnedBundle(t, vkeystore.CircuitIDPodStepV1, nil)
	b.CircuitPin = signedPin(t, testNodeKey(), CircuitPinInvoice(), b.PodHash, vkeystore.CircuitIDPodStepV1_1)
	r := runWithPin(t, b, nil, "")
	if pinDivergence(r) {
		t.Fatalf("an untrusted pin diverged: %v", divergenceStrings(r))
	}
	if pv := r.V2Verdict.CircuitPin; pv == nil || pv.Status != CircuitPinUnattributed || pv.AttributedTo != "" {
		t.Fatalf("pin verdict = %+v", pv)
	}
	// The environment pin still applies as the fallback.
	assertDiverged(t, runWithPin(t, b, nil, vkeystore.CircuitIDPodStepV1_1), ErrCircuitIDMismatch)
}

// TestCircuitPin_AbsentKeepsTodaysBehaviour: without circuit_pin, the
// verdict has no pin object and the result equals the result before
// this check existed, for every environment pin.
func TestCircuitPin_AbsentKeepsTodaysBehaviour(t *testing.T) {
	for _, tc := range []struct {
		circuit, env string
		refused      bool
	}{
		{vkeystore.CircuitIDPodStepV1, "", false},
		{vkeystore.CircuitIDPodStepV1_1, "", false},
		{vkeystore.CircuitIDPodStepV1, vkeystore.CircuitIDPodStepV1_1, true},
		{vkeystore.CircuitIDPodStepV1_1, vkeystore.CircuitIDPodStepV1_1, false},
	} {
		b := pinnedBundle(t, tc.circuit, nil)
		withPin := runWithPin(t, b, trustedTestKeys(), tc.env)
		before := runVerifyWithPolicy(t, b, CircuitPolicy{PublisherCircuitID: tc.env})
		if withPin.V2Verdict.CircuitPin != nil {
			t.Errorf("%s/%q: a pin verdict without a pin", tc.circuit, tc.env)
		}
		if hasDivergence(withPin, ErrCircuitIDMismatch) != tc.refused ||
			withPin.OK != before.OK || len(withPin.Divergences) != len(before.Divergences) {
			t.Errorf("%s/%q: result differs from the no-pin baseline: %v vs %v",
				tc.circuit, tc.env, divergenceStrings(withPin), divergenceStrings(before))
		}
	}
}

// TestCircuitPin_EnvironmentPrecedence: a trusted pin is the publisher
// pin; the environment pin is the fallback, and when both are present
// the bundle must match both (the environment cannot loosen a pin).
func TestCircuitPin_EnvironmentPrecedence(t *testing.T) {
	v11 := vkeystore.CircuitIDPodStepV1_1
	v1 := vkeystore.CircuitIDPodStepV1

	// Pin v1.1, environment v1, bundle v1.1: the environment is stricter.
	b := pinnedBundle(t, v11, nil)
	b.CircuitPin = signedPin(t, testNodeKey(), CircuitPinInvoice(), b.PodHash, v11)
	assertDiverged(t, runWithPin(t, b, trustedTestKeys(), v1), ErrCircuitIDMismatch)

	// Pin v1.1, environment v1.1, bundle v1.1: passes.
	if r := runWithPin(t, b, trustedTestKeys(), v11); pinDivergence(r) {
		t.Fatalf("pin and environment agree, but: %v", divergenceStrings(r))
	}

	// Pin v1.1, environment v1, bundle v1: the environment cannot loosen
	// the signed pin.
	b1 := pinnedBundle(t, v1, nil)
	b1.CircuitPin = signedPin(t, testNodeKey(), CircuitPinInvoice(), b1.PodHash, v11)
	assertDiverged(t, runWithPin(t, b1, trustedTestKeys(), v1), ErrCircuitIDMismatch)

	// Pin v1 (an older approval), no environment, bundle v1: passes.
	b1.CircuitPin = signedPin(t, testNodeKey(), CircuitPinInvoice(), b1.PodHash, v1)
	if r := runWithPin(t, b1, trustedTestKeys(), ""); pinDivergence(r) {
		t.Fatalf("a v1 pin on a v1 bundle diverged: %v", divergenceStrings(r))
	}
}
