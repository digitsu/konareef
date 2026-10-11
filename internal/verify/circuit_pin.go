// Copyright 2026 Jerry David Chan, Konareef.ai
// SPDX-License-Identifier: Apache-2.0

// circuit_pin.go — the node-signed publisher circuit pin (VHASH-ROLLOUT
// part 2, paygate-zk#14; konareef!152 review K-M2).
//
// A konareef-bundle/v2 bundle may carry `circuit_pin`: a statement, signed
// by the reef-core node identity key, that names the circuit the node
// approved the run against for the bundle's pod. The node signs it with
// the same wallet identity key and the same BRC-100 "anyone" signature
// form as the chain-head anchor attestation (anchor.go), so the same
// trusted node keys apply (PinnedTrustedNodeKeys and the configured keys).
//
// The signed statement is the deterministic CBOR map
//
//	{ "v": "konareef-circuit-pin/v1", "pod_hash": <bundle pod_hash>,
//	  "circuit_id": <the pinned circuit id> }
//
// and the bundle carries
//
//	"circuit_pin": { "circuit_id", "identity_key", "protocol":
//	  "konareef circuit pin", "key_id": "1", "sig" }
//
// Domain separation. The pin and the chain-head anchor attestation use
// different BRC-43 protocols ("konareef circuit pin" and "reef chain
// anchor"), so the wallet signs each with a different derived key, and
// different statement versions ("konareef-circuit-pin/v1" and
// "reef-core/chain-head-anchor/1") with different key sets. A chain-head
// signature therefore does not verify as a pin, and a pin signature does
// not verify as a chain-head attestation.
//
// Check order:
//
//  1. absent key: no pin; the policy is the same as before this check
//     existed (Verdict.CircuitPin stays nil);
//  2. map shape, key set and types, the fixed protocol and key id, a
//     supported circuit id — else ERR_CIRCUIT_PIN_MALFORMED;
//  3. the bundle has a 32-byte pod_hash, and the signature verifies over
//     the statement recomputed from that pod_hash and the pin's
//     circuit_id under the key derived from identity_key — else
//     ERR_CIRCUIT_PIN_INVALID;
//  4. identity_key is a trusted node key — else status "unattributed":
//     the pin is not used, and the policy falls back to the environment
//     pin (KONAREEF_PUBLISHER_CIRCUIT_ID), as for an absent pin;
//  5. status "verified": the pin's circuit_id is the publisher pin, and
//     circuitPolicy refuses a bundle on another circuit
//     (ERR_CIRCUIT_ID_MISMATCH).
//
// Residual risk. A pin binds the pair (pod_hash, circuit_id), not one
// run. A sender who removes the key gets the behaviour of a bundle
// without a pin, and a sender can copy a genuine pin of the same pod from
// another bundle. The pin stops a downgrade only for a pod that the node
// never approved on the older circuit, and only where the bundle keeps
// the key (follow-up konareef#43). reef-core ingest (reef-core!200) is
// still the check that a third party cannot see.
//
// Forward compatibility. decodeCircuitPinWire is strict, so a later pin
// form must use a new top-level key (for example circuit_pin_v2), never a
// new value under circuit_pin: old verifiers would refuse the bundle.
package verify

import (
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/fxamacker/cbor/v2"

	"github.com/digitsu/konareef/internal/spv"
	"github.com/digitsu/konareef/internal/vkeystore"
)

// Circuit pin constants. reef-core signs with exactly these
// (ReefCore.Proofs.CircuitPin).
const (
	// CircuitPinStatementVersion is the "v" value of the signed statement.
	CircuitPinStatementVersion = "konareef-circuit-pin/v1"
	// CircuitPinProtocol is the BRC-43 protocol name of the signature.
	CircuitPinProtocol = "konareef circuit pin"
	// CircuitPinKeyID is the BRC-43 key id of the signature.
	CircuitPinKeyID = "1"
	// CircuitPinSecurityLevel is the BRC-43 security level of the
	// signature.
	CircuitPinSecurityLevel = 2
)

// CircuitPinStatus is the outcome of the circuit pin check.
type CircuitPinStatus string

// Circuit pin statuses (Verdict.CircuitPin.Status). A pin that fails a
// check refuses the bundle, so it has no status of its own beyond
// "invalid".
const (
	CircuitPinVerified     CircuitPinStatus = "verified"
	CircuitPinUnattributed CircuitPinStatus = "unattributed"
	CircuitPinInvalid      CircuitPinStatus = "invalid"
)

// CircuitPinVerdict is the informative circuit pin object of the verdict.
// It is nil when the bundle carries no pin.
type CircuitPinVerdict struct {
	// Status is the check outcome.
	Status CircuitPinStatus `json:"status"`
	// CircuitID is the circuit id the pin names; empty when the pin is
	// malformed.
	CircuitID string `json:"circuit_id,omitempty"`
	// AttributedTo is the trusted node identity key (hex) that signed the
	// pin; empty unless the status is "verified".
	AttributedTo string `json:"attributed_to,omitempty"`
}

// circuitPinWire is the decoded circuit_pin map.
type circuitPinWire struct {
	CircuitID   string
	IdentityKey []byte
	Sig         []byte
}

// decodeCircuitPinWire decodes and shape-checks circuit_pin.
// Input: the raw CBOR value of the key.
// Output: the decoded pin, or an error for an unknown or missing key, a
// wrong type, a protocol or key id other than the fixed ones, an
// identity key that is not 33 bytes, a signature that is empty or longer
// than 80 bytes, or a circuit id this build does not accept.
func decodeCircuitPinWire(raw cbor.RawMessage) (*circuitPinWire, error) {
	m, err := decodeStrictMap(raw, map[string]byte{
		"circuit_id": cborMajorText, "identity_key": cborMajorBytes,
		"protocol": cborMajorText, "key_id": cborMajorText, "sig": cborMajorBytes,
	}, []string{"circuit_id", "identity_key", "protocol", "key_id", "sig"})
	if err != nil {
		return nil, err
	}
	w := &circuitPinWire{}
	var protocol, keyID string
	if err := detDecMode.Unmarshal(m["circuit_id"], &w.CircuitID); err != nil || !vkeystore.IsSupportedCircuitID(w.CircuitID) {
		return nil, fmt.Errorf("circuit_id %q is not a supported circuit id", w.CircuitID)
	}
	if err := detDecMode.Unmarshal(m["identity_key"], &w.IdentityKey); err != nil || len(w.IdentityKey) != 33 {
		return nil, errors.New("identity_key must be a 33-byte bstr")
	}
	if err := detDecMode.Unmarshal(m["protocol"], &protocol); err != nil || protocol != CircuitPinProtocol {
		return nil, fmt.Errorf("protocol must be %q", CircuitPinProtocol)
	}
	if err := detDecMode.Unmarshal(m["key_id"], &keyID); err != nil || keyID != CircuitPinKeyID {
		return nil, fmt.Errorf("key_id must be %q", CircuitPinKeyID)
	}
	if err := detDecMode.Unmarshal(m["sig"], &w.Sig); err != nil || len(w.Sig) == 0 || len(w.Sig) > 80 {
		return nil, errors.New("sig must be a DER bstr")
	}
	return w, nil
}

// CircuitPinStatement encodes the signed statement.
// Inputs: the bundle's pod_hash; the pinned circuit id.
// Output: the deterministic CBOR bytes the node signs (SHA-256 of them is
// the ECDSA digest). reef-core `CircuitPin.statement/2` builds the same
// bytes.
func CircuitPinStatement(podHash []byte, circuitID string) []byte {
	out, err := anchorStatementEncMode.Marshal(map[string]any{
		"v":          CircuitPinStatementVersion,
		"pod_hash":   podHash,
		"circuit_id": circuitID,
	})
	if err != nil {
		panic(err)
	}
	return out
}

// CircuitPinInvoice returns the BRC-43 invoice number of the pin key:
// "2-konareef circuit pin-1".
func CircuitPinInvoice() string {
	return spv.InvoiceNumber(CircuitPinSecurityLevel, CircuitPinProtocol, CircuitPinKeyID)
}

// checkCircuitPin runs the circuit pin check (see the file comment).
//
// Inputs: b, the decoded bundle; trustedKeys, the trusted node identity
// keys (the same list as the chain-head anchor check); v, the verdict to
// fill; r, the result to diverge on.
// Output: the pinned circuit id when the pin is present, valid and
// signed by a trusted key, else ""; and false after a divergence (the
// bundle is refused). An absent pin gives ("", true) and leaves
// v.CircuitPin nil.
func checkCircuitPin(b *BundleV2, trustedKeys [][]byte, v *Verdict, r *ResultV2) (string, bool) {
	if len(b.CircuitPin) == 0 {
		return "", true
	}
	pv := &CircuitPinVerdict{Status: CircuitPinInvalid}
	v.CircuitPin = pv
	w, err := decodeCircuitPinWire(b.CircuitPin)
	if err != nil {
		r.diverge(ErrCircuitPinMalformed, "circuit_pin: "+err.Error())
		return "", false
	}
	pv.CircuitID = w.CircuitID
	if len(b.PodHash) != 32 {
		r.diverge(ErrCircuitPinInvalid, fmt.Sprintf("circuit_pin: the bundle pod_hash is %d bytes, want 32", len(b.PodHash)))
		return "", false
	}
	statement := CircuitPinStatement(b.PodHash, w.CircuitID)
	if err := verifyAnyoneSignature(w.IdentityKey, w.Sig, statement, CircuitPinInvoice()); err != nil {
		r.diverge(ErrCircuitPinInvalid, "circuit_pin: "+err.Error())
		return "", false
	}
	if !trusted(w.IdentityKey, trustedKeys) {
		pv.Status = CircuitPinUnattributed
		return "", true
	}
	pv.Status = CircuitPinVerified
	pv.AttributedTo = hex.EncodeToString(w.IdentityKey)
	return w.CircuitID, true
}
