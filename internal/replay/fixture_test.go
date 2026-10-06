// Copyright 2026 Jerry David Chan, Konareef.ai
// SPDX-License-Identifier: Apache-2.0

// fixture_test.go — test helpers that build genuine replay evidence from
// the shared admission fixture
// (internal/commission/testdata/admission_v1/vectors.json, IB-00).
//
// A case's wire bytes carry the exact canonical proposal, key and
// signature the fixture signed. decodeWire turns them back into a
// commission.Commission, so the tests replay the same signed bytes that
// reef-core's IB-04 parity suite admits. receiptFor builds the receipt JSON
// with the field names and values of reef-core Claims.receipt/1 at
// origin/main a96c7bf (lib/pod/commission/claims.ex).

package replay

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/fxamacker/cbor/v2"

	"github.com/digitsu/konareef/internal/commission"
	"github.com/digitsu/konareef/internal/envelope"
	"github.com/digitsu/konareef/internal/identity"
)

// fixtureVectors is the part of vectors.json the replay tests read.
type fixtureVectors struct {
	Keys []struct {
		Name          string `json:"name"`
		PrivateKeyHex string `json:"private_key_hex"`
		PublicKeyHex  string `json:"public_key_hex"`
	} `json:"keys"`
	PublishedPods []struct {
		Name       string `json:"name"`
		Handle     string `json:"handle"`
		PodName    string `json:"pod_name"`
		PodVersion string `json:"pod_version"`
		Manifest   string `json:"manifest"`
		PodHash    string `json:"pod_hash"`
	} `json:"published_pods"`
	Cases []fixtureCase `json:"cases"`
}

// fixtureCase is one admission case.
type fixtureCase struct {
	ID      string `json:"id"`
	Why     string `json:"why"`
	WireHex string `json:"wire_hex"`
	Expect  struct {
		Verdict       string            `json:"verdict"`
		Code          string            `json:"code"`
		HCommission   string            `json:"h_commission"`
		PodRef        string            `json:"pod_ref"`
		PodHash       string            `json:"pod_hash"`
		MemoryClass   string            `json:"memory_class"`
		DerivedModels []string          `json:"derived_models"`
		DerivedTools  []string          `json:"derived_tools"`
		DerivedCMax   uint64            `json:"derived_c_max"`
		AuthorFeeSats uint64            `json:"author_fee_sats"`
		Dimensions    map[string]string `json:"dimensions"`
	} `json:"expect"`
}

// loadVectors reads the shared admission fixture.
func loadVectors(t *testing.T) *fixtureVectors {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "commission", "testdata", "admission_v1", "vectors.json"))
	if err != nil {
		t.Fatalf("read vectors: %v", err)
	}
	var v fixtureVectors
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatalf("decode vectors: %v", err)
	}
	return &v
}

// fixtureCaseByID returns the case with this id.
func (v *fixtureVectors) caseByID(t *testing.T, id string) fixtureCase {
	t.Helper()
	for _, c := range v.Cases {
		if c.ID == id {
			return c
		}
	}
	t.Fatalf("no fixture case %s", id)
	return fixtureCase{}
}

// manifestByRef returns the manifest of the row that the signed pod_ref
// names, as the server looks it up (by pod_ref, not by pod_hash).
func (v *fixtureVectors) manifestByRef(podRef string) ([]byte, bool) {
	handle, name, version, err := commission.ParsePodRef(podRef)
	if err != nil {
		return nil, false
	}
	for _, p := range v.PublishedPods {
		if p.Handle == handle && p.PodName == name && p.PodVersion == version {
			return []byte(p.Manifest), true
		}
	}
	return nil, false
}

// manifestByName returns a fixture pod's manifest.
func (v *fixtureVectors) manifestByName(t *testing.T, name string) []byte {
	t.Helper()
	for _, p := range v.PublishedPods {
		if p.Name == name {
			return []byte(p.Manifest)
		}
	}
	t.Fatalf("no fixture pod %s", name)
	return nil
}

// key returns a fixture identity by name.
func (v *fixtureVectors) key(t *testing.T, name string) *identity.Identity {
	t.Helper()
	for _, k := range v.Keys {
		if k.Name == name {
			return &identity.Identity{PrivateKeyHex: k.PrivateKeyHex, PublicKeyHex: k.PublicKeyHex}
		}
	}
	t.Fatalf("no fixture key %s", name)
	return nil
}

// canonicalMirror mirrors the canonical proposal map {1: models, 2: tools,
// 3: labels, 4: c_max, 5: binding, 6: prose} (contract §2).
type canonicalMirror struct {
	Models  []string           `cbor:"1,keyasint"`
	Tools   []string           `cbor:"2,keyasint"`
	Labels  []string           `cbor:"3,keyasint"`
	CMax    uint64             `cbor:"4,keyasint"`
	Binding commission.Binding `cbor:"5,keyasint"`
	Prose   string             `cbor:"6,keyasint"`
}

// decodeWire turns a case's v1 wire bytes into the commission they carry.
// The re-encoded canonical bytes must equal the carried ones, so the
// commission is exactly what was signed. Output: the commission, or an
// error for a wire-level case the replay's input format cannot express.
func decodeWire(wireHex string) (commission.Commission, error) {
	wire, err := hex.DecodeString(wireHex)
	if err != nil {
		return commission.Commission{}, err
	}
	var envelopeMap map[uint64]cbor.RawMessage
	if err := cbor.Unmarshal(wire, &envelopeMap); err != nil || len(envelopeMap) != 4 {
		return commission.Commission{}, fmt.Errorf("not a 4-key wire map: %v", err)
	}
	var canonical, pub, sig []byte
	for key, dst := range map[uint64]*[]byte{2: &canonical, 3: &pub, 4: &sig} {
		if err := cbor.Unmarshal(envelopeMap[key], dst); err != nil {
			return commission.Commission{}, fmt.Errorf("wire key %d: %v", key, err)
		}
	}
	var m canonicalMirror
	if err := cbor.Unmarshal(canonical, &m); err != nil {
		return commission.Commission{}, fmt.Errorf("canonical: %v", err)
	}
	p := commission.Proposal{
		Envelope: envelope.Envelope{
			Models: m.Models, Tools: m.Tools, Labels: m.Labels, CMax: m.CMax,
			ModelsSet: true, ToolsSet: true, LabelsSet: true, CMaxSet: true,
		},
		Binding: m.Binding,
		Prose:   m.Prose,
	}
	again, err := p.Canonical()
	if err != nil || !bytes.Equal(again, canonical) {
		return commission.Commission{}, fmt.Errorf("the canonical bytes do not round-trip")
	}
	return commission.Reconstruct(p, hex.EncodeToString(pub), sig), nil
}

// genuineCommission decodes a case's commission and fails the test if the
// wire does not decode.
func genuineCommission(t *testing.T, c fixtureCase) commission.Commission {
	t.Helper()
	com, err := decodeWire(c.WireHex)
	if err != nil {
		t.Fatalf("%s: decode wire: %v", c.ID, err)
	}
	return com
}

// testReceipt mirrors reef-core Claims.receipt/1. Tests mutate it and then
// marshal it.
type testReceipt struct {
	ReceiptID     string            `json:"receipt_id"`
	Contract      string            `json:"contract"`
	AssuranceMode string            `json:"assurance_mode"`
	HCommission   string            `json:"h_commission"`
	SignerPubkey  string            `json:"signer_pubkey"`
	SignerKeyID   string            `json:"signer_key_id"`
	PodHash       string            `json:"pod_hash"`
	PodRef        string            `json:"pod_ref"`
	FieldsRoot    string            `json:"fields_root"`
	MemoryClass   string            `json:"memory_class"`
	Derived       map[string]any    `json:"derived"`
	Fees          map[string]any    `json:"fees"`
	RunState      string            `json:"run_state"`
	Effective     map[string]any    `json:"effective"`
	Dimensions    map[string]string `json:"dimensions"`
	Inputs        string            `json:"inputs"`
	VerifierImpl  string            `json:"verifier_impl"`
	AdmittedAt    string            `json:"admitted_at"`
	Authenticity  string            `json:"authenticity"`
}

// receiptFor builds the receipt reef-core writes for an admitted case: the
// fixture's expected derivation, the commission's identity, the effective
// values §11 asserts (the derived model and cap), and zk_fee_sats 0.
func receiptFor(t *testing.T, com commission.Commission, c fixtureCase) *testReceipt {
	t.Helper()
	p := com.Proposal()
	h, err := com.HCommissionHex()
	if err != nil {
		t.Fatal(err)
	}
	fieldsRoot := ""
	if p.Binding.FieldsRoot != nil {
		fieldsRoot = hex.EncodeToString(p.Binding.FieldsRoot[:])
	}
	model := ""
	if len(c.Expect.DerivedModels) > 0 {
		model = c.Expect.DerivedModels[0]
	}
	return &testReceipt{
		ReceiptID:     "6f1f8a2e-0c43-4c1b-9d3c-2a4f5b6c7d8e",
		Contract:      commission.AdmissionContractV1,
		AssuranceMode: commission.AssuranceModeLimitedV1,
		HCommission:   h,
		SignerPubkey:  com.PubKeyHex,
		SignerKeyID:   "0b8e6d4c-1a2b-4c3d-8e9f-0a1b2c3d4e5f",
		PodHash:       hex.EncodeToString(p.Binding.HManifest[:]),
		PodRef:        p.Binding.PodRef,
		FieldsRoot:    fieldsRoot,
		MemoryClass:   c.Expect.MemoryClass,
		Derived:       map[string]any{"models": c.Expect.DerivedModels, "tools": c.Expect.DerivedTools, "c_max_sats": c.Expect.DerivedCMax},
		Fees:          map[string]any{"author_fee_sats": c.Expect.AuthorFeeSats, "zk_fee_sats": 0, "bounded_by_commission": true},
		RunState:      "started",
		Effective:     map[string]any{"model_id": model, "budget_sats": c.Expect.DerivedCMax},
		Dimensions:    c.Expect.Dimensions,
		Inputs:        "not_buyer_signed",
		VerifierImpl:  "reef-core/commission-verifier/v1 fields_root=elixir-poseidon-pallas params-sha256=test",
		AdmittedAt:    "2026-09-25T10:00:00Z",
		Authenticity:  "api_session_only",
	}
}

// bytes marshals the receipt.
func (r *testReceipt) bytes(t *testing.T) []byte {
	t.Helper()
	b, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// genuineEvidence is the complete, consistent evidence of an admitted case.
func genuineEvidence(t *testing.T, v *fixtureVectors, id string) (Evidence, *testReceipt) {
	t.Helper()
	c := v.caseByID(t, id)
	com := genuineCommission(t, c)
	manifest, ok := v.manifestByRef(com.Proposal().Binding.PodRef)
	if !ok {
		t.Fatalf("%s: no row for pod_ref", id)
	}
	rec := receiptFor(t, com, c)
	return Evidence{Commission: &com, Receipt: rec.bytes(t), Manifest: manifest}, rec
}

// checkOutcome returns the outcome of a check in a report.
func checkOutcome(rep *Report, id string) CheckOutcome {
	for _, c := range rep.Checks {
		if c.ID == id {
			return c.Outcome
		}
	}
	return ""
}

// dimensionOf returns a dimension of a report.
func dimensionOf(t *testing.T, rep *Report, name string) Dimension {
	t.Helper()
	for _, d := range rep.Dimensions {
		if d.Name == name {
			return d
		}
	}
	t.Fatalf("no dimension %s", name)
	return Dimension{}
}

// failedChecks lists the ids of the checks that failed.
func failedChecks(rep *Report) []string {
	var ids []string
	for _, c := range rep.Checks {
		if c.Outcome == CheckFail {
			ids = append(ids, c.ID)
		}
	}
	return ids
}
