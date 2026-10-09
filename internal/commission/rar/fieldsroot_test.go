// Copyright 2026 Jerry David Chan, Konareef.ai
// SPDX-License-Identifier: Apache-2.0

// fieldsroot_test.go — Binding.FieldsRoot presence across the RFC 9396
// boundary, in both directions.
//
// Parse once set every presence flag to true unconditionally, which let a
// Render/Parse round trip launder an envelope that omitted a dimension into
// one that appeared to state it. fields_root is the same kind of field and
// gets the same treatment: absent key means not pinned, and a present key
// must be well-formed or the whole document is refused.

package rar

import (
	"encoding/hex"
	"strings"
	"testing"

	"github.com/digitsu/konareef/internal/commission"
	"github.com/digitsu/konareef/internal/envelope"
)

func fullEnvelope() envelope.Envelope {
	return envelope.Envelope{
		Models: []string{"gpt-4o"}, ModelsSet: true,
		Tools: []string{"search"}, ToolsSet: true,
		Labels: []string{}, LabelsSet: true,
		CMax: 1000, CMaxSet: true,
	}
}

func binding(fr *[32]byte) commission.Binding {
	return commission.Binding{PodRef: "dave/probe@1.0.0", HManifest: [32]byte{0xAB}, FieldsRoot: fr}
}

func TestRAR_PinnedFieldsRootSurvives(t *testing.T) {
	var fr [32]byte
	copy(fr[:], []byte{0x09, 0x08, 0x07})

	raw, err := Render(fullEnvelope(), binding(&fr))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), "fields_root") {
		t.Fatalf("pinned commitment absent from the rendered document:\n%s", raw)
	}
	_, b, err := Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	if b.FieldsRoot == nil {
		t.Fatal("a pinned commitment came back UNPINNED through RAR")
	}
	if *b.FieldsRoot != fr {
		t.Fatalf("value changed: got %s want %s",
			hex.EncodeToString(b.FieldsRoot[:]), hex.EncodeToString(fr[:]))
	}
}

// The laundering direction: an omitted key must not become a pin.
func TestRAR_CannotLaunderUnpinnedIntoPinned(t *testing.T) {
	raw, err := Render(fullEnvelope(), binding(nil))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "fields_root") {
		t.Fatalf("unpinned binding emitted a fields_root key:\n%s", raw)
	}
	_, b, err := Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	if b.FieldsRoot != nil {
		t.Fatalf("RAR invented a pin (%s) for an unpinned binding",
			hex.EncodeToString(b.FieldsRoot[:]))
	}
}

func TestRAR_PinnedZeroSurvivesAsAPin(t *testing.T) {
	var zero [32]byte
	raw, err := Render(fullEnvelope(), binding(&zero))
	if err != nil {
		t.Fatal(err)
	}
	_, b, err := Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	if b.FieldsRoot == nil {
		t.Fatal("a pin of all-zero bytes was read back as no pin")
	}
}

func TestRAR_MalformedFieldsRootRefused(t *testing.T) {
	good := strings.Repeat("ab", 32)
	for _, bad := range []string{`"abc"`, `""`, `"` + strings.Repeat("z", 64) + `"`} {
		doc := `[{"type":"konareef-commission","models":["m"],"tools":[],"labels":[],` +
			`"c_max_sats":1,"pod_ref":"d/p@1","h_manifest":"` + good + `","fields_root":` + bad + `}]`
		if _, _, err := Parse([]byte(doc)); err == nil {
			t.Fatalf("accepted a malformed fields_root %s instead of refusing the document", bad)
		}
	}
}
