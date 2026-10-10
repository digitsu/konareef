// Copyright 2026 Jerry David Chan, Konareef.ai
// SPDX-License-Identifier: Apache-2.0

// main_commission_fieldsroot_test.go — presence of Binding.FieldsRoot
// across the TOML boundary, tested in BOTH directions.
//
// Both directions, separately, because this package's history says one is
// not enough. The TOML round trip lost dimension presence twice, in
// opposite directions, and the two failures needed different tests to see:
// stated-empty collapsing to omitted was fail-closed and caught early,
// while omitted-c_max inflating to stated was fail-OPEN and survived a
// probe that only looked the other way. fields_root has exactly the same
// shape — a pinned zero and no pin at all are different claims that a
// non-pointer field cannot tell apart — so both directions are pinned here
// before anything relies on the distinction.

package main

import (
	"encoding/hex"
	"strings"
	"testing"

	"github.com/digitsu/konareef/internal/commission"
	"github.com/digitsu/konareef/internal/envelope"
)

func statedEnvelope() envelope.Envelope {
	return envelope.Envelope{
		Models: []string{"gpt-4o"}, ModelsSet: true,
		Tools: []string{"search"}, ToolsSet: true,
		Labels: []string{}, LabelsSet: true,
		CMax: 1000, CMaxSet: true,
	}
}

func proposalWithPin(fr *[32]byte) commission.Proposal {
	return commission.Proposal{
		Envelope: statedEnvelope(),
		Binding: commission.Binding{
			PodRef:     "dave/probe@1.0.0",
			HManifest:  [32]byte{0xAB},
			FieldsRoot: fr,
		},
		Prose: "probe",
	}
}

// Direction 1 — a pinned commitment must survive. Fail-closed if lost, but
// it would silently strip the very binding this change exists to add.
func TestTOMLRoundTrip_PinnedFieldsRootSurvives(t *testing.T) {
	var fr [32]byte
	copy(fr[:], []byte{0x01, 0x02, 0x03})

	out, err := marshalProposal(proposalWithPin(&fr))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(out), "fields_root") {
		t.Fatalf("a pinned commitment was not written to TOML at all:\n%s", out)
	}
	back, err := unmarshalProposal(out)
	if err != nil {
		t.Fatal(err)
	}
	if back.Binding.FieldsRoot == nil {
		t.Fatal("a pinned commitment came back UNPINNED — the round trip stripped it")
	}
	if *back.Binding.FieldsRoot != fr {
		t.Fatalf("value changed: got %s want %s",
			hex.EncodeToString(back.Binding.FieldsRoot[:]), hex.EncodeToString(fr[:]))
	}
}

// Direction 2 — the fail-OPEN one. An unpinned proposal must NOT come back
// pinned, because ValidateAgainstManifest treats a pin as a claim about a
// v2 manifest, and a spurious all-zero pin would make a v1 proposal refuse
// (or, worse, appear to tie a proof to a commitment nobody published).
func TestTOMLRoundTrip_UnpinnedStaysUnpinned(t *testing.T) {
	out, err := marshalProposal(proposalWithPin(nil))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(out), "fields_root") {
		t.Fatalf("an unpinned proposal emitted a fields_root key:\n%s", out)
	}
	back, err := unmarshalProposal(out)
	if err != nil {
		t.Fatal(err)
	}
	if back.Binding.FieldsRoot != nil {
		t.Fatalf("an UNPINNED proposal came back pinned to %s — presence was invented",
			hex.EncodeToString(back.Binding.FieldsRoot[:]))
	}
}

// A pinned zero is a value, not an absence, and must survive as one.
// This is the case a non-pointer field cannot express at all.
func TestTOMLRoundTrip_PinnedZeroIsNotAbsence(t *testing.T) {
	var zero [32]byte
	out, err := marshalProposal(proposalWithPin(&zero))
	if err != nil {
		t.Fatal(err)
	}
	back, err := unmarshalProposal(out)
	if err != nil {
		t.Fatal(err)
	}
	if back.Binding.FieldsRoot == nil {
		t.Fatal("a pin of all-zero bytes was read back as no pin at all")
	}
	if *back.Binding.FieldsRoot != zero {
		t.Fatal("pinned zero changed value")
	}
}

// A malformed value must be refused, not zeroed. Zeroing would present a
// corrupt pin as an absent one, which the manifest gate accepts as a
// legitimate v1 proposal — turning a parse failure into a downgrade.
func TestTOMLRoundTrip_MalformedFieldsRootRefused(t *testing.T) {
	for _, bad := range []string{`"abc"`, `""`, `"` + strings.Repeat("z", 64) + `"`} {
		raw := "pod_ref = \"dave/probe@1.0.0\"\n" +
			"h_manifest = \"" + strings.Repeat("ab", 32) + "\"\n" +
			"fields_root = " + bad + "\n"
		if _, err := unmarshalProposal([]byte(raw)); err == nil {
			t.Fatalf("accepted a malformed fields_root %s instead of refusing it", bad)
		}
	}
}
