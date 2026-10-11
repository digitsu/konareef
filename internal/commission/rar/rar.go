// Copyright 2026 Jerry David Chan, Konareef.ai
// SPDX-License-Identifier: Apache-2.0

// Package rar renders a konareef commission envelope as an RFC 9396
// authorization_details entry, and parses one back.
//
// This package is deliberately a leaf. RFC 9396's expressiveness against
// the four constraint dimensions is untested, and a bespoke format is the
// recorded fallback. Confining the wire format here means taking that
// fallback replaces one package rather than forcing a redesign.
package rar

import (
	"encoding/hex"
	"encoding/json"
	"fmt"

	"github.com/digitsu/konareef/internal/commission"
	"github.com/digitsu/konareef/internal/envelope"
)

// authorizationDetailsType is the konareef-specific RFC 9396 type value.
const authorizationDetailsType = "https://konareef.ai/authz/commission/v1"

// hManifestHexLen is the length of HManifest ([32]byte) hex-encoded.
const hManifestHexLen = 64

// detail is one authorization_details entry.
//
// Models, Tools, Labels and CMaxSats are pointers, not plain values. JSON
// already distinguishes an absent key from a present-but-empty one, and
// that distinction is exactly the envelope's presence flags
// (ModelsSet/ToolsSet/LabelsSet/CMaxSet): a nil pointer marshals to no key
// at all (an omitted dimension), while a non-nil pointer marshals its
// pointee even when that pointee is a zero value or an empty slice (a
// dimension that was explicitly stated as empty, or stated as zero spend).
// `omitempty` on a pointer field checks only whether the pointer itself is
// nil, never what it points to, which is what makes this work: a pointer
// to an empty slice or to 0 is not "empty" by Go's encoding/json rules and
// so the key is still emitted. Earlier code used plain (non-pointer)
// fields and set every presence flag to true unconditionally in Parse;
// that let a Render/Parse round trip launder an envelope that omitted a
// dimension into one that appeared to state it, defeating
// envelope.ValidateAsCommission's fail-closed refusal of omitted
// dimensions (see TestParse_CannotLaunderOmittedDimension).
type detail struct {
	Type      string    `json:"type"`
	Models    *[]string `json:"models,omitempty"`
	Tools     *[]string `json:"tools,omitempty"`
	Labels    *[]string `json:"labels,omitempty"`
	CMaxSats  *uint64   `json:"c_max_sats,omitempty"`
	PodRef    string    `json:"pod_ref"`
	HManifest string    `json:"h_manifest"`
	// FieldsRoot is a pointer for the same reason the dimensions above are:
	// a commission that pins no circuit commitment and one that pins a
	// commitment of all-zero bytes are different claims, and a plain string
	// collapses them ("" round-tripping into a pinned zero). Absent key =>
	// nil => not pinned.
	FieldsRoot *string `json:"fields_root,omitempty"`
}

// statedSet returns a pointer to the normalised set for Render to emit, or
// nil if the dimension was never stated. A stated-but-empty set still
// returns a non-nil pointer to an empty (non-nil) slice, so it marshals as
// "[]" rather than being omitted: envelope.Normalise itself returns nil
// for an empty input, so that has to be re-substituted here.
func statedSet(set bool, s []string) *[]string {
	if !set {
		return nil
	}
	out := envelope.Normalise(s)
	if out == nil {
		out = []string{}
	}
	return &out
}

// Render encodes an envelope and its binding as a one-element
// authorization_details array, the RFC 9396 wire shape. A dimension the
// envelope did not state (its presence flag is false) is omitted from the
// JSON entirely, rather than written with a default value, so Parse can
// tell the two cases apart. See the detail type's doc comment for why.
func Render(e envelope.Envelope, b commission.Binding) ([]byte, error) {
	d := detail{
		Type:      authorizationDetailsType,
		Models:    statedSet(e.ModelsSet, e.Models),
		Tools:     statedSet(e.ToolsSet, e.Tools),
		Labels:    statedSet(e.LabelsSet, e.Labels),
		PodRef:    b.PodRef,
		HManifest: hex.EncodeToString(b.HManifest[:]),
	}
	if b.FieldsRoot != nil {
		fr := hex.EncodeToString(b.FieldsRoot[:])
		d.FieldsRoot = &fr
	}
	if e.CMaxSet {
		cMax := e.CMax
		d.CMaxSats = &cMax
	}
	return json.Marshal([]detail{d})
}

// Parse decodes an authorization_details array back into an envelope and
// binding. A dimension's presence flag (ModelsSet, ToolsSet, LabelsSet,
// CMaxSet) is set from whether its key was present in the document, not
// unconditionally: a dimension whose key is absent comes back unstated
// (flag false, zero value), and a dimension whose key is present -- even
// as "[]" or 0 -- comes back stated (flag true) with that value. This is
// what makes the round trip lossless for presence, and what stops an
// omitted dimension from being laundered into a stated one; see the
// detail type's doc comment and TestParse_CannotLaunderOmittedDimension.
//
// Parse rejects a document whose type is not the konareef
// authorization_details type, whose array does not contain exactly one
// entry, or whose h_manifest is not exactly 64 hex characters (32 bytes).
func Parse(raw []byte) (envelope.Envelope, commission.Binding, error) {
	var ds []detail
	if err := json.Unmarshal(raw, &ds); err != nil {
		return envelope.Envelope{}, commission.Binding{}, err
	}
	if len(ds) != 1 {
		return envelope.Envelope{}, commission.Binding{}, fmt.Errorf("want exactly one authorization_details entry, got %d", len(ds))
	}
	d := ds[0]
	if d.Type != authorizationDetailsType {
		return envelope.Envelope{}, commission.Binding{}, fmt.Errorf("unknown authorization_details type %q", d.Type)
	}
	if len(d.HManifest) != hManifestHexLen {
		return envelope.Envelope{}, commission.Binding{}, fmt.Errorf("h_manifest must be %d hex chars, got %d", hManifestHexLen, len(d.HManifest))
	}
	hm, err := hex.DecodeString(d.HManifest)
	if err != nil {
		return envelope.Envelope{}, commission.Binding{}, fmt.Errorf("h_manifest must be %d hex chars: %w", hManifestHexLen, err)
	}
	var b commission.Binding
	b.PodRef = d.PodRef
	copy(b.HManifest[:], hm)

	// A present fields_root must be well-formed. Zeroing a malformed value
	// would present it as "not pinned", which the manifest gate accepts as
	// a legitimate v1 proposal — the same laundering the dimensions above
	// were fixed for.
	if d.FieldsRoot != nil {
		if len(*d.FieldsRoot) != hManifestHexLen {
			return envelope.Envelope{}, commission.Binding{}, fmt.Errorf("fields_root must be %d hex chars, got %d", hManifestHexLen, len(*d.FieldsRoot))
		}
		frBytes, err := hex.DecodeString(*d.FieldsRoot)
		if err != nil {
			return envelope.Envelope{}, commission.Binding{}, fmt.Errorf("fields_root must be %d hex chars: %w", hManifestHexLen, err)
		}
		var fr [32]byte
		copy(fr[:], frBytes)
		b.FieldsRoot = &fr
	}

	var e envelope.Envelope
	if d.Models != nil {
		e.Models, e.ModelsSet = *d.Models, true
	}
	if d.Tools != nil {
		e.Tools, e.ToolsSet = *d.Tools, true
	}
	if d.Labels != nil {
		e.Labels, e.LabelsSet = *d.Labels, true
	}
	if d.CMaxSats != nil {
		e.CMax, e.CMaxSet = *d.CMaxSats, true
	}
	return e, b, nil
}
