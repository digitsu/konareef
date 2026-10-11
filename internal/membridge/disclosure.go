// Copyright 2026 Jerry David Chan, Konareef.ai
// SPDX-License-Identifier: Apache-2.0

// internal/membridge/disclosure.go — PRD 4 §B.2 + §B.2.1 disclosure controls.
//
// PolicyTypeC: bundle-disclosed salt; external re-derivation enabled.
// PolicyTypeD: salt committed via h_manifest but redacted from the
//
//	bundle. Audit trails are witness-confidential and MUST
//	NOT travel on the public channel.
package membridge

import (
	"encoding/hex"
	"encoding/json"
)

// DisclosurePolicy is the bundle-side confidentiality posture.
type DisclosurePolicy uint8

const (
	PolicyUnspecified DisclosurePolicy = 0
	PolicyTypeC       DisclosurePolicy = 1
	PolicyTypeD       DisclosurePolicy = 2
)

// PublicBundleView is the raw input to the public-bundle serializer.
// Serialize emits a confidentiality-aware SerializedView; passing a
// Type-D bundle with any confidential field populated (audit trail,
// per-cell logical_key, per-cell index) returns ErrTypeDConfidentialLeak.
type PublicBundleView struct {
	Policy     DisclosurePolicy
	PodSalt    []byte
	RInit      [32]byte
	AuditTrail []AuditTrailEntry // §B.5 — Type-D MUST be empty here.
	// Future fields (logical_keys, indices) are gated identically.
}

// SerializedView is the post-redaction view safe to publish.
type SerializedView struct {
	PolicyStr  string `json:"policy"`
	PodSaltHex string `json:"pod_salt,omitempty"`
	RInitHex   string `json:"r_init"`
}

// MarshalJSON emits the public bundle JSON. Wrapper exists so tests can
// scan for leaked bytes in the canonical serialized form.
func (s SerializedView) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		Policy  string `json:"policy"`
		PodSalt string `json:"pod_salt,omitempty"`
		RInit   string `json:"r_init"`
	}{
		Policy:  s.PolicyStr,
		PodSalt: s.PodSaltHex,
		RInit:   s.RInitHex,
	})
}

// Serialize applies PRD 4 §B.2.1 redaction rules.
func (v PublicBundleView) Serialize() (SerializedView, error) {
	switch v.Policy {
	case PolicyTypeC:
		return SerializedView{
			PolicyStr:  "C",
			PodSaltHex: hex.EncodeToString(v.PodSalt),
			RInitHex:   hex.EncodeToString(v.RInit[:]),
		}, nil
	case PolicyTypeD:
		// Reject ANY confidential field on the public path.
		if len(v.AuditTrail) > 0 {
			return SerializedView{}, ErrTypeDConfidentialLeak
		}
		return SerializedView{
			PolicyStr:  "D",
			PodSaltHex: "", // redacted
			RInitHex:   hex.EncodeToString(v.RInit[:]),
		}, nil
	default:
		return SerializedView{}, ErrTypeDConfidentialLeak
	}
}
