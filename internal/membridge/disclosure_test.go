// Copyright 2026 Jerry David Chan, Konareef.ai
// SPDX-License-Identifier: Apache-2.0

// internal/membridge/disclosure_test.go
package membridge

import (
	"errors"
	"strings"
	"testing"
)

// TestPublicBundleView_TypeC_IncludesSalt: Type C bundles expose salt.
func TestPublicBundleView_TypeC_IncludesSalt(t *testing.T) {
	salt := bytesRepeat(0xaa, 32)
	view, err := PublicBundleView{
		Policy:     PolicyTypeC,
		PodSalt:    salt,
		AuditTrail: nil,
		RInit:      [32]byte{},
	}.Serialize()
	if err != nil {
		t.Fatalf("Serialize: %v", err)
	}
	if view.PodSaltHex == "" {
		t.Fatal("Type-C bundle missing pod_salt")
	}
}

// TestPublicBundleView_TypeD_RedactsSalt: Type D bundles omit salt.
func TestPublicBundleView_TypeD_RedactsSalt(t *testing.T) {
	salt := bytesRepeat(0xdd, 32)
	view, err := PublicBundleView{
		Policy:     PolicyTypeD,
		PodSalt:    salt,
		AuditTrail: nil,
		RInit:      [32]byte{},
	}.Serialize()
	if err != nil {
		t.Fatalf("Serialize: %v", err)
	}
	if view.PodSaltHex != "" {
		t.Fatal("Type-D bundle leaked pod_salt")
	}
}

// TestPublicBundleView_TypeD_AuditTrailRejects: passing a non-nil audit
// trail to a Type-D Serialize MUST surface ErrTypeDConfidentialLeak.
func TestPublicBundleView_TypeD_AuditTrailRejects(t *testing.T) {
	salt := bytesRepeat(0xdd, 32)
	trail := []AuditTrailEntry{{ThoughtID: 1, Index: 7}}
	_, err := PublicBundleView{
		Policy:     PolicyTypeD,
		PodSalt:    salt,
		AuditTrail: trail,
	}.Serialize()
	if !errors.Is(err, ErrTypeDConfidentialLeak) {
		t.Fatalf("err = %v, want ErrTypeDConfidentialLeak", err)
	}
}

// TestPublicBundleView_TypeD_SerializeDoesNotEmbedSaltBytesInJSON
// scans the JSON output to confirm no salt-byte sequence appears.
func TestPublicBundleView_TypeD_SerializeDoesNotEmbedSaltBytesInJSON(t *testing.T) {
	salt := bytesRepeat(0xdd, 32)
	view, err := PublicBundleView{
		Policy:  PolicyTypeD,
		PodSalt: salt,
	}.Serialize()
	if err != nil {
		t.Fatalf("Serialize: %v", err)
	}
	js, err := view.MarshalJSON()
	if err != nil {
		t.Fatalf("MarshalJSON: %v", err)
	}
	if strings.Contains(string(js), "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd") {
		t.Fatal("Type-D JSON leaked salt bytes")
	}
}

// TestTypeDConfidentialLeakReject covers the DoD vector
// "type-d-confidential-leak-reject": every confidential-field
// population path on a Type-D bundle fails closed.
func TestTypeDConfidentialLeakReject(t *testing.T) {
	salt := bytesRepeat(0xdd, 32)
	// Audit trail populated → reject.
	_, err := PublicBundleView{
		Policy:     PolicyTypeD,
		PodSalt:    salt,
		AuditTrail: []AuditTrailEntry{{ThoughtID: 7, Index: 13}},
	}.Serialize()
	if !errors.Is(err, ErrTypeDConfidentialLeak) {
		t.Errorf("audit-trail leak err = %v, want ErrTypeDConfidentialLeak", err)
	}
	// PolicyUnspecified is treated as a leak (defensive default).
	_, err = PublicBundleView{Policy: PolicyUnspecified, PodSalt: salt}.Serialize()
	if !errors.Is(err, ErrTypeDConfidentialLeak) {
		t.Errorf("unspecified-policy err = %v, want ErrTypeDConfidentialLeak", err)
	}
}
