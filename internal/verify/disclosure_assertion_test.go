// Copyright 2026 Jerry David Chan, Konareef.ai
// SPDX-License-Identifier: Apache-2.0

// disclosure_assertion_test.go — P1.3 verify-side flag assertion.
package verify

import (
	"errors"
	"testing"
)

func TestAssertDisclosurePolicyMatch(t *testing.T) {
	b := &Bundle{Disclosure: "C"}
	if err := AssertDisclosurePolicy(b, "C"); err != nil {
		t.Errorf("matching policy: %v", err)
	}
}

func TestAssertDisclosurePolicyMismatch(t *testing.T) {
	b := &Bundle{Disclosure: "C"}
	err := AssertDisclosurePolicy(b, "D")
	if !errors.Is(err, ErrDisclosurePolicyViolation) {
		t.Fatalf("mismatch: err=%v, want ErrDisclosurePolicyViolation", err)
	}
}

func TestAssertDisclosurePolicyEmptyIsNoOp(t *testing.T) {
	b := &Bundle{Disclosure: "C"}
	if err := AssertDisclosurePolicy(b, ""); err != nil {
		t.Errorf("empty want is no-op; got %v", err)
	}
}

func TestAssertDisclosurePolicyNilBundle(t *testing.T) {
	if err := AssertDisclosurePolicy(nil, "C"); err == nil {
		t.Error("nil bundle must error")
	}
}
