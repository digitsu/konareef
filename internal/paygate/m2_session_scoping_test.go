// Copyright 2026 Jerry David Chan, Konareef.ai
// SPDX-License-Identifier: Apache-2.0

// internal/paygate/m2_session_scoping_test.go — M-2 session scoping.
package paygate_test

import (
	"context"
	"testing"

	"github.com/digitsu/konareef/internal/paygate"
	"github.com/digitsu/konareef/internal/paygate/stubserver"
)

// M-2: identical (circuit_id, step_index, h_p) in two distinct BRC-31
// sessions produces independent job_ids.
func TestM2SessionScoping(t *testing.T) {
	s := stubserver.New(stubserver.Options{ManifestProfile: "active"})
	defer s.Close()
	// Two clients with DIFFERENT identity keys → different BRC-31 session IDs.
	dirA, dirB := t.TempDir(), t.TempDir()
	cA := newSmokeClientWithDir(t, s, dirA)
	cB := newSmokeClientWithDir(t, s, dirB)
	sessA, err := cA.Open(context.Background(), paygate.OpenSessionInput{CircuitID: "konareef-pod-step-v1", DisclosurePolicy: paygate.DisclosureTypeC})
	if err != nil {
		t.Fatalf("Open A: %v", err)
	}
	sessB, err := cB.Open(context.Background(), paygate.OpenSessionInput{CircuitID: "konareef-pod-step-v1", DisclosurePolicy: paygate.DisclosureTypeC})
	if err != nil {
		t.Fatalf("Open B: %v", err)
	}
	if sessA.BRC31Session.ID == sessB.BRC31Session.ID {
		t.Fatalf("two clients produced same BRC-31 session ID")
	}
	in := paygate.FoldStepInput{StepIndex: 0, HP: [32]byte{0xaa}, BSVUSDRate: 15.0}
	rbA, err := cA.SubmitFold(context.Background(), sessA, in)
	if err != nil {
		t.Fatalf("SubmitFold A: %v", err)
	}
	rbB, err := cB.SubmitFold(context.Background(), sessB, in)
	if err != nil {
		t.Fatalf("SubmitFold B: %v", err)
	}
	if rbA.JobID == rbB.JobID {
		t.Errorf("M-2: same job_id across sessions: %q", rbA.JobID)
	}
}
