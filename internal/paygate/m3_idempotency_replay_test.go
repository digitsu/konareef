// Copyright 2026 Jerry David Chan, Konareef.ai
// SPDX-License-Identifier: Apache-2.0

// internal/paygate/m3_idempotency_replay_test.go — M-3 idempotency replay.
package paygate_test

import (
	"context"
	"testing"

	"github.com/digitsu/konareef/internal/paygate"
	"github.com/digitsu/konareef/internal/paygate/stubserver"
)

func TestM3IdempotencyReplay(t *testing.T) {
	s := stubserver.New(stubserver.Options{ManifestProfile: "active", IdempotencyReplay: true})
	defer s.Close()
	c := newSmokeClient(t, s)
	sess, err := c.Open(context.Background(), paygate.OpenSessionInput{CircuitID: "konareef-pod-step-v1", DisclosurePolicy: paygate.DisclosureTypeC})
	if err != nil {
		t.Fatal(err)
	}
	in := paygate.FoldStepInput{StepIndex: 0, HP: [32]byte{0xbb}, BSVUSDRate: 15.0}
	rb1, err := c.SubmitFold(context.Background(), sess, in)
	if err != nil {
		t.Fatalf("first SubmitFold: %v", err)
	}
	rb2, err := c.SubmitFold(context.Background(), sess, in)
	if err != nil {
		t.Fatalf("replay SubmitFold: %v", err)
	}
	if rb1.JobID != rb2.JobID {
		t.Errorf("M-3: replay job_id changed: %q vs %q", rb1.JobID, rb2.JobID)
	}
	if s.BEEFSubmits() != 1 {
		t.Errorf("M-3: BEEF submits = %d, want 1 (no double-debit)", s.BEEFSubmits())
	}
}
