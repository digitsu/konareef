// Copyright 2026 Jerry David Chan, Konareef.ai
// SPDX-License-Identifier: Apache-2.0

// internal/paygate/m4_credit_token_reuse_test.go — M-4 credit_token reuse.
package paygate_test

import (
	"context"
	"errors"
	"testing"

	"github.com/digitsu/konareef/internal/paygate"
	"github.com/digitsu/konareef/internal/paygate/stubserver"
)

// M-4: transient compute error → credit_token captured → resubmit accepted, no double-charge.
func TestM4CreditTokenReuse(t *testing.T) {
	s := stubserver.New(stubserver.Options{
		ManifestProfile:      "active",
		NextFailureCode:      "COMPUTE_WORKER_CRASH",
		CreditTokenInjection: "tok-good-7",
		// No RetryAfterDuration: failure body has retry_after_seconds=0
		// so SubmitFold's retry loop does NOT re-POST and the failure
		// surfaces directly to the caller.
	})
	defer s.Close()
	c := newSmokeClient(t, s)
	sess, err := c.Open(context.Background(), paygate.OpenSessionInput{CircuitID: "konareef-pod-step-v1", DisclosurePolicy: paygate.DisclosureTypeC})
	if err != nil {
		t.Fatal(err)
	}
	in := paygate.FoldStepInput{StepIndex: 0, HP: [32]byte{0xcc}, BSVUSDRate: 15.0}
	_, err = c.SubmitFold(context.Background(), sess, in)
	if !errors.Is(err, paygate.ErrComputeWorkerCrash) {
		t.Fatalf("first submit err = %v, want ErrComputeWorkerCrash", err)
	}
	if s.BEEFSubmits() != 1 {
		t.Errorf("first BEEF submits = %d, want 1", s.BEEFSubmits())
	}
	// Retry using credit_token — must NOT submit a second BEEF.
	rb, err := c.SubmitFoldWithCredit(context.Background(), sess, in, "tok-good-7")
	if err != nil {
		t.Fatalf("retry with credit: %v", err)
	}
	if rb.JobID == "" {
		t.Error("retry returned no JobID")
	}
	if s.BEEFSubmits() != 1 {
		t.Errorf("M-4: BEEF submits after retry = %d, want 1 (no second debit)", s.BEEFSubmits())
	}
}
