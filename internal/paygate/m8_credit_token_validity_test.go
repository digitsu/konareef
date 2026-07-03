// internal/paygate/m8_credit_token_validity_test.go — M-8 credit_token validity.
package paygate_test

import (
	"context"
	"testing"

	"github.com/digitsu/konareef/internal/paygate"
	"github.com/digitsu/konareef/internal/paygate/stubserver"
)

// M-8: credit_token from failed job → resubmit within window accepted,
// no fresh BEEF required.
func TestM8CreditTokenValidity(t *testing.T) {
	s := stubserver.New(stubserver.Options{
		ManifestProfile:      "active",
		NextFailureCode:      "COMPUTE_WORKER_CRASH",
		CreditTokenInjection: "tok-validity-1",
		// No RetryAfterDuration: surface failure to caller directly.
	})
	defer s.Close()
	c := newSmokeClient(t, s)
	sess, err := c.Open(context.Background(), paygate.OpenSessionInput{CircuitID: "konareef-pod-step-v1", DisclosurePolicy: paygate.DisclosureTypeC})
	if err != nil {
		t.Fatal(err)
	}

	in := paygate.FoldStepInput{StepIndex: 0, HP: [32]byte{0x11}, BSVUSDRate: 15.0}
	_, _ = c.SubmitFold(context.Background(), sess, in) // fails; ledger stores tok-validity-1

	// Resubmit using credit_token; assert 202 + no second BEEF.
	rb, err := c.SubmitFoldWithCredit(context.Background(), sess, in, "tok-validity-1")
	if err != nil {
		t.Fatalf("credit retry: %v", err)
	}
	if rb.JobID == "" {
		t.Error("no JobID on credit retry")
	}
	if s.BEEFSubmits() != 1 {
		t.Errorf("M-8: BEEF submits = %d, want 1 (credit_token honoured)", s.BEEFSubmits())
	}
}
