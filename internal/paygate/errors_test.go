// internal/paygate/errors_test.go — typed PRD 2 § 6.4 error model tests.
package paygate_test

import (
	"errors"
	"fmt"
	"testing"

	"github.com/digitsu/konareef/internal/paygate"
)

func TestSentinelCodes(t *testing.T) {
	cases := []struct {
		err  error
		code string
		cat  paygate.Category
	}{
		{paygate.ErrStaleScheduleBEEF, "ERR_STALE_SCHEDULE_BEEF", paygate.CategoryPayment},
		{paygate.ErrCircuitPinMismatch, "ERR_CIRCUIT_PIN_MISMATCH", paygate.CategoryValidation},
		{paygate.ErrResultExpired, "RESULT_EXPIRED", paygate.CategoryService},
		{paygate.ErrPaymentAmountInsufficient, "PAYMENT_AMOUNT_INSUFFICIENT", paygate.CategoryPayment},
		{paygate.ErrCreditTokenInvalid, "PAYMENT_CREDIT_TOKEN_INVALID", paygate.CategoryPayment},
		{paygate.ErrCreditTokenExpired, "PAYMENT_CREDIT_TOKEN_EXPIRED", paygate.CategoryPayment},
		{paygate.ErrComputeWorkerCrash, "COMPUTE_WORKER_CRASH", paygate.CategoryCompute},
		{paygate.ErrServiceUnavailable, "SERVICE_UNAVAILABLE", paygate.CategoryService},
		{paygate.ErrValidationWitnessShape, "VALIDATION_WITNESS_SHAPE", paygate.CategoryValidation},
		{paygate.ErrProofSelfVerifyFailed, "PROOF_SELF_VERIFY_FAILED", paygate.CategoryLogical},
	}
	for _, c := range cases {
		if paygate.Code(c.err) != c.code {
			t.Errorf("Code(%v)=%q want %q", c.err, paygate.Code(c.err), c.code)
		}
		if paygate.CategoryOf(c.err) != c.cat {
			t.Errorf("CategoryOf(%v)=%v want %v", c.err, paygate.CategoryOf(c.err), c.cat)
		}
		wrapped := fmt.Errorf("wrap: %w", c.err)
		if !errors.Is(wrapped, c.err) {
			t.Errorf("errors.Is wrap of %v: false", c.err)
		}
	}
}

func TestIsRetryable(t *testing.T) {
	cases := []struct {
		err  error
		want bool
	}{
		{paygate.ErrServiceUnavailable, true},
		{paygate.ErrComputeWorkerCrash, true},
		{paygate.ErrProofSelfVerifyFailed, false},
		{paygate.ErrCircuitPinMismatch, false},
		{paygate.ErrStaleScheduleBEEF, false},
		{paygate.ErrResultExpired, false},
	}
	for _, c := range cases {
		if got := paygate.IsRetryable(c.err); got != c.want {
			t.Errorf("IsRetryable(%v)=%v want %v", c.err, got, c.want)
		}
	}
}
