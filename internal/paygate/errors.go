// Copyright 2026 Jerry David Chan, Konareef.ai
// SPDX-License-Identifier: Apache-2.0

// internal/paygate/errors.go — typed PRD 2 § 6.4 error model.
//
// Every Err* sentinel is a *PaygateError; wrapped errors compare equal
// via errors.Is via the default pointer-equality unwrap. Code(err) and
// CategoryOf(err) extract the stable identifier strings for logging,
// telemetry, and golden-vector comparison.
package paygate

import "errors"

// Category is the closed enumeration from PRD 2 § 6.4.
type Category string

const (
	CategoryAuth       Category = "auth"
	CategoryPayment    Category = "payment"
	CategoryValidation Category = "validation"
	CategoryCompute    Category = "compute"
	CategoryLogical    Category = "logical"
	CategoryService    Category = "service"
)

// PaygateError is the concrete sentinel type.
type PaygateError struct {
	CodeStr  string
	Cat      Category
	Retryabl bool
}

// Error implements the error interface and returns the stable code string.
func (e *PaygateError) Error() string { return e.CodeStr }

// auth sentinels.
var (
	ErrAuthMissingBRC31   = &PaygateError{CodeStr: "AUTH_MISSING_BRC31", Cat: CategoryAuth, Retryabl: true}
	ErrAuthInvalidBRC31   = &PaygateError{CodeStr: "AUTH_INVALID_BRC31", Cat: CategoryAuth, Retryabl: true}
	ErrAuthSessionExpired = &PaygateError{CodeStr: "AUTH_SESSION_EXPIRED", Cat: CategoryAuth, Retryabl: true}
	ErrAuthScopeMismatch  = &PaygateError{CodeStr: "AUTH_SCOPE_MISMATCH", Cat: CategoryAuth, Retryabl: false}
)

// payment sentinels.
var (
	ErrPaymentBEEFInvalid        = &PaygateError{CodeStr: "PAYMENT_BEEF_INVALID", Cat: CategoryPayment, Retryabl: true}
	ErrPaymentAmountInsufficient = &PaygateError{CodeStr: "PAYMENT_AMOUNT_INSUFFICIENT", Cat: CategoryPayment, Retryabl: true}
	ErrPaymentDoubleSpend        = &PaygateError{CodeStr: "PAYMENT_DOUBLE_SPEND", Cat: CategoryPayment, Retryabl: false}
	ErrCreditTokenInvalid        = &PaygateError{CodeStr: "PAYMENT_CREDIT_TOKEN_INVALID", Cat: CategoryPayment, Retryabl: false}
	ErrCreditTokenExpired        = &PaygateError{CodeStr: "PAYMENT_CREDIT_TOKEN_EXPIRED", Cat: CategoryPayment, Retryabl: false}
	// Non-PRD-2 but normative per PRD P1.8 Obligation 3:
	ErrStaleScheduleBEEF = &PaygateError{CodeStr: "ERR_STALE_SCHEDULE_BEEF", Cat: CategoryPayment, Retryabl: false}
)

// validation sentinels.
var (
	ErrValidationSchema            = &PaygateError{CodeStr: "VALIDATION_SCHEMA", Cat: CategoryValidation, Retryabl: false}
	ErrValidationInputCapViolation = &PaygateError{CodeStr: "VALIDATION_INPUT_CAP_VIOLATION", Cat: CategoryValidation, Retryabl: false}
	ErrValidationUnknownCircuitID  = &PaygateError{CodeStr: "VALIDATION_UNKNOWN_CIRCUIT_ID", Cat: CategoryValidation, Retryabl: false}
	ErrValidationWitnessShape      = &PaygateError{CodeStr: "VALIDATION_WITNESS_SHAPE", Cat: CategoryValidation, Retryabl: true}
	ErrValidationOperationNotSupp  = &PaygateError{CodeStr: "VALIDATION_OPERATION_NOT_SUPPORTED", Cat: CategoryValidation, Retryabl: false}
	// Non-PRD-2 but normative per PRD P1.8 Obligation 6:
	ErrCircuitPinMismatch = &PaygateError{CodeStr: "ERR_CIRCUIT_PIN_MISMATCH", Cat: CategoryValidation, Retryabl: false}
)

// compute sentinels.
var (
	ErrComputeWorkerCrash       = &PaygateError{CodeStr: "COMPUTE_WORKER_CRASH", Cat: CategoryCompute, Retryabl: true}
	ErrComputeTimeout           = &PaygateError{CodeStr: "COMPUTE_TIMEOUT", Cat: CategoryCompute, Retryabl: true}
	ErrComputeResourceExhausted = &PaygateError{CodeStr: "COMPUTE_RESOURCE_EXHAUSTED", Cat: CategoryCompute, Retryabl: true}
)

// logical sentinels.
var (
	ErrProofSelfVerifyFailed  = &PaygateError{CodeStr: "PROOF_SELF_VERIFY_FAILED", Cat: CategoryLogical, Retryabl: false}
	ErrProofCircuitDeprecated = &PaygateError{CodeStr: "PROOF_CIRCUIT_DEPRECATED", Cat: CategoryLogical, Retryabl: false}
)

// service sentinels.
var (
	ErrServiceUnavailable    = &PaygateError{CodeStr: "SERVICE_UNAVAILABLE", Cat: CategoryService, Retryabl: true}
	ErrServiceQueueSaturated = &PaygateError{CodeStr: "SERVICE_QUEUE_SATURATED", Cat: CategoryService, Retryabl: true}
	ErrResultExpired         = &PaygateError{CodeStr: "RESULT_EXPIRED", Cat: CategoryService, Retryabl: false}
)

// Code extracts the stable code string from err (or any wrapper).
// Returns "" for nil or non-PaygateError.
func Code(err error) string {
	var pe *PaygateError
	if errors.As(err, &pe) {
		return pe.CodeStr
	}
	return ""
}

// CategoryOf returns the closed-enumeration category for err.
func CategoryOf(err error) Category {
	var pe *PaygateError
	if errors.As(err, &pe) {
		return pe.Cat
	}
	return ""
}

// IsRetryable returns the per-code retry hint from PRD 2 § 6.6.
// Caller MAY override based on other signals (e.g. Retry-After header).
func IsRetryable(err error) bool {
	var pe *PaygateError
	if errors.As(err, &pe) {
		return pe.Retryabl
	}
	return false
}
