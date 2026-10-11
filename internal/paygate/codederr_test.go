// Copyright 2026 Jerry David Chan, Konareef.ai
// SPDX-License-Identifier: Apache-2.0

// internal/paygate/codederr_test.go — errors.Is / Unwrap chain tests (B3)
// + Hermes round-3 B1 Retry-After-header test.
package paygate_test

import (
	"errors"
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/digitsu/konareef/internal/paygate"
)

// errors.Is must unwrap the codedErr produced by classifyHTTPError.
func TestErrorsIsUnwrapsPaygateError(t *testing.T) {
	body := []byte(`{"error":{"code":"COMPUTE_WORKER_CRASH","category":"compute","credit_token":"tok-99"}}`)
	err := paygate.ClassifyHTTPErrorForTest(503, nil, body)
	if err == nil {
		t.Fatal("ClassifyHTTPErrorForTest returned nil")
	}
	if !errors.Is(err, paygate.ErrComputeWorkerCrash) {
		t.Errorf("errors.Is(%v, ErrComputeWorkerCrash) = false, want true (wrap chain)", err)
	}
	// Wrap once more via fmt.Errorf — still must unwrap.
	wrapped := fmt.Errorf("submit: %w", err)
	if !errors.Is(wrapped, paygate.ErrComputeWorkerCrash) {
		t.Errorf("errors.Is(wrap, ErrComputeWorkerCrash) = false, want true through double wrap")
	}
	// Wrong sentinel must NOT match.
	if errors.Is(err, paygate.ErrCircuitPinMismatch) {
		t.Error("errors.Is must not falsely match ErrCircuitPinMismatch")
	}
}

// CreditTokenFrom must extract the credit_token even when the
// codedErr has been wrapped by fmt.Errorf.
func TestCreditTokenFromExtractsTokenFromCodedErr(t *testing.T) {
	body := []byte(`{"error":{"code":"COMPUTE_WORKER_CRASH","category":"compute","credit_token":"tok-abc-1"}}`)
	err := paygate.ClassifyHTTPErrorForTest(503, nil, body)
	if got := paygate.CreditTokenFrom(err); got != "tok-abc-1" {
		t.Errorf("CreditTokenFrom(direct) = %q, want %q", got, "tok-abc-1")
	}
	wrapped := fmt.Errorf("submit: %w", err)
	if got := paygate.CreditTokenFrom(wrapped); got != "tok-abc-1" {
		t.Errorf("CreditTokenFrom(wrapped) = %q, want %q (unwrap chain)", got, "tok-abc-1")
	}
	if got := paygate.CreditTokenFrom(errors.New("plain")); got != "" {
		t.Errorf("CreditTokenFrom(plain) = %q, want \"\"", got)
	}
}

// Hermes round-3 B1 fix — Retry-After supplied ONLY as an HTTP header
// (no JSON body field) must populate codedErr.RetryAfterSeconds.
func TestRetryAfterHeaderHonored(t *testing.T) {
	body := []byte(`{"error":{"code":"SERVICE_UNAVAILABLE","category":"availability"}}`)
	hdr := http.Header{}
	hdr.Set("Retry-After", "5")
	err := paygate.ClassifyHTTPErrorForTest(503, hdr, body)
	if err == nil {
		t.Fatal("ClassifyHTTPErrorForTest returned nil")
	}
	got := paygate.RetryAfterSecondsFromErrorForTest(err)
	if got != 5 {
		t.Errorf("RetryAfterSeconds from header-only response = %d, want 5", got)
	}

	// HTTP-date form of Retry-After is also honored.
	now := time.Now().UTC().Truncate(time.Second)
	hdr2 := http.Header{}
	hdr2.Set("Retry-After", now.Add(7*time.Second).Format(http.TimeFormat))
	err2 := paygate.ClassifyHTTPErrorForTest(503, hdr2, body)
	got2 := paygate.RetryAfterSecondsFromErrorForTest(err2)
	if got2 < 6 || got2 > 8 {
		t.Errorf("RetryAfterSeconds from HTTP-date header = %d, want ~7", got2)
	}

	// Header takes precedence over JSON body field when both present.
	bodyWithField := []byte(`{"error":{"code":"SERVICE_UNAVAILABLE","category":"availability","retry_after_seconds":99}}`)
	hdr3 := http.Header{}
	hdr3.Set("Retry-After", "3")
	err3 := paygate.ClassifyHTTPErrorForTest(503, hdr3, bodyWithField)
	if got3 := paygate.RetryAfterSecondsFromErrorForTest(err3); got3 != 3 {
		t.Errorf("header should win over body field: got %d, want 3", got3)
	}

	// JSON body field is still used when header is absent (back-compat).
	err4 := paygate.ClassifyHTTPErrorForTest(503, nil, bodyWithField)
	if got4 := paygate.RetryAfterSecondsFromErrorForTest(err4); got4 != 99 {
		t.Errorf("body-field fallback: got %d, want 99", got4)
	}
}
