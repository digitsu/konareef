// Copyright 2026 Jerry David Chan, Konareef.ai
// SPDX-License-Identifier: Apache-2.0

// internal/paygate/retry.go — PRD 2 § 6.6 retry semantics + Retry-After.
package paygate

import (
	"net/http"
	"strconv"
	"time"
)

const backoffCap = 60 * time.Second

// BackoffStep returns the exponential-backoff delay for retry attempt
// number attempt (0-indexed). 1s, 2s, 4s, …, capped at 60s.
func BackoffStep(attempt int) time.Duration {
	d := time.Duration(1<<attempt) * time.Second
	if d > backoffCap {
		return backoffCap
	}
	return d
}

// ParseRetryAfter reads a `Retry-After` header per RFC 9110 §10.2.3
// (delta-seconds OR HTTP-date). Returns 0 if absent or unparseable.
func ParseRetryAfter(h http.Header, now time.Time) time.Duration {
	v := h.Get("Retry-After")
	if v == "" {
		return 0
	}
	if secs, err := strconv.Atoi(v); err == nil {
		if secs < 0 {
			return 0
		}
		return time.Duration(secs) * time.Second
	}
	if t, err := http.ParseTime(v); err == nil {
		d := t.Sub(now)
		if d < 0 {
			return 0
		}
		return d
	}
	return 0
}
