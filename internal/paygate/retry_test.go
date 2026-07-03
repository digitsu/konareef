// internal/paygate/retry_test.go — backoff + Retry-After parser tests.
package paygate_test

import (
	"net/http"
	"testing"
	"time"

	"github.com/digitsu/konareef/internal/paygate"
)

func TestParseRetryAfterSeconds(t *testing.T) {
	h := http.Header{}
	h.Set("Retry-After", "30")
	if got := paygate.ParseRetryAfter(h, time.Now()); got != 30*time.Second {
		t.Errorf("ParseRetryAfter(\"30\") = %v, want 30s", got)
	}
}

func TestParseRetryAfterHTTPDate(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	target := now.Add(60 * time.Second)
	h := http.Header{}
	h.Set("Retry-After", target.Format(http.TimeFormat))
	got := paygate.ParseRetryAfter(h, now)
	if got < 59*time.Second || got > 61*time.Second {
		t.Errorf("HTTP-date Retry-After = %v, want ~60s", got)
	}
}

func TestParseRetryAfterMissing(t *testing.T) {
	h := http.Header{}
	if got := paygate.ParseRetryAfter(h, time.Now()); got != 0 {
		t.Errorf("missing Retry-After = %v, want 0", got)
	}
}

func TestBackoffStep(t *testing.T) {
	if paygate.BackoffStep(0) != 1*time.Second {
		t.Errorf("attempt 0 = %v, want 1s", paygate.BackoffStep(0))
	}
	if paygate.BackoffStep(1) != 2*time.Second {
		t.Errorf("attempt 1 = %v, want 2s", paygate.BackoffStep(1))
	}
	if paygate.BackoffStep(2) != 4*time.Second {
		t.Errorf("attempt 2 = %v, want 4s", paygate.BackoffStep(2))
	}
	if paygate.BackoffStep(10) > 60*time.Second {
		t.Errorf("attempt 10 capped: %v", paygate.BackoffStep(10))
	}
}
