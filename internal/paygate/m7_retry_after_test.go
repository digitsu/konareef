// internal/paygate/m7_retry_after_test.go — M-7 Retry-After honoured.
package paygate_test

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/digitsu/konareef/internal/paygate"
	"github.com/digitsu/konareef/internal/paygate/stubserver"
)

// M-7 (deterministic): on first attempt the server returns 503 with
// `Retry-After: 2` set ONLY as an HTTP header. On the second attempt
// it returns 200 OK with a valid job ID. Asserts:
//
//  1. attemptCount == 2 (proves the retry actually happened exactly
//     once before success)
//  2. attemptTimes[1] - attemptTimes[0] >= 2 * time.Second
//     (proves the Retry-After delay was respected)
//  3. SubmitFold returned nil error and a valid job ID
func TestM7RetryAfter(t *testing.T) {
	var (
		mu           sync.Mutex
		attemptTimes []time.Time
		attemptCount int
	)
	record := func() {
		mu.Lock()
		defer mu.Unlock()
		attemptCount++
		attemptTimes = append(attemptTimes, time.Now())
	}

	s := stubserver.New(stubserver.Options{
		ManifestProfile: "active",
		OnAttempt:       record,
		AttemptScript: []stubserver.AttemptResponse{
			{Status: 503, RetryAfter: 2 * time.Second},                  // attempt 1
			{Status: 200, JobID: "job-m7-success", AcceptedAtUTC: true}, // attempt 2
		},
	})
	defer s.Close()
	c := newSmokeClient(t, s)
	sess, err := c.Open(context.Background(), paygate.OpenSessionInput{
		CircuitID:        "konareef-pod-step-v1",
		DisclosurePolicy: paygate.DisclosureTypeC,
	})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}

	resp, err := c.SubmitFold(context.Background(), sess,
		paygate.FoldStepInput{StepIndex: 0, HP: [32]byte{0xff}, BSVUSDRate: 15.0})
	if err != nil {
		t.Fatalf("SubmitFold after retry: err=%v, want nil", err)
	}
	if resp == nil || resp.JobID != "job-m7-success" {
		t.Fatalf("SubmitFold: resp=%+v, want JobID=job-m7-success", resp)
	}

	mu.Lock()
	defer mu.Unlock()
	if attemptCount != 2 {
		t.Fatalf("M-7: attemptCount=%d, want 2", attemptCount)
	}
	gap := attemptTimes[1].Sub(attemptTimes[0])
	if gap < 2*time.Second {
		t.Errorf("M-7: gap between attempts = %v, want >= 2s (Retry-After honoured)", gap)
	}
}
