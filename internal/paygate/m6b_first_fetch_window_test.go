// internal/paygate/m6b_first_fetch_window_test.go — M-6b first-fetch window.
package paygate_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/digitsu/konareef/internal/paygate"
	"github.com/digitsu/konareef/internal/paygate/stubserver"
)

// M-6b: first-fetch-bound. First /result at t=0 returns 200; second at
// t=59m within the 1h first-fetch window returns 200 with identical
// body; third at t=61m returns 410 RESULT_EXPIRED.
//
// The stub uses a SHORT FirstFetchWindow (e.g. 200ms) so the test
// completes in real time without sleeping for 61 minutes.
func TestM6bFirstFetchWindow(t *testing.T) {
	s := stubserver.New(stubserver.Options{
		ManifestProfile:  "active",
		FirstFetchWindow: 200 * time.Millisecond,
	})
	defer s.Close()
	c := newSmokeClient(t, s)
	sess, err := c.Open(context.Background(), paygate.OpenSessionInput{CircuitID: "konareef-pod-step-v1", DisclosurePolicy: paygate.DisclosureTypeC})
	if err != nil {
		t.Fatal(err)
	}
	in := paygate.FoldStepInput{StepIndex: 0, HP: [32]byte{0xee}, BSVUSDRate: 15.0}

	// First /result (t≈0) — fetched as part of SubmitFold's poll→fetch loop.
	rb1, err := c.SubmitFold(context.Background(), sess, in)
	if err != nil {
		t.Fatalf("first fetch: %v", err)
	}

	// Second /result well within the window (t≈100ms) — same body.
	time.Sleep(100 * time.Millisecond)
	rb2, err := c.FetchResult(context.Background(), sess, rb1.JobID)
	if err != nil {
		t.Fatalf("within-window /result: %v", err)
	}
	if string(rb1.AccumulatorOut) != string(rb2.AccumulatorOut) {
		t.Errorf("within-window /result body differs; rb1=%x rb2=%x", rb1.AccumulatorOut, rb2.AccumulatorOut)
	}

	// Third /result past the window (t≈300ms > 200ms FirstFetchWindow) — 410.
	time.Sleep(200 * time.Millisecond)
	_, err = c.FetchResult(context.Background(), sess, rb1.JobID)
	if !errors.Is(err, paygate.ErrResultExpired) {
		t.Fatalf("past-window /result err = %v, want ErrResultExpired", err)
	}
}
