// internal/paygate/m6_retention_window_test.go — M-6 retention window.
package paygate_test

import (
	"context"
	"errors"
	"testing"

	"github.com/digitsu/konareef/internal/paygate"
	"github.com/digitsu/konareef/internal/paygate/stubserver"
)

// M-6: primary-bound retention. Fresh retention permits the first
// fetch (returned via SubmitFold's poll-and-fetch loop); a retention
// purge surfaces ErrResultExpired on subsequent /result fetches.
func TestM6PrimaryBoundRetention(t *testing.T) {
	// Phase A: fresh retention; first /result OK.
	s := stubserver.New(stubserver.Options{ManifestProfile: "active", RetentionState: "fresh"})
	defer s.Close()
	c := newSmokeClient(t, s)
	sess, err := c.Open(context.Background(), paygate.OpenSessionInput{CircuitID: "konareef-pod-step-v1", DisclosurePolicy: paygate.DisclosureTypeC})
	if err != nil {
		t.Fatal(err)
	}
	in := paygate.FoldStepInput{StepIndex: 0, HP: [32]byte{0xdd}, BSVUSDRate: 15.0}
	rb, err := c.SubmitFold(context.Background(), sess, in)
	if err != nil {
		t.Fatalf("first fetch must return 200; got %v", err)
	}
	if rb == nil {
		t.Fatal("nil result")
	}

	// Phase B: simulate retention purge — /result returns 410.
	s2 := stubserver.New(stubserver.Options{ManifestProfile: "active", RetentionState: "expired"})
	defer s2.Close()
	c2 := newSmokeClient(t, s2)
	sess2, err := c2.Open(context.Background(), paygate.OpenSessionInput{CircuitID: "konareef-pod-step-v1", DisclosurePolicy: paygate.DisclosureTypeC})
	if err != nil {
		t.Fatal(err)
	}
	// First submit a job so it exists in stub state, then attempt
	// a separate FetchResult on the resulting job_id (which the stub
	// unconditionally serves as 410 in expired mode).
	in2 := paygate.FoldStepInput{StepIndex: 0, HP: [32]byte{0xdd}, BSVUSDRate: 15.0}
	// The submit path itself will already encounter 410 in pollAndFetch
	// when expired mode is active and the result endpoint returns 410.
	_, err = c2.SubmitFold(context.Background(), sess2, in2)
	if !errors.Is(err, paygate.ErrResultExpired) {
		t.Fatalf("post-retention /result must surface ErrResultExpired; got %v", err)
	}
}
