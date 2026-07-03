// internal/paygate/m1_active_schedule_test.go — M-1 active-schedule check.
package paygate_test

import (
	"context"
	"errors"
	"testing"

	"github.com/digitsu/konareef/internal/paygate"
	"github.com/digitsu/konareef/internal/paygate/stubserver"
)

// M-1: stale-schedule BEEF surfaces ErrStaleScheduleBEEF non-refundably.
func TestM1ActiveScheduleCheck(t *testing.T) {
	s := stubserver.New(stubserver.Options{ManifestProfile: "stale", StaleScheduleEnforce: true})
	defer s.Close()
	c := newSmokeClient(t, s)
	sess, err := c.Open(context.Background(), paygate.OpenSessionInput{CircuitID: "konareef-pod-step-v1", DisclosurePolicy: paygate.DisclosureTypeC})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	_, err = c.SubmitFold(context.Background(), sess, paygate.FoldStepInput{StepIndex: 0, HP: [32]byte{0xaa}, BSVUSDRate: 15.0})
	if !errors.Is(err, paygate.ErrStaleScheduleBEEF) {
		t.Fatalf("M-1 expected ErrStaleScheduleBEEF; got %v", err)
	}
	if s.BEEFSubmits() != 0 {
		t.Errorf("M-1 non-refundable: BEEF must not have been debited; got %d submits", s.BEEFSubmits())
	}
}
