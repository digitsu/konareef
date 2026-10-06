// Copyright 2026 Jerry David Chan, Konareef.ai
// SPDX-License-Identifier: Apache-2.0

// internal/paygate/payment_brc29_test.go — BEEF construction tests.
package paygate_test

import (
	"errors"
	"testing"
	"time"

	"github.com/digitsu/konareef/internal/paygate"
)

func TestBuildBEEFAgainstActiveSchedule(t *testing.T) {
	mfor := time.Now().Add(time.Hour)
	m := &paygate.Manifest{
		Service: "paygate-zk",
		Circuits: map[string]paygate.Circuit{
			"konareef-pod-step-v1": {
				Pricing: map[string]paygate.Schedule{
					"nova-fold": {ComputeUSD: 0.0001, RetailUSD: 0.001},
				},
			},
		},
		MarginMultiplier:       10,
		ScheduleRevision:       1,
		ScheduleEffectiveAfter: &mfor, // future = active
	}
	beef, err := paygate.BuildBEEF(m, "konareef-pod-step-v1", "nova-fold", 15.0)
	if err != nil {
		t.Fatalf("BuildBEEF: %v", err)
	}
	if beef.Sats == 0 {
		t.Errorf("BEEF amount = 0, want >0")
	}
}

func TestBuildBEEFAgainstStaleScheduleRejects(t *testing.T) {
	past := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	m := &paygate.Manifest{
		Service: "paygate-zk",
		Circuits: map[string]paygate.Circuit{
			"konareef-pod-step-v1": {
				Pricing: map[string]paygate.Schedule{
					"nova-fold": {RetailUSD: 0.001},
				},
			},
		},
		ScheduleEffectiveAfter: &past,
	}
	_, err := paygate.BuildBEEF(m, "konareef-pod-step-v1", "nova-fold", 15.0)
	if !errors.Is(err, paygate.ErrStaleScheduleBEEF) {
		t.Errorf("stale-schedule BEEF err = %v, want ErrStaleScheduleBEEF", err)
	}
}

func TestRetailSatsFormula(t *testing.T) {
	// retail_sats = ceil(0.001 * 10 * (100_000_000 / 15)) = ceil(66666.6...) = 66667
	got := paygate.RetailSats(0.001, 10, 15.0)
	if got != 66667 {
		t.Errorf("RetailSats = %d, want 66667", got)
	}
}
