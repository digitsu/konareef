// Copyright 2026 Jerry David Chan, Konareef.ai
// SPDX-License-Identifier: Apache-2.0

// internal/paygate/payment_brc29.go — PRD 2 § 5.1 + PRD P1.8 Obligation 3.
//
// retail_sats = ceil(compute_cost_usd * margin_multiplier * (100_000_000 / bsv_usd_rate))
//
// BEEFs constructed after schedule_effective_after has elapsed are
// non-refundable per PRD P1.8 Obligation 3. BuildBEEF returns
// ErrStaleScheduleBEEF in that case so the runtime bears the cost
// observably rather than silently absorbing it.
package paygate

import (
	"fmt"
	"math"
	"time"
)

// BEEF is the constructed BRC-29 payment payload.
//
// Wire-byte construction is delegated to the existing konareef secp256k1
// publisher signing code (internal/identity/); BEEF.WireBytes is the
// finalised CBOR-ish payload to be hex-encoded into the X-Payment
// header. V1 ships a stub WireBytes that satisfies the conformance
// stub server; full BSV transaction graph is added by the live BEEF
// builder ticket (out of scope for v1 stub).
type BEEF struct {
	CircuitID string
	Op        string
	Sats      uint64
	WireBytes []byte
}

// RetailSats computes ceil(usd * margin * 100_000_000 / rate).
func RetailSats(computeUSD float64, marginMultiplier int, bsvUSDRate float64) uint64 {
	value := computeUSD * float64(marginMultiplier) * (100_000_000.0 / bsvUSDRate)
	return uint64(math.Ceil(value))
}

// BuildBEEF constructs the BEEF for (circuitID, op) against the
// manifest's CURRENT active schedule. Returns ErrStaleScheduleBEEF when
// the manifest's schedule_effective_after has elapsed (PRD P1.8
// Obligation 3 non-refundable contract).
func BuildBEEF(m *Manifest, circuitID, op string, bsvUSDRate float64) (*BEEF, error) {
	if m.IsScheduleStale(time.Now().UTC()) {
		return nil, ErrStaleScheduleBEEF
	}
	sched, err := m.ActiveSchedule(circuitID, op)
	if err != nil {
		return nil, fmt.Errorf("paygate: build beef: %w", err)
	}
	sats := RetailSats(sched.ComputeUSD, m.MarginMultiplier, bsvUSDRate)
	if sats == 0 {
		// Use retail if compute_usd missing (forward compat).
		sats = RetailSats(sched.RetailUSD/float64(m.MarginMultiplier), m.MarginMultiplier, bsvUSDRate)
	}
	wire := []byte(fmt.Sprintf("BEEF(stub|%s|%s|%d)", circuitID, op, sats))
	return &BEEF{CircuitID: circuitID, Op: op, Sats: sats, WireBytes: wire}, nil
}
