// Copyright 2026 Jerry David Chan, Konareef.ai
// SPDX-License-Identifier: Apache-2.0

// internal/paygate/pipelining.go — PRD P1.8 Obligation 1 durable-binding
// gate. Preparatory work for step i+1 MAY proceed in parallel, but a
// nova-fold submission for step i+1 MUST NOT precede durable binding of
// step i's accumulator+result.
package paygate

import (
	"errors"
	"fmt"
	"sync"
)

// ErrSpeculativeFold signals that the caller tried to submit step i+1
// before step i's result was durably bound (PRD P1.8 Obligation 1).
var ErrSpeculativeFold = errors.New("paygate: speculative fold rejected (PRD P1.8 Obligation 1)")

// PipeliningGate tracks the last durably-bound step index.
type PipeliningGate struct {
	mu        sync.Mutex
	bound     bool
	lastStep  uint64
	lastJob   string
	lastAccum []byte
}

// AssertNotSpeculative checks that stepIndex is the very-next step
// after the last durably-bound step OR the last durably-bound step
// itself (idempotent replay). Step 0 is always allowed (genesis);
// thereafter the request MUST be exactly lastStep or lastStep+1.
func (g *PipeliningGate) AssertNotSpeculative(stepIndex uint64) error {
	g.mu.Lock()
	defer g.mu.Unlock()
	if !g.bound {
		if stepIndex == 0 {
			return nil
		}
		return fmt.Errorf("%w: step=%d, no prior step bound", ErrSpeculativeFold, stepIndex)
	}
	if stepIndex != g.lastStep && stepIndex != g.lastStep+1 {
		return fmt.Errorf("%w: step=%d, last bound step=%d", ErrSpeculativeFold, stepIndex, g.lastStep)
	}
	return nil
}

// DurablyBind records the receipt of step stepIndex's /result. Only
// after this call may stepIndex+1 be submitted.
func (g *PipeliningGate) DurablyBind(stepIndex uint64, jobID string, accumulator []byte) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.bound = true
	g.lastStep = stepIndex
	g.lastJob = jobID
	g.lastAccum = append([]byte(nil), accumulator...)
}
