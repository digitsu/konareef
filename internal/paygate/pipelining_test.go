// Copyright 2026 Jerry David Chan, Konareef.ai
// SPDX-License-Identifier: Apache-2.0

// internal/paygate/pipelining_test.go — durable-binding gate tests.
package paygate_test

import (
	"errors"
	"testing"

	"github.com/digitsu/konareef/internal/paygate"
)

func TestPipeliningStep0AlwaysAllowed(t *testing.T) {
	g := &paygate.PipeliningGate{}
	if err := g.AssertNotSpeculative(0); err != nil {
		t.Errorf("step 0 must be allowed; got %v", err)
	}
}

func TestPipeliningRefusesSkipAhead(t *testing.T) {
	g := &paygate.PipeliningGate{}
	if err := g.AssertNotSpeculative(0); err != nil {
		t.Fatal(err)
	}
	// Skipping to step 2 without binding step 0's result is speculative.
	if err := g.AssertNotSpeculative(2); !errors.Is(err, paygate.ErrSpeculativeFold) {
		t.Errorf("speculative fold err = %v, want ErrSpeculativeFold", err)
	}
}

func TestPipeliningBindThenAdvance(t *testing.T) {
	g := &paygate.PipeliningGate{}
	if err := g.AssertNotSpeculative(0); err != nil {
		t.Fatal(err)
	}
	g.DurablyBind(0, "job-0", []byte{0xaa})
	if err := g.AssertNotSpeculative(1); err != nil {
		t.Errorf("step 1 after binding step 0 must be allowed; got %v", err)
	}
}
