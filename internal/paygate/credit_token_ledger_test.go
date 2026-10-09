// Copyright 2026 Jerry David Chan, Konareef.ai
// SPDX-License-Identifier: Apache-2.0

// internal/paygate/credit_token_ledger_test.go — single-use ledger tests.
package paygate_test

import (
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/digitsu/konareef/internal/paygate"
)

func tempLedger(t *testing.T) *paygate.TokenLedger {
	t.Helper()
	l, err := paygate.OpenTokenLedger(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatalf("OpenTokenLedger: %v", err)
	}
	t.Cleanup(func() { _ = l.Close() })
	return l
}

func TestTokenLedgerRoundTrip(t *testing.T) {
	l := tempLedger(t)
	now := time.Now().UTC()
	if err := l.Persist("tok-1", now, now.Add(time.Hour)); err != nil {
		t.Fatalf("Persist: %v", err)
	}
	got, err := l.Take("tok-1")
	if err != nil {
		t.Fatalf("Take: %v", err)
	}
	if got.Token != "tok-1" {
		t.Errorf("Take token = %q, want tok-1", got.Token)
	}
}

func TestTokenLedgerDoubleUseRejected(t *testing.T) {
	l := tempLedger(t)
	now := time.Now().UTC()
	if err := l.Persist("tok-1", now, now.Add(time.Hour)); err != nil {
		t.Fatalf("Persist: %v", err)
	}
	if _, err := l.Take("tok-1"); err != nil {
		t.Fatalf("first Take: %v", err)
	}
	_, err := l.Take("tok-1")
	if !errors.Is(err, paygate.ErrCreditTokenInvalid) {
		t.Errorf("second Take err = %v, want ErrCreditTokenInvalid", err)
	}
}

func TestTokenLedgerExpiredRejected(t *testing.T) {
	l := tempLedger(t)
	past := time.Now().UTC().Add(-2 * time.Hour)
	if err := l.Persist("tok-old", past.Add(-time.Hour), past); err != nil {
		t.Fatalf("Persist: %v", err)
	}
	_, err := l.Take("tok-old")
	if !errors.Is(err, paygate.ErrCreditTokenExpired) {
		t.Errorf("expired Take err = %v, want ErrCreditTokenExpired", err)
	}
}

func TestTokenLedgerUnknownTokenRejected(t *testing.T) {
	l := tempLedger(t)
	_, err := l.Take("tok-bogus")
	if !errors.Is(err, paygate.ErrCreditTokenInvalid) {
		t.Errorf("unknown Take err = %v, want ErrCreditTokenInvalid", err)
	}
}
