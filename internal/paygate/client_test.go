// Copyright 2026 Jerry David Chan, Konareef.ai
// SPDX-License-Identifier: Apache-2.0

// internal/paygate/client_test.go — basic Client shape + Type-C/D
// disclosure-policy tests (B2).
package paygate_test

import (
	"context"
	"errors"
	"path/filepath"
	"testing"

	"github.com/digitsu/konareef/internal/paygate"
	"github.com/digitsu/konareef/internal/saltstore"
)

func TestClientOpenSessionShape(t *testing.T) {
	dir := t.TempDir()
	c := &paygate.Client{
		BaseURL:      "http://localhost:1",
		IdentityPath: filepath.Join(dir, "identity.key"),
	}
	if c.BaseURL == "" {
		t.Fatal("baseurl missing")
	}
}

// missingSaltBackend is a saltstore.Backend that always returns
// ErrSaltNotFound — proves Type-D is FATAL when salt is absent.
type missingSaltBackend struct{}

func (missingSaltBackend) Name() string                     { return "missing" }
func (missingSaltBackend) Available() error                 { return nil }
func (missingSaltBackend) Put(_ [16]byte, _ [32]byte) error { return nil }
func (missingSaltBackend) Delete(_ [16]byte) error          { return nil }
func (missingSaltBackend) List() ([][16]byte, error)        { return nil, nil }
func (missingSaltBackend) Get(_ [16]byte) ([32]byte, error) {
	return [32]byte{}, saltstore.ErrSaltNotFound
}

// fixedSaltBackend returns a deterministic non-zero salt — proves
// Type-D succeeds when salt is present.
type fixedSaltBackend struct{ salt [32]byte }

func (fixedSaltBackend) Name() string                     { return "fixed" }
func (fixedSaltBackend) Available() error                 { return nil }
func (fixedSaltBackend) Put(_ [16]byte, _ [32]byte) error { return nil }
func (fixedSaltBackend) Delete(_ [16]byte) error          { return nil }
func (fixedSaltBackend) List() ([][16]byte, error)        { return nil, nil }
func (f fixedSaltBackend) Get(_ [16]byte) ([32]byte, error) {
	return f.salt, nil
}

// spyingSaltBackend counts Get() calls — proves Type-C does NOT consult
// the backend.
type spyingSaltBackend struct{ n int }

func (s *spyingSaltBackend) Name() string                     { return "spying" }
func (s *spyingSaltBackend) Available() error                 { return nil }
func (s *spyingSaltBackend) Put(_ [16]byte, _ [32]byte) error { return nil }
func (s *spyingSaltBackend) Delete(_ [16]byte) error          { return nil }
func (s *spyingSaltBackend) List() ([][16]byte, error)        { return nil, nil }
func (s *spyingSaltBackend) Get(_ [16]byte) ([32]byte, error) {
	s.n++
	return [32]byte{}, saltstore.ErrSaltNotFound
}

// TestOpenRequiresDisclosurePolicy proves the zero-value DisclosurePolicy
// is rejected (neither "C" nor "D" defaults silently).
func TestOpenRequiresDisclosurePolicy(t *testing.T) {
	dir := t.TempDir()
	c := newOpenFixtureClient(t, dir, fixedSaltBackend{salt: [32]byte{0x42}})
	_, err := c.Open(context.Background(), paygate.OpenSessionInput{
		CircuitID: "konareef-pod-step-v1",
		// DisclosurePolicy omitted on purpose.
	})
	if err == nil {
		t.Fatal("Open with empty DisclosurePolicy must fail")
	}
}

// TestOpenTypeDMissingSaltIsFatal proves saltstore.ErrSaltNotFound is
// FATAL for Type-D — no zero-value [32]byte fallback.
func TestOpenTypeDMissingSaltIsFatal(t *testing.T) {
	dir := t.TempDir()
	c := newOpenFixtureClient(t, dir, missingSaltBackend{})
	sess, err := c.Open(context.Background(), paygate.OpenSessionInput{
		CircuitID:        "konareef-pod-step-v1",
		LineageID:        [16]byte{0x01, 0x02, 0x03},
		DisclosurePolicy: paygate.DisclosureTypeD,
	})
	if err == nil {
		t.Fatal("Type-D with missing salt must fail, got nil")
	}
	if !errors.Is(err, saltstore.ErrSaltNotFound) {
		t.Errorf("Type-D missing salt: err=%v, want errors.Is(err, ErrSaltNotFound)", err)
	}
	if sess != nil {
		t.Errorf("Type-D missing salt: session must be nil, got %+v", sess)
	}
}

// TestOpenTypeDSuccessLoadsSalt proves Type-D succeeds when salt is
// present and the salt is propagated to the Session.
func TestOpenTypeDSuccessLoadsSalt(t *testing.T) {
	dir := t.TempDir()
	want := [32]byte{0xab, 0xcd}
	c := newOpenFixtureClient(t, dir, fixedSaltBackend{salt: want})
	sess, err := c.Open(context.Background(), paygate.OpenSessionInput{
		CircuitID:        "konareef-pod-step-v1",
		LineageID:        [16]byte{0x77},
		DisclosurePolicy: paygate.DisclosureTypeD,
	})
	if err != nil {
		t.Fatalf("Type-D with present salt: err=%v", err)
	}
	if sess.TypeDSalt != want {
		t.Errorf("Type-D salt: got %x, want %x", sess.TypeDSalt, want)
	}
}

// TestOpenTypeCSkipsSaltstoreLookup proves Type-C does NOT consult the
// saltstore backend at all.
func TestOpenTypeCSkipsSaltstoreLookup(t *testing.T) {
	dir := t.TempDir()
	spy := &spyingSaltBackend{}
	c := newOpenFixtureClient(t, dir, spy)
	sess, err := c.Open(context.Background(), paygate.OpenSessionInput{
		CircuitID:        "konareef-pod-step-v1",
		DisclosurePolicy: paygate.DisclosureTypeC,
	})
	if err != nil {
		t.Fatalf("Type-C: err=%v", err)
	}
	if spy.n != 0 {
		t.Errorf("Type-C consulted saltstore %d times, want 0", spy.n)
	}
	if sess.TypeDSalt != ([32]byte{}) {
		t.Errorf("Type-C: TypeDSalt should remain zero-value, got %x", sess.TypeDSalt)
	}
}
