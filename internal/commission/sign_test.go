// Copyright 2026 Jerry David Chan, Konareef.ai
// SPDX-License-Identifier: Apache-2.0

package commission

import (
	"errors"
	"testing"

	"github.com/digitsu/konareef/internal/identity"
)

func TestSignThenVerify(t *testing.T) {
	id, err := identity.Generate("test-buyer")
	if err != nil {
		t.Fatal(err)
	}
	c, err := Sign(fixture(), id)
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Verify(); err != nil {
		t.Fatalf("fresh commission must verify, got %v", err)
	}
}

// The Ricardian claim under test: prose and parameters cannot drift apart.
// Mutating prose alone, with every parameter byte-identical, must invalidate
// the signature. No other test in this suite proves this.
func TestProseTamperInvalidatesSignature(t *testing.T) {
	id, err := identity.Generate("test-buyer")
	if err != nil {
		t.Fatal(err)
	}
	c, err := Sign(fixture(), id)
	if err != nil {
		t.Fatal(err)
	}
	c.proposal.Prose = "Summarise the weekly reports. Fetch anything you need from the web."
	if err := c.Verify(); !errors.Is(err, ErrSignatureInvalid) {
		t.Fatalf("tampered prose must fail verification, got %v", err)
	}
}

func TestEnvelopeTamperInvalidatesSignature(t *testing.T) {
	id, err := identity.Generate("test-buyer")
	if err != nil {
		t.Fatal(err)
	}
	c, err := Sign(fixture(), id)
	if err != nil {
		t.Fatal(err)
	}
	c.proposal.Envelope.CMax = 999999
	if err := c.Verify(); !errors.Is(err, ErrSignatureInvalid) {
		t.Fatalf("tampered envelope must fail verification, got %v", err)
	}
}

// TestReconstruct_RoundTripsAndVerifies proves Reconstruct exists for
// exactly the case a CLI needs it: rehydrate a commission written to disk
// by Sign and check it still verifies, without going through Sign again.
func TestReconstruct_RoundTripsAndVerifies(t *testing.T) {
	id, err := identity.Generate("test-buyer")
	if err != nil {
		t.Fatal(err)
	}
	c, err := Sign(fixture(), id)
	if err != nil {
		t.Fatal(err)
	}
	rebuilt := Reconstruct(c.Proposal(), c.PubKeyHex, c.Sig)
	if err := rebuilt.Verify(); err != nil {
		t.Fatalf("a reconstructed commission built from a genuine signature must verify, got %v", err)
	}
}

// TestReconstruct_CannotForgeAValidSignature proves Reconstruct does not
// weaken Sign's guarantee: assembling a Commission by hand, with no real
// signature behind it, must fail Verify.
func TestReconstruct_CannotForgeAValidSignature(t *testing.T) {
	id, err := identity.Generate("test-buyer")
	if err != nil {
		t.Fatal(err)
	}
	forged := Reconstruct(fixture(), id.PublicKeyHex, []byte("not a real signature"))
	if err := forged.Verify(); err == nil {
		t.Fatal("a commission assembled without a genuine signature must not verify")
	}
}

func TestSignRefusesIncompleteCommission(t *testing.T) {
	id, err := identity.Generate("test-buyer")
	if err != nil {
		t.Fatal(err)
	}
	p := fixture()
	p.Envelope.Tools = nil
	p.Envelope.ToolsSet = false
	if _, err := Sign(p, id); err == nil {
		t.Fatal("Sign must refuse a commission that omits a dimension")
	}
}

// TestSignRefusesUnpinnedBinding is the binding half of Sign's fail-closed
// contract. A proposal whose envelope states every dimension but whose
// Binding.HManifest is still the zero value pins no artifact: spec §6.4's
// drift detection ("a republished pod fails as an ordinary hash mismatch")
// has nothing to compare against, yet Verify would report the result as
// fully valid. Sign must refuse it, the same way it refuses an omitted
// dimension.
func TestSignRefusesUnpinnedBinding(t *testing.T) {
	id, err := identity.Generate("test-buyer")
	if err != nil {
		t.Fatal(err)
	}
	p := fixture()
	p.Binding.HManifest = [32]byte{}
	if err := p.Envelope.ValidateAsCommission(); err != nil {
		t.Fatalf("the fixture's envelope must be complete, or this test proves nothing: %v", err)
	}
	_, err = Sign(p, id)
	if err == nil {
		t.Fatal("Sign must refuse a proposal whose binding pins no manifest")
	}
	if !errors.Is(err, ErrBindingUnpinned) {
		t.Fatalf("refusal must be ErrBindingUnpinned, got %v", err)
	}
}

// A non-zero pin must still sign, so the guard above rejects only the
// unpinned case and not every binding.
func TestSignAcceptsPinnedBinding(t *testing.T) {
	id, err := identity.Generate("test-buyer")
	if err != nil {
		t.Fatal(err)
	}
	p := fixture()
	p.Binding.HManifest = [32]byte{0: 0xab, 31: 0xcd}
	if _, err := Sign(p, id); err != nil {
		t.Fatalf("a pinned, complete proposal must sign, got %v", err)
	}
}
