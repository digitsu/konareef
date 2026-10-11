// Copyright 2026 Jerry David Chan, Konareef.ai
// SPDX-License-Identifier: Apache-2.0

// verify_manifest_test.go — the package-API half of the one bug this branch
// has now fixed three times: a path that reports on a commission without
// applying ValidateSignable.
//
// `check` and `sign` drifted apart over `labels`, then over `h_manifest`.
// ValidateSignable was introduced so validity has exactly one home, and the
// CLI's loader and `show` were routed through it. VerifyAgainstManifest was
// the path left over: a caller holding the internal package could hand it a
// genuinely signed artifact that `sign` would have refused and be told
// nothing was wrong. These tests hold that path shut.

package commission

import (
	"crypto/sha256"
	"errors"
	"testing"

	"github.com/digitsu/konareef/internal/envelope"
	"github.com/digitsu/konareef/internal/identity"
)

// signBypassingTheGate produces the (proposal, pubkey, signature) triple
// Sign would have produced, WITHOUT Sign's ValidateSignable refusal. It is
// the attacker's position stated honestly: the presence flags and pod_ref
// shape are outside the signed canonical form, so anyone holding the buyer's
// key — or simply editing a stored artifact — can arrive at a semantically
// invalid proposal carrying a signature that checks out perfectly.
//
// Every test here goes through it rather than through Sign, because a
// proposal Sign accepts is by definition not the case under test.
func signBypassingTheGate(t *testing.T, p Proposal, id *identity.Identity) Commission {
	t.Helper()
	canonical, err := p.Canonical()
	if err != nil {
		t.Fatal(err)
	}
	sig, err := id.Sign(canonical)
	if err != nil {
		t.Fatal(err)
	}
	return Reconstruct(p, id.PublicKeyHex, sig)
}

// manifestFixture returns manifest bytes and a proposal pinned to them, so
// VerifyAgainstManifest's hash and containment checks both pass and the only
// thing a case varies is semantic validity.
func manifestFixture() ([]byte, envelope.Envelope, Proposal) {
	manifest := []byte("#!konareef-toml/v1\nname = \"mybot\"\n")
	p := fixture()
	p.Binding.HManifest = sha256.Sum256(manifest)
	declared := envelope.Envelope{
		Models: []string{"anthropic/claude-sonnet-5"}, ModelsSet: true,
		Tools: []string{"fs_read"}, ToolsSet: true,
		Labels: []string{"public"}, LabelsSet: true,
		CMax: 4200, CMaxSet: true,
	}
	return manifest, declared, p
}

// TestVerifyAgainstManifest_AcceptsAGenuineCommission is the control. Without
// it the refusals below would also be satisfied by a VerifyAgainstManifest
// that refused everything.
func TestVerifyAgainstManifest_AcceptsAGenuineCommission(t *testing.T) {
	id, err := identity.Generate("test-buyer")
	if err != nil {
		t.Fatal(err)
	}
	manifest, declared, p := manifestFixture()
	c, err := Sign(p, id)
	if err != nil {
		t.Fatal(err)
	}
	if err := c.VerifyAgainstManifest(manifest, declared); err != nil {
		t.Fatalf("a genuine commission against its pinned manifest must verify, got %v", err)
	}
}

// TestVerifyAgainstManifest_RejectsASignedButUnsignableProposal is the
// discriminating case. Each input carries a signature that VERIFIES — the
// test asserts that first, because a case whose signature had simply broken
// would prove nothing about the semantic gate — over a proposal
// ValidateSignable refuses.
func TestVerifyAgainstManifest_RejectsASignedButUnsignableProposal(t *testing.T) {
	id, err := identity.Generate("test-buyer")
	if err != nil {
		t.Fatal(err)
	}
	manifest, declared, base := manifestFixture()

	cases := map[string]struct {
		mutate func(*Proposal)
		want   error
	}{
		// The flags are excluded from the canonical form on purpose, so
		// this artifact's signature is byte-identical to the genuine one.
		// Nothing but ValidateSignable can tell the two apart.
		"omitted labels dimension": {
			mutate: func(p *Proposal) { p.Envelope.LabelsSet = false },
			want:   envelope.ErrDimensionAbsent,
		},
		"omitted models dimension": {
			mutate: func(p *Proposal) { p.Envelope.ModelsSet = false },
			want:   envelope.ErrDimensionAbsent,
		},
		// pod_ref IS inside the canonical form, so this one is signed over
		// its own altered bytes rather than reusing the genuine signature.
		// It still verifies, which is the point: a valid signature is not
		// evidence that the ref names one exact artifact.
		"unversioned pod_ref": {
			mutate: func(p *Proposal) { p.Binding.PodRef = "dave/mybot" },
			want:   ErrPodRefMalformed,
		},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			p := base
			tc.mutate(&p)
			c := signBypassingTheGate(t, p, id)

			if err := c.Verify(); err != nil {
				t.Fatalf("setup: this artifact must carry a signature that checks out, else the case proves nothing; got %v", err)
			}
			if err := ValidateSignable(c.Proposal()); !errors.Is(err, tc.want) {
				t.Fatalf("setup: ValidateSignable must refuse this proposal with %v, got %v", tc.want, err)
			}

			err := c.VerifyAgainstManifest(manifest, declared)
			if err == nil {
				t.Fatal("VerifyAgainstManifest reported success on a signed proposal `sign` would have refused")
			}
			if !errors.Is(err, ErrNotAValidCommission) {
				t.Fatalf("want ErrNotAValidCommission, got %v", err)
			}
			// The refusal must also carry the specific rule that failed:
			// "not a valid commission" alone does not tell a buyer which
			// dimension to go and fix.
			if !errors.Is(err, tc.want) {
				t.Fatalf("the refusal must name WHICH rule failed (%v), got %v", tc.want, err)
			}
		})
	}
}
