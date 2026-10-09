// Copyright 2026 Jerry David Chan, Konareef.ai
// SPDX-License-Identifier: Apache-2.0

package commission

import (
	"errors"
	"fmt"

	"github.com/digitsu/konareef/internal/envelope"
	"github.com/digitsu/konareef/internal/identity"
)

var (
	// ErrSignatureInvalid means the signature does not verify against the
	// carried public key and the artifact's own hash.
	ErrSignatureInvalid = errors.New("commission signature is invalid")
	// ErrHashMismatch means the artifact's contents do not hash to the
	// value that was signed.
	ErrHashMismatch = errors.New("commission hash does not match its contents")
	// ErrManifestHashMismatch means the supplied manifest is not the
	// artifact the commission was bound to. This is how a republished pod
	// surfaces: as a hash fact, not a policy judgment.
	ErrManifestHashMismatch = errors.New("manifest does not match the pinned h_manifest")
	// ErrNotContained means the pod declares more than the commission permits.
	ErrNotContained = errors.New("manifest envelope is not contained in the commission envelope")
	// ErrBindingUnpinned means the proposal's Binding carries the zero
	// h_manifest, so it pins no artifact at all.
	//
	// This is the same fail-closed posture envelope.ErrDimensionAbsent takes
	// for an omitted dimension, applied to the one field spec §6.4 makes
	// drift detection depend on: "because the binding pins h_manifest, a
	// republished pod fails ... as an ordinary hash mismatch". A commission
	// with no pin detects no drift, yet Verify and show would report it as
	// fully valid. A caller that cannot say which artifact it is committing
	// to does not get a default yes.
	ErrBindingUnpinned = errors.New("commission binding pins no manifest (h_manifest is zero)")
	// ErrNotAValidCommission means the signature checks out but the
	// artifact fails ValidateSignable, so it is not a commission anything
	// may act on. It is a distinct error from ErrSignatureInvalid because
	// the two are different facts: an invalid signature means nobody
	// attested these bytes, while this means somebody did and the result
	// is still not a usable commission.
	ErrNotAValidCommission = errors.New("signature checks out but the artifact is not a valid commission")
)

// Sign turns a proposal into a commission by attesting its canonical bytes
// with the buyer's key. It is the ONLY constructor for a Commission.
//
// This is the constraint-value provenance decision expressed as a type: it
// does not matter what drafted the proposal, because the buyer's key
// attests the values that result.
//
// Sign refuses anything ValidateSignable refuses: an envelope that omits a
// dimension, a malformed pod_ref, and a binding that pins no manifest. It
// states no rule of its own — see signable.go's header comment for why the
// rules live in one predicate that `check` calls too, rather than in a
// matching pair of checks that drifted apart twice.
//
// Those checks are deliberately here and not in the on-disk decoder: an
// unpinned DRAFT is legitimate (a buyer may be editing constraints before
// choosing a pod version), but an unpinned SIGNATURE is not, because a
// commission whose whole purpose is pinning one exact artifact must not be
// signable without a pin. See ErrBindingUnpinned.
func Sign(p Proposal, id *identity.Identity) (Commission, error) {
	if err := ValidateSignable(p); err != nil {
		return Commission{}, fmt.Errorf("refusing to sign: %w", err)
	}
	canonical, err := p.Canonical()
	if err != nil {
		return Commission{}, err
	}
	// identity.Sign SHA-256s its argument, so this is a signature over
	// exactly h_commission.
	sig, err := id.Sign(canonical)
	if err != nil {
		return Commission{}, err
	}
	return Commission{proposal: p, PubKeyHex: id.PublicKeyHex, Sig: sig}, nil
}

// Verify checks the artifact's integrity and its signature. It is fully
// offline and needs no manifest: it answers "is this commission genuine",
// not "does some pod still satisfy it".
func (c Commission) Verify() error {
	h, err := c.proposal.HCommission()
	if err != nil {
		return err
	}
	// VerifyDigest is the companion for callers that already hold a 32-byte
	// SHA-256 digest and must NOT re-hash it.
	ok, err := identity.VerifyDigest(c.PubKeyHex, h[:], c.Sig)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrSignatureInvalid, err)
	}
	if !ok {
		return ErrSignatureInvalid
	}
	return nil
}

// VerifyAgainstManifest additionally checks that the commission is a valid
// commission, that the supplied manifest is the pinned artifact, and that
// its declared envelope is contained in the commission. declared is the
// envelope derived from manifest via FromSpec.
//
// An artifact that is only over the admission contract's size limits
// (ErrOverAdmissionLimit) still verifies here: those limits decide what the
// server admits, not whether the buyer attested a valid commission. The
// wire encoder refuses such an artifact.
//
// The ValidateSignable call is the difference between this and Verify, and
// it is not redundant. Verify answers one narrow question — did this key
// attest these canonical bytes — and it must keep answering only that,
// because `show` reports a bad signature and a bad artifact as two separate
// facts (see runCommissionShowCore). But the canonical bytes exclude the
// four presence flags and say nothing about the shape of pod_ref, so a
// perfectly valid signature can sit on a proposal `sign` would have
// refused. This method reports on an artifact as a whole, so it applies the
// same one predicate `check` and `sign` apply — see signable.go's header
// comment for why that predicate has exactly one home.
func (c Commission) VerifyAgainstManifest(manifest []byte, declared envelope.Envelope) error {
	if err := c.Verify(); err != nil {
		return err
	}
	// An artifact over the admission contract's size limits is still a
	// valid commission to verify offline; only the server refuses it.
	// ErrOverAdmissionLimit is reported only after every shape rule passed
	// (ValidateAdmissionLimits), so ignoring it here hides nothing else.
	if err := ValidateSignable(c.proposal); err != nil && !errors.Is(err, ErrOverAdmissionLimit) {
		return fmt.Errorf("%w: %w", ErrNotAValidCommission, err)
	}
	if err := c.proposal.Binding.ValidateAgainstManifest(manifest); err != nil {
		return err
	}
	if res := c.proposal.Envelope.Contains(declared); !res.OK {
		return fmt.Errorf("%w: %v", ErrNotContained, res.Failures)
	}
	return nil
}
