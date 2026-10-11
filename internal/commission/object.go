// Copyright 2026 Jerry David Chan, Konareef.ai
// SPDX-License-Identifier: Apache-2.0

package commission

import (
	"crypto/sha256"

	"github.com/fxamacker/cbor/v2"

	"github.com/digitsu/konareef/internal/envelope"
)

// Binding pins a proposal to one exact pod artifact. Pinning the manifest
// hash rather than the pod identity is what makes drift a hash fact instead
// of a policy decision: a republished pod simply fails the comparison.
//
// FieldsRoot pins the SECOND thing a commission has to name, and it is a
// different fact from HManifest. HManifest identifies the manifest document
// the buyer read; FieldsRoot identifies the commitment the ZK circuit
// consumes. Containment is checked against the document, the proof is taken
// against the commitment, and nothing joins them unless the buyer signs
// both. Signing only HManifest leaves that join trusted rather than checked
// — see the intent-bridge analysis §13.5 and the 2026-09-01 decision.
//
// It is a POINTER because "no circuit commitment was pinned" and "a
// commitment of all-zero bytes was pinned" are different claims and a
// [32]byte cannot tell them apart. This package has been bitten four times
// by zero-versus-absent at a serialisation boundary; presence here is
// carried by key presence in the CBOR map, so it survives the round trip
// instead of being reconstructed by guesswork.
//
// It is nil for any manifest that is not konareef-toml/v2, because a v1
// manifest carries no [_commit] trailer and therefore commits no
// fields_root to pin. That is not a defect to route around: it is the v2
// dependency made visible, and ValidateAgainstManifest refuses BOTH
// mismatches — a pin that disagrees with the manifest, and a missing pin on
// a manifest that has one.
type Binding struct {
	PodRef     string    `cbor:"1,keyasint"`
	HManifest  [32]byte  `cbor:"2,keyasint"`
	FieldsRoot *[32]byte `cbor:"3,keyasint,omitempty"`
}

// PinsCircuitCommitment reports whether this binding names the fields_root
// the circuit consumes. When false, a proof about this pod's run cannot be
// tied to this commission by anything stronger than trust in whoever
// derived the manifest's fields, so no caller may describe the constraints
// as proven.
func (b Binding) PinsCircuitCommitment() bool { return b.FieldsRoot != nil }

// Proposal is an unsigned commission. Anything may produce one — a person,
// a reduction from prose, a counterparty agent — because a proposal
// authorises nothing. Only Sign turns it into a Commission.
type Proposal struct {
	Envelope envelope.Envelope `cbor:"1,keyasint"`
	Binding  Binding           `cbor:"2,keyasint"`
	Prose    string            `cbor:"3,keyasint"`
}

// Commission is a proposal the buyer has signed. Its unexported proposal
// field is what makes Sign the only constructor that can produce one from
// scratch: no caller outside this package can assemble a commission that
// attests something it never actually signed.
type Commission struct {
	proposal  Proposal
	PubKeyHex string
	Sig       []byte
}

// Proposal returns the proposal this commission attests.
func (c Commission) Proposal() Proposal { return c.proposal }

// Reconstruct rebuilds a Commission from its three persisted parts — the
// proposal, the signer's public key, and the signature bytes — so a caller
// that has read a commission artifact back off disk or the wire can call
// Verify on it.
//
// This does not weaken the guarantee Sign's doc comment describes. Sign
// stays the only way to produce a (proposal, pubkey, sig) triple that
// VERIFIES: forging one still requires the buyer's private key. Reconstruct
// just rehydrates bytes the caller already has; it makes no claim about
// their authenticity. Every caller MUST check the result before relying on
// it for anything — Reconstruct alone proves nothing.
//
// Which check depends on what the caller needs to know. VerifyAgainstManifest
// is the complete one: signature, semantic validity, manifest binding and
// containment. Verify answers the narrower "did this key attest these bytes"
// and is NOT on its own evidence that the artifact is a valid commission,
// because the canonical bytes it covers exclude the presence flags (see
// canonicalProposal). A caller that has no manifest to check against and
// still needs the whole answer must pair Verify with ValidateSignable, the
// way loadAndVerifyCommission does.
func Reconstruct(p Proposal, pubKeyHex string, sig []byte) Commission {
	return Commission{proposal: p, PubKeyHex: pubKeyHex, Sig: sig}
}

// canonicalProposal is the wire shape hashed and signed. Sets are
// normalised so declaration order cannot change the hash. The presence
// flags (ModelsSet, ToolsSet, LabelsSet, CMaxSet) are deliberately excluded:
// they describe how a dimension was written, not what it permits, so two
// proposals that permit identical things must hash identically regardless
// of how they were expressed. Before adding the flags back, read
// TestCanonicalFormIgnoresPresenceFlagsAndOrder in object_test.go — it
// exists to guard this exact decision.
type canonicalProposal struct {
	Models  []string `cbor:"1,keyasint"`
	Tools   []string `cbor:"2,keyasint"`
	Labels  []string `cbor:"3,keyasint"`
	CMax    uint64   `cbor:"4,keyasint"`
	Binding Binding  `cbor:"5,keyasint"`
	Prose   string   `cbor:"6,keyasint"`
}

// Canonical returns the deterministic byte encoding of the proposal. Prose
// and machine parameters are encoded together in one artifact, which is why
// they cannot drift apart unnoticed.
func (p Proposal) Canonical() ([]byte, error) {
	enc, err := cbor.CanonicalEncOptions().EncMode()
	if err != nil {
		return nil, err
	}
	return enc.Marshal(canonicalProposal{
		Models:  envelope.Normalise(p.Envelope.Models),
		Tools:   envelope.Normalise(p.Envelope.Tools),
		Labels:  envelope.Normalise(p.Envelope.Labels),
		CMax:    p.Envelope.CMax,
		Binding: p.Binding,
		Prose:   p.Prose,
	})
}

// HCommission is the SHA-256 of the canonical form. It identifies the
// commission and is what the buyer signs.
func (p Proposal) HCommission() ([32]byte, error) {
	b, err := p.Canonical()
	if err != nil {
		return [32]byte{}, err
	}
	return sha256.Sum256(b), nil
}
