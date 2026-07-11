// Copyright 2026 Jerry David Chan, Konareef.ai
// SPDX-License-Identifier: Apache-2.0

// Package verify — P1.2 error taxonomy and structured-verdict types.
//
// This file defines the 14-code wire-stable error taxonomy from PRD 3
// § 12.3 plus the structured verdict types from PRD 3 § 11.1.
package verify

import "errors"

// The 14 stable, final error codes from konareef-bundle-v2-wire-format-v1
// § 12.3. No code in this list may be renamed, merged, or removed in a
// v2-compatible revision.
var (
	ErrMalformedCBOR          = errors.New("ERR_MALFORMED_CBOR")
	ErrUnknownVersion         = errors.New("ERR_UNKNOWN_VERSION")
	ErrProofFieldRenamed      = errors.New("ERR_PROOF_FIELD_RENAMED")
	ErrCircuitIDMismatch      = errors.New("ERR_CIRCUIT_ID_MISMATCH")
	ErrUnsupportedCircuit     = errors.New("ERR_UNSUPPORTED_CIRCUIT")
	ErrVkeyMismatch           = errors.New("ERR_VKEY_MISMATCH")
	ErrVkeyUnavailable        = errors.New("ERR_VKEY_UNAVAILABLE")
	ErrCommitmentMismatch     = errors.New("ERR_COMMITMENT_MISMATCH")
	ErrProofRejected          = errors.New("ERR_PROOF_REJECTED")
	ErrDisclosureInconsistent = errors.New("ERR_DISCLOSURE_INCONSISTENT")
	ErrProjectionLossy        = errors.New("ERR_PROJECTION_LOSSY")
	ErrAttestationMismatch    = errors.New("ERR_ATTESTATION_MISMATCH")
	ErrSignatureInvalid       = errors.New("ERR_SIGNATURE_INVALID")
	ErrChainBroken            = errors.New("ERR_CHAIN_BROKEN")
)

// ErrFieldsRootMismatch is the CL-5(a) soundness-gate divergence: the
// manifest's [_commit].fields_root does not bind to the proof's carried
// genesis lane (genesis_fields_root). It is a verifier-internal
// divergence code; it is NOT part of the PRD § 12.3 wire-stable
// taxonomy. Every path that surfaces it MUST also keep
// CommitmentsValid=false so the all-or-none gate fails the bundle.
var ErrFieldsRootMismatch = errors.New("ERR_FIELDS_ROOT_MISMATCH")

// Implementation-side fail-closed sentinels. These are NOT part of the
// PRD § 12.3 wire-stable taxonomy; they only surface in operator-facing
// divergence strings when the verifier is mis-configured at runtime.
var (
	// ErrSnarkVerifierNotConfigured fires when verifyWith is invoked on
	// a v2 bundle and no SpartanVerifier was wired into VerifyOptions.
	// Production paths must inject a real Spartan verifier.
	ErrSnarkVerifierNotConfigured = errors.New("ERR_SNARK_VERIFIER_NOT_CONFIGURED")
)

// PublisherIdentityStatus is the § 11.3 enum.
type PublisherIdentityStatus string

const (
	PISUnbound          PublisherIdentityStatus = "unbound"
	PISSelfSigned       PublisherIdentityStatus = "self_signed"
	PISMismatch         PublisherIdentityStatus = "mismatch"
	PISSignatureInvalid PublisherIdentityStatus = "signature_invalid"
	PISBound            PublisherIdentityStatus = "bound"
)
