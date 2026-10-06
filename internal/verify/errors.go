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

// ErrCircuitRetired is the VHASH-M1 divergence (paygate-zk#14) for a
// konareef-pod-step-v1 bundle verified after the configured v1 cutoff
// (circuit_policy.go). Verifier-internal, NOT part of the PRD § 12.3
// wire-stable taxonomy.
var ErrCircuitRetired = errors.New("ERR_CIRCUIT_RETIRED")

// ErrCircuitPolicyInvalid is the divergence for a circuit policy the live
// path cannot read (a bad KONAREEF_POD_STEP_V1_CUTOFF or
// KONAREEF_PUBLISHER_CIRCUIT_ID). The bundle is refused so a typo cannot
// switch a check off. Verifier-internal, NOT part of the PRD § 12.3
// wire-stable taxonomy.
var ErrCircuitPolicyInvalid = errors.New("ERR_CIRCUIT_POLICY_INVALID")

// ErrCustodyRecordInvalid is the custody-rule divergence of the v2
// verifier (MCP-K04): the custody link's data is bound to its link hash
// and fails a custody rule (see ParseCustodyBlob). It is a
// verifier-internal code, NOT part of the PRD § 12.3 wire-stable
// taxonomy. The path that surfaces it also sets CommitmentsValid=false.
var ErrCustodyRecordInvalid = errors.New("ERR_CUSTODY_RECORD_INVALID")

// ErrManifestMagicNearMiss is the CL-5 divergence for a disclosed manifest
// whose first line is a near miss of a konareef-toml magic line
// (canon.CheckMagicLine, canon code MAGIC_NEAR_MISS; KR-MAGIC). Such a
// manifest claims a canonical version this verifier cannot read, so none
// of the fields_root bindings can be applied. Like ErrFieldsRootMismatch
// it is verifier-internal, NOT part of the PRD § 12.3 wire-stable
// taxonomy, and every path that surfaces it keeps CommitmentsValid=false.
var ErrManifestMagicNearMiss = errors.New("ERR_MANIFEST_MAGIC_NEAR_MISS")

// ErrCTotalMismatch is the divergence for a proof whose proven cost `c`
// (the fold lane Z_C_ACC) differs from the custody record's TOTAL_SATS, or
// whose genesis cost lane is not zero (paygate-zk MCP-Z00 §7 and §11,
// owner decision O1 option B). The Rust verifier makes the check; this
// verifier passes it the bundle's custody total and surfaces the refusal.
// It also covers a bound custody record whose TOTAL_SATS cannot be read.
// Verifier-internal, NOT part of the PRD § 12.3 wire-stable taxonomy. The
// path that surfaces it sets ProofValid=false.
var ErrCTotalMismatch = errors.New("ERR_C_TOTAL_MISMATCH")

// ErrPublicInputLaneMismatch is the divergence for a bundle whose two
// public-input buffers are not both exactly 298 bytes, or disagree on a
// lane from t_root to sig_manifest. It is
// verifier-internal, NOT part of the PRD § 12.3 wire-stable taxonomy, and
// the path that surfaces it keeps CommitmentsValid=false.
var ErrPublicInputLaneMismatch = errors.New("ERR_PUBLIC_INPUT_LANE_MISMATCH")

// Chain-head anchor divergences (reef-core#76, proposed PRD 3 § 8.5 and
// § 12.3 additions; additive codes, § 14.1). Each one fails the bundle:
// a present anchor that does not check out is evidence of tampering
// (owner decision A3(a)). A missing header, a low depth or an untrusted
// node key only set the anchor status; they are not divergences.
var (
	// ErrAnchorMalformed: the chain_head_anchor map, its attestation or
	// its BEEF does not have the required shape, or the BEEF subject is
	// not the anchor txid.
	ErrAnchorMalformed = errors.New("ERR_ANCHOR_MALFORMED")
	// ErrAnchorMismatch: the subject transaction does not hash to the
	// txid, the output is not the OP_RETURN of the chain head hash, or
	// the block time predates the chain head.
	ErrAnchorMismatch = errors.New("ERR_ANCHOR_MISMATCH")
	// ErrAnchorProofInvalid: the merkle path is missing, is for another
	// height, or does not contain the txid.
	ErrAnchorProofInvalid = errors.New("ERR_ANCHOR_PROOF_INVALID")
	// ErrAnchorHeaderUntrusted: the header fails proof of work or the
	// difficulty floor, or the header sources disagree.
	ErrAnchorHeaderUntrusted = errors.New("ERR_ANCHOR_HEADER_UNTRUSTED")
	// ErrAnchorHeaderMismatch: the header merkle root differs from the
	// root the merkle path gives.
	ErrAnchorHeaderMismatch = errors.New("ERR_ANCHOR_HEADER_MISMATCH")
	// ErrAnchorUnattributed: the attestation signature does not verify
	// over the statement recomputed from this bundle.
	ErrAnchorUnattributed = errors.New("ERR_ANCHOR_UNATTRIBUTED")
)

// ErrCustodyLaneMismatch is the divergence for a Type-C bundle whose
// bound custody record states a TASK_HASH or RESULT_HASH that differs
// from the proof's h_p or h_r lane, or states either line zero times or
// more than once (reef-core#76 decision A8). reef-core writes
// TASK_HASH = SHA-256(P) and RESULT_HASH = SHA-256(R) for the same P and
// R it discloses, so a genuine bundle always agrees. Verifier-internal,
// NOT part of the PRD § 12.3 wire-stable taxonomy; the path that
// surfaces it sets CommitmentsValid=false.
var ErrCustodyLaneMismatch = errors.New("ERR_CUSTODY_LANE_MISMATCH")

// ErrCustodyToolLogRootMismatch is the divergence for a Type-C bundle
// whose disclosed T_log records do not reproduce the TOOL_LOG_ROOT of its
// bound v4 or v5 custody link, when the disclosed manifest is
// konareef-toml/v3 (broker-priced). See custody_root_xcheck.go
// (konareef#37, D7-XCHK). The custody chain is not anchored in a
// bundle-only check, so a pass does not bind the records to reef-core's
// stored record. Verifier-internal, NOT part of the PRD § 12.3 wire-stable
// taxonomy; the path that surfaces it sets CommitmentsValid=false.
var ErrCustodyToolLogRootMismatch = errors.New("ERR_CUSTODY_TOOL_LOG_ROOT_MISMATCH")

// ErrCustodyLinkUnbound is the divergence for a Type-C bundle with a
// konareef-toml/v3 manifest whose chain does not end in exactly one
// custody link carrying a v4 or v5 custody record with a TOOL_LOG_ROOT
// (konareef#37, D7-XCHK fix round 1). Without that link the disclosed
// T_log records cannot be checked against the custody TOOL_LOG_ROOT, so
// the bundle is refused instead of skipping the check. The message names
// the shape problem: no custody link at the tail, a proof_type other than
// "custody" on the tail, a second custody record (by label or by content),
// a record that fails the custody rules, or a v3 record. Verifier-internal,
// NOT part of the PRD § 12.3 wire-stable taxonomy; the path that surfaces
// it sets CommitmentsValid=false.
var ErrCustodyLinkUnbound = errors.New("ERR_CUSTODY_LINK_UNBOUND")

// Implementation-side fail-closed sentinels. These are NOT part of the
// PRD § 12.3 wire-stable taxonomy; they only surface in operator-facing
// divergence strings when the verifier is mis-configured at runtime.
var (
	// ErrAnchorConfigInvalid fires when the live path was asked to check
	// chain-head anchors with a configuration it cannot use (an
	// unreadable headers file, a malformed trusted key or confirmation
	// count). The bundle fails rather than skip the requested check.
	ErrAnchorConfigInvalid = errors.New("ERR_ANCHOR_CONFIG_INVALID")

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
