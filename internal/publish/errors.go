// errors.go — sentinel errors for the P1.3 ZK opt-in flags.
//
// Each Error() returns the upstream stable code from
// paygate-zk/docs/prds/konareef-integration-contract-v1.md § 6 (PRD 4
// error taxonomy) so the CLI surface, structured logs, and downstream
// consumers all see the same identifier.
package publish

import "errors"

// ErrZkRequiresCircuitID is returned at flag-parse time when --zk
// is set without --circuit-id. Terminal; the publisher must supply
// --circuit-id before re-invoking.
var ErrZkRequiresCircuitID = errors.New("ERR_ZK_REQUIRES_CIRCUIT_ID")

// ErrZkRequiresDisclosurePolicy is returned at flag-parse time when
// --zk is set without --disclosure-policy. Terminal; the publisher
// must supply --disclosure-policy {C|D}.
var ErrZkRequiresDisclosurePolicy = errors.New("ERR_ZK_REQUIRES_DISCLOSURE_POLICY")

// ErrInvalidDisclosurePolicy is returned when --disclosure-policy is
// supplied with a value other than the literal upper-case strings
// "C" or "D". Terminal.
var ErrInvalidDisclosurePolicy = errors.New("ERR_INVALID_DISCLOSURE_POLICY")

// ErrDisclosurePolicyViolation is returned by konareef verify when
// the --disclosure-policy assertion does not match the bundle's
// embedded `disclosure` field. PRD 4 § 6 stable code.
var ErrDisclosurePolicyViolation = errors.New("ERR_DISCLOSURE_POLICY_VIOLATION")

// ErrDisclosurePolicySealed is returned when SealDisclosurePolicy is
// called twice on the same witness — once sealed, the witness's
// disclosure policy is irrevocable per PRD 4 § 4.3.3.
var ErrDisclosurePolicySealed = errors.New("ERR_DISCLOSURE_POLICY_SEALED")

// ErrAnchorBroadcastUnsupported is returned by EnsureVkeyAnchor when
// no on-chain anchor exists yet for (circuit_id, vkey_sha256) AND the
// BSV wallet integration has not landed. The publisher must wait for
// P1.8 (BSV wallet wiring) before --pin-circuit-vkey can initiate a
// fresh anchor transaction.
var ErrAnchorBroadcastUnsupported = errors.New("ERR_ANCHOR_BROADCAST_UNSUPPORTED")

// ErrCircuitIDRequiredForPinCircuitVkey is returned at flag-parse
// time when --pin-circuit-vkey is set without --circuit-id. The
// runtime path fetches the discovery manifest and looks up the vkey
// sha256 for flags.CircuitID before anchoring, so an empty CircuitID
// is internally inconsistent — there is no manifest entry to anchor
// against. Terminal; the publisher must supply --circuit-id before
// re-invoking. (Round-6 B1.)
var ErrCircuitIDRequiredForPinCircuitVkey = errors.New("ERR_CIRCUIT_ID_REQUIRED_FOR_PIN_CIRCUIT_VKEY")
