// Copyright 2026 Jerry David Chan, Konareef.ai
// SPDX-License-Identifier: Apache-2.0

// zk_session.go — ZK-session orchestration for `konareef pod publish`
// per PRD 4 § 4.3.
//
// The four publish flags (--circuit-id, --pin-circuit-vkey,
// --disclosure-policy, --zk) carry distinct semantics with a
// fail-closed combination matrix. ValidateZKFlags is the single
// parse-time gate; downstream code can assume any ZKFlags value
// passing through it is structurally valid.
//
// PreflightPinCheck is the pre-session vkey pin check per PRD 4
// § 4.3.1. It is invoked AFTER ValidateZKFlags and BEFORE any
// network submission. A pin failure halts the session with
// vkeystore.ErrCircuitPinMismatch — no fold request reaches PayGate.
//
// SealDisclosurePolicy is the witness-time enforcement point per
// PRD 4 § 4.3.3. Once called, the witness's disclosure policy is
// irrevocable; a second call returns ErrDisclosurePolicySealed.
//
// EnsureSaltForTypeD provisions a 32-byte salt for the pod's
// lineage_id and persists it via the supplied saltstore backend for
// Type-D publishes (PRD 4 § B.1). No-op for Type-C and non-ZK.
package publish

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"

	"github.com/digitsu/konareef/internal/pod"
	"github.com/digitsu/konareef/internal/saltstore"
	"github.com/digitsu/konareef/internal/vkeystore"
)

// ZKFlags captures the four ZK-related publish flags. The zero
// value represents a legacy publish (no ZK opt-in).
type ZKFlags struct {
	// CircuitID is the value of --circuit-id. Empty when absent.
	// Mandatory when ZK is true (PRD 4 § 4.3.4 + § 4.3.1).
	CircuitID string

	// PinCircuitVkey is the value of --pin-circuit-vkey. True
	// triggers the on-chain anchor flow per PRD 4 § 4.3.2.
	PinCircuitVkey bool

	// DisclosurePolicy is the value of --disclosure-policy,
	// normalised to upper-case at parse time by the caller. Valid
	// values: "C", "D". Empty when absent. Mandatory when ZK is true
	// (PRD 4 § 4.3.4 + § 4.3.3).
	DisclosurePolicy string

	// ZK is the value of --zk. True activates the full ZK path:
	// witness construction, Spartan proof generation, v2 bundle
	// emission. Sets published_pods.zk_enabled = true on reef-core.
	ZK bool
}

// ValidateZKFlags enforces the parse-time fail-closed matrix per PRD
// 4 § 4.3.4. Returns one of:
//
//   - nil — the combination is valid; the caller may proceed.
//   - ErrZkRequiresCircuitID — --zk without --circuit-id.
//   - ErrZkRequiresDisclosurePolicy — --zk without --disclosure-policy.
//   - ErrInvalidDisclosurePolicy — --disclosure-policy with a value
//     other than the literal upper-case strings "C" or "D".
//   - ErrCircuitIDRequiredForPinCircuitVkey — --pin-circuit-vkey
//     without --circuit-id (round-6 B1). The runtime path fetches
//     the discovery manifest and looks up VkeySha256For(flags.CircuitID)
//     before anchoring; an empty CircuitID is internally inconsistent.
//
// Non-ZK invocations are accepted unchanged: --circuit-id is usable
// standalone. --pin-circuit-vkey is NOT usable standalone — it
// requires an explicit --circuit-id (round-6 B1).
func ValidateZKFlags(flags ZKFlags) error {
	// --disclosure-policy structural validation (independent of --zk).
	if flags.DisclosurePolicy != "" &&
		flags.DisclosurePolicy != "C" &&
		flags.DisclosurePolicy != "D" {
		return fmt.Errorf("%w: got %q, want \"C\" or \"D\"",
			ErrInvalidDisclosurePolicy, flags.DisclosurePolicy)
	}
	// Round-6 B1: --pin-circuit-vkey requires --circuit-id. Validated
	// BEFORE the --zk gate so the standalone case is rejected here.
	if flags.PinCircuitVkey && flags.CircuitID == "" {
		return fmt.Errorf("%w: --pin-circuit-vkey requires --circuit-id",
			ErrCircuitIDRequiredForPinCircuitVkey)
	}
	if !flags.ZK {
		return nil
	}
	if flags.CircuitID == "" {
		return fmt.Errorf("%w: --zk requires --circuit-id",
			ErrZkRequiresCircuitID)
	}
	if flags.DisclosurePolicy == "" {
		return fmt.Errorf("%w: --zk requires --disclosure-policy {C|D}",
			ErrZkRequiresDisclosurePolicy)
	}
	return nil
}

// DiscoveryManifest is the slice of the PRD 2 § 5.3 manifest this
// package consumes. The caller fetches and decodes the full manifest;
// this package only needs the paygate-zk domain + the circuits list.
type DiscoveryManifest interface {
	// PaygateZKDomainHost returns the host portion (no scheme) of the
	// PayGate ZK service domain.
	PaygateZKDomainHost() string

	// VkeySha256For returns the vkey_sha256 hex string committed in
	// the manifest for circuitID, or ("", false) if the circuit is
	// absent.
	VkeySha256For(circuitID string) (string, bool)
}

// Resolver is the narrow interface PreflightPinCheck consumes from
// internal/vkeystore. Declaring it inline here lets the publish
// package depend on the abstraction (and the test wire a fake without
// a full vkeystore.Resolver).
type Resolver interface {
	Resolve(ctx context.Context, req vkeystore.ResolveRequest) (*vkeystore.Vkey, error)
}

// PreflightPinCheck is the pre-session vkey pin check per PRD 4
// § 4.3.1. When flags.ZK is true:
//
//  1. Look up the manifest's vkey_sha256 for flags.CircuitID; absent
//     → return a wrapped error (the manifest does not advertise the
//     requested circuit).
//  2. Resolve the vkey through the resolver (cache → Tier 1 → Tier 2);
//     the resolver itself enforces the SHA-256(vkey) == vkey_sha256
//     contract via vkeystore.VerifyPin.
//  3. On vkeystore.ErrCircuitPinMismatch: propagate; the caller MUST
//     halt with no submission.
//  4. On vkeystore.ErrVkeyUnavailable: propagate; the caller MUST
//     halt — verification cannot proceed without the vkey.
//
// When flags.ZK is false this function is a no-op (legacy publish
// does not pin to a circuit).
func PreflightPinCheck(ctx context.Context, resolver Resolver, flags ZKFlags, manifest DiscoveryManifest) error {
	if !flags.ZK {
		return nil
	}
	if resolver == nil {
		return fmt.Errorf("PreflightPinCheck: resolver is nil")
	}
	if manifest == nil {
		return fmt.Errorf("PreflightPinCheck: manifest is nil")
	}
	pin, ok := manifest.VkeySha256For(flags.CircuitID)
	if !ok {
		return fmt.Errorf("PreflightPinCheck: circuit %q not advertised in discovery manifest", flags.CircuitID)
	}
	// MR !21 round-2 B2 (note 680): the discovery manifest publishes
	// `paygate_zk_domain` as the SERVICE host (e.g.
	// `paygate-zk.example.com`); the resolver expects the publisher
	// BASE domain (e.g. `example.com`) and rejects already-prefixed
	// inputs with ErrDomainAlreadyPrefixed. PublisherBaseDomain bridges
	// the contract.
	baseDomain, err := PublisherBaseDomain(manifest.PaygateZKDomainHost())
	if err != nil {
		return fmt.Errorf("PreflightPinCheck: %w", err)
	}
	req := vkeystore.ResolveRequest{
		CircuitID:       flags.CircuitID,
		VkeySha256:      pin,
		PublisherDomain: baseDomain,
	}
	if _, err := resolver.Resolve(ctx, req); err != nil {
		return err
	}
	return nil
}

// Witness is the publisher's intent envelope passed into PayGate ZK
// proof construction. Reduced to the fields this PRD touches; the
// full payload (P, R, M_in, M_out, T_log_records) is the V2 packer's
// concern (P1.2).
type Witness struct {
	// DisclosurePolicy is the per-session policy sealed by
	// SealDisclosurePolicy. After Sealed is true, it MUST NOT change.
	DisclosurePolicy string

	// Sealed is true once SealDisclosurePolicy has been called. A
	// second seal call returns ErrDisclosurePolicySealed.
	Sealed bool

	// LineageID is the 16-byte pod lineage identifier provisioned by
	// EnsureSaltForTypeD on Type-D publishes. Zero for Type-C and for
	// non-ZK publishes.
	LineageID [16]byte

	// Salt is the 32-byte CSPRNG-derived salt persisted by the
	// saltstore backend for Type-D publishes. Zero for Type-C and
	// non-ZK. Consumed LOCALLY by the v2 packer per PRD 4 § B.1 then
	// discarded; NEVER serialised over the wire (§ B.2).
	Salt [32]byte
}

// SealDisclosurePolicy is the witness-time enforcement point per PRD
// 4 § 4.3.3. It is the single permitted place to set
// witness.DisclosurePolicy. Once sealed, the witness's policy is
// irrevocable for the session — a downstream serialiser cannot
// subvert the publisher's choice.
//
// When flags.ZK is false this function is a no-op (legacy publish
// has no witness).
func SealDisclosurePolicy(flags ZKFlags, w *Witness) error {
	if !flags.ZK {
		return nil
	}
	if w == nil {
		return fmt.Errorf("SealDisclosurePolicy: witness is nil")
	}
	if w.Sealed {
		return fmt.Errorf("%w: witness already sealed with policy %q",
			ErrDisclosurePolicySealed, w.DisclosurePolicy)
	}
	if flags.DisclosurePolicy != "C" && flags.DisclosurePolicy != "D" {
		return fmt.Errorf("%w: SealDisclosurePolicy requires \"C\" or \"D\", got %q",
			ErrInvalidDisclosurePolicy, flags.DisclosurePolicy)
	}
	w.DisclosurePolicy = flags.DisclosurePolicy
	w.Sealed = true
	return nil
}

// EnsureSaltForTypeD provisions a 32-byte salt for the pod's
// lineage_id and persists it via the supplied saltstore backend.
// Idempotent: if a salt is already stored for the lineage_id, the
// stored value is returned unchanged.
//
// No-op for Type C (the salt rides in the public bundle and is not
// stored separately) and for non-ZK publishes.
//
// When backend is nil (the publisher's environment has no usable
// salt-storage backend), returns saltstore.ErrSaltStorageUnavailable
// so the caller can halt the publish before any submission.
//
// Spec: paygate-zk @ konareef-integration-contract-v1.md § 4.3.3
// + P1.7.1 plan (saltstore.Resolve).
func EnsureSaltForTypeD(flags ZKFlags, spec *pod.Spec, backend saltstore.Backend) ([16]byte, [32]byte, error) {
	if !flags.ZK || flags.DisclosurePolicy != "D" {
		return [16]byte{}, [32]byte{}, nil
	}
	if backend == nil {
		return [16]byte{}, [32]byte{}, saltstore.ErrSaltStorageUnavailable
	}
	lineageID, err := saltstore.LineageIDFromManifest(spec)
	if err != nil {
		return [16]byte{}, [32]byte{}, fmt.Errorf("EnsureSaltForTypeD: %w", err)
	}
	salt, getErr := backend.Get(lineageID)
	if getErr == nil {
		return lineageID, salt, nil
	}
	if !errors.Is(getErr, saltstore.ErrSaltNotFound) {
		return [16]byte{}, [32]byte{}, fmt.Errorf("EnsureSaltForTypeD get: %w", getErr)
	}
	// First use: CSPRNG-generate a fresh 32-byte salt and persist.
	if _, rerr := rand.Read(salt[:]); rerr != nil {
		return [16]byte{}, [32]byte{}, fmt.Errorf("EnsureSaltForTypeD rand: %w", rerr)
	}
	if perr := backend.Put(lineageID, salt); perr != nil {
		return [16]byte{}, [32]byte{}, fmt.Errorf("EnsureSaltForTypeD put: %w", perr)
	}
	return lineageID, salt, nil
}
