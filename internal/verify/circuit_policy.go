// Copyright 2026 Jerry David Chan, Konareef.ai
// SPDX-License-Identifier: Apache-2.0

// circuit_policy.go — the circuit-binding policy of the v2 verifier
// (VHASH-M1, paygate-zk#14).
//
// The allow-list in vkeystore/known.go accepts both pod-step circuits during
// the VHASH migration. That alone lets a proof maker pick the circuit: a
// konareef-pod-step-v1 proof does not bind value_hash_out, so it can stand in
// for a pod whose publisher moved to v1.1. CircuitPolicy narrows that; it
// does not close it for every verifier (see "What this does not close"):
//
//   - the publisher pin: the circuit id the publisher chose. When there is
//     one, the bundle's circuit_id must equal it (ErrCircuitIDMismatch).
//     It comes from two sources, with this precedence:
//     1. the bundle's node-signed circuit_pin (circuit_pin.go), when it is
//     present, valid and signed by a trusted node key;
//     2. PublisherCircuitID (KONAREEF_PUBLISHER_CIRCUIT_ID), the fallback
//     for a bundle without a trusted pin.
//     When both are present, the bundle must equal both. The environment
//     can make the check stricter; it cannot loosen a signed pin. A
//     present pin that does not check out refuses the bundle.
//   - a bundle vkey_anchor that carries a "circuit_id" entry must name the
//     bundle's circuit_id (ErrCircuitIDMismatch). vkey_anchor is unsigned
//     bundle data that no producer emits, so this catches only an honest
//     inconsistency; it is not a control against a sender.
//   - V1Cutoff: the end of v1 acceptance. After it, by the verifier's clock,
//     every v1 bundle is refused (ErrCircuitRetired). The verifier clock is
//     used, not a time in the bundle, because a Type-D bundle's link times
//     are the sender's claim and could be backdated.
//
// What this does not close (konareef!152 review K-M2). Before the cutoff,
// a verifier with no trusted circuit_pin and no environment pin has no
// downgrade protection: a v1 bundle for a pod whose publisher moved to v1.1
// verifies. The environment pin is process-wide, so a verifier of bundles
// from many publishers (the verdict server, for example) cannot set it.
// The signed pin is optional bundle data: a sender can remove it, or copy
// a genuine pin of the same pod from an older bundle, and get the same
// result as a bundle without one (circuit_pin.go, "Residual risk";
// follow-up konareef#43). For those bundles, the protection is reef-core
// ingest (reef-core!200), which a third party cannot see.
//
// The production path reads the policy from the environment
// (CircuitPolicyFromEnv). The v1 cutoff defaults to DefaultPodStepV1Cutoff,
// which a release build can set with -ldflags; it is empty (no end) until the
// owner picks the date (O5-A step 4).
package verify

import (
	"fmt"
	"os"
	"time"

	"github.com/digitsu/konareef/internal/vkeystore"
)

// PublisherCircuitIDEnv names the environment variable that holds the
// circuit id the publisher chose for the pod being verified. It is the
// fallback for a bundle without a trusted node-signed circuit_pin, and an
// extra constraint for a bundle with one (see the file comment).
const PublisherCircuitIDEnv = "KONAREEF_PUBLISHER_CIRCUIT_ID"

// PodStepV1CutoffEnv names the environment variable that holds the end of
// konareef-pod-step-v1 acceptance, as an RFC 3339 time.
const PodStepV1CutoffEnv = "KONAREEF_POD_STEP_V1_CUTOFF"

// DefaultPodStepV1Cutoff is the build default of the v1 cutoff, as an RFC
// 3339 time, used when PodStepV1CutoffEnv is unset or empty. Empty means v1
// has no end. Set it at release time with
// -ldflags "-X github.com/digitsu/konareef/internal/verify.DefaultPodStepV1Cutoff=<time>".
var DefaultPodStepV1Cutoff = ""

// CircuitPolicy is the circuit-binding policy. The zero value checks only
// a vkey_anchor's circuit_id, so it keeps the pre-VHASH-M1 behaviour for
// bundles without one.
type CircuitPolicy struct {
	// PublisherCircuitID is the circuit id the publisher chose, from the
	// environment. Empty means the caller has no environment pin. It is
	// the fallback for a bundle without a trusted node-signed circuit_pin;
	// with one, the bundle must match both.
	PublisherCircuitID string
	// V1Cutoff is the end of konareef-pod-step-v1 acceptance. Zero means no
	// end.
	V1Cutoff time.Time
	// Now is the verifier clock. Nil means time.Now.
	Now func() time.Time
}

// CircuitPolicyFromEnv reads the production circuit policy from the
// environment.
//
// Output: the policy, or an error when PublisherCircuitIDEnv names a circuit
// this build does not accept or the cutoff (from PodStepV1CutoffEnv, else
// DefaultPodStepV1Cutoff) is not an RFC 3339 time. The caller must refuse
// the bundle on an error, so a typo cannot switch a check off.
func CircuitPolicyFromEnv() (CircuitPolicy, error) {
	var p CircuitPolicy
	if id := os.Getenv(PublisherCircuitIDEnv); id != "" {
		if !vkeystore.IsSupportedCircuitID(id) {
			return p, fmt.Errorf("%s=%q is not a supported circuit id (want one of %v)",
				PublisherCircuitIDEnv, id, vkeystore.SupportedCircuitIDs())
		}
		p.PublisherCircuitID = id
	}
	cutoff := os.Getenv(PodStepV1CutoffEnv)
	if cutoff == "" {
		cutoff = DefaultPodStepV1Cutoff
	}
	if cutoff != "" {
		at, err := time.Parse(time.RFC3339, cutoff)
		if err != nil {
			return p, fmt.Errorf("v1 cutoff %q is not an RFC 3339 time: %v", cutoff, err)
		}
		p.V1Cutoff = at
	}
	return p, nil
}

// checkCircuitPolicy applies p to a bundle whose circuit_id already passed
// the allow-list.
//
// Inputs: the decoded bundle; the policy; trustedKeys, the trusted node
// identity keys that may sign a circuit_pin; the verdict (for the pin
// outcome); and the result to diverge on.
// Output: true when the bundle passes; false after a divergence.
func checkCircuitPolicy(b *BundleV2, p CircuitPolicy, trustedKeys [][]byte, v *Verdict, r *ResultV2) bool {
	signedPin, ok := checkCircuitPin(b, trustedKeys, v, r)
	if !ok {
		return false
	}
	if signedPin != "" && b.CircuitID != signedPin {
		r.diverge(ErrCircuitIDMismatch, fmt.Sprintf("circuit_id=%q, the node-signed circuit_pin names %q",
			b.CircuitID, signedPin))
		return false
	}
	if p.PublisherCircuitID != "" && b.CircuitID != p.PublisherCircuitID {
		r.diverge(ErrCircuitIDMismatch, fmt.Sprintf("circuit_id=%q, publisher pinned %q",
			b.CircuitID, p.PublisherCircuitID))
		return false
	}
	if anchored, ok := b.VkeyAnchor["circuit_id"]; ok && anchored != b.CircuitID {
		r.diverge(ErrCircuitIDMismatch, fmt.Sprintf("circuit_id=%q, vkey_anchor names %v",
			b.CircuitID, anchored))
		return false
	}
	if b.CircuitID == vkeystore.CircuitIDPodStepV1 && !p.V1Cutoff.IsZero() {
		now := time.Now
		if p.Now != nil {
			now = p.Now
		}
		if now().After(p.V1Cutoff) {
			r.diverge(ErrCircuitRetired, fmt.Sprintf("%s is not accepted after %s",
				vkeystore.CircuitIDPodStepV1, p.V1Cutoff.Format(time.RFC3339)))
			return false
		}
	}
	return true
}
