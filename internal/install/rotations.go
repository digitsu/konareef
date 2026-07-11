// Copyright 2026 Jerry David Chan, Konareef.ai
// SPDX-License-Identifier: Apache-2.0

// rotations.go — buyer-side rotation chain fetch + walk.
//
// When `konareef install` hits a TrustChange divergence (the local
// known_publishers shows K_old, reef-core's response carries K_new),
// the CLI fetches the publisher's rotation history and walks the
// chain from K_old to K_new. Each hop's signature is verified under
// the predecessor's pubkey, so the chain has integrity even though
// reef-core does no verification on the read path.
//
// The two-function shape mirrors install.go (Fetch + Verify):
// FetchRotations decodes the wire response into typed structs;
// WalkRotationChain enforces the cryptographic invariants. Keeping
// them separate makes both unit-testable without spinning up a
// signing primitive in the HTTP path.

package install

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/digitsu/konareef/internal/identity"
)

// FetchedRotation is one chain link as the install client uses it
// internally — the typed attestation plus the raw signature bytes
// (base64-decoded from the wire form).
type FetchedRotation struct {
	Attestation       identity.RotationAttestation
	SignatureByOldKey []byte
}

// rotationsWire mirrors reef-core's
// `ReefCoreWeb.PublisherRotationController :: serialize/1` shape.
// Field names are JSON-tagged to make the dependency on the
// reef-core response explicit: any wire change there will surface
// here as a decode failure rather than silently producing zero-value
// attestations.
type rotationsWire struct {
	Rotations []rotationWire `json:"rotations"`
}

type rotationWire struct {
	Attestation       attestationWire `json:"attestation"`
	SignatureByOldKey string          `json:"signature_by_old_key"`
}

type attestationWire struct {
	Kind         string `json:"kind"`
	Handle       string `json:"handle"`
	OldPubkeyHex string `json:"old_pubkey_hex"`
	NewPubkeyHex string `json:"new_pubkey_hex"`
	RotatedAt    string `json:"rotated_at"`
	Reason       string `json:"reason"`
}

// FetchRotations GETs `<serverURL>/api/publishers/<handle>/rotations`
// and decodes the response into the typed FetchedRotation slice.
//
// An empty rotations array is NOT an error — the publisher may
// never have rotated. The caller branches on len before invoking
// WalkRotationChain.
//
// Any non-2xx status, network failure, JSON parse error, or
// non-base64 signature is a fatal error. The chain walker assumes
// its inputs are at least well-formed.
func FetchRotations(serverURL, handle string) ([]FetchedRotation, error) {
	url := strings.TrimRight(serverURL, "/") + "/api/publishers/" + handle + "/rotations"
	resp, err := http.Get(url)
	if err != nil {
		return nil, fmt.Errorf("GET %s: %w", url, err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("GET %s: status %d: %s",
			url, resp.StatusCode, strings.TrimSpace(string(body)))
	}

	var w rotationsWire
	if err := json.Unmarshal(body, &w); err != nil {
		return nil, fmt.Errorf("parse rotations response: %w", err)
	}

	out := make([]FetchedRotation, 0, len(w.Rotations))
	for i, r := range w.Rotations {
		sigBytes, err := base64.StdEncoding.DecodeString(r.SignatureByOldKey)
		if err != nil {
			return nil, fmt.Errorf("decode rotation[%d].signature_by_old_key: %w", i, err)
		}
		out = append(out, FetchedRotation{
			Attestation: identity.RotationAttestation{
				Kind:         r.Attestation.Kind,
				Handle:       r.Attestation.Handle,
				OldPubkeyHex: r.Attestation.OldPubkeyHex,
				NewPubkeyHex: r.Attestation.NewPubkeyHex,
				RotatedAt:    r.Attestation.RotatedAt,
				Reason:       r.Attestation.Reason,
			},
			SignatureByOldKey: sigBytes,
		})
	}
	return out, nil
}

// WalkRotationChain verifies a chain of rotation hops from
// fromPubkeyHex to toPubkeyHex for the given handle, returning the
// hops actually traversed (in order) on success.
//
// At each step the walker:
//
//  1. Finds a hop whose `attestation.old_pubkey_hex` is the current
//     position. If multiple hops have the same old_pubkey (which
//     reef-core's unique_index on (handle, old_pubkey, new_pubkey)
//     does NOT prevent — a key could legitimately have been rotated
//     to two different keys at different times if reef-core
//     overrode the constraint), the first match in the input list
//     wins. The server returns rotations oldest-first.
//  2. Confirms attestation.handle matches the walker's handle
//     argument (defends against cross-publisher attestation reuse).
//  3. Verifies signature_by_old_key under the current pubkey.
//  4. Advances to attestation.new_pubkey_hex.
//
// A maximum-hop guard prevents infinite loops on cyclic input
// (A→B, B→A, …). The guard fires before pathological CPU use; the
// resulting error names the cycle as "chain did not reach target".
//
// Errors are descriptive enough for the CLI to surface in the
// blocking-key-change dialog — they name the offending step.
func WalkRotationChain(rotations []FetchedRotation, handle, fromPubkeyHex, toPubkeyHex string) ([]FetchedRotation, error) {
	if fromPubkeyHex == toPubkeyHex {
		return nil, fmt.Errorf("from == to (%s); nothing to walk", fromPubkeyHex)
	}

	// Bound the walk by the number of available hops — each hop can
	// be consumed at most once on a valid chain. This terminates
	// even pathological inputs (cycles, duplicate hops) deterministically.
	maxHops := len(rotations) + 1
	used := make(map[int]bool, len(rotations))

	chain := make([]FetchedRotation, 0, len(rotations))
	current := fromPubkeyHex

	for step := 0; step < maxHops; step++ {
		idx := -1
		for i, hop := range rotations {
			if used[i] {
				continue
			}
			if hop.Attestation.OldPubkeyHex == current {
				idx = i
				break
			}
		}
		if idx == -1 {
			return nil, fmt.Errorf(
				"no rotation hop from %s; chain did not reach target %s",
				current, toPubkeyHex)
		}

		hop := rotations[idx]
		used[idx] = true

		if hop.Attestation.Handle != handle {
			return nil, fmt.Errorf(
				"rotation hop %s → %s has handle %q, expected %q",
				hop.Attestation.OldPubkeyHex,
				hop.Attestation.NewPubkeyHex,
				hop.Attestation.Handle, handle)
		}

		ok, err := identity.VerifyRotationSignature(current, hop.Attestation, hop.SignatureByOldKey)
		if err != nil {
			return nil, fmt.Errorf(
				"verify rotation hop %s → %s: %w",
				hop.Attestation.OldPubkeyHex, hop.Attestation.NewPubkeyHex, err)
		}
		if !ok {
			return nil, fmt.Errorf(
				"rotation hop %s → %s: signature does not verify under %s",
				hop.Attestation.OldPubkeyHex, hop.Attestation.NewPubkeyHex, current)
		}

		chain = append(chain, hop)
		current = hop.Attestation.NewPubkeyHex
		if current == toPubkeyHex {
			return chain, nil
		}
	}

	return nil, fmt.Errorf(
		"chain did not reach target %s after %d hops (last at %s)",
		toPubkeyHex, maxHops, current)
}
