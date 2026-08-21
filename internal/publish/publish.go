// Copyright 2026 Jerry David Chan, Konareef.ai
// SPDX-License-Identifier: Apache-2.0

// Package publish orchestrates the local half of `konareef pod
// publish` — turning a pod directory into a signed bundle ready to
// POST to reef-core's `/api/pods` endpoint.
//
// Prepare composes the three existing primitives:
//
//   - internal/pod   — parse + schema validation
//   - internal/canon — canonicalization + pod_hash (SHA-256)
//   - internal/identity — secp256k1 ECDSA over the canonical bytes
//
// It is deliberately offline-only: anything that needs the network
// (the actual POST, the install URL, the published-pod row) lives in
// the Submit function, so the local steps can be `--dry-run`-tested
// without a running reef-core.
package publish

import (
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"

	"github.com/digitsu/konareef/internal/canon"
	"github.com/digitsu/konareef/internal/identity"
	"github.com/digitsu/konareef/internal/pod"
)

// PreparedPod is the local result of `Prepare`: the canonical
// manifest bytes, the SHA-256 pod_hash they produced, and the
// publisher's signature over those bytes — plus the metadata fields
// (`handle`, `pod_name`, `pod_version`, `publisher_pubkey`) that
// reef-core needs to register the pod.
//
// Submit consumes one of these directly; the CLI's `--dry-run` mode
// just renders it.
type PreparedPod struct {
	Handle         string
	PodName        string
	PodVersion     string
	PodHash        [32]byte
	CanonicalBytes []byte
	Signature      []byte
	PublicKeyHex   string

	// ContentTarball is the deterministic gzip tar of podDir produced
	// by PackTarball (Task B2). Extracting it and re-running
	// canon.Canonicalize MUST reproduce PodHash — that reproduction is
	// what lets `konareef install` (Task B3) trust the tarball bytes
	// instead of the signature alone. Set by Prepare for an OPEN pod,
	// and non-empty for one: an open pod must always ship its content.
	// Deliberately nil for a closed pod, whose body ships sealed in
	// Sealed instead — the two are mutually exclusive by construction.
	ContentTarball []byte

	// Visibility mirrors Spec.Pod.Visibility: "closed" for a closed pod,
	// empty for an open one (the absent-means-open default). Hoisted
	// onto PreparedPod so Submit branches on the prepared result rather
	// than re-reading the spec, keeping the "sealed body implies closed
	// visibility" pairing in one place.
	Visibility string

	// Sealed is the AES-256-GCM-encrypted body of a closed pod, packed
	// over exactly the `[_files]` path set and bound to PodHash via the
	// AEAD's AAD. Nil for an open pod. It carries K_body, which Submit
	// transmits once over TLS and which must never be logged or written
	// to disk.
	Sealed *SealedBody

	// Spec is the parsed pod.toml. Carried through so the CLI can
	// derive the lineage_id for Type-D salt provisioning without
	// re-parsing the manifest. Set by Prepare.
	Spec *pod.Spec
}

// VisibilityClosed is the pod.toml `visibility` value that makes a pod's
// body private: encrypted at publish, never served in the clear, and run
// only on konareef's own infrastructure. Any other value (including the
// absent/empty default) is an open pod.
const VisibilityClosed = "closed"

// Prepare runs the offline half of `konareef pod publish`:
//
//  1. Read `<podDir>/pod.toml`.
//
//  2. Parse + validate against the v0.1 schema. Any validation issue
//     is fatal — `pod publish` is not the place to discover schema
//     bugs.
//
//  3. Canonicalize the manifest + the pod-directory contents (the
//     synthetic `[_files]` section binds every other file in podDir
//     into pod_hash, defeating post-sign file-swap attacks).
//
//  4. `pod_hash = SHA-256(canonical_bytes)`.
//
//  5. Sign the canonical bytes with `id`. The Sign primitive hashes
//     internally, so the signature is over pod_hash (matches the
//     publisher-signing-design v0 §"Stage 2" algorithm).
//
//  6. Package the body, the ONE step that branches on visibility:
//
//     - open pod (no `visibility`, or `"open"`): pack `podDir` into the
//     deterministic content tarball (Task B2). A packing failure is
//     fatal here rather than a degrade-to-no-tarball fallback: an open
//     pod must always ship its content, so the publisher sees a
//     pathological (e.g. oversized) pod at publish time, not as a
//     mystery later at install time.
//     - closed pod: pack only the `[_files]` path set — enumerated by
//     canon.BodyFiles, the same walk that built the table pod_hash
//     commits to — and seal it with AES-256-GCM under a fresh K_body,
//     AAD'd to pod_hash. No plaintext tarball is produced.
//
//     Steps 1-5 are identical either way. A closed pod is canonicalized,
//     hashed and signed exactly like an open one; `visibility` is an
//     ordinary manifest field the signature covers, and nothing about
//     the seal enters the signed bytes.
//
// The returned PreparedPod is ready for Submit or `--dry-run`
// rendering; no network call is performed here.
func Prepare(podDir string, id *identity.Identity) (*PreparedPod, error) {
	tomlPath := filepath.Join(podDir, "pod.toml")
	body, err := os.ReadFile(tomlPath)
	if err != nil {
		return nil, fmt.Errorf("read pod.toml: %w", err)
	}

	spec, issues, err := pod.ParseAndValidate(body)
	if err != nil {
		return nil, fmt.Errorf("parse pod.toml: %w", err)
	}
	if len(issues) > 0 {
		return nil, fmt.Errorf(
			"pod.toml has %d validation issue(s); fix with `konareef pod validate %s` first",
			len(issues), tomlPath,
		)
	}

	canonBytes, err := canon.Canonicalize(body, podDir)
	if err != nil {
		return nil, fmt.Errorf("canonicalize manifest: %w", err)
	}
	sig, err := id.Sign(canonBytes)
	if err != nil {
		return nil, fmt.Errorf("sign canonical manifest: %w", err)
	}
	podHash := sha256.Sum256(canonBytes)

	prepared := &PreparedPod{
		Handle:         id.Handle,
		PodName:        spec.Pod.Name,
		PodVersion:     spec.Pod.Version,
		PodHash:        podHash,
		CanonicalBytes: canonBytes,
		Signature:      sig,
		PublicKeyHex:   id.PublicKeyHex,
		Visibility:     spec.Pod.Visibility,
		Spec:           &spec,
	}

	// Everything above is visibility-independent, and deliberately so:
	// a closed pod is canonicalized, hashed and signed exactly like an
	// open one. Only the body's packaging differs below.
	if spec.Pod.Visibility == VisibilityClosed {
		bodyPaths, err := canon.BodyFiles(podDir)
		if err != nil {
			return nil, fmt.Errorf("enumerate body files: %w", err)
		}
		bodyTar, err := PackTarballPaths(podDir, bodyPaths)
		if err != nil {
			return nil, fmt.Errorf("pack closed-pod body: %w", err)
		}
		// AAD is the raw digest, not its hex rendering: the wire carries
		// hex, but the binding is over the 32 bytes reef-core will have
		// after decoding it.
		sealed, err := SealBody(bodyTar, podHash[:])
		if err != nil {
			return nil, fmt.Errorf("seal closed-pod body: %w", err)
		}
		prepared.Sealed = sealed
		// ContentTarball is left nil on purpose — a closed pod's whole
		// point is that its plaintext body never leaves this machine.
		return prepared, nil
	}

	tarball, err := PackTarball(podDir)
	if err != nil {
		return nil, fmt.Errorf("pack content tarball: %w", err)
	}
	prepared.ContentTarball = tarball
	return prepared, nil
}
