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
	// instead of the signature alone. Set by Prepare; always non-empty
	// on success, since a demo-era pod must always ship its content.
	ContentTarball []byte

	// Spec is the parsed pod.toml. Carried through so the CLI can
	// derive the lineage_id for Type-D salt provisioning without
	// re-parsing the manifest. Set by Prepare.
	Spec *pod.Spec
}

// Prepare runs the offline half of `konareef pod publish`:
//
//  1. Read `<podDir>/pod.toml`.
//  2. Parse + validate against the v0.1 schema. Any validation issue
//     is fatal — `pod publish` is not the place to discover schema
//     bugs.
//  3. Canonicalize the manifest + the pod-directory contents (the
//     synthetic `[_files]` section binds every other file in podDir
//     into pod_hash, defeating post-sign file-swap attacks).
//  4. `pod_hash = SHA-256(canonical_bytes)`.
//  5. Sign the canonical bytes with `id`. The Sign primitive hashes
//     internally, so the signature is over pod_hash (matches the
//     publisher-signing-design v0 §"Stage 2" algorithm).
//  6. Pack `podDir` into the deterministic content tarball (Task B2).
//     A packing failure is fatal here rather than a degrade-to-no-
//     tarball fallback: a demo-era pod must always ship its content,
//     so the publisher sees a pathological (e.g. oversized) pod at
//     publish time, not as a mystery later at install time.
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
	tarball, err := PackTarball(podDir)
	if err != nil {
		return nil, fmt.Errorf("pack content tarball: %w", err)
	}
	return &PreparedPod{
		Handle:         id.Handle,
		PodName:        spec.Pod.Name,
		PodVersion:     spec.Pod.Version,
		PodHash:        sha256.Sum256(canonBytes),
		CanonicalBytes: canonBytes,
		Signature:      sig,
		PublicKeyHex:   id.PublicKeyHex,
		ContentTarball: tarball,
		Spec:           &spec,
	}, nil
}
