// Copyright 2026 Jerry David Chan, Konareef.ai
// SPDX-License-Identifier: Apache-2.0

// attestation.go — assemble a pod_attestation wire payload from
// the local install cache.
//
// `konareef install` writes three files into
// `<home>/.konareef/installed/<handle>/<pod>/<version>/`:
//
//	manifest.canon  — the canonical pod.toml bytes (pre-image of pod_hash)
//	signature.bin   — the DER-encoded ECDSA signature
//	meta.json       — pod_hash hex + publisher_pubkey_hex + identifiers
//
// LoadCachedAttestation reads all three and assembles the
// `api.PodAttestation` shape reef-core's POST /api/pods/spawn
// endpoint expects (pod_hash as 64-char
// lowercase hex, signature/pubkey as standard base64). The shape
// is byte-for-byte locked by ReefCoreWeb.AttestationParser; any
// drift would fail the server's 422 validation before spawn.

package install

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/digitsu/konareef/internal/api"
)

// LoadCachedAttestation returns the wire-shape attestation for a
// pod previously cached by `konareef install`. Returns an error if
// the cache directory is missing or any of the three files (
// meta.json, signature.bin) are absent or malformed.
//
// The caller attaches the result to api.SpawnPodRequest.PodAttestation
// when it spawns the cached pod with its own content (`pod run`).
// reef-core refuses it on POST /api/agents (reef-core#99).
func LoadCachedAttestation(home, handle, podName, version string) (*api.PodAttestation, error) {
	dir := filepath.Join(home, ".konareef", "installed", handle, podName, version)

	metaBytes, err := os.ReadFile(filepath.Join(dir, "meta.json"))
	if err != nil {
		return nil, fmt.Errorf("read meta.json: %w", err)
	}

	var meta struct {
		PodHash         string `json:"pod_hash"`
		PublisherPubkey string `json:"publisher_pubkey_hex"`
	}
	if err := json.Unmarshal(metaBytes, &meta); err != nil {
		return nil, fmt.Errorf("parse meta.json: %w", err)
	}
	if meta.PodHash == "" {
		return nil, fmt.Errorf("meta.json has empty pod_hash")
	}
	if meta.PublisherPubkey == "" {
		return nil, fmt.Errorf("meta.json has empty publisher_pubkey_hex")
	}

	// publisher_pubkey is stored hex in meta.json; the wire format
	// is base64, so re-encode here.
	pubBytes, err := hex.DecodeString(meta.PublisherPubkey)
	if err != nil {
		return nil, fmt.Errorf("decode publisher_pubkey_hex: %w", err)
	}

	sig, err := os.ReadFile(filepath.Join(dir, "signature.bin"))
	if err != nil {
		return nil, fmt.Errorf("read signature.bin: %w", err)
	}

	return &api.PodAttestation{
		PodHash:            meta.PodHash,
		PodVersion:         version,
		PublisherID:        handle,
		PublisherSignature: base64.StdEncoding.EncodeToString(sig),
		PublisherPubkey:    base64.StdEncoding.EncodeToString(pubBytes),
	}, nil
}
