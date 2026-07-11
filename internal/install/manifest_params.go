// Copyright 2026 Jerry David Chan, Konareef.ai
// SPDX-License-Identifier: Apache-2.0

// manifest_params.go — assemble feeder.ManifestParams from the local
// install cache (C1 Phase-C, spec §3.2).
//
// `konareef install` writes three files into
// `<home>/.konareef/installed/<handle>/<pod>/<version>/`:
//
//	manifest.canon  — the canonical pod.toml bytes (pre-image of pod_hash)
//	signature.bin   — the DER-encoded ECDSA signature
//	meta.json       — pod_hash hex + publisher_pubkey_hex + identifiers
//
// LoadManifestParams reads all three and derives the fields the sidecar's
// WitnessWriter needs but does NOT get from the reef-core step-disclosure
// seam: Manifest, Models, Tools, CMax, SigManifest, PkPub. Modeled on
// LoadCachedAttestation (attestation.go) but returns raw bytes (no wire
// base64 re-encoding) since these fields feed feeder.WriteWitness, not an
// HTTP request body.
package install

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/digitsu/konareef/internal/feeder"
	"github.com/digitsu/konareef/internal/pod"
)

// LoadManifestParams returns the feeder.ManifestParams for a pod previously
// cached by `konareef install`. Returns an error if the cache directory is
// missing, any of the three files (manifest.canon, signature.bin,
// meta.json) is absent or malformed, or the manifest has no [model].name.
//
// Manifest is the byte-exact manifest.canon contents — its SHA-256 is the
// signed h_manifest, so it is never re-serialized. SigManifest is the
// signature.bin DER padded into the fixed 74-byte PS-1 sig_manifest lane
// ([derLen][DER][zero pad]) that PS-1 and the verifier expect. PkPub is
// the 33-byte compressed pubkey, hex-decoded from meta.json. Models is a
// single-element slice holding [model].name from the manifest. Tools is
// the declared context.tools source list (empty, non-nil slice when the
// manifest declares none). CMax is [budget].max_sats.
func LoadManifestParams(home, handle, podName, version string) (feeder.ManifestParams, error) {
	dir := filepath.Join(home, ".konareef", "installed", handle, podName, version)

	manifest, err := os.ReadFile(filepath.Join(dir, "manifest.canon"))
	if err != nil {
		return feeder.ManifestParams{}, fmt.Errorf("read manifest.canon: %w", err)
	}

	sigDER, err := os.ReadFile(filepath.Join(dir, "signature.bin"))
	if err != nil {
		return feeder.ManifestParams{}, fmt.Errorf("read signature.bin: %w", err)
	}
	// PS-1 (and the verifier, internal/verify snark.go) expect sig_manifest as
	// the fixed 74-byte lane [derLen(1)][DER][zero pad], NOT the raw DER stored
	// in signature.bin. Pad it here. The raw DER must fit: 1..73 bytes (a
	// strict-DER secp256k1 low-S signature is ~70-72 B).
	if n := len(sigDER); n < 1 || n > 73 {
		return feeder.ManifestParams{}, fmt.Errorf("signature.bin: raw DER must be 1..73 bytes to fit the 74-byte sig_manifest lane, got %d", n)
	}
	sigLane := make([]byte, 74)
	sigLane[0] = byte(len(sigDER))
	copy(sigLane[1:], sigDER)

	metaBytes, err := os.ReadFile(filepath.Join(dir, "meta.json"))
	if err != nil {
		return feeder.ManifestParams{}, fmt.Errorf("read meta.json: %w", err)
	}
	var meta struct {
		PublisherPubkey string `json:"publisher_pubkey_hex"`
	}
	if err := json.Unmarshal(metaBytes, &meta); err != nil {
		return feeder.ManifestParams{}, fmt.Errorf("parse meta.json: %w", err)
	}
	if meta.PublisherPubkey == "" {
		return feeder.ManifestParams{}, fmt.Errorf("meta.json has empty publisher_pubkey_hex")
	}
	pkPub, err := hex.DecodeString(meta.PublisherPubkey)
	if err != nil {
		return feeder.ManifestParams{}, fmt.Errorf("decode publisher_pubkey_hex: %w", err)
	}

	spec, err := pod.Parse(manifest)
	if err != nil {
		return feeder.ManifestParams{}, fmt.Errorf("parse manifest.canon: %w", err)
	}
	if spec.Model == nil || spec.Model.Name == "" {
		return feeder.ManifestParams{}, fmt.Errorf("manifest.canon has no [model].name")
	}

	tools := []string{}
	if spec.Context != nil {
		for _, t := range spec.Context.Tools {
			tools = append(tools, t.Source)
		}
	}

	var cMax uint64
	if spec.Budget != nil {
		cMax = uint64(spec.Budget.MaxSats)
	}

	return feeder.ManifestParams{
		Manifest:    manifest,
		Models:      []string{spec.Model.Name},
		Tools:       tools,
		CMax:        cMax,
		SigManifest: sigLane,
		PkPub:       pkPub,
	}, nil
}
