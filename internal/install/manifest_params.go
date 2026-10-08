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
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/digitsu/konareef/internal/canon"
	"github.com/digitsu/konareef/internal/commission"
	"github.com/digitsu/konareef/internal/feeder"
	"github.com/digitsu/konareef/internal/membridge"
	"github.com/digitsu/konareef/internal/pod"
)

// LoadManifestParams returns the feeder.ManifestParams for a pod previously
// cached by `konareef install`. Returns an error if the cache directory is
// missing, any of the three files (manifest.canon, signature.bin,
// meta.json) is absent or malformed, or the manifest does not carry the
// two values the commitment requires: a [model] naming both provider and
// name, and a [budget].max_sats.
//
// It also refuses a cache entry whose identity or commitment does not hold
// (manifest_identity.go, IB-03): manifest.canon must hash to meta.json's
// pod_hash (ErrInstalledManifestHashMismatch); a canonical version this
// build does not read is refused (commission.ErrManifestVersionUnsupported);
// and a konareef-toml/v2 or v3 manifest must carry a parseable [_commit] trailer
// whose fields_root equals the root recomputed from the returned Models,
// Tools and CMax (ErrCommittedFieldsRootMismatch). A root of the right
// length is not accepted on its length alone. The publisher signature is
// not checked again here; install checked it, and PS-1 and the verifier
// check sig_manifest against pk_pub.
//
// Manifest is the byte-exact manifest.canon contents — its SHA-256 is the
// signed h_manifest, so it is never re-serialized. SigManifest is the
// signature.bin DER padded into the fixed 74-byte PS-1 sig_manifest lane
// ([derLen][DER][zero pad]) that PS-1 and the verifier expect. PkPub is
// the 33-byte compressed pubkey, hex-decoded from meta.json. Tools is
// the committed declared_tools list (canon.CommittedTools): for v1 and v2
// the [[context.tools]] source list in manifest order (empty, non-nil
// slice when the manifest declares none); for konareef-toml/v3 that list
// unioned with every brokered MCP tool id "<mcp_name>.<tool>", sorted by
// bytes. A v3 closed pod with a brokered grant is refused
// (COMMIT_SEALED_GRANT_ZK_UNSUPPORTED; MCP-Z00 §10.5).
//
// Models is a single-element slice holding canon.ModelID(provider, name) —
// "<provider>/<name>" (spec §4.1, R-V2.5), NOT [model].name alone. This
// value feeds feeder.ManifestParams → feeder.WriteWitness → the circuit,
// which recomputes models_root and compares it against the fields_root
// internal/publish.DeriveCommitParams committed at publish time. The two
// MUST derive the identifier identically, so both call canon.ModelID.
// Until 2026-09-21 this site emitted the bare name while publish emitted
// "<provider>/<name>": a --zk publish of a pod with a [model] succeeded,
// burned a pod_hash, and could then never prove.
//
// CMax is [budget].max_sats, and the section is REQUIRED (spec §4.3,
// R-V2.7) — exactly as internal/publish.DeriveCommitParams requires it.
// A missing [budget].max_sats is an error here rather than a silent 0,
// because 0 is a MEANINGFUL committed value ("this pod cannot spend")
// that an absent section does not carry: the server's 200,000-sat
// ceiling applies instead. Committing a witness c_max of 0 for a
// manifest that never committed one would fail the proof, and reporting
// the manifest as capped at 0 to anything reading these params would be
// the same false premise §4.3 rejects for containment. Detecting the
// absence needs pod.ParseWithMeta, because Budget.MaxSats is an `int`
// with omitempty and the struct alone cannot tell "absent" from "= 0".
func LoadManifestParams(home, handle, podName, version string) (feeder.ManifestParams, error) {
	return LoadManifestParamsWithMemory(home, handle, podName, version, nil)
}

// LoadManifestParamsWithMemory is LoadManifestParams for the salt holder
// of a memory-bearing pod (konareef-rinit/v1 spec §6.2, §8 "root check").
//
// Inputs: as LoadManifestParams, plus mem — the lineage salt and the
// cells the runtime loaded (nil when the caller has none). Output: the
// params with RInit set to the checked r_init (E20 for a memory-free
// konareef-rinit/v1 manifest) and, for a memory-bearing manifest,
// MemoryCells set to the checked cells. A memory-bearing manifest without
// evidence fails with ErrMemoryEvidenceRequired; evidence that does not
// reproduce the committed root fails with ErrCommittedFieldsRootMismatch;
// a legacy zero-root manifest fails with ErrLegacyZeroMemoryRoot. In every
// failure no params are returned, so no witness can be built.
func LoadManifestParamsWithMemory(home, handle, podName, version string, mem *MemoryEvidence) (feeder.ManifestParams, error) {
	return loadManifestParams(home, handle, podName, version, mem, nil)
}

// loadManifestParams is the shared body of LoadManifestParamsWithMemory
// (salt-holder evidence) and LoadManifestParamsForRun (the sidecar's
// salt-free run check, run_memory.go). mem and run are each optional;
// the production sidecar passes run and no mem.
func loadManifestParams(home, handle, podName, version string, mem *MemoryEvidence, run *RunMemory) (feeder.ManifestParams, error) {
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
		PodHash         string `json:"pod_hash"`
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
	if err := checkInstalledManifestHash(manifest, meta.PodHash); err != nil {
		return feeder.ManifestParams{}, err
	}

	spec, manifestMeta, err := pod.ParseWithMeta(manifest)
	if err != nil {
		return feeder.ManifestParams{}, fmt.Errorf("parse manifest.canon: %w", err)
	}
	if spec.Model == nil {
		return feeder.ManifestParams{}, fmt.Errorf("manifest.canon has no [model] table")
	}
	modelID, err := canon.ModelID(spec.Model.Provider, spec.Model.Name)
	if err != nil {
		return feeder.ManifestParams{}, fmt.Errorf("manifest.canon [model]: %w", err)
	}

	// declared_tools depends on the canonical version: v3 commits the
	// brokered MCP tool ids beside [[context.tools]], v2 does not. The
	// derivation is canon.CommittedTools, the one publish's
	// CanonicalizeV3 uses, so the witness carries exactly the committed set.
	//
	// The version is gated first, with the same function the commitment
	// check below uses, so a version this build does not read is reported
	// as commission.ErrManifestVersionUnsupported (and a v2/v3 manifest
	// with an unreadable trailer as ErrManifestCommitmentUnreadable) before
	// any version-specific derivation runs.
	if _, err := commission.ManifestFieldsRoot(manifest); err != nil {
		return feeder.ManifestParams{}, fmt.Errorf("manifest.canon: %w", err)
	}
	manifestVersion, _ := canon.VersionIdentifier(manifest)
	sources, grants := pod.CommitToolInputs(*spec)
	if manifestVersion == "v3" && len(grants) > 0 && spec.Pod.Visibility == "closed" {
		return feeder.ManifestParams{}, fmt.Errorf("manifest.canon: %w",
			canon.NewError(canon.ErrCommitSealedGrantZKUnsupported,
				"a closed pod with a brokered MCP grant is not proof-eligible until sealed grants are supported (MCP-C00)"))
	}
	tools, toolsErr := canon.CommittedTools(manifestVersion, sources, grants)
	if toolsErr != nil {
		return feeder.ManifestParams{}, fmt.Errorf("manifest.canon declared_tools: %w", toolsErr)
	}

	if !manifestMeta.IsDefined("budget", "max_sats") {
		return feeder.ManifestParams{}, fmt.Errorf(
			"manifest.canon has no [budget].max_sats; a manifest whose c_max was never " +
				"committed has no witness value to load, and 0 is not a safe stand-in " +
				"(see spec R-V2.7)")
	}
	if spec.Budget.MaxSats < 0 {
		return feeder.ManifestParams{}, fmt.Errorf(
			"manifest.canon [budget].max_sats is negative (%d)", spec.Budget.MaxSats)
	}

	models := []string{modelID}
	cMax := uint64(spec.Budget.MaxSats)
	declaresMemory := spec.Context != nil && len(spec.Context.Memory) > 0
	var table *membridge.LeafTable
	if run != nil {
		// checkInstalledManifestHash above has already bound these bytes
		// to meta.json's pod_hash.
		podHash := sha256.Sum256(manifest)
		if table, err = checkRunMemory(manifest, spec, declaresMemory, podHash, meta.PublisherPubkey, *run); err != nil {
			return feeder.ManifestParams{}, fmt.Errorf("manifest.canon run memory: %w", err)
		}
	}
	memory, err := checkCommittedFieldsRoot(manifest, models, tools, cMax, declaresMemory, mem, table)
	if err != nil {
		return feeder.ManifestParams{}, fmt.Errorf("manifest.canon: %w", err)
	}

	return feeder.ManifestParams{
		Manifest:    manifest,
		Models:      models,
		Tools:       tools,
		CMax:        cMax,
		SigManifest: sigLane,
		PkPub:       pkPub,
		RInit:       memory.rInit,
		MemoryCells: memory.cells,
	}, nil
}
