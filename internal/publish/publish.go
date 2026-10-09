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
	"github.com/digitsu/konareef/internal/membridge"
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

	// Warnings are the advisory warnings pod.ValidateWithWarnings
	// produced for the manifest (today: GATEWAY_SECRET_LEAVES_ENV for
	// each [[network.gateway]] entry). Validation issues remain fatal
	// and are never carried here — only advisories that did not stop
	// the publish. The CLI prints these to stderr before proceeding,
	// the same shape `pod validate` uses.
	Warnings []pod.Warning

	// SealedGrants says whether the head carries the sealed-grants
	// marker, how many sealed grants the body holds, and whether this
	// publish added the carrier or rotated its salt. It holds no sealed
	// value. The CLI checks it against the server's capabilities before
	// Submit (CheckSealedGrantsCapability).
	SealedGrants SealedGrantsState

	// MemoryLeafTable is the canonical salt-free leaf table of a
	// memory-bearing --zk publish (membridge.LeafTable.Bytes), and
	// MemoryLeafTableSignature the publisher's DER signature over
	// SHA-256 of it (konareef-rinit/v1 spec §6.4). Both are nil for every
	// other publish. They hold no salt and no memory content; Submit sends
	// them as optional fields, and reef-core serves them only to the
	// proving path.
	MemoryLeafTable          []byte
	MemoryLeafTableSignature []byte
}

// VisibilityClosed is the pod.toml `visibility` value that makes a pod's
// body private: encrypted at publish, never served in the clear, and run
// only on konareef's own infrastructure. Any other value (including the
// absent/empty default) is an open pod.
const VisibilityClosed = "closed"

// PrepareOptions carries publish-time choices that change the signed
// bytes. ZK selects konareef-toml/v2 (R-V2.12), or konareef-toml/v3 for a
// pod with a brokered MCP grant (canonicalizeZK): the same `--zk` flag
// the CLI already threads into submitRequest.ZkEnabled (main.go,
// internal/publish/submit.go) is the single source of truth for this
// choice — Prepare does not re-derive it from the manifest.
type PrepareOptions struct {
	ZK bool

	// DisclosurePolicy is the --disclosure-policy value ("C" or "D"). It
	// is read only on the memory-bearing path (memoryroot.go), which
	// refuses Type C.
	DisclosurePolicy string

	// MemorySalt returns the lineage salt for a memory-bearing --zk
	// publish (konareef-rinit/v1 R-M12). Prepare calls it only when the
	// pod declares [[context.memory]] AND MemoryPublishEnabled() is true,
	// so a publish that will be refused never provisions a salt. nil means
	// "no salt available", which refuses a memory-bearing publish.
	MemorySalt func(spec *pod.Spec) ([32]byte, error)

	// SealedGrantsAlwaysEmit adds the sealed-grants marker and an empty,
	// salted sealed/grants.toml to a closed pod that has neither, on
	// disk, before validation (owner decision D3 = a). The CLI sets it
	// only when the server advertises closed grants as enabled, which
	// releases the behaviour at rollout step 6 (MCP-C00 section 11.4).
	SealedGrantsAlwaysEmit bool

	// RotateSealedSalt writes a fresh salt into sealed/grants.toml on
	// disk before canonicalizing (owner decision D14 = a). The CLI sets
	// it for a real publish and leaves it off for --dry-run, which
	// writes nothing.
	RotateSealedSalt bool
}

// Prepare runs the offline half of `konareef pod publish`:
//
//  1. Read `<podDir>/pod.toml`.
//
//  2. Parse + validate against the v0.1 schema. Any validation issue
//     is fatal — `pod publish` is not the place to discover schema
//     bugs. Advisory warnings (e.g. GATEWAY_SECRET_LEAVES_ENV) do not
//     stop the publish; they ride on the returned PreparedPod.Warnings
//     for the CLI to print.
//
//     Then the sealed closed-pod grants rules G1–G17 run over
//     sealed/grants.toml (sealed_grants.go). With RotateSealedSalt the
//     file gets a fresh salt, and the rotated bytes are checked again.
//     With SealedGrantsAlwaysEmit a closed pod without the carrier gets
//     one first (prepareSealedCarrier).
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
func Prepare(podDir string, id *identity.Identity, opts PrepareOptions) (*PreparedPod, error) {
	tomlPath := filepath.Join(podDir, "pod.toml")
	body, err := os.ReadFile(tomlPath)
	if err != nil {
		return nil, fmt.Errorf("read pod.toml: %w", err)
	}
	// Refuse a near-miss magic line (KR-MAGIC) before anything parses or
	// rewrites pod.toml. The canonicalizers refuse it too, but the TOML
	// parser below reads most such lines as a comment and refuses others
	// (a lone CR) with a parse error that does not name the problem.
	if err := canon.CheckMagicLine(body); err != nil {
		return nil, fmt.Errorf("pod.toml: %w", err)
	}

	sealedState, err := prepareSealedCarrier(podDir, body, opts)
	if err != nil {
		return nil, err
	}
	if sealedState.Emitted {
		if body, err = os.ReadFile(tomlPath); err != nil {
			return nil, fmt.Errorf("read pod.toml: %w", err)
		}
	}

	spec, meta, err := pod.ParseWithMeta(body)
	if err != nil {
		return nil, fmt.Errorf("parse pod.toml: %w", err)
	}
	issues, warnings, err := pod.ValidateWithWarnings(body)
	if err != nil {
		return nil, fmt.Errorf("parse pod.toml: %w", err)
	}
	if len(issues) > 0 {
		return nil, fmt.Errorf(
			"pod.toml has %d validation issue(s); fix with `konareef pod validate %s` first",
			len(issues), tomlPath,
		)
	}

	// G1–G17 (MCP-C00): run before anything is canonicalized, signed or
	// sealed. The issues are value-free, so they can go in the error.
	sealedIssues, _, err := CheckSealedGrants(body, podDir, opts.ZK)
	if err != nil {
		return nil, fmt.Errorf("check sealed grants: %w", err)
	}
	if len(sealedIssues) > 0 {
		return nil, fmt.Errorf("sealed grants: %d validation issue(s):\n%s",
			len(sealedIssues), formatSealedIssues(sealedIssues))
	}
	sealedState.Marker = pod.HasSealedGrantsMarker(*spec)
	warnings = append(warnings, openPodSealedFileWarnings(*spec, podDir)...)
	var validatedGrants []byte
	if sealedState.Marker {
		if opts.RotateSealedSalt {
			if err := rotateSealedGrantsSaltOnDisk(podDir); err != nil {
				return nil, err
			}
			sealedState.SaltRotated = true
		}
		// Read the file once more and judge exactly these bytes: they are
		// the bytes the [_files] check below compares with, and the count
		// the capability check uses comes from them too.
		grants, _, err := readSealedGrantsFile(podDir)
		if err != nil {
			return nil, err
		}
		recheck, err := pod.ValidateSealedGrants(pod.SealedGrantsInput{
			Head: body, Grants: grants, GrantsPresent: true, ZK: opts.ZK,
		})
		if err != nil {
			return nil, fmt.Errorf("check sealed grants: %w", err)
		}
		if len(recheck) > 0 {
			return nil, fmt.Errorf("sealed grants: %d validation issue(s):\n%s",
				len(recheck), formatSealedIssues(recheck))
		}
		parsed, err := pod.ParseSealedGrantsFile(grants)
		if err != nil {
			return nil, err
		}
		sealedState.GrantCount = len(parsed.Grants)
		validatedGrants = grants
	}

	var canonBytes []byte
	var memory memoryResolution
	if opts.ZK {
		mem, merr := memoryCommitInput(spec, podDir, opts)
		if merr != nil {
			return nil, fmt.Errorf("derive v2/v3 commitment: %w", merr)
		}
		params, res, derr := deriveCommitParams(spec, meta, mem)
		if derr != nil {
			return nil, fmt.Errorf("derive v2/v3 commitment: %w", derr)
		}
		memory = res
		canonBytes, err = canonicalizeZK(body, podDir, spec, params)
		if err == nil {
			err = checkMemoryFilesUnchanged(spec, canonBytes, res.used)
		}
	} else {
		canonBytes, err = canon.Canonicalize(body, podDir)
	}
	if err != nil {
		return nil, fmt.Errorf("canonicalize manifest: %w", err)
	}
	if validatedGrants != nil {
		if err := verifySealedGrantsCommitted(canonBytes, validatedGrants); err != nil {
			return nil, err
		}
	}
	sig, err := id.Sign(canonBytes)
	if err != nil {
		return nil, fmt.Errorf("sign canonical manifest: %w", err)
	}
	podHash := sha256.Sum256(canonBytes)

	// A memory-bearing publish also signs its salt-free leaf table
	// (konareef-rinit/v1 spec §6.4, MEM-SEAM A1). It binds each cell to the
	// tree position and value hash the salt produced, so the proving path
	// can build the memory witness without the salt. It is bound to this
	// pod_hash and signed with the same key as the manifest.
	var leafTable, leafTableSig []byte
	if memory.memoryBearing() {
		table, terr := membridge.NewLeafTable(podHash, memory.rInit, memory.cells, memory.derived)
		if terr != nil {
			return nil, fmt.Errorf("build memory leaf table: %w", terr)
		}
		leafTable = table.Bytes()
		if leafTableSig, err = id.Sign(leafTable); err != nil {
			return nil, fmt.Errorf("sign memory leaf table: %w", err)
		}
	}

	prepared := &PreparedPod{
		Handle:         id.Handle,
		PodName:        spec.Pod.Name,
		PodVersion:     spec.Pod.Version,
		PodHash:        podHash,
		CanonicalBytes: canonBytes,
		Signature:      sig,
		PublicKeyHex:   id.PublicKeyHex,
		Visibility:     spec.Pod.Visibility,
		Spec:           spec,
		Warnings:       warnings,
		SealedGrants:   sealedState,

		MemoryLeafTable:          leafTable,
		MemoryLeafTableSignature: leafTableSig,
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

// memoryCommitInput builds the MemoryCommitInput for a --zk publish.
//
// Inputs: the parsed spec, the pod directory and the publish options.
// Output: nil for a memory-free pod, and also nil when memory-bearing
// publish is disabled or no salt source is configured — the resolver
// then refuses with COMMIT_MEMORY_RESOLUTION_UNAVAILABLE. Otherwise the
// input with the lineage salt, or the salt source's error.
func memoryCommitInput(spec *pod.Spec, podDir string, opts PrepareOptions) (*MemoryCommitInput, error) {
	if spec.Context == nil || len(spec.Context.Memory) == 0 || !memoryPublishEnabled || opts.MemorySalt == nil {
		return nil, nil
	}
	salt, err := opts.MemorySalt(spec)
	if err != nil {
		return nil, fmt.Errorf("lineage salt: %w", err)
	}
	return &MemoryCommitInput{PodDir: podDir, DisclosurePolicy: opts.DisclosurePolicy, Salt: salt}, nil
}

// canonicalizeZK picks the committed canonical version for a --zk publish
// and emits it.
//
// Inputs: the author's pod.toml bytes, the pod directory, the parsed spec
// and the derived commit params. Output: the canonical bytes, or a coded
// *canon.Error.
//
// A pod with no brokered MCP grant emits konareef-toml/v2, byte for byte
// as before konareef-toml/v3 existed, so an unchanged pod republishes to
// the same bytes and a reef-core that reads only v1/v2 still accepts it.
// A pod with a grant emits konareef-toml/v3, whose declared_tools also
// commits every "<mcp_name>.<tool>" id (canon.DeclaredToolsV3; MCP-Z00
// §10.2, D3 option A). A closed pod with a grant is refused with
// COMMIT_SEALED_GRANT_ZK_UNSUPPORTED: committing its tool inventory would
// expose it (MCP-Z00 §10.5), and the sealed-grant carrier (MCP-C00) is not
// approved (D8).
func canonicalizeZK(body []byte, podDir string, spec *pod.Spec, params canon.CommitParams) ([]byte, error) {
	if len(params.BrokerGrants) == 0 {
		return canon.CanonicalizeV2(body, podDir, params)
	}
	if spec.Pod.Visibility == VisibilityClosed {
		return nil, canon.NewError(canon.ErrCommitSealedGrantZKUnsupported,
			"a closed pod with a brokered MCP grant ([[network.gateway]] protocol = \"mcp\") cannot be "+
				"published with --zk: the commitment would publish its tool inventory, and sealed grants "+
				"are not supported for proofs yet (MCP-C00); publish without --zk")
	}
	return canon.CanonicalizeV3(body, podDir, params)
}

// prepareSealedCarrier applies the always-emit rule (owner decision
// D3 = a) before validation: a closed pod with neither the marker nor
// sealed/grants.toml gets both, on disk, so the marker no longer says
// whether the pod uses grants. It changes nothing when
// opts.SealedGrantsAlwaysEmit is off, for an open pod, or when either
// half of the carrier already exists (G1/G4 then judge the pod as
// authored). It also changes nothing for a head that fails validation or
// has a public protocol = "mcp" entry.
//
// Inputs: the pod root, the pod.toml bytes, and the options.
// Output: the state with Emitted set when files were written, or an
// error.
func prepareSealedCarrier(podDir string, body []byte, opts PrepareOptions) (SealedGrantsState, error) {
	var state SealedGrantsState
	if !opts.SealedGrantsAlwaysEmit {
		return state, nil
	}
	// Only a head that is valid as authored gets the carrier, and never
	// one with a public protocol = "mcp" entry, which G3 would then
	// refuse: the author's tree must not be left edited by a publish
	// that fails anyway.
	if issues, _, err := pod.ValidateWithWarnings(body); err != nil || len(issues) > 0 {
		return state, nil
	}
	spec, err := pod.Parse(body)
	if err != nil {
		return state, nil
	}
	if spec.Pod.Visibility != VisibilityClosed || pod.HasSealedGrantsMarker(spec) {
		return state, nil
	}
	if spec.Network != nil {
		for _, entry := range spec.Network.Gateway {
			if entry.Protocol == "mcp" {
				return state, nil
			}
		}
	}
	if _, present, err := readSealedGrantsFile(podDir); err != nil || present {
		return state, err
	}
	if _, err := InitSealedGrants(podDir); err != nil {
		return state, fmt.Errorf("add the sealed-grants carrier: %w", err)
	}
	state.Emitted = true
	return state, nil
}
