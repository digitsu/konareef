// Copyright 2026 Jerry David Chan, Konareef.ai
// SPDX-License-Identifier: Apache-2.0

// Package verify — P1.2 deterministic CBOR decoder + BundleV2 typed
// shape per PRD 3 §§ 4-9.
//
// The decoder enforces RFC 8949 § 4.2 + PRD 3 § 3.1 rules where the
// fxamacker/cbor library supports them: shortest-form encoding,
// definite-length only, duplicate-key rejection (DupMapKeyEnforcedAPF),
// indefinite-length forbidden, and tags forbidden. Trailing-bytes
// rejection runs as an explicit guard in decodeBundleV2.
//
// PRD 3 § 14.1 forward-compat: unknown OPTIONAL keys MUST be silently
// ignored on decode. fxamacker/cbor's default behaviour is to drop
// unknown keys when decoding into a typed struct, so we deliberately
// do NOT set ExtraReturnErrors=ExtraDecErrorUnknownField. A negative
// test in cbor_test.go locks the behaviour in.
package verify

import (
	"bytes"
	"fmt"

	"github.com/fxamacker/cbor/v2"
)

// BundleV2 is the decoded top-level shape of konareef-bundle/v2. Only
// the fields P1.2 actively cross-checks are typed. Unknown optional
// keys are silently ignored on decode (PRD 3 § 14.1 forward-compat).
type BundleV2 struct {
	Version               string                `cbor:"version"`
	CircuitID             string                `cbor:"circuit_id"`
	Disclosure            string                `cbor:"disclosure"`
	SpartanCompressResult SpartanCompressResult `cbor:"spartan_compress_result"`
	Chain                 []ChainLinkV2         `cbor:"chain"`
	Vkey                  []byte                `cbor:"vkey,omitempty"`
	VkeyAnchor            map[string]any        `cbor:"vkey_anchor,omitempty"`
	PodHash               []byte                `cbor:"pod_hash,omitempty"`
	PodVersion            string                `cbor:"pod_version,omitempty"`
	PublisherID           string                `cbor:"publisher_id,omitempty"`
	PublisherSignature    []byte                `cbor:"publisher_signature,omitempty"`
	PublisherPubkey       []byte                `cbor:"publisher_pubkey,omitempty"`
	Manifest              []byte                `cbor:"manifest,omitempty"`
	// ChainPolicyMode is an optional declaration of the chain rule. It is
	// not a PRD 3 wire field: the disclosure tag selects the rule, and
	// checkChainPolicy refuses a declaration that disagrees (R2b).
	ChainPolicyMode string `cbor:"chain_policy_mode,omitempty"`
	// BsvTxids maps a chain link hash (lowercase hex) to its broadcast
	// txid (PRD 3 § 8.4). checkChainAnchors cross-references it against
	// the chain; it is not recomputed.
	BsvTxids          map[string]string  `cbor:"bsv_txids,omitempty"`
	WitnessDisclosure *WitnessDisclosure `cbor:"witness_disclosure,omitempty"`
	// ChainHeadAnchor is the optional chain-head anchor map (reef-core#76,
	// PRD 3 § 8.5). It is kept raw so checkChainHeadAnchor can refuse
	// unknown keys and wrong types inside it (anchor.go).
	ChainHeadAnchor cbor.RawMessage `cbor:"chain_head_anchor,omitempty"`
}

// SpartanCompressResult is the PRD 2 § 3.3 floor-field carrier.
//
// Z0 carries the full 23-lane genesis fold-IO vector (Z_ARITY = 23 post-CL-6,
// 23 × 32 B LE Fq = 736 bytes) required by the Rust SNARK verify subprocess.
// It is present in C0 bundles and consumed by Task 5's verify binary; the Go
// verifier does not inspect its contents beyond passing it through.
type SpartanCompressResult struct {
	SpartanSnark          []byte `cbor:"spartan_snark"`
	FirstStepPublicInputs []byte `cbor:"first_step_public_inputs"`
	LastStepPublicInputs  []byte `cbor:"last_step_public_inputs"`
	VkeyHash              []byte `cbor:"vkey_hash"`
	CircuitID             string `cbor:"circuit_id"`
	// PkPub is the publisher's 33-byte compressed secp256k1 public key,
	// carried out-of-circuit so Check 4 (§11.2) can run without an
	// attestation envelope. Optional/additive (CL-5a genesis_fields_root
	// precedent). Empty when a legacy/envelope-only producer omits it.
	PkPub []byte `cbor:"pk_pub,omitempty"`
	// Z0 carries the full 23-lane genesis fold-IO vector (Z_ARITY = 23 post-CL-6,
	// 23 × 32 B LE Fq = 736 bytes) required by the Rust SNARK verify subprocess.
	// Consumed by the verify binary; the Go verifier passes it through without
	// inspecting its contents.
	Z0 []byte `cbor:"z0,omitempty"`
	// GenesisFieldsRoot carries z0[Z_FIELDS_ROOT] — the genesis fold-IO
	// lane value (fq_to_le_bytes(witness.fields_root), 32-byte LE Fq). It
	// is the one datum the 298-byte X-assembly does NOT expose (PRD 1
	// §5.1: fields_root is a fold-IO lane, not a Spartan X slot), so the
	// out-of-circuit fields_root binding (CL-5(a)) needs it carried here.
	// Additive + forward-compatible: old artifacts without it decode fine
	// (the field stays nil and the v2-gated binding diverges fail-closed).
	GenesisFieldsRoot []byte `cbor:"genesis_fields_root,omitempty"`
}

// ChainLinkV2 is one commitment in the per-task proof chain (CBOR).
type ChainLinkV2 struct {
	ProofType string `cbor:"proof_type"`
	Hash      []byte `cbor:"hash"`
	PrevHash  []byte `cbor:"prev_hash,omitempty"`
	// Data is present in Type-C, ABSENT in Type-D.
	Data      []byte `cbor:"data,omitempty"`
	Scrubbed  bool   `cbor:"scrubbed"`
	Timestamp string `cbor:"timestamp"`
	Txid      string `cbor:"txid,omitempty"`
}

// WitnessDisclosure is the Type-C only payload per PRD 3 § 9.
type WitnessDisclosure struct {
	P           []byte        `cbor:"P"`
	R           []byte        `cbor:"R"`
	MIn         TouchedMemory `cbor:"M_in"`
	MOut        TouchedMemory `cbor:"M_out"`
	TLogRecords [][]byte      `cbor:"T_log_records"`
}

// TouchedMemory carries M_in/M_out leaves (PRD 3 § 9.2).
type TouchedMemory struct {
	Leaves []TouchedLeaf `cbor:"leaves"`
}

// TouchedLeaf is one leaf in a touched-memory tree.
type TouchedLeaf struct {
	Index     uint32   `cbor:"index"`
	ValueHash []byte   `cbor:"value_hash"`
	Value     []byte   `cbor:"value,omitempty"`
	Siblings  [][]byte `cbor:"siblings"`
}

// detDecMode is the deterministic-CBOR decode mode enforcing the
// RFC 8949 § 4.2 + PRD 3 § 3.1 rules supported by fxamacker/cbor.
//
// Forward-compat (PRD 3 § 14.1): unknown OPTIONAL keys are silently
// dropped when decoding into a typed struct — the default behaviour of
// the library. We do NOT set ExtraReturnErrors=ExtraDecErrorUnknownField.
var detDecMode cbor.DecMode

func init() {
	opts := cbor.DecOptions{
		DupMapKey:   cbor.DupMapKeyEnforcedAPF,
		IndefLength: cbor.IndefLengthForbidden,
		TagsMd:      cbor.TagsForbidden,
	}
	var err error
	detDecMode, err = opts.DecMode()
	if err != nil {
		panic(fmt.Sprintf("cbor det dec mode: %v", err))
	}
}

// DecodeBundleV2 decodes konareef-bundle/v2 CBOR bytes into a *BundleV2 for
// out-of-band inspection of the disclosed fields (e.g. the verdict demo server
// rendering the pod / publisher / tool-log evidence alongside the verdict). It
// performs the identical decode as the verify path but exposes the struct to
// other packages. It does NOT verify — callers must run VerifyV2Production for
// the trust verdict; this only reads what the bundle discloses.
func DecodeBundleV2(input []byte) (*BundleV2, error) { return decodeBundleV2(input) }

// decodeBundleV2 parses bytes into BundleV2, enforcing the
// deterministic-CBOR rules and rejecting empty / top-level-non-map /
// trailing-byte / non-canonical inputs.
func decodeBundleV2(input []byte) (*BundleV2, error) {
	if len(input) == 0 {
		return nil, fmt.Errorf("%w: empty input", ErrMalformedCBOR)
	}
	first := input[0]
	// Top-level MUST be a definite-length map head (0xA0..0xBB).
	if first < 0xA0 || first > 0xBB {
		return nil, fmt.Errorf("%w: top-level not a CBOR map (first byte 0x%02X)", ErrMalformedCBOR, first)
	}

	// Round-1 B3 fix: enforce RFC 8949 § 4.2 deterministic encoding rules
	// the fxamacker/cbor library does NOT enforce on decode — namely
	// shortest-form integer/length encodings and canonical (length-then-
	// lexicographic) map-key ordering. The library's DupMapKey /
	// IndefLength / TagsMd options cover only a subset of "core
	// deterministic" rules; a raw-bytes pass is required for the rest.
	if err := validateCanonicalCBOR(input); err != nil {
		return nil, err
	}

	// Trailing-bytes guard: decode raw, then assert reader consumed
	// everything by re-marshalling. The cleanest portable approach is
	// to use Decoder.NumBytesRead().
	var raw map[string]cbor.RawMessage
	dec := detDecMode.NewDecoder(bytes.NewReader(input))
	if err := dec.Decode(&raw); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrMalformedCBOR, err)
	}
	if dec.NumBytesRead() != len(input) {
		return nil, fmt.Errorf("%w: trailing bytes after top-level item", ErrMalformedCBOR)
	}

	// Version check (PRD 3 § 10.1 step 3i / 3ii).
	versionRaw, ok := raw["version"]
	if !ok {
		return nil, ErrUnknownVersion
	}
	var version string
	if err := detDecMode.Unmarshal(versionRaw, &version); err != nil {
		return nil, fmt.Errorf("%w: version is not a text string", ErrMalformedCBOR)
	}
	if version != "konareef-bundle/v2" {
		return nil, ErrUnknownVersion
	}

	// Re-decode into the typed struct. Unknown optional keys are
	// silently dropped (default fxamacker/cbor behaviour).
	var b BundleV2
	if err := detDecMode.Unmarshal(input, &b); err != nil {
		return nil, fmt.Errorf("%w: typed decode: %v", ErrMalformedCBOR, err)
	}
	return &b, nil
}
