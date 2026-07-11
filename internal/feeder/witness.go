// Package feeder is the konareef Pod-Trust-Domain sidecar: it reads the
// relayed step data, assembles the PS-1 PodRecord, calls the prover, and
// POSTs the artifact to reef-core. It is the witness-of-record; reef-core
// never assembles a PodRecord.
package feeder

import (
	"fmt"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
)

// ToolCallRecord is one tool invocation in the disclosed T_log. The JSON
// shape matches paygate-zk's PS-1 wire ToolCallRecord (wire.rs): the tool
// NAME (PS-1 computes tool_id_digest = SHA-256(name) itself), the two
// base64 32-byte hashes, ts (u64 microseconds), and sats (0 for
// unpaid/local tools like bash; the circuit binds Σ sats ≤ c).
type ToolCallRecord struct {
	Tool    string `json:"tool"`
	InHash  []byte `json:"in_hash"`
	OutHash []byte `json:"out_hash"`
	Ts      uint64 `json:"ts"`
	Sats    uint64 `json:"sats"`
}

// Witness is the disclosed step data reef-core relays into the PTD
// workspace (spec §2/§4). For Type C every field is publicly re-derivable.
type Witness struct {
	Manifest    []byte           `json:"manifest"`
	P           []byte           `json:"p"`
	R           []byte           `json:"r"`
	Index       uint32           `json:"index"`
	C           uint64           `json:"c"`
	CMax        uint64           `json:"c_max"`
	Model       string           `json:"model"`
	Models      []string         `json:"models"`
	Tools       []string         `json:"tools"`
	ToolLog     []ToolCallRecord `json:"tool_log"`
	SigManifest []byte           `json:"sig_manifest"`
	PkPub       []byte           `json:"pk_pub"`
}

// PodRecord mirrors paygate-zk crates/paygate-zk-prove/src/wire.rs, whose
// byte fields (manifest, p, r, sig_manifest, pk_pub) are declared as Rust
// `String` holding base64. Wire compatibility relies on Go encoding/json
// emitting a []byte field as a base64 string: callers MUST set these fields
// to raw, un-encoded bytes — never to a pre-encoded base64 string — or the
// JSON would double-encode and the Rust side would fail to decode.
type PodRecord struct {
	Manifest    []byte           `json:"manifest"`
	P           []byte           `json:"p"`
	R           []byte           `json:"r"`
	Index       uint32           `json:"index"`
	C           uint64           `json:"c"`
	CMax        uint64           `json:"c_max"`
	Model       string           `json:"model"`
	Models      []string         `json:"models"`
	Tools       []string         `json:"tools"`
	ToolLog     []ToolCallRecord `json:"tool_log"`
	SigManifest []byte           `json:"sig_manifest"`
	PkPub       []byte           `json:"pk_pub"`
}

// sigManifestLaneLen is the fixed width of the PS-1/verifier sig_manifest
// lane: [derLen(1)][DER][zero pad] (see install.LoadManifestParams and
// internal/verify snark.go). A strict-DER secp256k1 low-S signature is
// ~70-72 B, so the DER always fits and the lane is always zero-padded to 74.
const sigManifestLaneLen = 74

// AssemblePodRecord builds the fixed PS-1 wire contract from relayed data.
// sig_manifest/pk_pub come from the published, pre-signed manifest — no
// signing-key custody at the feeder.
//
// It is the fail-closed producer gate: a malformed sig_manifest lane or a
// structurally invalid publisher pubkey is rejected HERE, before the witness
// is written / sent to PS-1, rather than surfacing as an opaque prover or
// verifier failure downstream.
func AssemblePodRecord(w Witness) (PodRecord, error) {
	if err := validateSigManifestLane(w.SigManifest); err != nil {
		return PodRecord{}, err
	}
	if err := validatePkPub(w.PkPub); err != nil {
		return PodRecord{}, err
	}
	return PodRecord{
		Manifest: w.Manifest, P: w.P, R: w.R, Index: w.Index, C: w.C, CMax: w.CMax,
		Model: w.Model, Models: w.Models, Tools: w.Tools, ToolLog: w.ToolLog,
		SigManifest: w.SigManifest, PkPub: w.PkPub,
	}, nil
}

// validateSigManifestLane enforces the fixed 74-byte PS-1/verifier lane
// contract [derLen(1)][DER][zero pad]: exactly 74 bytes, a DER-length prefix
// in [1,73] (at least one DER byte, and the DER plus its 1-byte prefix cannot
// overflow the lane), and every byte past the DER region zero. Without this,
// an all-zero or short-DER lane would pass the feeder seam and only fail
// opaquely inside PS-1 / the verifier's signature check.
func validateSigManifestLane(sig []byte) error {
	if len(sig) != sigManifestLaneLen {
		return fmt.Errorf("feeder: sig_manifest must be %d bytes, got %d", sigManifestLaneLen, len(sig))
	}
	derLen := int(sig[0])
	if derLen < 1 || derLen > sigManifestLaneLen-1 {
		return fmt.Errorf("feeder: sig_manifest derLen=%d out of range [1,%d]", derLen, sigManifestLaneLen-1)
	}
	for i := 1 + derLen; i < sigManifestLaneLen; i++ {
		if sig[i] != 0 {
			return fmt.Errorf("feeder: sig_manifest padding byte %d is 0x%02x, want 0x00", i, sig[i])
		}
	}
	return nil
}

// validatePkPub requires a structurally valid 33-byte compressed secp256k1
// public key — the SAME gate the verifier applies in its §11.2 Check-4
// (internal/identity signing.go uses secp256k1.ParsePubKey). ParsePubKey
// enforces the 0x02/0x03 prefix and on-curve validity, so a 33-byte-but-bogus
// carrier (wrong prefix, off-curve) is rejected at the producer seam rather
// than crossing to PS-1/reef-core and failing later as a signature divergence.
func validatePkPub(pk []byte) error {
	if len(pk) != 33 {
		return fmt.Errorf("feeder: pk_pub must be 33 bytes, got %d", len(pk))
	}
	if _, err := secp256k1.ParsePubKey(pk); err != nil {
		return fmt.Errorf("feeder: pk_pub is not a valid compressed secp256k1 public key: %w", err)
	}
	return nil
}
