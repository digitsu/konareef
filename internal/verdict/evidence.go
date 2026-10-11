// Copyright 2026 Jerry David Chan, Konareef.ai
// SPDX-License-Identifier: Apache-2.0

// Package verdict serves a live, public-facing rendering of a KonaReef
// Type-C proof: it fetches a konareef-bundle/v2, runs the REAL verifier
// (verify.VerifyV2Production + the Rust `verify` subprocess), decodes the
// disclosed evidence, and serves a single self-contained page that shows the
// six verification checks resolving to a verdict.
//
// evidence.go maps a decoded bundle + verdict into the Evidence JSON the page
// consumes. Every field is derived from the real bundle bytes and the real
// verifier output — nothing is synthesised.
package verdict

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"unicode/utf8"

	"github.com/digitsu/konareef/internal/pod"
	"github.com/digitsu/konareef/internal/verify"
)

// First-step public-input byte offsets (verify snark.go / PRD 3). The buffer is
// 298 bytes: eight 32-byte lanes at 0..255 then the 74-byte sig_manifest lane.
const (
	piRIn        = 0
	piROut       = 32
	piTRoot      = 64
	piHP         = 96
	piHR         = 128
	piHManifest  = 160
	piChainHead  = 192
	piSigManOff  = 224
	piLaneLen    = 32
	toolRecordLn = 113 // 0x20 | digest(32) | args(32) | result(32) | ts_us BE(8) | sats BE(8)
	// toolRecordMarker is the canonical leading tag byte on every 113-B
	// tool-log record. A record whose first byte differs is not a record we
	// committed to and must not be decoded into presented fields.
	toolRecordMarker = 0x20
)

// Evidence is the JSON payload the verdict page renders. It pairs the real
// verifier verdict with the bundle's disclosed fields.
type Evidence struct {
	OK          bool            `json:"ok"`
	Verdict     *verify.Verdict `json:"verdict"`
	Divergences []string        `json:"divergences"`
	Meta        Meta            `json:"meta"`
	Pod         PodInfo         `json:"pod"`
	Publisher   PublisherInfo   `json:"publisher"`
	Execution   Execution       `json:"execution"`
	Proof       ProofInfo       `json:"proof"`
	Commitments Commitments     `json:"commitments"`
	Chain       []ChainLink     `json:"chain"`
}

// Meta identifies which proof this verdict is for and where it came from.
type Meta struct {
	ProofHash   string `json:"proof_hash"`
	Version     string `json:"version"`
	SourceLabel string `json:"source_label"`
}

// PodInfo is the identity of the pod that produced the proof.
type PodInfo struct {
	Name       string `json:"name"`
	Version    string `json:"version"`
	Circuit    string `json:"circuit"`
	Disclosure string `json:"disclosure"`
	PodHash    string `json:"pod_hash"`
}

// PublisherInfo is the publisher-binding evidence.
type PublisherInfo struct {
	ID        string `json:"id"`
	Pubkey    string `json:"pubkey"`
	Signature string `json:"signature"`
	Curve     string `json:"curve"`
}

// Execution is the disclosed step trace: input commitment P, response R, and
// the tool-log records.
type Execution struct {
	P     string     `json:"p"`
	R     string     `json:"r"`
	Tools []ToolCall `json:"tools"`
}

// ToolCall is one 113-byte tool-log record, decoded. Name is resolved from the
// manifest's declared tools when SHA-256(name) matches the committed digest.
type ToolCall struct {
	Name       string `json:"name"`
	IDDigest   string `json:"id_digest"`
	ArgsHash   string `json:"args_hash"`
	ResultHash string `json:"result_hash"`
	TsUs       uint64 `json:"ts_us"`
	Sats       uint64 `json:"sats"`
}

// ProofInfo describes the Spartan proof artifact.
type ProofInfo struct {
	Scheme        string `json:"scheme"`
	SnarkBytes    int    `json:"snark_bytes"`
	Z0Bytes       int    `json:"z0_bytes"`
	ManifestBytes int    `json:"manifest_bytes"`
	VkeyHash      string `json:"vkey_hash"`
}

// Commitments are the bound public inputs surfaced for display.
type Commitments struct {
	TRoot string `json:"t_root"`
	RIn   string `json:"r_in"`
	ROut  string `json:"r_out"`
}

// ChainLink is one custody-chain entry.
type ChainLink struct {
	Type string `json:"type"`
	Hash string `json:"hash"`
	Ts   string `json:"ts"`
}

// BuildEvidence maps a decoded bundle + verifier result into the page's
// Evidence JSON. proofHash/sourceLabel are display-only provenance.
func BuildEvidence(b *verify.BundleV2, r *verify.ResultV2, proofHash, sourceLabel string) Evidence {
	ev := Evidence{
		OK:          r.OK,
		Verdict:     r.V2Verdict,
		Divergences: divergenceMessages(r),
		Meta:        Meta{ProofHash: proofHash, Version: b.Version, SourceLabel: sourceLabel},
		Pod: PodInfo{
			Name:       podNameFromManifest(b.Manifest),
			Version:    b.PodVersion,
			Circuit:    b.CircuitID,
			Disclosure: b.Disclosure,
			PodHash:    hex.EncodeToString(b.PodHash),
		},
		Publisher: PublisherInfo{
			ID:        b.PublisherID,
			Pubkey:    hex.EncodeToString(b.PublisherPubkey),
			Signature: hex.EncodeToString(b.PublisherSignature),
			Curve:     "secp256k1",
		},
		Proof: ProofInfo{
			Scheme:        "Spartan SNARK",
			SnarkBytes:    len(b.SpartanCompressResult.SpartanSnark),
			Z0Bytes:       len(b.SpartanCompressResult.Z0),
			ManifestBytes: len(b.Manifest),
			VkeyHash:      hex.EncodeToString(b.SpartanCompressResult.VkeyHash),
		},
	}

	// Execution trace + tool-log records.
	if wd := b.WitnessDisclosure; wd != nil {
		ev.Execution.P = asText(wd.P)
		ev.Execution.R = asText(wd.R)
		names := declaredToolDigests(b.Manifest)
		for _, rec := range wd.TLogRecords {
			ev.Execution.Tools = append(ev.Execution.Tools, decodeToolRecord(rec, names))
		}
	}
	if ev.Execution.Tools == nil {
		ev.Execution.Tools = []ToolCall{}
	}

	// Bound public inputs.
	pi := b.SpartanCompressResult.FirstStepPublicInputs
	ev.Commitments = Commitments{
		TRoot: lane(pi, piTRoot),
		RIn:   lane(pi, piRIn),
		ROut:  lane(pi, piROut),
	}

	// Custody chain.
	for _, c := range b.Chain {
		ev.Chain = append(ev.Chain, ChainLink{
			Type: c.ProofType,
			Hash: hex.EncodeToString(c.Hash),
			Ts:   c.Timestamp,
		})
	}
	if ev.Chain == nil {
		ev.Chain = []ChainLink{}
	}
	return ev
}

// lane returns the hex of the 32-byte public-input lane at offset off, or ""
// if the buffer is too short (fail-soft: display only).
func lane(pi []byte, off int) string {
	if len(pi) < off+piLaneLen {
		return ""
	}
	return hex.EncodeToString(pi[off : off+piLaneLen])
}

// decodeToolRecord parses one 113-byte tool-log record and resolves its
// tool_id digest back to a declared tool name when possible.
func decodeToolRecord(rec []byte, names map[string]string) ToolCall {
	// Fail closed: a committed tool-log record must be EXACTLY 113 bytes and
	// carry the canonical 0x20 marker. Short, long, or wrong-prefix bytes are
	// surfaced as malformed rather than sliced into fields the verdict card
	// would present as committed facts. (len is checked first so rec[0] is
	// only read when the length is known-good.)
	if len(rec) != toolRecordLn || rec[0] != toolRecordMarker {
		return ToolCall{Name: "malformed", IDDigest: hex.EncodeToString(rec)}
	}
	digest := hex.EncodeToString(rec[1:33])
	tc := ToolCall{
		Name:       names[digest], // "" if unresolved
		IDDigest:   digest,
		ArgsHash:   hex.EncodeToString(rec[33:65]),
		ResultHash: hex.EncodeToString(rec[65:97]),
		TsUs:       binary.BigEndian.Uint64(rec[97:105]),
		Sats:       binary.BigEndian.Uint64(rec[105:113]),
	}
	if tc.Name == "" {
		tc.Name = "tool"
	}
	return tc
}

// declaredToolDigests builds a digest→name map from the manifest's declared
// context.tools, so a committed SHA-256(tool_id) can be labelled with the human
// tool name. A demo point: the opaque digest resolves to a declared tool.
func declaredToolDigests(manifest []byte) map[string]string {
	out := map[string]string{}
	spec, err := pod.Parse(manifest)
	if err != nil || spec.Context == nil {
		return out
	}
	for _, t := range spec.Context.Tools {
		if t.Source == "" {
			continue
		}
		sum := sha256.Sum256([]byte(t.Source))
		out[hex.EncodeToString(sum[:])] = t.Source
	}
	return out
}

// podNameFromManifest reads [pod].name (falling back to "") for display.
func podNameFromManifest(manifest []byte) string {
	spec, err := pod.Parse(manifest)
	if err != nil {
		return ""
	}
	return spec.Pod.Name
}

// asText renders disclosed bytes as UTF-8 text when valid, else as hex, so the
// P/R commitments display readably without assuming they are strings.
func asText(b []byte) string {
	if utf8.Valid(b) {
		return string(b)
	}
	return hex.EncodeToString(b)
}

// divergenceMessages flattens the verifier's divergences to display strings.
func divergenceMessages(r *verify.ResultV2) []string {
	out := make([]string, 0, len(r.Divergences))
	for _, d := range r.Divergences {
		out = append(out, d.Msg)
	}
	return out
}
