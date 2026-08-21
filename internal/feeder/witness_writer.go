// Package feeder — WitnessWriter (C1 Phase-C, spec §3).
//
// WitnessWriter is the konareef sidecar's step, run before feeder.Run: it
// combines the reef-core-relayed step-disclosure.json (§2) with the
// installed, signed pod manifest's fields (never re-derived, never crossing
// the seam) to assemble a feeder.Witness, and writes it to witness.json for
// feeder.Run to consume unchanged.
//
// WriteWitness populates Witness.ToolLog from the seam's tool_log (Step 2):
// each record's tool_id/args_hash/result_hash/ts_us maps into a
// ToolCallRecord with per-tool sats = 0 (reef-core discloses no per-tool
// sats; local tools like bash are free). An empty seam tool_log yields an
// empty (non-nil) ToolLog.
package feeder

import (
	"encoding/json"
	"fmt"
	"os"
)

// StepDisclosure is the seam file reef-core writes and the sidecar reads
// (spec §2.1). Only fields not re-derivable from the published/installed
// pod manifest cross the seam. Byte fields are raw bytes — encoding/json
// base64-encodes []byte on the wire, matching the feeder's existing
// convention (see witness.go's PodRecord doc comment).
type StepDisclosure struct {
	Index   uint32           `json:"index"`
	P       []byte           `json:"p"`
	R       []byte           `json:"r"`
	C       uint64           `json:"c"`
	Model   string           `json:"model"`
	ToolLog []SeamToolRecord `json:"tool_log"`
}

// SeamToolRecord is one tool record as disclosed by reef-core's
// step-disclosure.json `tool_log` (seam contract §2.2). args_hash/
// result_hash are base64-encoded 32-byte SHA-256 digests (encoding/json
// decodes a base64 string into []byte); ts_us is microseconds since the
// Unix epoch. reef-core does not disclose per-tool sats (local tools like
// bash are free), so the witness carries sats = 0.
type SeamToolRecord struct {
	ToolID     string `json:"tool_id"`
	ArgsHash   []byte `json:"args_hash"`
	ResultHash []byte `json:"result_hash"`
	TsUs       uint64 `json:"ts_us"`
}

// ManifestParams carries the fields sourced from the installed, signed pod
// manifest (spec §3.2) rather than the step-disclosure seam. SigManifest and
// PkPub come from the published, pre-signed manifest — no signing-key
// custody at the sidecar.
type ManifestParams struct {
	Manifest    []byte
	Models      []string
	Tools       []string
	CMax        uint64
	SigManifest []byte
	PkPub       []byte
}

// WriteWitness reads step-disclosure.json from seamPath, combines it with
// mp (the installed manifest's fields), and writes the resulting
// feeder.Witness as witness.json to outPath (spec §3).
//
// ToolLog is mapped from the seam's tool_log (empty when the pod made no
// recorded tool calls); each record carries sats = 0 (local tools are free).
//
// WriteWitness fails early — before writing outPath — if AssemblePodRecord
// would reject the assembled Witness, so a malformed SigManifest or PkPub is
// caught at witness-write time rather than surfacing later in feeder.Run.
func WriteWitness(seamPath string, mp ManifestParams, outPath string) error {
	raw, err := os.ReadFile(seamPath)
	if err != nil {
		return fmt.Errorf("feeder: witness_writer: read step-disclosure: %w", err)
	}
	var sd StepDisclosure
	if err := json.Unmarshal(raw, &sd); err != nil {
		return fmt.Errorf("feeder: witness_writer: parse step-disclosure: %w", err)
	}

	// Map the reef-core-disclosed tool_log into witness tool records. Order
	// is preserved (reef-core discloses per-call in call order); PS-1 and the
	// verifier fold the records in this order. Local tools carry sats = 0.
	toolLog := make([]ToolCallRecord, len(sd.ToolLog))
	for i, t := range sd.ToolLog {
		// Fail closed at the seam boundary: args_hash/result_hash MUST be
		// exactly 32-byte SHA-256 digests. Without this, the downstream
		// `copy(...[:], ...)` into a [32]byte in ingest.go would silently
		// zero-pad (<32) or truncate (>32), producing a wrong 113-B record
		// and a t_root that only fails opaquely far downstream. tool_id must
		// be non-empty, else the record commits SHA-256("") as tool_id_digest.
		if len(t.ArgsHash) != 32 || len(t.ResultHash) != 32 {
			return fmt.Errorf("feeder: witness_writer: tool_log[%d] hashes must be 32 bytes, got args=%d result=%d", i, len(t.ArgsHash), len(t.ResultHash))
		}
		if t.ToolID == "" {
			return fmt.Errorf("feeder: witness_writer: tool_log[%d] has empty tool_id", i)
		}
		toolLog[i] = ToolCallRecord{
			Tool:    t.ToolID,
			InHash:  t.ArgsHash,
			OutHash: t.ResultHash,
			Ts:      t.TsUs,
			Sats:    0,
		}
	}

	w := Witness{
		Manifest:    mp.Manifest,
		P:           sd.P,
		R:           sd.R,
		Index:       sd.Index,
		C:           sd.C,
		CMax:        mp.CMax,
		Model:       sd.Model,
		Models:      mp.Models,
		Tools:       mp.Tools,
		ToolLog:     toolLog,
		SigManifest: mp.SigManifest,
		PkPub:       mp.PkPub,
	}

	if _, err := AssemblePodRecord(w); err != nil {
		return fmt.Errorf("feeder: witness_writer: %w", err)
	}

	out, err := json.Marshal(w)
	if err != nil {
		return fmt.Errorf("feeder: witness_writer: marshal witness: %w", err)
	}
	if err := os.WriteFile(outPath, out, 0o644); err != nil {
		return fmt.Errorf("feeder: witness_writer: write witness: %w", err)
	}
	return nil
}
