// Package feeder — WitnessWriter (C1 Phase-C, spec §3).
//
// WitnessWriter is the konareef sidecar's step, run before feeder.Run: it
// combines the reef-core-relayed step-disclosure.json (§2) with the
// installed, signed pod manifest's fields (never re-derived, never crossing
// the seam) to assemble a feeder.Witness, and writes it to witness.json for
// feeder.Run to consume unchanged.
//
// WriteWitness populates Witness.ToolLog from the seam's tool_log (Step 2):
// each record's tool_id/args_hash/result_hash/ts_us/sats maps into a
// ToolCallRecord. sats is the per-call price reef-core's broker recorded
// under the broker-priced-v1 tool_log_format, and 0 under unpriced-v1 (an
// absent label); see tool_log_format.go (MCP-Z02). An empty seam tool_log
// yields an empty (non-nil) ToolLog.
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
//
// Model is the bare model name. ModelID is the qualified
// "<provider>/<name>" ID reef-core added in reef-core#50; its presence
// marks that seam version, and it is omitted when empty so a legacy seam
// marshals to the legacy bytes. witnessModelID (model_identity.go) decides
// which one the witness uses.
//
// ToolLogFormat is the seam's tool_log_format label (MCP-Z00 §9). It is
// nil when the key is absent, which means unpriced-v1; a pointer keeps an
// absent key apart from an empty string, which is refused.
type StepDisclosure struct {
	Index   uint32           `json:"index"`
	P       []byte           `json:"p"`
	R       []byte           `json:"r"`
	C       uint64           `json:"c"`
	Model   string           `json:"model"`
	ModelID string           `json:"model_id,omitempty"`
	ToolLog []SeamToolRecord `json:"tool_log"`

	ToolLogFormat *string `json:"tool_log_format,omitempty"`

	// InitialMemory is the seam/2 initial_memory value (seam_memory.go).
	// It is kept raw here: ReadSeamMemory parses and checks it, and the
	// install loader compares it with the signed manifest before any
	// witness is written. WriteWitness does not read it.
	InitialMemory json.RawMessage `json:"initial_memory,omitempty"`
}

// SeamToolRecord is one tool record as disclosed by reef-core's
// step-disclosure.json `tool_log` (seam contract §2.2). args_hash/
// result_hash are base64-encoded 32-byte SHA-256 digests (encoding/json
// decodes a base64 string into []byte); ts_us is microseconds since the
// Unix epoch.
//
// Sats is the raw JSON value of the per-call price, nil when the key is
// absent. It stays raw so that absence, a non-integer literal and a
// negative value can each be refused by name (parseSeamSats) instead of
// being read as the Go zero value.
type SeamToolRecord struct {
	ToolID     string          `json:"tool_id"`
	ArgsHash   []byte          `json:"args_hash"`
	ResultHash []byte          `json:"result_hash"`
	TsUs       uint64          `json:"ts_us"`
	Sats       json.RawMessage `json:"sats,omitempty"`
}

// ManifestParams carries the fields sourced from the installed, signed pod
// manifest (spec §3.2) rather than the step-disclosure seam. SigManifest and
// PkPub come from the published, pre-signed manifest — no signing-key
// custody at the sidecar.
//
// RInit is the r_init the manifest commits, already bound to its
// fields_root by the loader (install.LoadManifestParams): E20 for a
// memory-free konareef-rinit/v1 manifest. MemoryCells (index → Poseidon
// value hash) is set only for a memory-bearing manifest whose cells the
// salt holder checked against RInit (install.LoadManifestParamsWithMemory);
// it is what the memory lane is built from.
type ManifestParams struct {
	Manifest    []byte
	Models      []string
	Tools       []string
	CMax        uint64
	SigManifest []byte
	PkPub       []byte
	RInit       [32]byte
	MemoryCells map[uint32][32]byte
}

// WriteWitness reads step-disclosure.json from seamPath, combines it with
// mp (the installed manifest's fields), and writes the resulting
// feeder.Witness as witness.json to outPath (spec §3).
//
// ToolLog is mapped from the seam's tool_log (empty when the pod made no
// recorded tool calls). Each record carries the seam's sats under
// broker-priced-v1 and 0 under unpriced-v1; Witness.ToolLogFormat records
// which. A duplicate or case-variant seam key, an unknown or inconsistent
// label, a missing, non-integer, negative or out-of-range sats, a missing
// or out-of-range ts_us, or a log longer than the proof capacity fails
// before outPath is written (tool_log_format.go).
//
// Model is the seam's qualified model_id, checked by witnessModelID
// against mp.Models. A missing, malformed, inconsistent or undeclared
// model_id fails before outPath is written.
//
// WriteWitness fails early — before writing outPath — if AssemblePodRecord
// would reject the assembled Witness, so a malformed SigManifest or PkPub is
// caught at witness-write time rather than surfacing later in feeder.Run.
func WriteWitness(seamPath string, mp ManifestParams, outPath string) error {
	raw, err := os.ReadFile(seamPath)
	if err != nil {
		return fmt.Errorf("feeder: witness_writer: read step-disclosure: %w", err)
	}
	// The strict key pre-pass runs first: the struct decode below would
	// silently resolve a duplicate or case-variant key (MCP-Z02).
	shape, err := scanSeamKeys(raw)
	if err != nil {
		return fmt.Errorf("feeder: witness_writer: parse step-disclosure: %w", err)
	}
	var sd StepDisclosure
	if err := json.Unmarshal(raw, &sd); err != nil {
		return fmt.Errorf("feeder: witness_writer: parse step-disclosure: %w", err)
	}

	format, err := resolveToolLogFormat(sd.ToolLogFormat)
	if err != nil {
		return fmt.Errorf("feeder: witness_writer: %w", err)
	}
	if err := requirePricedSeamFields(shape, format); err != nil {
		return fmt.Errorf("feeder: witness_writer: %w", err)
	}

	// Map the reef-core-disclosed tool_log into witness tool records. Order
	// is preserved (reef-core discloses per-call in call order); PS-1 and the
	// verifier fold the records in this order. sats is carried from the seam
	// unchanged; the feeder never computes a price.
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
		sats, err := parseSeamSats(t.Sats, format)
		if err != nil {
			return fmt.Errorf("feeder: witness_writer: tool_log[%d]: %w", i, err)
		}
		toolLog[i] = ToolCallRecord{
			Tool:    t.ToolID,
			InHash:  t.ArgsHash,
			OutHash: t.ResultHash,
			Ts:      t.TsUs,
			Sats:    sats,
		}
	}

	// The model gate (model_identity.go) owns the witness model. It refuses
	// a seam without a qualified model_id rather than using the bare model.
	model, err := witnessModelID(sd, mp.Models)
	if err != nil {
		return fmt.Errorf("feeder: witness_writer: %w", err)
	}

	// Memory lane (memory_lane.go): none for a memory-free manifest; built
	// from checked cells for a memory-bearing one; refused when the params
	// name a populated root without evidence. Fails before outPath exists.
	lane, err := memoryLaneFor(mp, sd.Index)
	if err != nil {
		return fmt.Errorf("feeder: witness_writer: %w", err)
	}

	w := Witness{
		Manifest:    mp.Manifest,
		P:           sd.P,
		R:           sd.R,
		Index:       sd.Index,
		C:           sd.C,
		CMax:        mp.CMax,
		Model:       model,
		Models:      mp.Models,
		Tools:       mp.Tools,
		ToolLog:     toolLog,
		SigManifest: mp.SigManifest,
		PkPub:       mp.PkPub,
		Memory:      lane,
	}
	w.ToolLogFormat = format

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
