// Copyright 2026 Jerry David Chan, Konareef.ai
// SPDX-License-Identifier: Apache-2.0

// Package feeder — tool-log format and per-call price rules (MCP-Z02,
// konareef#14; paygate-zk MCP-Z00 spec §5, §8, §9, §11).
//
// reef-core labels each step-disclosure seam with a tool_log_format:
//
//   - unpriced-v1 (also the meaning of an absent label): every record's
//     sats is 0 and makes no claim about spend. This is every seam from a
//     reef-core without MCP-Z01.
//   - broker-priced-v1: every tool_log entry carries sats, the authoritative
//     per-call price reef-core's broker recorded.
//
// This file holds the checks the feeder applies to a tool log:
//
//   - scanSeamKeys: a strict key pre-pass over the raw seam, which refuses
//     duplicate and case-variant keys that Go's decoder would otherwise
//     resolve silently, and a negative ts_us;
//   - resolveToolLogFormat, parseSeamSats, requirePricedSeamFields: the
//     label and the presence, JSON type and range of each sats value;
//   - validateWitnessToolLog: the label/sats consistency, sats and ts_us
//     ranges, and the proof capacity of an assembled Witness. It runs in
//     AssemblePodRecord, so it covers both WriteWitness and a witness.json
//     that feeder.Run reads back.
//
// Each refusal names its MCP-Z00 §11 code (or ERR_SEAM_KEY /
// ERR_SEAM_FIELD_MISSING for seam shape) in the error text. The feeder
// carries the price; it never computes or changes it.
package feeder

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
)

// Tool-log format labels (MCP-Z00 §9.1).
const (
	ToolLogFormatUnpriced = "unpriced-v1"
	ToolLogFormatPriced   = "broker-priced-v1"
)

// Bounds from MCP-Z00 §5 and §8.
const (
	// satsMax is the largest accepted sats value, 2^63 − 1. reef-core stores
	// sats in a Postgres bigint, so larger u64 values are refused.
	satsMax uint64 = 1<<63 - 1
	// tsUsMax is 9999-12-31T23:59:59.999999Z in Unix microseconds, the
	// largest timestamp every implementation round-trips.
	tsUsMax uint64 = 253402300799999999
	// maxProofToolLog is the effective proof capacity,
	// min(PS-1 MAX_TOOL_LOG = 4, circuit MAX_TLOG_RECORDS = 16). A longer
	// log is proof-ineligible; the feeder never proves a prefix of it.
	maxProofToolLog = 4
	// maxErrLiteral caps how much of a refused raw value an error repeats.
	maxErrLiteral = 64
)

// seamTopKeys and seamEntryKeys are the step-disclosure field names
// (json tags of StepDisclosure and SeamToolRecord). scanSeamKeys refuses a
// key that matches one of these only without regard to case.
var (
	seamTopKeys   = []string{"index", "p", "r", "c", "model", "model_id", "tool_log", "tool_log_format", "initial_memory"}
	seamEntryKeys = []string{"tool_id", "args_hash", "result_hash", "ts_us", "sats"}
)

// seamShape is what scanSeamKeys learns about a raw seam that the struct
// decode loses: whether tool_log is a JSON array, and which keys each
// tool_log entry has.
type seamShape struct {
	toolLogIsArray bool
	entryKeys      []map[string]json.RawMessage
}

// scanSeamKeys is the strict key pre-pass over a raw step-disclosure body.
// Go's encoding/json keeps the last of duplicate keys and matches keys
// without regard to case, so `"sats":250,"sats":0` or `"SATS":0` would
// otherwise change the price read. Input: the raw seam bytes. Output: the
// seam's shape, or an error: ERR_SEAM_KEY for a duplicate key or a
// case variant of a known key (top level or in a tool_log entry),
// ERR_TS_OUT_OF_RANGE for a negative ts_us, or a JSON syntax error.
// Unknown keys in their exact case are allowed, for forward compatibility.
func scanSeamKeys(raw []byte) (seamShape, error) {
	top, err := scanObjectKeys(raw, seamTopKeys, "step-disclosure")
	if err != nil {
		return seamShape{}, err
	}
	var shape seamShape
	logRaw := bytes.TrimSpace(top["tool_log"])
	if len(logRaw) == 0 || logRaw[0] != '[' {
		return shape, nil
	}
	shape.toolLogIsArray = true
	var entries []json.RawMessage
	if err := json.Unmarshal(logRaw, &entries); err != nil {
		return seamShape{}, err
	}
	for i, e := range entries {
		e = bytes.TrimSpace(e)
		if len(e) == 0 || e[0] != '{' {
			// Not an object: the struct decode refuses it.
			shape.entryKeys = append(shape.entryKeys, nil)
			continue
		}
		keys, err := scanObjectKeys(e, seamEntryKeys, fmt.Sprintf("tool_log[%d]", i))
		if err != nil {
			return seamShape{}, err
		}
		if ts := bytes.TrimSpace(keys["ts_us"]); len(ts) > 0 && ts[0] == '-' {
			return seamShape{}, fmt.Errorf("ERR_TS_OUT_OF_RANGE: tool_log[%d] ts_us %s is negative", i, clipLiteral(ts))
		}
		shape.entryKeys = append(shape.entryKeys, keys)
	}
	return shape, nil
}

// scanObjectKeys reads one JSON object's keys in order. Inputs: the raw
// object, the known field names, and a location for error text. Output:
// each key's raw value, or an ERR_SEAM_KEY error for a repeated key or a
// key that equals a known name only without regard to case.
func scanObjectKeys(raw []byte, known []string, where string) (map[string]json.RawMessage, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	tok, err := dec.Token()
	if err != nil {
		return nil, err
	}
	if d, ok := tok.(json.Delim); !ok || d != '{' {
		return nil, fmt.Errorf("%s is not a JSON object", where)
	}
	out := map[string]json.RawMessage{}
	for dec.More() {
		tok, err := dec.Token()
		if err != nil {
			return nil, err
		}
		key, _ := tok.(string)
		if _, dup := out[key]; dup {
			return nil, fmt.Errorf("ERR_SEAM_KEY: %s has duplicate key %q", where, clipLiteral([]byte(key)))
		}
		for _, k := range known {
			if key != k && strings.EqualFold(key, k) {
				return nil, fmt.Errorf("ERR_SEAM_KEY: %s key %q differs from %q only in case", where, clipLiteral([]byte(key)), k)
			}
		}
		var v json.RawMessage
		if err := dec.Decode(&v); err != nil {
			return nil, err
		}
		out[key] = v
	}
	return out, nil
}

// requirePricedSeamFields refuses a broker-priced-v1 seam whose tool_log is
// absent or not an array, or whose entry has no ts_us. The struct decode
// would read either as a zero value. Inputs: the scanned shape and the
// resolved format. Output: nil, or an ERR_SEAM_FIELD_MISSING error.
// (A missing sats is refused by parseSeamSats as ERR_SATS_MISSING; a
// missing tool_id or hash by WriteWitness's existing checks.)
func requirePricedSeamFields(shape seamShape, format string) error {
	if format != ToolLogFormatPriced {
		return nil
	}
	if !shape.toolLogIsArray {
		return fmt.Errorf("ERR_SEAM_FIELD_MISSING: tool_log must be an array under %s", ToolLogFormatPriced)
	}
	for i, keys := range shape.entryKeys {
		if _, ok := keys["ts_us"]; !ok {
			return fmt.Errorf("ERR_SEAM_FIELD_MISSING: tool_log[%d] has no ts_us under %s", i, ToolLogFormatPriced)
		}
	}
	return nil
}

// clipLiteral shortens a raw value for error text to maxErrLiteral bytes.
func clipLiteral(b []byte) string {
	if len(b) > maxErrLiteral {
		return string(b[:maxErrLiteral]) + "..."
	}
	return string(b)
}

// resolveToolLogFormat returns the seam's tool-log format. Input: the
// seam's tool_log_format, nil when the key is absent. Output: the label,
// with an absent key read as unpriced-v1, or an ERR_TOOL_LOG_FORMAT error
// for any other value (including an empty string).
func resolveToolLogFormat(label *string) (string, error) {
	if label == nil {
		return ToolLogFormatUnpriced, nil
	}
	switch *label {
	case ToolLogFormatUnpriced, ToolLogFormatPriced:
		return *label, nil
	default:
		return "", fmt.Errorf("ERR_TOOL_LOG_FORMAT: unknown tool_log_format %q", clipLiteral([]byte(*label)))
	}
}

// parseSeamSats decodes one tool_log entry's sats under format. Input:
// the raw JSON value of the sats key (nil when the key is absent) and the
// resolved format. Output: the price, or an error naming the refusal code:
//
//   - broker-priced-v1 with no sats key: ERR_SATS_MISSING (absence is
//     never read as 0);
//   - a value that is not a JSON integer literal (float, exponent, string,
//     boolean, null): ERR_SATS_TYPE;
//   - a negative value or one above 2^63 − 1: ERR_SATS_OUT_OF_RANGE;
//   - unpriced-v1 with a nonzero sats: ERR_TOOL_LOG_FORMAT, because a
//     price under the unpriced label would otherwise be dropped silently.
//
// Under unpriced-v1 an absent sats key or sats = 0 yields 0.
func parseSeamSats(raw json.RawMessage, format string) (uint64, error) {
	if raw == nil {
		if format == ToolLogFormatPriced {
			return 0, fmt.Errorf("ERR_SATS_MISSING: sats is required under %s", ToolLogFormatPriced)
		}
		return 0, nil
	}
	lit := bytes.TrimSpace(raw)
	if !isJSONIntegerLiteral(lit) {
		return 0, fmt.Errorf("ERR_SATS_TYPE: sats must be a JSON integer, got %s", clipLiteral(lit))
	}
	if lit[0] == '-' {
		return 0, fmt.Errorf("ERR_SATS_OUT_OF_RANGE: sats %s is negative", clipLiteral(lit))
	}
	sats, err := strconv.ParseUint(string(lit), 10, 64)
	if err != nil || sats > satsMax {
		return 0, fmt.Errorf("ERR_SATS_OUT_OF_RANGE: sats %s exceeds %d", clipLiteral(lit), satsMax)
	}
	if format == ToolLogFormatUnpriced && sats != 0 {
		return 0, fmt.Errorf("ERR_TOOL_LOG_FORMAT: sats %d under %s (a priced record needs %s)", sats, ToolLogFormatUnpriced, ToolLogFormatPriced)
	}
	return sats, nil
}

// isJSONIntegerLiteral reports whether lit is a JSON number with no
// fraction and no exponent: an optional '-' followed by one or more
// digits. Input: a trimmed JSON value. Output: true for an integer literal.
func isJSONIntegerLiteral(lit []byte) bool {
	digits := lit
	if len(digits) > 0 && digits[0] == '-' {
		digits = digits[1:]
	}
	if len(digits) == 0 {
		return false
	}
	for _, b := range digits {
		if b < '0' || b > '9' {
			return false
		}
	}
	return true
}

// validateWitnessToolLog checks an assembled Witness's tool log. Input:
// the witness. Output: nil, or an error naming the code:
//
//   - ERR_TOOL_LOG_FORMAT: a label other than unpriced-v1, broker-priced-v1
//     or "" (a witness.json written before MCP-Z02, read as unpriced-v1),
//     or a nonzero sats under unpriced-v1;
//   - ERR_TLOG_OVER_CAPACITY: more records than the proof capacity (the
//     custody log in reef-core stays complete; only no proof is made);
//   - ERR_SATS_OUT_OF_RANGE: sats above 2^63 − 1;
//   - ERR_TS_OUT_OF_RANGE: ts above 9999-12-31T23:59:59.999999Z (which
//     also keeps the int64 cast in PostArtifact from wrapping).
//
// AssemblePodRecord runs it, so both WriteWitness and feeder.Run, which
// reads witness.json back from disk, refuse before PS-1 or ingest.
func validateWitnessToolLog(w Witness) error {
	priced := false
	switch w.ToolLogFormat {
	case "", ToolLogFormatUnpriced:
	case ToolLogFormatPriced:
		priced = true
	default:
		return fmt.Errorf("ERR_TOOL_LOG_FORMAT: unknown tool_log_format %q", clipLiteral([]byte(w.ToolLogFormat)))
	}
	if len(w.ToolLog) > maxProofToolLog {
		return fmt.Errorf("ERR_TLOG_OVER_CAPACITY: tool_log has %d records, proof capacity is %d", len(w.ToolLog), maxProofToolLog)
	}
	for i, tc := range w.ToolLog {
		if tc.Sats > satsMax {
			return fmt.Errorf("ERR_SATS_OUT_OF_RANGE: tool_log[%d] sats %d exceeds %d", i, tc.Sats, satsMax)
		}
		if !priced && tc.Sats != 0 {
			return fmt.Errorf("ERR_TOOL_LOG_FORMAT: tool_log[%d] sats %d under %s", i, tc.Sats, ToolLogFormatUnpriced)
		}
		if tc.Ts > tsUsMax {
			return fmt.Errorf("ERR_TS_OUT_OF_RANGE: tool_log[%d] ts_us %d exceeds %d", i, tc.Ts, tsUsMax)
		}
	}
	return nil
}
