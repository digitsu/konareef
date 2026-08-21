package feeder

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/digitsu/konareef/internal/tlog"
)

// PostArtifact POSTs the spec-§2 ingest body to reef-core's internal seam.
func PostArtifact(ctx context.Context, ingestURL, token string, scr *SpartanCompressResult, w Witness) error {
	// T_log_records are the canonical 113-B record bytes the verifier folds
	// into the Poseidon t_root; they MUST match what PS-1 committed (PS-1
	// re-derives the same encode_record from the wire tool_log). Order is
	// preserved (call order); CallIndex = i.
	tlogRecords := make([][]byte, 0, len(w.ToolLog))
	toolCalls := make([]map[string]any, 0, len(w.ToolLog))
	for i, tc := range w.ToolLog {
		var argsHash, resultHash [32]byte
		copy(argsHash[:], tc.InHash)
		copy(resultHash[:], tc.OutHash)
		tlogRecords = append(tlogRecords, tlog.RecordBytes(tlog.Row{
			ToolID:     tc.Tool,
			ArgsHash:   argsHash,
			ResultHash: resultHash,
			TS:         time.UnixMicro(int64(tc.Ts)), //nolint:gosec // ts_us fits in int64
			CallIndex:  uint32(i),                    //nolint:gosec // bounded by circuit tool cap
			Sats:       tc.Sats,
		}))
		toolCalls = append(toolCalls, map[string]any{
			"call_index": i, "tool": tc.Tool, "in_hash": tc.InHash, "out_hash": tc.OutHash, "ts": tc.Ts, "sats": tc.Sats,
		})
	}

	body, err := json.Marshal(map[string]any{
		"spartan_compress_result": map[string]any{
			"circuit_id":               scr.CircuitID,
			"spartan_snark":            scr.SpartanSnark,
			"first_step_public_inputs": scr.FirstStepPublicInputs,
			"last_step_public_inputs":  scr.LastStepPublicInputs,
			"vkey_hash":                scr.VkeyHash,
			"genesis_fields_root":      scr.GenesisFieldsRoot,
			"z0":                       scr.Z0,
			"vkey":                     scr.Vkey,
		},
		"witness_disclosure": map[string]any{
			"P": w.P, "R": w.R, "T_log_records": tlogRecords,
			"M_in": map[string]any{"leaves": []any{}}, "M_out": map[string]any{"leaves": []any{}},
		},
		"zk_stamp": map[string]any{
			// tool_log_root: spec §5 reef-core custody placeholder, NOT the
			// proof-bound Poseidon t_root — the verifier never compares this
			// field, so leave it zero. Do not "fix" it to a real hash.
			"tool_log_root": make([]byte, 32), "model_id": w.Model, "disclosure_policy": "C",
		},
		"tool_calls": toolCalls,
	})
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, ingestURL, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("feeder: ingest post: %w", err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK {
		return fmt.Errorf("feeder: ingest %d: %s", resp.StatusCode, string(raw))
	}
	return nil
}
