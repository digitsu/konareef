// Copyright 2026 Jerry David Chan, Konareef.ai
// SPDX-License-Identifier: Apache-2.0

// internal/ws/llm.go
//
// The client side of reef-core's `agent_llm` event, version 1 (reef-core
// P3-08, `ReefCore.Llm.Event`). One event is sent for each LLM call of a
// run under LLM custody: a settled call (its `sats` are the charge), a
// released reserve (`settle_basis: "unsent"`, 0 sats) or a refused call
// (`refused: true`, no `call_id`, 0 sats).
//
// reef-core sends the same map on two pushes: `agent_llm` on pod:events
// (with `agent_id`) and `llm` on agent:<id>. The GET /api/agents/:id/log
// entry has the same keys with `id` in place of `agent_id`.
//
// Consumer rules this file serves (P3-08 spec §3):
//   - `call_id` is the deduplication key; a replay counts once.
//   - `over_budget_sats` is cumulative; never add two values.
//   - Under custody the LLM spend is on `agent_llm.sats` only, so a client
//     that sums `agent_cost` and `agent_llm` counts every sat once.
//
// Public surface:
//   - LLMEventVersion — the schema version this client understands
//   - LLMEvent, QuarantinedEntry — the typed payload (nullable fields are pointers)
//   - ParseLLMEvent — decodes a push or log payload
//   - LLMEvent.Supported / Countable / ChargeSats / Describe
package ws

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
)

// LLMEventVersion is the only `agent_llm` schema version this client reads.
// An event with another `v` is shown as unsupported and never counted.
const LLMEventVersion = 1

// QuarantinedEntry is the price-table entry a pricing mismatch quarantined.
type QuarantinedEntry struct {
	Provider      string `json:"provider"`
	RequestModel  string `json:"request_model"`
	EntrySHA256   string `json:"entry_sha256"`
	ResponseModel string `json:"response_model"`
}

// LLMEvent is one `agent_llm` payload. A pointer field is nil when the
// server sent JSON null (or left the key out). Keys the client does not
// know are ignored, so a later server can add fields without breaking it.
type LLMEvent struct {
	V                        int               `json:"v"`
	AgentID                  string            `json:"agent_id"`
	ID                       string            `json:"id"` // log form of agent_id
	CallID                   *string           `json:"call_id"`
	Model                    *string           `json:"model"`
	ResponseModel            *string           `json:"response_model"`
	Status                   *int              `json:"status"`
	Streamed                 *bool             `json:"streamed"`
	Refused                  bool              `json:"refused"`
	Reason                   *string           `json:"reason"`
	InputTokens              *int64            `json:"input_tokens"`
	OutputTokens             *int64            `json:"output_tokens"`
	CacheCreationInputTokens *int64            `json:"cache_creation_input_tokens"`
	CacheReadInputTokens     *int64            `json:"cache_read_input_tokens"`
	ImageCount               *int64            `json:"image_count"`
	ImageTokenBound          *int64            `json:"image_token_bound"`
	Sats                     int64             `json:"sats"`
	ReserveSats              *int64            `json:"reserve_sats"`
	PriceBasis               *string           `json:"price_basis"`
	SettleBasis              *string           `json:"settle_basis"`
	OverBudgetSats           *int64            `json:"over_budget_sats"`
	QuarantinedEntry         *QuarantinedEntry `json:"quarantined_entry"`
	HarnessKeySignal         *bool             `json:"harness_key_signal"`
	DurationMS               *int64            `json:"duration_ms"`

	// unreadable is set by the dispatcher when the payload failed to parse,
	// so Describe renders a fixed line.
	unreadable bool
}

// ParseLLMEvent decodes an `agent_llm` payload (a push, or a log entry's
// payload) into an LLMEvent.
//
// Input: payload, the JSON object as decoded into a map.
// Output: the event; an error when a known key has the wrong JSON type.
// When `agent_id` is absent the log form `id` fills AgentID.
func ParseLLMEvent(payload map[string]any) (LLMEvent, error) {
	var ev LLMEvent
	raw, err := json.Marshal(payload)
	if err != nil {
		return LLMEvent{unreadable: true}, fmt.Errorf("agent_llm: %w", err)
	}
	if err := json.Unmarshal(raw, &ev); err != nil {
		return LLMEvent{unreadable: true}, fmt.Errorf("agent_llm: %w", err)
	}
	if ev.AgentID == "" {
		ev.AgentID = ev.ID
	}
	return ev, nil
}

// Supported reports whether the event has the schema version this client
// reads and was decoded.
func (e LLMEvent) Supported() bool {
	return !e.unreadable && e.V == LLMEventVersion
}

// Countable reports whether the event is a charge to add to a spend total:
// a supported, non-refused event with a `call_id` (the dedup key) and
// positive sats. Released reserves and refusals are never countable.
func (e LLMEvent) Countable() bool {
	return e.Supported() && !e.Refused && e.CallID != nil && *e.CallID != "" && e.Sats > 0
}

// ChargeSats returns the sats this event charges, or 0 when it is not
// countable.
func (e LLMEvent) ChargeSats() int64 {
	if !e.Countable() {
		return 0
	}
	return e.Sats
}

// Describe renders the event as one line for the Inspector. It holds only
// numbers, fixed words and server strings that pass the same shape checks
// reef-core applies (printable ASCII model names, snake_case reasons), so a
// hostile or corrupted payload cannot put control characters on screen.
func (e LLMEvent) Describe() string {
	if e.unreadable {
		return "llm event: unreadable"
	}
	if e.V != LLMEventVersion {
		return fmt.Sprintf("llm event: unsupported version %d", e.V)
	}

	model := safeModel(e.Model)
	var b strings.Builder
	switch {
	case e.Refused:
		fmt.Fprintf(&b, "llm refused: %s", safeReason(e.Reason))
		if e.Status != nil {
			fmt.Fprintf(&b, " (HTTP %d)", *e.Status)
		}
		if e.Model != nil {
			fmt.Fprintf(&b, " · model %s", model)
		}
	case e.SettleBasis != nil && *e.SettleBasis == "unsent":
		fmt.Fprintf(&b, "llm %s: reserve released, 0 sats (never sent)", model)
	default:
		fmt.Fprintf(&b, "llm %s: %d sats", model, e.Sats)
		if e.ReserveSats != nil {
			fmt.Fprintf(&b, " (reserve %d)", *e.ReserveSats)
		}
		if e.SettleBasis != nil && *e.SettleBasis == "reserve_floor" {
			b.WriteString(" · reserve floor (no final usage)")
		}
		if e.PriceBasis != nil && *e.PriceBasis == "mismatch_ceiling" {
			b.WriteString(" · pricing mismatch, entry quarantined")
			if e.ResponseModel != nil {
				fmt.Fprintf(&b, ", response model %s", safeModel(e.ResponseModel))
			}
		}
	}
	if e.OverBudgetSats != nil && *e.OverBudgetSats > 0 {
		fmt.Fprintf(&b, " · run over budget by %d sats (cumulative)", *e.OverBudgetSats)
	}
	if e.HarnessKeySignal != nil && *e.HarnessKeySignal {
		b.WriteString(" · harness key signal")
	}
	return b.String()
}

// modelShape and reasonShape are the shapes reef-core's Event module
// enforces; the client re-checks them before rendering.
var (
	modelShape  = regexp.MustCompile(`\A[\x21-\x7e]{1,128}\z`)
	reasonShape = regexp.MustCompile(`\A[a-z0-9_]{1,64}\z`)
)

// safeModel returns the model name, "-" when absent, or "<invalid>".
func safeModel(s *string) string {
	if s == nil {
		return "-"
	}
	if !modelShape.MatchString(*s) {
		return "<invalid>"
	}
	return *s
}

// safeReason returns the refusal reason, or "refused" when absent or not
// a plain snake_case name.
func safeReason(s *string) string {
	if s == nil || !reasonShape.MatchString(*s) {
		return "refused"
	}
	return *s
}

// WsLLMMsg carries an `llm` push from agent:<id> (the Inspector's feed).
// Err is set when the payload failed to parse.
type WsLLMMsg struct {
	AgentID string
	Event   LLMEvent
	Err     error
}

// WsPodLLMMsg carries an `agent_llm` push from pod:events (the Budget
// tab's feed; the only path that adds LLM spend to a total).
type WsPodLLMMsg struct {
	Event LLMEvent
	Err   error
}
