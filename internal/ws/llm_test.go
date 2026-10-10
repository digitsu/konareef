// Copyright 2026 Jerry David Chan, Konareef.ai
// SPDX-License-Identifier: Apache-2.0

// internal/ws/llm_test.go
//
// Tests for the agent_llm (version 1) consumer: the vendored reef-core
// P3-08 fixture parses, nulls stay null, unknown fields are ignored, and
// the rendered line never carries unsafe text. The fixture is also read by
// internal/tui and internal/verify tests (see testdata/p3_08/README.md).

package ws

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"strings"
	"testing"
)

// llmFixturePath is the vendored reef-core P3-08 fixture.
const llmFixturePath = "testdata/p3_08/llm-billing-v1.json"

// llmFixtureSHA256 pins the vendored bytes; see testdata/p3_08/README.md.
const llmFixtureSHA256 = "c9d3996ba3677f9c548ee4247ba20f0b2ba1cd2336f11978d4da541ff639e08b"

// llmFixture is the part of the fixture file these tests read.
type llmFixture struct {
	Version          int      `json:"version"`
	AgentLLMVersion  int      `json:"agent_llm_version"`
	PodEventsPush    string   `json:"pod_events_push"`
	AgentChannelPush string   `json:"agent_channel_push"`
	WireKeys         []string `json:"wire_keys"`
	Events           []struct {
		Name string         `json:"name"`
		Push map[string]any `json:"push"`
	} `json:"events"`
}

// loadLLMFixture reads the fixture, checks its hash and decodes it.
func loadLLMFixture(t *testing.T) llmFixture {
	t.Helper()
	raw, err := os.ReadFile(llmFixturePath)
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	sum := sha256.Sum256(raw)
	if got := hex.EncodeToString(sum[:]); got != llmFixtureSHA256 {
		t.Fatalf("fixture sha256 = %s, want %s (re-vendor and update README)", got, llmFixtureSHA256)
	}
	var fx llmFixture
	if err := json.Unmarshal(raw, &fx); err != nil {
		t.Fatalf("decode fixture: %v", err)
	}
	return fx
}

// fixtureEvent returns the push of the fixture event with the given name.
func fixtureEvent(t *testing.T, fx llmFixture, name string) map[string]any {
	t.Helper()
	for _, ev := range fx.Events {
		if ev.Name == name {
			return ev.Push
		}
	}
	t.Fatalf("fixture has no event %q", name)
	return nil
}

func TestLLMFixtureContract(t *testing.T) {
	fx := loadLLMFixture(t)
	if fx.AgentLLMVersion != LLMEventVersion {
		t.Fatalf("fixture agent_llm_version = %d, konareef supports %d", fx.AgentLLMVersion, LLMEventVersion)
	}
	if fx.PodEventsPush != "agent_llm" || fx.AgentChannelPush != "llm" {
		t.Fatalf("push names = %q/%q, want agent_llm/llm", fx.PodEventsPush, fx.AgentChannelPush)
	}
	if len(fx.Events) != 9 {
		t.Fatalf("fixture has %d events, want 9", len(fx.Events))
	}
	// Every event carries every wire key, and each parses as supported.
	for _, ev := range fx.Events {
		for _, k := range fx.WireKeys {
			if _, ok := ev.Push[k]; !ok {
				t.Errorf("%s: missing wire key %q", ev.Name, k)
			}
		}
		parsed, err := ParseLLMEvent(ev.Push)
		if err != nil {
			t.Errorf("%s: parse: %v", ev.Name, err)
			continue
		}
		if !parsed.Supported() {
			t.Errorf("%s: not supported", ev.Name)
		}
		if parsed.AgentID != "agent-fixture-1" {
			t.Errorf("%s: agent id = %q", ev.Name, parsed.AgentID)
		}
	}
}

func TestParseLLMEventKinds(t *testing.T) {
	fx := loadLLMFixture(t)
	cases := []struct {
		name      string
		charge    int64 // ChargeSats
		countable bool
		refused   bool
		contains  []string
	}{
		{"settled-usage", 118, true, false, []string{"claude-sonnet-4-5", "118 sats", "reserve 300"}},
		{"settled-floor-by-worker", 300, true, false, []string{"300 sats", "reserve floor"}},
		{"settled-floor-by-run", 300, true, false, []string{"300 sats", "reserve floor"}},
		{"settled-pricing-mismatch", 450, true, false, []string{"450 sats", "pricing mismatch", "quarantined", "claude-unknown-9"}},
		{"settled-over-budget", 700, true, false, []string{"700 sats", "over budget by 250 sats"}},
		{"released-unsent", 0, false, false, []string{"reserve released", "0 sats"}},
		{"refused-before-body", 0, false, true, []string{"refused", "not_found", "404"}},
		{"refused-model-not-allowed", 0, false, true, []string{"refused", "model_not_allowed", "403"}},
		{"refused-budget-exhausted", 0, false, true, []string{"refused", "budget_exhausted", "429"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ev, err := ParseLLMEvent(fixtureEvent(t, fx, tc.name))
			if err != nil {
				t.Fatalf("parse: %v", err)
			}
			if got := ev.ChargeSats(); got != tc.charge {
				t.Errorf("ChargeSats = %d, want %d", got, tc.charge)
			}
			if got := ev.Countable(); got != tc.countable {
				t.Errorf("Countable = %v, want %v", got, tc.countable)
			}
			if ev.Refused != tc.refused {
				t.Errorf("Refused = %v, want %v", ev.Refused, tc.refused)
			}
			line := ev.Describe()
			for _, s := range tc.contains {
				if !strings.Contains(line, s) {
					t.Errorf("Describe() = %q, want it to contain %q", line, s)
				}
			}
		})
	}
}

// Null fields decode as absent, not as zero: a run-settled row has no
// worker-only fields, and a refused call has no call_id or reserve.
func TestParseLLMEventNulls(t *testing.T) {
	fx := loadLLMFixture(t)

	run, err := ParseLLMEvent(fixtureEvent(t, fx, "settled-floor-by-run"))
	if err != nil {
		t.Fatal(err)
	}
	if run.Status != nil || run.Streamed != nil || run.DurationMS != nil ||
		run.ImageCount != nil || run.HarnessKeySignal != nil || run.ResponseModel != nil {
		t.Errorf("run-settled worker-only fields should be nil: %+v", run)
	}

	ref, err := ParseLLMEvent(fixtureEvent(t, fx, "refused-before-body"))
	if err != nil {
		t.Fatal(err)
	}
	if ref.CallID != nil || ref.ReserveSats != nil || ref.Model != nil || ref.InputTokens != nil {
		t.Errorf("refused event should have nil call_id/reserve/model/tokens: %+v", ref)
	}
	if ref.Status == nil || *ref.Status != 404 {
		t.Errorf("refused status = %v, want 404", ref.Status)
	}
}

// A field the client does not know (a later server) is ignored; the event
// still parses and counts.
func TestParseLLMEventUnknownFields(t *testing.T) {
	fx := loadLLMFixture(t)
	push := map[string]any{}
	for k, v := range fixtureEvent(t, fx, "settled-usage") {
		push[k] = v
	}
	push["future_field"] = map[string]any{"nested": []any{1, 2}}
	ev, err := ParseLLMEvent(push)
	if err != nil {
		t.Fatalf("parse with unknown field: %v", err)
	}
	if !ev.Countable() || ev.ChargeSats() != 118 {
		t.Errorf("unknown field changed the event: countable=%v sats=%d", ev.Countable(), ev.ChargeSats())
	}
}

// A different schema version is not counted; its line says so and shows
// nothing else from the payload.
func TestParseLLMEventUnsupportedVersion(t *testing.T) {
	fx := loadLLMFixture(t)
	push := map[string]any{}
	for k, v := range fixtureEvent(t, fx, "settled-usage") {
		push[k] = v
	}
	push["v"] = float64(2)
	ev, err := ParseLLMEvent(push)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if ev.Supported() || ev.Countable() {
		t.Errorf("v2 event must not be supported or countable")
	}
	if got := ev.Describe(); got != "llm event: unsupported version 2" {
		t.Errorf("Describe() = %q", got)
	}
}

// A payload with a wrong type fails to parse; the dispatcher turns it into
// a fixed line and never a debit.
func TestParseLLMEventMalformed(t *testing.T) {
	if _, err := ParseLLMEvent(map[string]any{"v": float64(1), "sats": "lots"}); err == nil {
		t.Fatal("want error for string sats")
	}
	msg := decodeMsg(PhoenixMsg{Topic: "pod:events", Event: "agent_llm",
		Payload: map[string]any{"v": float64(1), "sats": "lots", "agent_id": "a1"}})
	pm, ok := msg.(WsPodLLMMsg)
	if !ok {
		t.Fatalf("decodeMsg = %T, want WsPodLLMMsg", msg)
	}
	if pm.Err == nil || pm.Event.Countable() {
		t.Errorf("malformed event must carry Err and not be countable")
	}
	if got := pm.Event.Describe(); got != "llm event: unreadable" {
		t.Errorf("Describe() = %q", got)
	}
}

// Text from the server is shown only when it is plain printable ASCII of
// the shape reef-core itself enforces; anything else is replaced.
func TestLLMEventDescribeIsSafe(t *testing.T) {
	model := "claude\x1b[31m-evil"
	reason := "bad\nreason"
	callID := "c1"
	ev := LLMEvent{V: 1, CallID: &callID, Model: &model, Sats: 5, Refused: true, Reason: &reason}
	line := ev.Describe()
	if strings.ContainsAny(line, "\x1b\n\r") {
		t.Fatalf("Describe() leaked control characters: %q", line)
	}
	if !strings.Contains(line, "refused") || strings.Contains(line, "bad") {
		t.Errorf("unsafe reason not replaced: %q", line)
	}

	ev = LLMEvent{V: 1, CallID: &callID, Model: &model, Sats: 5}
	line = ev.Describe()
	if strings.Contains(line, "evil") || !strings.Contains(line, "<invalid>") {
		t.Errorf("unsafe model not replaced: %q", line)
	}
}

// decodeMsg routes the two pushes of the same event to distinct messages:
// pod:events agent_llm feeds the budget, agent:<id> llm feeds the inspector.
func TestDecodeMsgLLMRoutes(t *testing.T) {
	fx := loadLLMFixture(t)
	push := fixtureEvent(t, fx, "settled-usage")

	pod := decodeMsg(PhoenixMsg{Topic: "pod:events", Event: "agent_llm", Payload: push})
	pm, ok := pod.(WsPodLLMMsg)
	if !ok || pm.Err != nil || pm.Event.AgentID != "agent-fixture-1" || pm.Event.ChargeSats() != 118 {
		t.Fatalf("pod:events agent_llm → %#v", pod)
	}

	agent := decodeMsg(PhoenixMsg{Topic: "agent:agent-fixture-1", Event: "llm", Payload: push})
	am, ok := agent.(WsLLMMsg)
	if !ok || am.Err != nil || am.AgentID != "agent-fixture-1" {
		t.Fatalf("agent llm → %#v", agent)
	}
}

// Events the client does not know, replies and non-map payloads yield no
// message and do not panic.
func TestDecodeMsgUnknownEvents(t *testing.T) {
	for _, m := range []PhoenixMsg{
		{Topic: "pod:events", Event: "agent_something_new", Payload: map[string]any{"x": 1}},
		{Topic: "pod:events", Event: "agent_llm", Payload: "not a map"},
		{Topic: "pod:events", Event: "agent_llm", Payload: nil},
		{Topic: "pod:events", Event: "phx_reply", Payload: map[string]any{}},
	} {
		if got := decodeMsg(m); got != nil {
			t.Errorf("decodeMsg(%s %v) = %#v, want nil", m.Event, m.Payload, got)
		}
	}
}
