// Copyright 2026 Jerry David Chan, Konareef.ai
// SPDX-License-Identifier: Apache-2.0

// internal/tui/budget_llm_test.go
//
// Tests that the Budget tab counts agent_llm spend once per call_id, never
// debits a refused or released call, keeps the cumulative overage as a
// maximum, and still counts legacy agent_cost. Sequences come from the
// vendored reef-core P3-08 fixture (internal/ws/testdata/p3_08).

package tui

import (
	"encoding/json"
	"os"
	"strconv"
	"strings"
	"testing"

	"github.com/digitsu/konareef/internal/api"
	"github.com/digitsu/konareef/internal/ws"
)

// llmSequences is the "sequences" part of the P3-08 fixture.
type llmSequences struct {
	Sequences []struct {
		Name           string           `json:"name"`
		Pushes         []map[string]any `json:"pushes"`
		AgentCostPushs []struct {
			AgentID string `json:"agent_id"`
			Sats    int64  `json:"sats"`
		} `json:"agent_cost_pushes"`
		Expect struct {
			LLMSats        int64  `json:"llm_sats"`
			SettledCalls   int    `json:"settled_calls"`
			OverBudgetSats *int64 `json:"over_budget_sats"`
			AgentCostSats  int64  `json:"agent_cost_sats"`
		} `json:"expect"`
	} `json:"sequences"`
	Events []struct {
		Name string         `json:"name"`
		Push map[string]any `json:"push"`
	} `json:"events"`
}

// loadLLMSequences reads the vendored fixture. Its hash is pinned by the
// internal/ws tests.
func loadLLMSequences(t *testing.T) llmSequences {
	t.Helper()
	raw, err := os.ReadFile("../ws/testdata/p3_08/llm-billing-v1.json")
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	var fx llmSequences
	if err := json.Unmarshal(raw, &fx); err != nil {
		t.Fatalf("decode fixture: %v", err)
	}
	return fx
}

// freshBudget is a budget as if just fetched, with nothing spent.
func freshBudget() BudgetModel {
	return BudgetModel{budget: &api.Budget{TotalBudget: 10_000, Remaining: 10_000, AgentSpend: map[string]int64{}}}
}

// parse turns a fixture push into an event, failing the test on error.
func parse(t *testing.T, push map[string]any) ws.LLMEvent {
	t.Helper()
	ev, err := ws.ParseLLMEvent(push)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	return ev
}

func TestBudgetLLMSequences(t *testing.T) {
	fx := loadLLMSequences(t)
	if len(fx.Sequences) != 3 {
		t.Fatalf("fixture has %d sequences, want 3", len(fx.Sequences))
	}
	for _, seq := range fx.Sequences {
		t.Run(seq.Name, func(t *testing.T) {
			m := freshBudget()
			for _, p := range seq.Pushes {
				m.ApplyLLM(parse(t, p))
			}
			for _, c := range seq.AgentCostPushs {
				m.ApplyCost(c.AgentID, c.Sats)
			}
			want := seq.Expect.LLMSats + seq.Expect.AgentCostSats
			if m.budget.TotalSpent != want {
				t.Errorf("TotalSpent = %d, want %d", m.budget.TotalSpent, want)
			}
			if got := m.budget.AgentSpend["agent-fixture-1"]; got != want {
				t.Errorf("AgentSpend = %d, want %d", got, want)
			}
			if m.budget.Remaining != 10_000-want {
				t.Errorf("Remaining = %d", m.budget.Remaining)
			}
			if seq.Expect.OverBudgetSats != nil {
				if got := m.overBudget["agent-fixture-1"]; got != *seq.Expect.OverBudgetSats {
					t.Errorf("overBudget = %d, want %d (cumulative, not a sum)", got, *seq.Expect.OverBudgetSats)
				}
			}
		})
	}
}

// Every single event kind: only settled calls debit.
func TestBudgetLLMEventKinds(t *testing.T) {
	fx := loadLLMSequences(t)
	want := map[string]int64{
		"settled-usage": 118, "settled-floor-by-worker": 300, "settled-floor-by-run": 300,
		"settled-pricing-mismatch": 450, "settled-over-budget": 700,
		"released-unsent": 0, "refused-before-body": 0, "refused-model-not-allowed": 0,
		"refused-budget-exhausted": 0,
	}
	for _, ev := range fx.Events {
		m := freshBudget()
		m.ApplyLLM(parse(t, ev.Push))
		m.ApplyLLM(parse(t, ev.Push)) // duplicate delivery
		if m.budget.TotalSpent != want[ev.Name] {
			t.Errorf("%s: TotalSpent = %d, want %d", ev.Name, m.budget.TotalSpent, want[ev.Name])
		}
	}
}

// A replay that arrives after a REST refetch is still counted once: the
// seen call_ids survive the snapshot, and a call seen before the first
// fetch is not debited again after it.
func TestBudgetLLMDedupAcrossFetch(t *testing.T) {
	fx := loadLLMSequences(t)
	push := fx.Events[0].Push // settled-usage, 118 sats

	m := BudgetModel{} // nothing fetched yet
	m.ApplyLLM(parse(t, push))

	// The server snapshot already includes the 118 sats.
	m, _ = m.Update(budgetFetchedMsg{budget: api.Budget{TotalBudget: 1000, TotalSpent: 118, Remaining: 882,
		AgentSpend: map[string]int64{"agent-fixture-1": 118}}})
	m.ApplyLLM(parse(t, push)) // reconnect backfill replay
	if m.budget.TotalSpent != 118 {
		t.Errorf("TotalSpent = %d, want 118 (no double debit)", m.budget.TotalSpent)
	}
}

// An unsupported version or an unreadable payload never debits.
func TestBudgetLLMUnsupportedNeverDebits(t *testing.T) {
	m := freshBudget()
	id := "c1"
	m.ApplyLLM(ws.LLMEvent{V: 2, AgentID: "a", CallID: &id, Sats: 50})
	m.ApplyLLM(ws.LLMEvent{V: 1, AgentID: "a", Sats: 50}) // no call_id
	if m.budget.TotalSpent != 0 {
		t.Errorf("TotalSpent = %d, want 0", m.budget.TotalSpent)
	}
}

// The seen set is bounded; the oldest call_ids are forgotten first.
func TestBudgetLLMSeenBounded(t *testing.T) {
	m := freshBudget()
	m.budget.TotalBudget = 1 << 40
	for i := 0; i < llmSeenCap+10; i++ {
		id := "call-" + strconv.Itoa(i)
		m.ApplyLLM(ws.LLMEvent{V: 1, AgentID: "a", CallID: &id, Sats: 1})
	}
	if len(m.llmSeen) != llmSeenCap || len(m.llmSeenOrder) != llmSeenCap {
		t.Errorf("seen set = %d/%d, want %d", len(m.llmSeen), len(m.llmSeenOrder), llmSeenCap)
	}
}

// The overage is shown once per agent, labeled cumulative.
func TestBudgetViewShowsOverage(t *testing.T) {
	fx := loadLLMSequences(t)
	m := freshBudget()
	for _, p := range fx.Sequences[1].Pushes { // cumulative-overage
		m.ApplyLLM(parse(t, p))
	}
	view := m.View()
	if !strings.Contains(view, "agent-fixture-1: 350 sats") || strings.Contains(view, "650") {
		t.Errorf("view does not show the cumulative overage 350:\n%s", view)
	}
}

// The polled event log renders agent_llm entries (log form, "id" key) and
// never crashes on an unknown or malformed entry.
func TestFormatEventLLM(t *testing.T) {
	fx := loadLLMSequences(t)
	logPayload := map[string]any{}
	for k, v := range fx.Events[0].Push {
		logPayload[k] = v
	}
	delete(logPayload, "agent_id")
	logPayload["id"] = "agent-fixture-1"

	line := formatEvent(api.AgentEvent{Event: "agent_llm", Payload: logPayload})
	if !strings.Contains(line, "118 sats") {
		t.Errorf("formatEvent(agent_llm) = %q", line)
	}
	bad := formatEvent(api.AgentEvent{Event: "agent_llm", Payload: map[string]any{"sats": "x"}})
	if !strings.Contains(bad, "llm event: unreadable") {
		t.Errorf("formatEvent(bad agent_llm) = %q", bad)
	}
	_ = formatEvent(api.AgentEvent{Event: "agent_from_the_future", Payload: nil})
}

// The App routes the pod-wide push to the budget and the per-agent push to
// the inspector, so one call is debited once and shown once.
func TestAppRoutesLLMMessages(t *testing.T) {
	fx := loadLLMSequences(t)
	ev := parse(t, fx.Events[0].Push)

	a := App{budget: freshBudget(), inspector: NewInspectorModel(nil)}
	a.inspector.agentID = "agent-fixture-1"
	model, _ := a.Update(ws.WsPodLLMMsg{Event: ev})
	model, _ = model.(App).Update(ws.WsLLMMsg{AgentID: "agent-fixture-1", Event: ev})
	got := model.(App)
	if got.budget.budget.TotalSpent != 118 {
		t.Errorf("budget TotalSpent = %d, want 118 (agent channel push must not debit)", got.budget.budget.TotalSpent)
	}
	if len(got.inspector.liveLog) != 1 || !strings.Contains(got.inspector.liveLog[0], "118 sats") {
		t.Errorf("inspector live log = %q", got.inspector.liveLog)
	}
}
