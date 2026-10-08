// Copyright 2026 Jerry David Chan, Konareef.ai
// SPDX-License-Identifier: Apache-2.0

// internal/tui/budget.go
//
// BudgetModel displays the pod-wide budget summary, including total/spent/remaining
// satoshi counts, a utilization progress bar, and a per-agent spend breakdown.
//
// Live updates between REST polls come from two pod:events pushes:
// agent_cost (ApplyCost) and, for runs under LLM custody, agent_llm
// (ApplyLLM). reef-core never sends both for the same sats, so both add to
// the same total. ApplyLLM counts each call_id once and keeps the
// cumulative overage as a maximum. The REST snapshot stays authoritative.

package tui

import (
	"fmt"
	"sort"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"github.com/digitsu/konareef/internal/api"
	"github.com/digitsu/konareef/internal/ws"
)

// llmSeenCap bounds the call_ids the Budget tab remembers for
// deduplication; the oldest are forgotten first.
const llmSeenCap = 4096

// BudgetModel displays the pod-wide budget summary.
type BudgetModel struct {
	client *api.Client
	budget *api.Budget
	err    error
	width  int
	height int

	// llmSeen holds the call_ids already counted (or seen before the first
	// fetch); llmSeenOrder is their arrival order, for eviction. Both
	// survive a REST refetch, so a backfill replay is never counted twice.
	llmSeen      map[string]struct{}
	llmSeenOrder []string
	// overBudget is each agent's cumulative LLM overage: the largest
	// over_budget_sats seen, never a sum.
	overBudget map[string]int64
}

// NewBudgetModel creates a BudgetModel wired to the given API client.
func NewBudgetModel(client *api.Client) BudgetModel {
	return BudgetModel{client: client}
}

// Init fires the first budget fetch.
func (m BudgetModel) Init() tea.Cmd {
	return m.fetchCmd()
}

// Update handles budget messages.
func (m BudgetModel) Update(msg tea.Msg) (BudgetModel, tea.Cmd) {
	switch msg := msg.(type) {
	case budgetTickMsg:
		return m, m.fetchCmd()

	case budgetFetchedMsg:
		b := msg.budget
		m.budget = &b
		m.err = nil
		return m, m.tickCmd()

	case budgetErrMsg:
		m.err = msg.err
		return m, m.tickCmd()

	case tea.KeyMsg:
		if msg.String() == "r" {
			return m, m.fetchCmd()
		}
	}
	return m, nil
}

// ApplyCost applies a pod-wide cost delta from the PodEventsChannel
// agent_cost event. It mutates the currently-cached budget optimistically
// so the Budget tab updates between REST polls; the next budgetFetchedMsg
// reconciles any drift with the server snapshot.
//
// If no budget has been fetched yet (m.budget == nil) the delta is dropped
// — the subsequent fetch will include the already-recorded spend.
func (m *BudgetModel) ApplyCost(agentID string, sats int64) {
	if m.budget == nil || sats <= 0 {
		return
	}
	b := m.budget
	b.TotalSpent += sats
	b.Remaining = b.TotalBudget - b.TotalSpent
	if b.TotalBudget > 0 {
		b.Utilization = float64(b.TotalSpent) / float64(b.TotalBudget)
	}
	if b.AgentSpend == nil {
		b.AgentSpend = make(map[string]int64)
	}
	b.AgentSpend[agentID] += sats
}

// ApplyLLM applies one pod-wide agent_llm event.
//
// Input: ev, the parsed event.
// Effect: a countable event (settled, positive sats, call_id present,
// schema v1) whose call_id was not seen before is added through ApplyCost.
// Refused, released, unsupported and repeated events add nothing. The
// agent's overage is raised to over_budget_sats when that is larger.
func (m *BudgetModel) ApplyLLM(ev ws.LLMEvent) {
	if !ev.Supported() {
		return
	}
	if ev.OverBudgetSats != nil && *ev.OverBudgetSats > 0 {
		if m.overBudget == nil {
			m.overBudget = make(map[string]int64)
		}
		if *ev.OverBudgetSats > m.overBudget[ev.AgentID] {
			m.overBudget[ev.AgentID] = *ev.OverBudgetSats
		}
	}
	if !ev.Countable() {
		return
	}
	id := *ev.CallID
	if _, seen := m.llmSeen[id]; seen {
		return
	}
	if m.llmSeen == nil {
		m.llmSeen = make(map[string]struct{})
	}
	m.llmSeen[id] = struct{}{}
	m.llmSeenOrder = append(m.llmSeenOrder, id)
	if len(m.llmSeenOrder) > llmSeenCap {
		delete(m.llmSeen, m.llmSeenOrder[0])
		m.llmSeenOrder = m.llmSeenOrder[1:]
	}
	// Before the first fetch ApplyCost drops the delta; the snapshot will
	// include it, and the call_id is already marked seen.
	m.ApplyCost(ev.AgentID, ev.ChargeSats())
}

// SetSize stores terminal dimensions for layout.
func (m *BudgetModel) SetSize(w, h int) {
	m.width = w
	m.height = h
}

// View renders the budget summary.
func (m BudgetModel) View() string {
	if m.err != nil {
		return ErrorStyle.Render(fmt.Sprintf("⚠ %v", m.err))
	}
	if m.budget == nil {
		return SubtitleStyle.Render("loading budget...")
	}

	b := m.budget

	// Utilization bar.
	barWidth := 30
	filled := int(b.Utilization * float64(barWidth))
	if filled > barWidth {
		filled = barWidth
	}
	barFull := RunningDotStyle.Render(repeatChar("█", filled))
	barEmpty := StoppedDotStyle.Render(repeatChar("░", barWidth-filled))
	bar := barFull + barEmpty

	header := TitleStyle.Render("Pod Budget")
	lines := []string{
		header,
		"",
		fmt.Sprintf("  Total:     %d sats", b.TotalBudget),
		fmt.Sprintf("  Spent:     %d sats", b.TotalSpent),
		fmt.Sprintf("  Remaining: %d sats", b.Remaining),
		fmt.Sprintf("  Usage:     %s %.0f%%", bar, b.Utilization*100),
	}

	if len(b.AgentSpend) > 0 {
		lines = append(lines, "", SubtitleStyle.Render("  Per-agent spend:"))

		// Sort agent IDs for stable output.
		ids := make([]string, 0, len(b.AgentSpend))
		for id := range b.AgentSpend {
			ids = append(ids, id)
		}
		sort.Strings(ids)
		for _, id := range ids {
			sats := b.AgentSpend[id]
			lines = append(lines, fmt.Sprintf("    %s: %d sats", id, sats))
		}
	}

	if len(m.overBudget) > 0 {
		lines = append(lines, "", ErrorStyle.Render("  LLM over budget (cumulative, per agent):"))
		ids := make([]string, 0, len(m.overBudget))
		for id := range m.overBudget {
			ids = append(ids, id)
		}
		sort.Strings(ids)
		for _, id := range ids {
			lines = append(lines, fmt.Sprintf("    %s: %d sats", id, m.overBudget[id]))
		}
	}

	return lipgloss.JoinVertical(lipgloss.Left, lines...)
}

// KeyHints returns contextual help for the status bar.
func (m BudgetModel) KeyHints() string {
	return "r refresh"
}

// Commands.

// fetchCmd fetches the current budget from the API and returns the appropriate message.
func (m BudgetModel) fetchCmd() tea.Cmd {
	return func() tea.Msg {
		budget, err := m.client.GetBudget()
		if err != nil {
			return budgetErrMsg{err: err}
		}
		return budgetFetchedMsg{budget: *budget}
	}
}

// tickCmd schedules the next automatic budget refresh after pollInterval.
func (m BudgetModel) tickCmd() tea.Cmd {
	return tea.Tick(pollInterval, func(time.Time) tea.Msg {
		return budgetTickMsg{}
	})
}

// repeatChar repeats a string n times.
func repeatChar(s string, n int) string {
	out := ""
	for i := 0; i < n; i++ {
		out += s
	}
	return out
}
