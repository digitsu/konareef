// Copyright 2026 Jerry David Chan, Konareef.ai
// SPDX-License-Identifier: Apache-2.0

// internal/tui/agents.go

package tui

import (
	"fmt"
	"strings"
	"time"

	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"github.com/digitsu/konareef/internal/api"
	"github.com/digitsu/konareef/internal/smoke"
)

// pollInterval controls how often the active tab refreshes data.
const pollInterval = 3 * time.Second

// spawnStep tracks single-field spawn input state. The Phase 3 spawn API
// only needs a task prompt — all other fields (pod_kind, structured memory,
// model, etc.) are canned for the v1 TUI.
type spawnStep int

const (
	spawnOff spawnStep = iota
	spawnTask
	spawnKind
)

// AgentsModel displays the agent list with navigation and spawn/kill actions.
type AgentsModel struct {
	client *api.Client
	agents []api.Agent
	cursor int
	err    error
	width  int
	height int

	// Inline spawn prompt state.
	spawning  spawnStep
	taskInput textinput.Model
	podKind   string // "lobster" or "dolphin" (wire value; TUI shows "orca" for dolphin)

	// Kill confirmation.
	confirmKill bool
}

// NewAgentsModel creates an AgentsModel wired to the given API client.
func NewAgentsModel(client *api.Client) AgentsModel {
	ti := textinput.New()
	ti.Placeholder = "describe the task for the pod..."
	ti.CharLimit = 512

	return AgentsModel{
		client:    client,
		taskInput: ti,
	}
}

// Init fires the first fetch.
func (m AgentsModel) Init() tea.Cmd {
	return m.fetchCmd()
}

// Update handles messages for the agents view.
func (m AgentsModel) Update(msg tea.Msg) (AgentsModel, tea.Cmd) {
	// If spawning, route keys to the active text input.
	if m.spawning != spawnOff {
		return m.updateSpawn(msg)
	}

	switch msg := msg.(type) {
	case agentsTickMsg:
		return m, m.fetchCmd()

	case agentsFetchedMsg:
		m.agents = msg.agents
		m.err = nil
		if m.cursor >= len(m.agents) && len(m.agents) > 0 {
			m.cursor = len(m.agents) - 1
		}
		return m, m.tickCmd()

	case agentsErrMsg:
		m.err = msg.err
		return m, m.tickCmd()

	case tea.KeyMsg:
		if m.confirmKill {
			return m.updateConfirmKill(msg)
		}
		switch msg.String() {
		case "up", "k":
			if m.cursor > 0 {
				m.cursor--
			}
		case "down", "j":
			if m.cursor < len(m.agents)-1 {
				m.cursor++
			}
		case "n":
			if m.client.SessionToken == "" {
				return m, func() tea.Msg {
					return flashMsg{text: "no session token — start konareef with --token or $KONAREEF_TOKEN to spawn"}
				}
			}
			m.spawning = spawnTask
			m.taskInput.Reset()
			m.taskInput.Focus()
			return m, m.taskInput.Cursor.BlinkCmd()
		case "d":
			if len(m.agents) > 0 {
				m.confirmKill = true
			}
		case "r":
			return m, m.fetchCmd()
		}
	}
	return m, nil
}

// updateSpawn handles key input during the spawn agent prompt.
func (m AgentsModel) updateSpawn(msg tea.Msg) (AgentsModel, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch msg.String() {
		case "esc":
			m.spawning = spawnOff
			return m, nil
		case "enter":
			if m.spawning == spawnTask {
				task := strings.TrimSpace(m.taskInput.Value())
				if task == "" {
					m.spawning = spawnOff
					return m, nil
				}
				m.spawning = spawnKind
				m.podKind = "lobster" // default
				return m, nil
			}
			if m.spawning == spawnKind {
				m.spawning = spawnOff
				return m, m.spawnCmd(strings.TrimSpace(m.taskInput.Value()))
			}
		case "o":
			if m.spawning == spawnKind {
				m.podKind = "dolphin" // wire value; TUI displays as "orca"
				return m, nil
			}
		case "l":
			if m.spawning == spawnKind {
				m.podKind = "lobster"
				return m, nil
			}
		}
	}

	if m.spawning == spawnTask {
		var cmd tea.Cmd
		m.taskInput, cmd = m.taskInput.Update(msg)
		return m, cmd
	}
	return m, nil
}

// updateConfirmKill handles y/n for kill confirmation.
func (m AgentsModel) updateConfirmKill(msg tea.KeyMsg) (AgentsModel, tea.Cmd) {
	switch msg.String() {
	case "y":
		m.confirmKill = false
		if m.cursor < len(m.agents) {
			id := m.agents[m.cursor].ID
			return m, m.killCmd(id)
		}
	case "n", "esc":
		m.confirmKill = false
	}
	return m, nil
}

// IsCapturingInput returns true when the model is showing an inline text
// prompt (spawn task input, etc.) and Enter should NOT be intercepted
// by the parent App for tab navigation.
func (m AgentsModel) IsCapturingInput() bool {
	return m.spawning != spawnOff || m.confirmKill
}

// SelectedAgent returns the agent under the cursor, if any.
func (m AgentsModel) SelectedAgent() (api.Agent, bool) {
	if m.cursor < len(m.agents) {
		return m.agents[m.cursor], true
	}
	return api.Agent{}, false
}

// SetSize stores terminal dimensions for layout.
func (m *AgentsModel) SetSize(w, h int) {
	m.width = w
	m.height = h
}

// View renders the agent list.
func (m AgentsModel) View() string {
	if m.err != nil {
		return ErrorStyle.Render(fmt.Sprintf("⚠ %v", m.err))
	}

	if len(m.agents) == 0 {
		return SubtitleStyle.Render("no agents — press n to spawn one")
	}

	var rows []string
	for i, a := range m.agents {
		cursor := "  "
		if m.cursor == i {
			cursor = CursorStyle.Render("▶ ")
		}

		// Icon by name prefix — reef-core uses "dolphin" internally, TUI shows as orca.
		icon := "🦞"
		if strings.Contains(a.Name, "dolphin") {
			icon = "🐋"
		}

		var dot, name string
		if a.Status == "running" {
			dot = RunningDotStyle.Render("●")
			name = RunningNameStyle.Render(a.Name)
		} else {
			dot = StoppedDotStyle.Render("○")
			name = StoppedNameStyle.Render(a.Name)
		}

		// TODO: spent/budget tracking moved server-side; re-expose via /api/budget
		rows = append(rows, fmt.Sprintf("%s%s  %s  %s", cursor, icon, dot, name))
	}

	list := lipgloss.JoinVertical(lipgloss.Left, rows...)

	// Append inline prompt or confirm if active.
	if m.spawning == spawnTask {
		list += "\n\n" + HelpStyle.Render("Task: ") + m.taskInput.View()
	} else if m.spawning == spawnKind {
		list += "\n\n" + HelpStyle.Render("Task: ") + m.taskInput.Value()
		orca := "  🐋 o orca  "
		lobster := "  🦞 l lobster  "
		if m.podKind == "dolphin" {
			orca = CursorStyle.Render("▶ 🐋 o orca  ")
		} else {
			lobster = CursorStyle.Render("▶ 🦞 l lobster  ")
		}
		list += "\n" + HelpStyle.Render("Kind: ") + orca + lobster
	}

	if m.confirmKill && m.cursor < len(m.agents) {
		list += "\n\n" + ErrorStyle.Render(fmt.Sprintf("Kill %s? (y/n)", m.agents[m.cursor].Name))
	}

	return list
}

// KeyHints returns contextual help for the status bar.
func (m AgentsModel) KeyHints() string {
	if m.spawning == spawnKind {
		return "o orca · l lobster · enter confirm · esc cancel"
	}
	if m.spawning != spawnOff {
		return "enter confirm · esc cancel"
	}
	if m.confirmKill {
		return "y confirm · n cancel"
	}
	return "↑/↓ navigate · enter inspect · n spawn · d kill · r refresh"
}

// Commands.

func (m AgentsModel) fetchCmd() tea.Cmd {
	return func() tea.Msg {
		agents, err := m.client.ListAgents()
		if err != nil {
			return agentsErrMsg{err: err}
		}
		return agentsFetchedMsg{agents: agents}
	}
}

func (m AgentsModel) tickCmd() tea.Cmd {
	return tea.Tick(pollInterval, func(time.Time) tea.Msg {
		return agentsTickMsg{}
	})
}

// spawnCmd hits POST /api/agents with the task plus a canned structured
// memory bundle (shared with the smoke subcommand). On success it flashes
// the agent_id and the returned bundle file count so the operator has
// something to trace in the proofs API.
func (m AgentsModel) spawnCmd(task string) tea.Cmd {
	return func() tea.Msg {
		resp, err := m.client.SpawnAgent(api.SpawnRequest{
			Task:             task,
			PodKind:          m.podKind,
			Model:            "claude-sonnet-4-5",
			BudgetSats:       1_000_000,
			MaxIterations:    5,
			StructuredMemory: smoke.CannedBundle,
		})
		if err != nil {
			return flashMsg{text: fmt.Sprintf("spawn failed: %v", err)}
		}
		return flashMsg{
			text: fmt.Sprintf("spawned %s (bundle=%d files)", resp.AgentID, resp.BundleFileCount),
		}
	}
}

func (m AgentsModel) killCmd(id string) tea.Cmd {
	return func() tea.Msg {
		err := m.client.KillAgent(id)
		if err != nil {
			return flashMsg{text: fmt.Sprintf("kill failed: %v", err)}
		}
		return flashMsg{text: "agent killed"}
	}
}
