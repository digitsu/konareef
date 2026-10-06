// Copyright 2026 Jerry David Chan, Konareef.ai
// SPDX-License-Identifier: Apache-2.0

// internal/tui/inspector.go
//
// InspectorModel shows detail for a single selected agent with a split-pane
// layout: agent details at top, live output stream (or polled event log
// fallback) at bottom.

package tui

import (
	"fmt"
	"strings"
	"time"

	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"github.com/digitsu/konareef/internal/api"
	"github.com/digitsu/konareef/internal/ws"
)

// InspectorModel shows detail for a single agent with live output + actions.
type InspectorModel struct {
	client   *api.Client
	agentID  string
	agent    *api.Agent
	events   []api.AgentEvent // polled event log (fallback)
	err      error
	width    int
	height   int
	logStart int // scroll offset into log

	// Live output from WebSocket.
	liveLog    []string // formatted live event lines
	liveMode   bool     // true once first WS event received
	autoScroll bool     // auto-scroll to bottom on new events

	// Send task prompt.
	sendingTask bool
	taskInput   textinput.Model

	// Kill confirmation.
	confirmKill bool
}

// NewInspectorModel creates an empty inspector. Call SetAgent to load one.
func NewInspectorModel(client *api.Client) InspectorModel {
	ti := textinput.New()
	ti.Placeholder = "describe the task..."
	ti.CharLimit = 200

	return InspectorModel{
		client:     client,
		taskInput:  ti,
		autoScroll: true,
	}
}

// SetAgent switches the inspector to a new agent and triggers a fetch.
func (m *InspectorModel) SetAgent(id string) tea.Cmd {
	m.agentID = id
	m.agent = nil
	m.events = nil
	m.liveLog = nil
	m.liveMode = false
	m.autoScroll = true
	m.err = nil
	m.sendingTask = false
	m.confirmKill = false
	m.logStart = 0
	return m.fetchCmd()
}

// ── Live output append methods ──────────────────────────────────────

// AppendStream adds streaming text to the live log. Streaming chunks
// are appended to the last line (no newline per chunk).
func (m *InspectorModel) AppendStream(data string) {
	m.liveMode = true
	if len(m.liveLog) == 0 || !strings.HasPrefix(m.liveLog[len(m.liveLog)-1], "💬 ") {
		m.liveLog = append(m.liveLog, "💬 "+data)
	} else {
		m.liveLog[len(m.liveLog)-1] += data
	}
	m.scrollToBottomIfAuto()
}

// AppendToolCall adds a tool call event to the live log.
func (m *InspectorModel) AppendToolCall(tool string) {
	m.liveMode = true
	m.liveLog = append(m.liveLog, CursorStyle.Render("🔧 tool: "+tool))
	m.scrollToBottomIfAuto()
}

// AppendCost adds a cost event to the live log.
func (m *InspectorModel) AppendCost(sats int64) {
	m.liveMode = true
	m.liveLog = append(m.liveLog, HelpStyle.Render(fmt.Sprintf("💰 +%d sats", sats)))
	m.scrollToBottomIfAuto()
}

// AppendLLM adds one agent_llm call (accepted, released or refused) to the
// live log. It never touches a spend total; the Budget tab counts spend.
func (m *InspectorModel) AppendLLM(ev ws.LLMEvent) {
	m.liveMode = true
	line := "🤖 " + ev.Describe()
	if ev.Refused || !ev.Supported() {
		line = ErrorStyle.Render("⛔ " + ev.Describe())
	}
	m.liveLog = append(m.liveLog, line)
	m.scrollToBottomIfAuto()
}

// AppendComplete adds a completion event to the live log.
func (m *InspectorModel) AppendComplete(result string) {
	m.liveMode = true
	m.liveLog = append(m.liveLog, RunningDotStyle.Render("✅ "+result))
	m.scrollToBottomIfAuto()
}

// AppendError adds an error event to the live log.
func (m *InspectorModel) AppendError(message string) {
	m.liveMode = true
	m.liveLog = append(m.liveLog, ErrorStyle.Render("❌ "+message))
	m.scrollToBottomIfAuto()
}

// scrollToBottomIfAuto scrolls the log viewport to the bottom when autoScroll
// is enabled, ensuring newly appended live events are visible.
func (m *InspectorModel) scrollToBottomIfAuto() {
	if m.autoScroll {
		vis := m.logVisibleLines()
		log := m.activeLog()
		if len(log) > vis {
			m.logStart = len(log) - vis
		}
	}
}

// activeLog returns the live log if in live mode, otherwise the formatted polled events.
func (m InspectorModel) activeLog() []string {
	if m.liveMode {
		return m.liveLog
	}
	lines := make([]string, len(m.events))
	for i, ev := range m.events {
		lines[i] = formatEvent(ev)
	}
	return lines
}

// Init returns nil — SetAgent triggers the initial fetch.
func (m InspectorModel) Init() tea.Cmd { return nil }

// Update handles inspector messages.
func (m InspectorModel) Update(msg tea.Msg) (InspectorModel, tea.Cmd) {
	if m.sendingTask {
		return m.updateSendTask(msg)
	}

	switch msg := msg.(type) {
	case inspectorTickMsg:
		if !m.liveMode {
			return m, m.fetchCmd()
		}
		return m, m.tickCmd()

	case inspectorFetchedMsg:
		a := msg.agent
		m.agent = &a
		if !m.liveMode {
			m.events = msg.events
		}
		m.err = nil
		m.scrollToBottomIfAuto()
		return m, m.tickCmd()

	case inspectorErrMsg:
		m.err = msg.err
		return m, m.tickCmd()

	case tea.KeyMsg:
		if m.confirmKill {
			return m.updateConfirmKill(msg)
		}
		switch msg.String() {
		case "t":
			m.sendingTask = true
			m.taskInput.Reset()
			m.taskInput.Focus()
			return m, m.taskInput.Cursor.BlinkCmd()
		case "d":
			if m.agent != nil {
				m.confirmKill = true
			}
		case "r":
			return m, m.fetchCmd()
		case "up", "k":
			if m.logStart > 0 {
				m.logStart--
				m.autoScroll = false
			}
		case "down", "j":
			log := m.activeLog()
			maxStart := len(log) - m.logVisibleLines()
			if maxStart < 0 {
				maxStart = 0
			}
			if m.logStart < maxStart {
				m.logStart++
			}
			if m.logStart >= maxStart {
				m.autoScroll = true
			}
		case "G":
			log := m.activeLog()
			maxStart := len(log) - m.logVisibleLines()
			if maxStart < 0 {
				maxStart = 0
			}
			m.logStart = maxStart
			m.autoScroll = true
		case "g":
			m.logStart = 0
			m.autoScroll = false
		}
	}
	return m, nil
}

// updateSendTask handles typing in the task input.
func (m InspectorModel) updateSendTask(msg tea.Msg) (InspectorModel, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch msg.String() {
		case "esc":
			m.sendingTask = false
			return m, nil
		case "enter":
			task := m.taskInput.Value()
			m.sendingTask = false
			if task == "" {
				return m, nil
			}
			return m, m.sendTaskCmd(task)
		}
	}

	var cmd tea.Cmd
	m.taskInput, cmd = m.taskInput.Update(msg)
	return m, cmd
}

// updateConfirmKill handles y/n for kill.
func (m InspectorModel) updateConfirmKill(msg tea.KeyMsg) (InspectorModel, tea.Cmd) {
	switch msg.String() {
	case "y":
		m.confirmKill = false
		return m, m.killCmd()
	case "n", "esc":
		m.confirmKill = false
	}
	return m, nil
}

// SetSize stores terminal dimensions.
func (m *InspectorModel) SetSize(w, h int) {
	m.width = w
	m.height = h
}

// HasAgent returns true if an agent is loaded.
func (m InspectorModel) HasAgent() bool {
	return m.agentID != ""
}

// logVisibleLines returns how many log lines fit given current height.
func (m InspectorModel) logVisibleLines() int {
	avail := m.height - 12
	if avail < 3 {
		avail = 3
	}
	return avail
}

// View renders the agent detail + output log.
func (m InspectorModel) View() string {
	if m.agentID == "" {
		return SubtitleStyle.Render("no agent selected — press enter on an agent in the list")
	}

	if m.err != nil {
		return ErrorStyle.Render(fmt.Sprintf("⚠ %v", m.err))
	}

	if m.agent == nil {
		return SubtitleStyle.Render("loading...")
	}

	a := m.agent
	header := TitleStyle.Render(fmt.Sprintf("Agent: %s", a.Name))

	var statusDot string
	if a.Status == "running" {
		statusDot = RunningDotStyle.Render("●") + " running"
	} else {
		statusDot = StoppedDotStyle.Render("○") + " " + a.Status
	}

	lines := []string{
		header,
		"",
		fmt.Sprintf("  ID:       %s", a.ID),
		fmt.Sprintf("  Status:   %s", statusDot),
		"",
	}

	// Output log section (live or polled)
	log := m.activeLog()
	logLabel := "Events"
	if m.liveMode {
		logLabel = "Live Output"
	}

	if len(log) == 0 {
		lines = append(lines, HelpStyle.Render("  (no events yet)"))
	} else {
		lines = append(lines, SubtitleStyle.Render(fmt.Sprintf("  %s (%d):", logLabel, len(log))))

		visible := m.logVisibleLines()
		start := m.logStart
		if start < 0 {
			start = 0
		}
		end := start + visible
		if end > len(log) {
			end = len(log)
		}

		for _, line := range log[start:end] {
			lines = append(lines, "  "+line)
		}

		if start > 0 {
			lines = append(lines, HelpStyle.Render("  ↑ scroll up for more"))
		}
		if end < len(log) {
			lines = append(lines, HelpStyle.Render("  ↓ scroll down for more"))
		}
	}

	if m.sendingTask {
		lines = append(lines, "", HelpStyle.Render("Task: ")+m.taskInput.View())
	}

	if m.confirmKill {
		lines = append(lines, "", ErrorStyle.Render(fmt.Sprintf("Kill %s? (y/n)", a.Name)))
	}

	return lipgloss.JoinVertical(lipgloss.Left, lines...)
}

// formatEvent renders a single polled event log entry as a compact one-liner.
func formatEvent(ev api.AgentEvent) string {
	switch ev.Event {
	case "agent_stream":
		text, _ := ev.Payload["text"].(string)
		if len(text) > 80 {
			text = text[:77] + "..."
		}
		return fmt.Sprintf("💬 %s", text)
	case "agent_tool_call":
		name, _ := ev.Payload["name"].(string)
		return fmt.Sprintf("🔧 tool: %s", name)
	case "agent_cost":
		sats, _ := ev.Payload["sats"].(float64)
		return fmt.Sprintf("💰 cost: %.0f sats", sats)
	case "agent_llm":
		// Parse errors leave the event unreadable; Describe then prints a
		// fixed line.
		llm, _ := ws.ParseLLMEvent(ev.Payload)
		if llm.Refused {
			return "⛔ " + llm.Describe()
		}
		return "🤖 " + llm.Describe()
	case "agent_complete":
		return "✅ task complete"
	case "agent_thought_capture":
		return "🧠 thought captured"
	case "agent_error":
		msg, _ := ev.Payload["message"].(string)
		return fmt.Sprintf("❌ error: %s", msg)
	default:
		return fmt.Sprintf("  %s", strings.ReplaceAll(ev.Event, "agent_", ""))
	}
}

// KeyHints returns contextual help for the status bar.
func (m InspectorModel) KeyHints() string {
	if m.sendingTask {
		return "enter send · esc cancel"
	}
	if m.confirmKill {
		return "y confirm · n cancel"
	}
	if m.agentID == "" {
		return "esc back"
	}
	return "↑/↓ scroll · G bottom · g top · t task · d kill · esc back · r refresh"
}

// Commands.

// fetchCmd fetches agent detail + event log in one shot.
func (m InspectorModel) fetchCmd() tea.Cmd {
	id := m.agentID
	return func() tea.Msg {
		agents, err := m.client.ListAgents()
		if err != nil {
			return inspectorErrMsg{err: err}
		}
		var agent *api.Agent
		for _, a := range agents {
			if a.ID == id {
				agent = &a
				break
			}
		}
		if agent == nil {
			return inspectorErrMsg{err: fmt.Errorf("agent %s not found", id)}
		}

		events, err := m.client.GetEventLog(id)
		if err != nil {
			events = nil
		}

		return inspectorFetchedMsg{agent: *agent, events: events}
	}
}

// tickCmd schedules the next automatic inspector refresh.
func (m InspectorModel) tickCmd() tea.Cmd {
	return tea.Tick(pollInterval, func(time.Time) tea.Msg {
		return inspectorTickMsg{}
	})
}

// sendTaskCmd sends a task string to the agent.
func (m InspectorModel) sendTaskCmd(task string) tea.Cmd {
	id := m.agentID
	return func() tea.Msg {
		err := m.client.SendTask(id, task)
		if err != nil {
			return flashMsg{text: fmt.Sprintf("task failed: %v", err)}
		}
		return flashMsg{text: "task sent"}
	}
}

// killCmd sends a kill request for the agent.
func (m InspectorModel) killCmd() tea.Cmd {
	id := m.agentID
	return func() tea.Msg {
		err := m.client.KillAgent(id)
		if err != nil {
			return flashMsg{text: fmt.Sprintf("kill failed: %v", err)}
		}
		return flashMsg{text: "agent killed"}
	}
}
