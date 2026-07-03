// internal/tui/app.go
//
// App is the root Bubble Tea model for KonaReef. It owns all sub-models
// (AgentsModel, BudgetModel, InspectorModel) and the StatusBar, handles tab
// switching via keyboard, and delegates updates and rendering to the active tab.

package tui

import (
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"github.com/digitsu/konareef/internal/api"
	"github.com/digitsu/konareef/internal/ws"
)

// tab identifies which view is active.
type tab int

const (
	tabAgents tab = iota
	tabBudget
	tabInspector
)

var tabNames = []string{"Agents", "Budget", "Inspector"}

// App is the root Bubble Tea model that owns sub-models and tab switching.
type App struct {
	client    *api.Client
	wsClient  *ws.Client
	activeTab tab
	agents    AgentsModel
	budget    BudgetModel
	inspector InspectorModel
	statusbar StatusBar
	width     int
	height    int
}

// NewApp creates the root model wired to the given reef-core client and an
// optional WebSocket client (may be nil if no session token is available).
func NewApp(client *api.Client, wsClient *ws.Client) App {
	return App{
		client:    client,
		wsClient:  wsClient,
		activeTab: tabAgents,
		agents:    NewAgentsModel(client),
		budget:    NewBudgetModel(client),
		inspector: NewInspectorModel(client),
		statusbar: NewStatusBar(),
	}
}

// Init starts the default tab's polling.
func (a App) Init() tea.Cmd {
	return a.agents.Init()
}

// Update handles global keys, then delegates to the active sub-model.
func (a App) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		a.width = msg.Width
		a.height = msg.Height
		// Reserve space for box border (2) + padding (2) + status bar (2) + tab bar (1).
		innerW := msg.Width - 8
		innerH := msg.Height - 8
		a.agents.SetSize(innerW, innerH)
		a.budget.SetSize(innerW, innerH)
		a.inspector.SetSize(innerW, innerH)
		a.statusbar.SetSize(innerW)
		return a, nil

	// ── WebSocket connection lifecycle ──
	case wsConnectedMsg:
		a.statusbar.SetWsConnected(true)
		return a, nil

	case wsDisconnectedMsg:
		a.statusbar.SetWsConnected(false)
		return a, nil

	// ── WebSocket agent events → inspector ──
	case wsStreamMsg:
		a.inspector.AppendStream(msg.Data)
		return a, nil

	case wsToolCallMsg:
		a.inspector.AppendToolCall(msg.Tool)
		return a, nil

	case wsCostMsg:
		a.inspector.AppendCost(msg.Sats)
		return a, nil

	// ── WebSocket pod-wide cost → budget tab ──
	// pod:events forwards every agent's cost deltas so the Budget tab
	// updates live regardless of which agent (if any) is inspected.
	case wsPodCostMsg:
		a.budget.ApplyCost(msg.AgentID, msg.Sats)
		return a, nil

	case wsCompleteMsg:
		a.inspector.AppendComplete(msg.Result)
		return a, a.agents.fetchCmd()

	case wsErrorMsg:
		a.inspector.AppendError(msg.Message)
		return a, nil

	// ── WebSocket pod lifecycle → agent list refresh ──
	case wsAgentStarted:
		return a, a.agents.fetchCmd()

	case wsAgentExited:
		return a, a.agents.fetchCmd()

	case tea.KeyMsg:
		// Global keys — only when no sub-model is capturing input.
		switch msg.String() {
		case "ctrl+c", "q":
			if a.wsClient != nil {
				a.wsClient.Close()
			}
			return a, tea.Quit
		case "1":
			a.activeTab = tabAgents
			return a, a.fetchForTab(tabAgents)
		case "2":
			a.activeTab = tabBudget
			return a, a.fetchForTab(tabBudget)
		case "3":
			a.activeTab = tabInspector
			return a, a.fetchForTab(tabInspector)
		case "tab":
			next := (a.activeTab + 1) % 3
			a.activeTab = next
			return a, a.fetchForTab(next)
		case "shift+tab":
			prev := (a.activeTab + 2) % 3
			a.activeTab = prev
			return a, a.fetchForTab(prev)
		}

		// Agent list: Enter opens inspector — but NOT when the agents model
		// is capturing input (e.g. the spawn task prompt). In that case the
		// Enter key must reach AgentsModel.updateSpawn to submit the task.
		if a.activeTab == tabAgents && msg.String() == "enter" && !a.agents.IsCapturingInput() {
			if agent, ok := a.agents.SelectedAgent(); ok {
				a.activeTab = tabInspector
				cmd := a.inspector.SetAgent(agent.ID)
				if a.wsClient != nil {
					a.wsClient.JoinAgent(agent.ID)
				}
				return a, cmd
			}
		}

		// Inspector: Esc goes back to agents.
		if a.activeTab == tabInspector && msg.String() == "esc" && !a.inspector.sendingTask && !a.inspector.confirmKill {
			if a.wsClient != nil {
				a.wsClient.LeaveAgent()
			}
			a.activeTab = tabAgents
			return a, a.fetchForTab(tabAgents)
		}

	case flashMsg:
		cmd := a.statusbar.SetFlash(msg.text)
		return a, cmd

	case clearFlashMsg:
		a.statusbar.ClearFlash()
		return a, nil

	// Update connection indicator based on fetch results.
	case agentsFetchedMsg:
		a.statusbar.SetConnected(true)
	case agentsErrMsg:
		a.statusbar.SetConnected(false)
	case budgetFetchedMsg:
		a.statusbar.SetConnected(true)
	case budgetErrMsg:
		a.statusbar.SetConnected(false)
	case inspectorFetchedMsg:
		a.statusbar.SetConnected(true)
	case inspectorErrMsg:
		a.statusbar.SetConnected(false)
	}

	// Delegate to active sub-model.
	var cmd tea.Cmd
	switch a.activeTab {
	case tabAgents:
		a.agents, cmd = a.agents.Update(msg)
	case tabBudget:
		a.budget, cmd = a.budget.Update(msg)
	case tabInspector:
		a.inspector, cmd = a.inspector.Update(msg)
	}
	return a, cmd
}

// View renders the tab bar, active view, and status bar inside the styled box.
func (a App) View() string {
	// Tab bar.
	var tabs []string
	for i, name := range tabNames {
		if tab(i) == a.activeTab {
			tabs = append(tabs, ActiveTabStyle.Render(name))
		} else {
			tabs = append(tabs, InactiveTabStyle.Render(name))
		}
	}
	tabBar := lipgloss.JoinHorizontal(lipgloss.Top, tabs[0], "  ", tabs[1], "  ", tabs[2])

	// Active view.
	var view, hints string
	switch a.activeTab {
	case tabAgents:
		view = a.agents.View()
		hints = a.agents.KeyHints()
	case tabBudget:
		view = a.budget.View()
		hints = a.budget.KeyHints()
	case tabInspector:
		view = a.inspector.View()
		hints = a.inspector.KeyHints()
	}

	// Status bar.
	statusBar := a.statusbar.View(tabNames[a.activeTab], hints)

	body := lipgloss.JoinVertical(lipgloss.Left, tabBar, "", view, statusBar)
	// Fill each line to the inner content width so the panel background
	// covers ragged short lines (border 2 + horizontal padding 6 = 8).
	return renderPanel(body, a.width-8)
}

// fetchForTab returns the initial fetch command for the given tab without
// mutating any state. Called after activeTab has already been set in Update.
func (a App) fetchForTab(t tab) tea.Cmd {
	switch t {
	case tabAgents:
		return a.agents.fetchCmd()
	case tabBudget:
		return a.budget.fetchCmd()
	case tabInspector:
		if a.inspector.HasAgent() {
			return a.inspector.fetchCmd()
		}
	}
	return nil
}
