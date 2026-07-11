// Copyright 2026 Jerry David Chan, Konareef.ai
// SPDX-License-Identifier: Apache-2.0

// internal/tui/messages.go

package tui

import (
	"github.com/digitsu/konareef/internal/api"
	"github.com/digitsu/konareef/internal/ws"
)

// Async fetch results — each sub-model handles its own message types.

// agentsFetchedMsg carries a successful agent list fetch.
type agentsFetchedMsg struct{ agents []api.Agent }

// agentsErrMsg carries an agent list fetch error.
type agentsErrMsg struct{ err error }

// budgetFetchedMsg carries a successful budget fetch.
type budgetFetchedMsg struct{ budget api.Budget }

// budgetErrMsg carries a budget fetch error.
type budgetErrMsg struct{ err error }

// inspectorFetchedMsg carries a successful agent + event log fetch.
type inspectorFetchedMsg struct {
	agent  api.Agent
	events []api.AgentEvent
}

// inspectorErrMsg carries an inspector fetch error.
type inspectorErrMsg struct{ err error }

// Tick messages — trigger a re-fetch on the active tab's polling interval.
type agentsTickMsg struct{}
type budgetTickMsg struct{}
type inspectorTickMsg struct{}

// flashMsg displays a temporary message in the status bar.
type flashMsg struct{ text string }

// clearFlashMsg clears the status bar flash.
type clearFlashMsg struct{}

// WebSocket event messages — re-exported from internal/ws for use in
// sub-model Update handlers without importing ws directly.
type (
	wsConnectedMsg    = ws.WsConnectedMsg
	wsDisconnectedMsg = ws.WsDisconnectedMsg
	wsStreamMsg       = ws.WsStreamMsg
	wsToolCallMsg     = ws.WsToolCallMsg
	wsCostMsg         = ws.WsCostMsg
	wsPodCostMsg      = ws.WsPodCostMsg
	wsCompleteMsg     = ws.WsCompleteMsg
	wsErrorMsg        = ws.WsErrorMsg
	wsAgentStarted    = ws.WsAgentStarted
	wsAgentExited     = ws.WsAgentExited
)
