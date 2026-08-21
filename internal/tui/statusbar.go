// Copyright 2026 Jerry David Chan, Konareef.ai
// SPDX-License-Identifier: Apache-2.0

// internal/tui/statusbar.go

package tui

import (
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

// StatusBar renders connection state, active tab, and contextual key hints.
type StatusBar struct {
	connected   bool // REST API reachable
	wsConnected bool // WebSocket connected
	flash       string
	width       int
}

// NewStatusBar creates a StatusBar with default state.
func NewStatusBar() StatusBar {
	return StatusBar{connected: false, wsConnected: false}
}

// SetConnected updates the REST connection indicator.
func (s *StatusBar) SetConnected(ok bool) {
	s.connected = ok
}

// SetWsConnected updates the WebSocket connection indicator.
func (s *StatusBar) SetWsConnected(ok bool) {
	s.wsConnected = ok
}

// SetFlash sets a temporary message and returns a command to clear it.
func (s *StatusBar) SetFlash(text string) tea.Cmd {
	s.flash = text
	return tea.Tick(3*time.Second, func(time.Time) tea.Msg {
		return clearFlashMsg{}
	})
}

// ClearFlash removes the flash message.
func (s *StatusBar) ClearFlash() {
	s.flash = ""
}

// SetSize stores the terminal width for layout.
func (s *StatusBar) SetSize(width int) {
	s.width = width
}

// View renders the status bar as a single line.
func (s StatusBar) View(tabLabel string, hints string) string {
	// Connection dot: green = REST + WS, yellow = REST only, red = down
	var dot string
	if s.connected && s.wsConnected {
		dot = ConnectedStyle.Render("●")
	} else if s.connected {
		dot = lipgloss.NewStyle().Foreground(lipgloss.Color("#F39C12")).Render("●")
	} else {
		dot = DisconnectedStyle.Render("●")
	}

	left := dot + " " + ActiveTabStyle.Render(tabLabel)

	right := HelpStyle.Render(hints)
	if s.flash != "" {
		right = FlashStyle.Render(s.flash)
	}

	gap := s.width - lipgloss.Width(left) - lipgloss.Width(right)
	if gap < 1 {
		gap = 1
	}
	spacer := lipgloss.NewStyle().Width(gap).Render("")

	return StatusBarStyle.Render(left + spacer + right)
}
