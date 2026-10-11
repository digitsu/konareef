// Copyright 2026 Jerry David Chan, Konareef.ai
// SPDX-License-Identifier: Apache-2.0

// Package tui implements the KonaReef terminal interface.
package tui

import (
	"strings"

	"github.com/charmbracelet/lipgloss"
)

// KonaReef dark-mode palette — matches the konareef.ai hero illustration.
var (
	ColorUltramarine = lipgloss.Color("#0A1F3D")
	ColorCerulean    = lipgloss.Color("#4EA5D9")
	ColorLobsterRed  = lipgloss.Color("#E63946")
	ColorTurquoise   = lipgloss.Color("#40E0D0")
	ColorInk         = lipgloss.Color("#E6F1FF")
	ColorMuted       = lipgloss.Color("#6B7C93")
	ColorGreen       = lipgloss.Color("#2ECC71")
	ColorRed         = lipgloss.Color("#E74C3C")
)

var (
	TitleStyle = lipgloss.NewStyle().
			Foreground(ColorCerulean).
			Bold(true).
			MarginBottom(1)

	SubtitleStyle = lipgloss.NewStyle().
			Foreground(ColorMuted).
			Italic(true).
			MarginBottom(1)

	CursorStyle = lipgloss.NewStyle().
			Foreground(ColorLobsterRed).
			Bold(true)

	RunningNameStyle = lipgloss.NewStyle().
				Foreground(ColorInk)

	StoppedNameStyle = lipgloss.NewStyle().
				Foreground(ColorMuted).
				Faint(true)

	RunningDotStyle = lipgloss.NewStyle().
			Foreground(ColorTurquoise)

	StoppedDotStyle = lipgloss.NewStyle().
			Foreground(ColorMuted)

	HelpStyle = lipgloss.NewStyle().
			Foreground(ColorMuted).
			Italic(true).
			MarginTop(1)

	BoxStyle = lipgloss.NewStyle().
			Border(lipgloss.RoundedBorder()).
			BorderForeground(ColorCerulean).
			Background(ColorUltramarine).
			Padding(1, 3)

	// Tab bar styles.
	ActiveTabStyle = lipgloss.NewStyle().
			Foreground(ColorCerulean).
			Bold(true).
			Underline(true)

	InactiveTabStyle = lipgloss.NewStyle().
				Foreground(ColorMuted)

	// Status bar styles.
	StatusBarStyle = lipgloss.NewStyle().
			Foreground(ColorMuted).
			MarginTop(1)

	ConnectedStyle = lipgloss.NewStyle().
			Foreground(ColorGreen)

	DisconnectedStyle = lipgloss.NewStyle().
				Foreground(ColorRed)

	// Error and flash styles.
	ErrorStyle = lipgloss.NewStyle().
			Foreground(ColorRed)

	FlashStyle = lipgloss.NewStyle().
			Foreground(ColorTurquoise)
)

// renderPanel background-fills every line of body to innerWidth and wraps
// the result in the bordered BoxStyle.
//
// lipgloss applies a block Background only as wide as the widest line, so
// ragged shorter lines get plain (uncolored) padding from JoinVertical and
// their background reverts to the terminal default after the text ends.
// Pre-filling each line to a uniform innerWidth with a background-bearing
// style closes that gap. innerWidth is the content width inside the box
// padding; callers derive it from the available width (total - border -
// horizontal padding). A non-positive innerWidth (pre-layout) degrades to
// a plain box render. See styles_test.go for the regression.
func renderPanel(body string, innerWidth int) string {
	if innerWidth < 1 {
		return BoxStyle.Render(body)
	}
	fill := lipgloss.NewStyle().Background(ColorUltramarine).Width(innerWidth)
	lines := strings.Split(body, "\n")
	for i, ln := range lines {
		// Strip JoinVertical's uncolored trailing padding first: lipgloss
		// won't recolor spaces that already sit inside the line, so the
		// fill must re-add the right pad itself (as background). Left-
		// aligned joins only ever right-pad, so trailing spaces are safe
		// to drop.
		lines[i] = fill.Render(strings.TrimRight(ln, " "))
	}
	return BoxStyle.Render(strings.Join(lines, "\n"))
}
