// Copyright 2026 Jerry David Chan, Konareef.ai
// SPDX-License-Identifier: Apache-2.0

// internal/tui/styles_test.go
//
// Regression for the panel-background defect: lipgloss applies a block
// Background only as wide as the widest line, so ragged short lines get
// uncolored padding from JoinVertical and lose the panel background after
// their text. renderPanel must close that gap on every line.

package tui

import (
	"regexp"
	"strings"
	"testing"

	"github.com/charmbracelet/lipgloss"
	"github.com/muesli/termenv"
)

// uncoloredGap matches the defect: a reset, then 2+ plain spaces, then
// another reset — an interior run carrying no background.
var uncoloredGap = regexp.MustCompile(`\x1b\[0m {2,}\x1b\[0m`)

func countGapLines(s string) int {
	n := 0
	for _, ln := range strings.Split(s, "\n") {
		if uncoloredGap.MatchString(ln) {
			n++
		}
	}
	return n
}

// withTrueColor forces the global lipgloss profile to TrueColor for the
// duration of the test (the default renderer detects no-color under
// `go test`, which would strip every style) and restores it after so the
// change cannot leak into sibling tests.
func withTrueColor(t *testing.T) {
	t.Helper()
	prev := lipgloss.ColorProfile()
	lipgloss.SetColorProfile(termenv.TrueColor)
	t.Cleanup(func() { lipgloss.SetColorProfile(prev) })
}

func raggedBody() string {
	return lipgloss.JoinVertical(lipgloss.Left,
		TitleStyle.Render("konareef"),
		SubtitleStyle.Render("a much longer subtitle line here"),
		RunningDotStyle.Render("✅ ok"),
		"",
		ErrorStyle.Render("  • short"),
	)
}

// TestRenderPanel_NoUncoloredGaps is the core regression: the fixed
// renderer must leave zero uncolored interior gaps, while the old plain
// BoxStyle.Render path exhibits them (guarding that the test is meaningful).
func TestRenderPanel_NoUncoloredGaps(t *testing.T) {
	withTrueColor(t)
	body := raggedBody()

	if buggy := countGapLines(BoxStyle.Render(body)); buggy == 0 {
		t.Fatal("expected the plain BoxStyle.Render path to show uncolored gaps; test is not exercising the defect")
	}
	if got := countGapLines(renderPanel(body, 40)); got != 0 {
		t.Errorf("renderPanel left %d uncolored-gap line(s); want 0", got)
	}
}

// TestRenderPanel_AppliesBackground confirms the panel background SGR is
// actually emitted (i.e. the fill is colored, not just padded).
func TestRenderPanel_AppliesBackground(t *testing.T) {
	withTrueColor(t)
	out := renderPanel(raggedBody(), 40)
	const ultramarineBG = "48;2;10;31;60"
	if !strings.Contains(out, ultramarineBG) {
		t.Errorf("expected panel background %q in output", ultramarineBG)
	}
}

// TestRenderPanel_NonPositiveWidthDegrades guards the pre-layout path
// (width 0 before the first WindowSizeMsg) — it must not panic and must
// fall back to a plain box render.
func TestRenderPanel_NonPositiveWidthDegrades(t *testing.T) {
	withTrueColor(t)
	body := raggedBody()
	if got := renderPanel(body, 0); got != BoxStyle.Render(body) {
		t.Error("non-positive innerWidth should degrade to a plain BoxStyle.Render")
	}
}
