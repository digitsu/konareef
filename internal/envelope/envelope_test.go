// Copyright 2026 Jerry David Chan, Konareef.ai
// SPDX-License-Identifier: Apache-2.0

package envelope

import "testing"

func TestContains_ManifestInsideCommission(t *testing.T) {
	commission := Envelope{
		Models: []string{"anthropic/claude-opus-5", "anthropic/claude-sonnet-5"},
		Tools:  []string{"fs_read", "web_fetch"},
		CMax:   10000,
	}
	manifest := Envelope{
		Models: []string{"anthropic/claude-sonnet-5"},
		Tools:  []string{"fs_read"},
		CMax:   5000,
	}
	got := commission.Contains(manifest)
	if !got.OK {
		t.Fatalf("expected contained, got failures: %v", got.Failures)
	}
}

func TestContains_ToolNotPermitted(t *testing.T) {
	commission := Envelope{Models: []string{"m"}, Tools: []string{"fs_read"}, CMax: 10}
	manifest := Envelope{Models: []string{"m"}, Tools: []string{"fs_read", "web_fetch"}, CMax: 10}
	got := commission.Contains(manifest)
	if got.OK {
		t.Fatal("expected not contained")
	}
	if len(got.Failures) != 1 || got.Failures[0].Dimension != "tools" {
		t.Fatalf("want one tools failure, got %v", got.Failures)
	}
}

func TestContains_SpendExceeds(t *testing.T) {
	commission := Envelope{Models: []string{"m"}, Tools: []string{"t"}, CMax: 100}
	manifest := Envelope{Models: []string{"m"}, Tools: []string{"t"}, CMax: 101}
	got := commission.Contains(manifest)
	if got.OK || got.Failures[0].Dimension != "spend" {
		t.Fatalf("want spend failure, got %v", got)
	}
}

func TestContains_ReportsEveryFailedDimension(t *testing.T) {
	commission := Envelope{Models: []string{"a"}, Tools: []string{"t"}, CMax: 1}
	manifest := Envelope{Models: []string{"b"}, Tools: []string{"u"}, CMax: 2}
	got := commission.Contains(manifest)
	if len(got.Failures) != 3 {
		t.Fatalf("want 3 failures (models, tools, spend), got %d: %v", len(got.Failures), got.Failures)
	}
}
