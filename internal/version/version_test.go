// Copyright 2026 Jerry David Chan, Konareef.ai
// SPDX-License-Identifier: Apache-2.0

package version

import "testing"

// TestStringLdflagsWins verifies that an ldflags-injected version takes
// precedence over build-info fallback and is returned verbatim.
func TestStringLdflagsWins(t *testing.T) {
	prev := version
	t.Cleanup(func() { version = prev })

	version = "v1.2.3"
	if got := String(); got != "v1.2.3" {
		t.Fatalf("String() = %q, want %q", got, "v1.2.3")
	}
}

// TestStringNeverEmpty verifies the fallback chain never yields an empty
// string, even when no ldflags value is injected (the `go test` case, where
// build info reports "(devel)" or is absent).
func TestStringNeverEmpty(t *testing.T) {
	prev := version
	t.Cleanup(func() { version = prev })

	version = ""
	if got := String(); got == "" {
		t.Fatal("String() returned empty; want non-empty fallback")
	}
}
