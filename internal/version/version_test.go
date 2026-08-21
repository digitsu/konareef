// Copyright 2026 Jerry David Chan, Konareef.ai
// SPDX-License-Identifier: Apache-2.0

package version

import "testing"

// TestSeamVersion_IsPinnedLiteral pins the seam constant to a literal.
//
// Every other seam assertion on both sides of the handshake is
// self-referential — this repo's TestFeederSeamVersion_PrintsBareVersionAndExits
// compares the CLI's stdout against version.SeamVersion, and reef-core's
// fake feeder echoes FeederSpawner.expected_seam_version(). A unilateral
// bump on either side would therefore leave BOTH suites green while every
// beta run declined with :feeder_version_mismatch, because nothing compares
// the two constants to each other.
//
// This test, and its counterpart in reef-core's feeder_spawner_test.exs
// ("the expected seam version is exactly \"seam/1\""), pin the same literal
// on each side, so bumping the seam format forces a reviewable test edit in
// both repos rather than a silent divergence.
func TestSeamVersion_IsPinnedLiteral(t *testing.T) {
	if SeamVersion != "seam/1" {
		t.Fatalf("SeamVersion = %q, want %q — bumping the seam format requires a "+
			"lockstep change in reef-core's @expected_seam_version and its own "+
			"pinned-literal test", SeamVersion, "seam/1")
	}
}

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
