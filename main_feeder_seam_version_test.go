// Copyright 2026 Jerry David Chan, Konareef.ai
// SPDX-License-Identifier: Apache-2.0

// main_feeder_seam_version_test.go — black-box CLI exec test for the B1
// task-5 feeder/reef-core version handshake. reef-core shells out to
// `konareef feeder --seam-version` before spawning the feeder proper and
// parses the bare stdout to decide whether the seam formats match; this
// test pins that exact wire contract from the konareef side.
package main_test

import (
	"testing"

	"github.com/digitsu/konareef/internal/version"
)

// TestFeederSeamVersion_PrintsBareVersionAndExits verifies `konareef
// feeder --seam-version` prints exactly version.SeamVersion followed by
// a newline — nothing else on stdout, nothing on stderr — and exits 0
// without requiring any of the feeder's other flags. reef-core parses
// this stdout verbatim (see feeder_spawner.ex); any extra text (a log
// line, a prompt) would break that parse.
func TestFeederSeamVersion_PrintsBareVersionAndExits(t *testing.T) {
	bin := buildKonareef(t)

	stdout, stderr, code := runCLI(t, bin, nil, "feeder", "--seam-version")

	if code != 0 {
		t.Fatalf("exit code = %d, want 0; stderr=%s", code, stderr)
	}
	if stderr != "" {
		t.Fatalf("stderr = %q, want empty", stderr)
	}
	want := version.SeamVersion + "\n"
	if stdout != want {
		t.Fatalf("stdout = %q, want %q", stdout, want)
	}
}
