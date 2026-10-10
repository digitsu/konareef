// Copyright 2026 Jerry David Chan, Konareef.ai
// SPDX-License-Identifier: Apache-2.0

// Publish-time handling of a reserved [dependencies].secrets name
// (secret_reserved), in parity with reef-core's SecretsVault list.
package publish

import (
	"strings"
	"testing"

	"github.com/digitsu/konareef/internal/pod"
)

// TestPrepareWarnsOnAReservedDependencySecret checks that publish carries
// a secret_reserved warning for a [dependencies].secrets name reef-core
// reserves (here one of the two OpenCode flags P3-07 sets), and does not
// refuse the pod, because a self-host reef-core can still run it. The
// control publishes the same pod with a plain name and gets no warning.
func TestPrepareWarnsOnAReservedDependencySecret(t *testing.T) {
	withSecret := func(name string) string {
		return strings.Replace(validMemoryFreePodTOML, "[directive]",
			"[dependencies]\nsecrets = [\""+name+"\"]\n\n[directive]", 1)
	}
	reservedWarnings := func(prepared *PreparedPod) int {
		count := 0
		for _, warning := range prepared.Warnings {
			if warning.Code == pod.CodeSecretReserved && warning.Path == "dependencies.secrets[0]" {
				count++
			}
		}
		return count
	}
	for _, name := range []string{"OPENCODE_DISABLE_PROJECT_CONFIG", "REEF_RUN_CREDENTIAL", "ANTHROPIC_BASE_URL"} {
		prepared, err := Prepare(writePodFixture(t, withSecret(name)), testIdentity(t), PrepareOptions{})
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if reservedWarnings(prepared) != 1 {
			t.Fatalf("%s: warnings = %v, want one secret_reserved", name, prepared.Warnings)
		}
	}
	prepared, err := Prepare(writePodFixture(t, withSecret("ELEVENLABS_API_KEY")), testIdentity(t), PrepareOptions{})
	if err != nil || reservedWarnings(prepared) != 0 {
		t.Fatalf("control: err=%v warnings=%v", err, prepared.Warnings)
	}
}
