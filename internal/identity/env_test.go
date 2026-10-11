// Copyright 2026 Jerry David Chan, Konareef.ai
// SPDX-License-Identifier: Apache-2.0

// env_test.go — unit tests for the KONAREEF_STRICT_DER_GATE env-var initializer.
//
// These tests cover LoadEnv(), the only path by which the application binary
// activates StrictDerGateEnabled from an environment variable. Running
//
//	go test ./internal/identity/...
//
// with KONAREEF_STRICT_DER_GATE=true set therefore exercises the same
// code path that main() uses, satisfying the P1.4 smoke-test requirement
// without needing to invoke the compiled binary.
package identity

import (
	"testing"
)

// TestLoadEnv_EnablesStrictDerGate verifies that LoadEnv sets
// StrictDerGateEnabled to true when KONAREEF_STRICT_DER_GATE=true.
func TestLoadEnv_EnablesStrictDerGate(t *testing.T) {
	// Reset flag before and after so parallel tests are unaffected.
	orig := StrictDerGateEnabled
	StrictDerGateEnabled = false
	t.Cleanup(func() { StrictDerGateEnabled = orig })

	t.Setenv("KONAREEF_STRICT_DER_GATE", "true")
	LoadEnv()

	if !StrictDerGateEnabled {
		t.Fatal("LoadEnv(): StrictDerGateEnabled is false, want true when KONAREEF_STRICT_DER_GATE=true")
	}
}

// TestLoadEnv_DefaultsOff verifies that LoadEnv leaves StrictDerGateEnabled
// false when KONAREEF_STRICT_DER_GATE is unset (the zero-value default).
func TestLoadEnv_DefaultsOff(t *testing.T) {
	orig := StrictDerGateEnabled
	StrictDerGateEnabled = false
	t.Cleanup(func() { StrictDerGateEnabled = orig })

	// Ensure the env var is absent for this test.
	t.Setenv("KONAREEF_STRICT_DER_GATE", "")
	LoadEnv()

	if StrictDerGateEnabled {
		t.Fatal("LoadEnv(): StrictDerGateEnabled is true, want false when KONAREEF_STRICT_DER_GATE is unset")
	}
}

// TestLoadEnv_IgnoresNonTrueValues verifies that LoadEnv does not enable
// the gate for truthy-but-not-"true" values such as "1", "yes", "TRUE".
func TestLoadEnv_IgnoresNonTrueValues(t *testing.T) {
	for _, val := range []string{"1", "yes", "TRUE", "on"} {
		val := val
		t.Run(val, func(t *testing.T) {
			orig := StrictDerGateEnabled
			StrictDerGateEnabled = false
			t.Cleanup(func() { StrictDerGateEnabled = orig })

			t.Setenv("KONAREEF_STRICT_DER_GATE", val)
			LoadEnv()

			if StrictDerGateEnabled {
				t.Fatalf("LoadEnv(): StrictDerGateEnabled is true for KONAREEF_STRICT_DER_GATE=%q, want false (only exact \"true\" activates the gate)", val)
			}
		})
	}
}
