// Copyright 2026 Jerry David Chan, Konareef.ai
// SPDX-License-Identifier: Apache-2.0

// main_feeder_circuit_default_test.go — black-box CLI test for the feeder
// --circuit-id default (VHASH-M1, paygate-zk#14, review finding L-3). A
// feeder run that does not name a circuit must prove v1.1, the circuit that
// binds value_hash_out, not the pre-VHASH v1.
package main_test

import (
	"strings"
	"testing"
)

// TestFeederCircuitIDDefaultsToV1_1 checks that `konareef feeder -h`
// reports konareef-pod-step-v1.1 as the --circuit-id default.
func TestFeederCircuitIDDefaultsToV1_1(t *testing.T) {
	bin := buildKonareef(t)

	_, stderr, _ := runCLI(t, bin, nil, "feeder", "-h")

	if !strings.Contains(stderr, `(default "konareef-pod-step-v1.1")`) {
		t.Fatalf("feeder -h does not show the v1.1 default; stderr=%s", stderr)
	}
}
