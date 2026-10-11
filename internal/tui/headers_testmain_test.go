// Copyright 2026 Jerry David Chan, Konareef.ai
// SPDX-License-Identifier: Apache-2.0

// headers_testmain_test.go: the test entry point of the tui package. It clears the default
// header services of the chain-head anchor check, so that no test here
// can reach the public header services, also if a future test fixture
// carries a chain-head anchor.
package tui

import (
	"os"
	"testing"

	"github.com/digitsu/konareef/internal/verify"
)

// TestMain clears verify.DefaultHeaderServices, turns off the node key
// file and the konabeans PATH lookup (so that the files and PATH of a
// developer cannot change a test result), and runs the tests.
// Input: m. Output: the exit code of the test run.
func TestMain(m *testing.M) {
	verify.DefaultHeaderServices = nil
	verify.DefaultNodeKeyFile = ""
	verify.DefaultVerifyBinName = ""
	_ = os.Setenv(verify.NodeKeyFileEnv, "")
	os.Exit(m.Run())
}
