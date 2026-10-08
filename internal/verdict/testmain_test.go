// Copyright 2026 Jerry David Chan, Konareef.ai
// SPDX-License-Identifier: Apache-2.0

// testmain_test.go: the test entry point of the verdict package. It keeps
// the tests here away from the configuration of the developer: no default
// header services, no node key file (~/.proof_server_node_key) and no
// konabeans lookup on PATH.
package verdict

import (
	"os"
	"testing"

	"github.com/digitsu/konareef/internal/verify"
)

// TestMain clears verify.DefaultHeaderServices, turns off the node key
// file and the konabeans PATH lookup, and runs the tests.
// Input: m. Output: the exit code of the test run.
func TestMain(m *testing.M) {
	verify.DefaultHeaderServices = nil
	verify.DefaultNodeKeyFile = ""
	verify.DefaultVerifyBinName = ""
	_ = os.Setenv(verify.NodeKeyFileEnv, "")
	os.Exit(m.Run())
}
