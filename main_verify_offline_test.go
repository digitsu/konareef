// Copyright 2026 Jerry David Chan, Konareef.ai
// SPDX-License-Identifier: Apache-2.0

// main_verify_offline_test.go: tests for the usage errors of
// `konareef verify` that come from the anchor flags and environment
// (--offline, KONAREEF_OFFLINE, KONAREEF_MIN_CONFIRMATIONS). Each case
// runs runVerify in a child test process and checks for exit code 2 and
// the error message, before any bundle source is read.
package main

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// Environment variables of the child test process: the first makes it
// run runVerify, the second carries its arguments (separated by 0x1F).
const (
	verifyOfflineSubprocessEnv = "VERIFY_OFFLINE_SUBPROCESS"
	verifyOfflineArgsEnv       = "VERIFY_OFFLINE_ARGS"
)

// TestRunVerify_AnchorConfigUsageErrors: a malformed anchor environment
// variable, or --offline with header URLs from a flag or the
// environment, makes runVerify print the error and the usage text and
// exit 2. The bundle is a v1 JSON file, which never reaches the v2 anchor
// check, so only the parse-time check can report these errors.
func TestRunVerify_AnchorConfigUsageErrors(t *testing.T) {
	if os.Getenv(verifyOfflineSubprocessEnv) == "1" {
		runVerify(strings.Split(os.Getenv(verifyOfflineArgsEnv), "\x1f"))
		// Reached only if runVerify did not exit.
		os.Exit(0)
	}

	bundlePath := filepath.Join(t.TempDir(), "bundle.json")
	if err := os.WriteFile(bundlePath, []byte(`{}`), 0o600); err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name        string
		args        []string
		env         []string
		wantMessage string
	}{
		{"bogus KONAREEF_OFFLINE", []string{bundlePath},
			[]string{"KONAREEF_OFFLINE=bogus"}, `KONAREEF_OFFLINE="bogus"`},
		{"bad KONAREEF_MIN_CONFIRMATIONS", []string{bundlePath},
			[]string{"KONAREEF_MIN_CONFIRMATIONS=many"}, `KONAREEF_MIN_CONFIRMATIONS="many"`},
		{"offline flag with header url flag", []string{"--offline", "--headers-url", "https://a.example", bundlePath},
			nil, "--offline cannot be combined with --headers-url"},
		{"offline env with header urls env", []string{bundlePath},
			[]string{"KONAREEF_OFFLINE=1", "KONAREEF_HEADERS_URLS=https://a.example,https://b.example"},
			"--offline cannot be combined with --headers-url"},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			cmd := exec.Command(os.Args[0], "-test.run=^TestRunVerify_AnchorConfigUsageErrors$")
			cmd.Env = append(os.Environ(),
				verifyOfflineSubprocessEnv+"=1",
				verifyOfflineArgsEnv+"="+strings.Join(testCase.args, "\x1f"),
				"KONAREEF_OFFLINE=", "KONAREEF_HEADERS_URLS=", "KONAREEF_MIN_CONFIRMATIONS=")
			cmd.Env = append(cmd.Env, testCase.env...)
			output, err := cmd.CombinedOutput()
			var exitErr *exec.ExitError
			if !errors.As(err, &exitErr) || exitErr.ExitCode() != 2 {
				t.Fatalf("err = %v, want exit code 2\n%s", err, output)
			}
			if !strings.Contains(string(output), testCase.wantMessage) {
				t.Fatalf("output does not name the error %q:\n%s", testCase.wantMessage, output)
			}
			if !strings.Contains(string(output), "usage: konareef verify") {
				t.Fatalf("output has no usage text:\n%s", output)
			}
		})
	}
}
