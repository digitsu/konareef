// Copyright 2026 Jerry David Chan, Konareef.ai
// SPDX-License-Identifier: Apache-2.0

// main_verify_containment_test.go: tests of the containment row of
// `konareef verify` (US-111; reef-core OpenShell adapter, phase 2, design
// section 8.4). Each case runs runVerify in a child test process on a
// golden OpenShell bundle and checks the text report, the JSON field
// "containment" and the exit code of --strict.
package main

import (
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// Environment variables of the child test process: the first makes it run
// runVerify, the second carries its arguments (separated by 0x1F).
const (
	verifyContainmentSubprocessEnv = "VERIFY_CONTAINMENT_SUBPROCESS"
	verifyContainmentArgsEnv       = "VERIFY_CONTAINMENT_ARGS"
)

// openShellGoldenDir holds the reef-core OpenShell golden bundles.
var openShellGoldenDir = filepath.Join("internal", "verify", "testdata", "openshell_custody")

// runVerifyChild runs `konareef verify args...` in a child test process.
//
// Input: the arguments. Output: the combined output and the exit code.
func runVerifyChild(t *testing.T, args ...string) (string, int) {
	t.Helper()
	cmd := exec.Command(os.Args[0], "-test.run=^TestRunVerify_Containment$")
	cmd.Env = append(os.Environ(),
		verifyContainmentSubprocessEnv+"=1",
		verifyContainmentArgsEnv+"="+strings.Join(args, "\x1f"),
		"KONAREEF_OFFLINE=", "KONAREEF_HEADERS_URLS=", "KONAREEF_MIN_CONFIRMATIONS=")
	output, err := cmd.CombinedOutput()
	code := 0
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		code = exitErr.ExitCode()
	} else if err != nil {
		t.Fatalf("run child: %v", err)
	}
	return string(output), code
}

// TestRunVerify_Containment: the report prints the grade, the reasons and
// the informational lines; the JSON report has the containment field with
// the design 8.1 names; --strict fails the public OpenShell bundle on its
// grade.
func TestRunVerify_Containment(t *testing.T) {
	if os.Getenv(verifyContainmentSubprocessEnv) == "1" {
		runVerify(strings.Split(os.Getenv(verifyContainmentArgsEnv), "\x1f"))
		os.Exit(0)
	}
	verifiable := filepath.Join(openShellGoldenDir, "full.bundle.json")
	public := filepath.Join(openShellGoldenDir, "full.public.bundle.json")

	t.Run("text report of the public bundle", func(t *testing.T) {
		output, code := runVerifyChild(t, public)
		if code == 1 {
			t.Fatalf("verify failed:\n%s", output)
		}
		for _, want := range []string{
			"Containment (isolation backend, full form): claimed, redacted",
			"  - reason: evidence withheld in the public bundle; verify the verifiable bundle for operator_attested",
			"  - info: supervisor session ended at the stop (informational)",
			"operator attested: the node operator's own software recorded this. It is not a proof against the operator.",
		} {
			if !strings.Contains(output, want) {
				t.Errorf("report lacks %q:\n%s", want, output)
			}
		}
	})

	t.Run("JSON report of the verifiable bundle", func(t *testing.T) {
		output, code := runVerifyChild(t, verifiable, "--json")
		if code == 1 {
			t.Fatalf("verify failed:\n%s", output)
		}
		var doc struct {
			OK          bool           `json:"ok"`
			Containment map[string]any `json:"containment"`
		}
		if err := json.Unmarshal([]byte(output), &doc); err != nil {
			t.Fatalf("JSON: %v\n%s", err, output)
		}
		if !doc.OK || doc.Containment["grade"] != "operator_attested" || doc.Containment["form"] != "full" {
			t.Errorf("ok %t containment %v", doc.OK, doc.Containment)
		}
		for _, key := range []string{"grade", "form", "reasons", "redacted", "gapless", "policy_changed",
			"drain_end_seq", "supervisor_markers", "listener_served", "listener_seen", "policy_v1_source",
			"cross_check", "informational"} {
			if _, ok := doc.Containment[key]; !ok {
				t.Errorf("containment lacks %q: %v", key, doc.Containment)
			}
		}
	})

	t.Run("strict fails the public bundle on its grade", func(t *testing.T) {
		output, code := runVerifyChild(t, public, "--strict")
		if code != 1 {
			t.Fatalf("exit %d, want 1:\n%s", code, output)
		}
		if !strings.Contains(output, "--strict requires containment grade operator_attested for a bundle with an isolation backend; grade is claimed") {
			t.Errorf("output lacks the containment divergence:\n%s", output)
		}
	})
}
