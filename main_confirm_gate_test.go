// Copyright 2026 Jerry David Chan, Konareef.ai
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// buildGateCLI compiles the binary once per test that needs it.
func buildGateCLI(t *testing.T) string {
	t.Helper()
	bin := filepath.Join(t.TempDir(), "konareef")
	if out, err := exec.Command("go", "build", "-o", bin, ".").CombinedOutput(); err != nil {
		t.Fatalf("build konareef: %v\n%s", err, out)
	}
	return bin
}

// The gate's central property. A caller with no terminal and no flag must be
// refused. Anything else is a default yes handed to whoever cannot answer,
// which is exactly the case the gate exists for: an agent running headless.
func TestConfirmOrExit_FailsClosedWithoutTerminalOrFlag(t *testing.T) {
	restore := stdinIsTerminal
	stdinIsTerminal = func() bool { return false }
	defer func() { stdinIsTerminal = restore }()

	if os.Getenv("GATE_SUBPROCESS") == "1" {
		confirmOrExit(false, confirmFlagPublish, "do something irreversible")
		// Reached only if the gate wrongly allowed the action.
		os.Exit(0)
	}

	cmd := exec.Command(os.Args[0], "-test.run=TestConfirmOrExit_FailsClosedWithoutTerminalOrFlag")
	cmd.Env = append(os.Environ(), "GATE_SUBPROCESS=1")
	out, err := cmd.CombinedOutput()

	if err == nil {
		t.Fatal("gate allowed the action with no terminal and no flag; it must refuse")
	}
	exitErr, ok := err.(*exec.ExitError)
	if !ok {
		t.Fatalf("expected the gate to exit, got %v", err)
	}
	if exitErr.ExitCode() != 3 {
		t.Fatalf("exit code = %d, want 3", exitErr.ExitCode())
	}
	if !strings.Contains(string(out), "refusing to continue without confirmation") {
		t.Fatalf("refusal did not explain itself:\n%s", out)
	}
	if !strings.Contains(string(out), "--"+confirmFlagPublish) {
		t.Fatalf("refusal did not name the flag that would work:\n%s", out)
	}
}

// The flag is the documented way through, so it must actually work.
func TestConfirmOrExit_FlagAllowsTheAction(t *testing.T) {
	restore := stdinIsTerminal
	stdinIsTerminal = func() bool { return false }
	defer func() { stdinIsTerminal = restore }()

	// Returns normally, or the process dies and the test fails with it.
	confirmOrExit(true, confirmFlagPublish, "do something irreversible")
}

// One approval must not cover both commands. A shared flag would let a single
// "yes, publish" authorise a run that spends money, which is the seam this
// design exists to close.
func TestConfirmFlags_ArePerCommandAndDistinct(t *testing.T) {
	flags := map[string]string{
		"publish": confirmFlagPublish,
		"run":     confirmFlagSpend,
		"listing": confirmFlagFee,
	}
	seen := map[string]string{}
	for cmd, f := range flags {
		if other, dup := seen[f]; dup {
			t.Fatalf("%s and %s share the flag --%s; one approval would cover both", cmd, other, f)
		}
		seen[f] = cmd
	}
	bin := buildGateCLI(t)

	// `pod run` must reject the publish flag, and vice versa. An unknown flag
	// makes flag.ExitOnError exit 2 before anything can happen.
	for _, tc := range []struct {
		name string
		args []string
	}{
		{"run rejects the publish flag", []string{"pod", "run", "--" + confirmFlagPublish, "h/p@0.1.0", "--out", "."}},
		{"publish rejects the spend flag", []string{"pod", "publish", "--" + confirmFlagSpend, "."}},
		{"publish rejects the fee flag", []string{"pod", "publish", "--" + confirmFlagFee, "."}},
		{"run rejects the fee flag", []string{"pod", "run", "--" + confirmFlagFee, "h/p@0.1.0", "--out", "."}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			out, err := exec.Command(bin, tc.args...).CombinedOutput()
			if err == nil {
				t.Fatalf("command accepted the other command's flag:\n%s", out)
			}
			if !strings.Contains(string(out), "flag provided but not defined") {
				t.Fatalf("expected an unknown-flag rejection, got:\n%s", out)
			}
		})
	}
}

// The rehearsal step must stay free and unprompted, or agents lose the safe
// way to prove a pod is publishable and the gate becomes an obstacle to
// doing the right thing.
func TestPublishDryRun_IsNotGated(t *testing.T) {
	bin := buildGateCLI(t)
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "pod.toml"), []byte(
		"pod_spec_version = \"0.1\"\n\n[pod]\nname = \"gate-check\"\nversion = \"0.1.0\"\n\n"+
			"[runtime]\nkind = \"lobster\"\n\n[directive]\ntask = \"Say hello.\"\n"), 0o644); err != nil {
		t.Fatalf("write pod.toml: %v", err)
	}

	out, _ := exec.Command(bin, "pod", "publish", "--dry-run", dir).CombinedOutput()
	// The dry run may still fail for unrelated local reasons (no identity on
	// this machine). What must never appear is the gate's refusal.
	if strings.Contains(string(out), "refusing to continue without confirmation") {
		t.Fatalf("--dry-run hit the confirmation gate; rehearsal must stay free:\n%s", out)
	}
}
