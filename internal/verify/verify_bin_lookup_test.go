// Copyright 2026 Jerry David Chan, Konareef.ai
// SPDX-License-Identifier: Apache-2.0

// verify_bin_lookup_test.go: tests for how the production path finds the
// SNARK verifier (ZK-008). KONAREEF_VERIFY_BIN, when set, wins. When it
// is not set, konareef uses "konabeans" on PATH. With neither, the
// verdict fails closed as before (ERR_SNARK_VERIFIER_NOT_CONFIGURED,
// proof_valid=false). TestMain turns the PATH lookup off; each test here
// turns it on with useDefaultVerifyBinName.
package verify

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

// acceptingVerifierStderr is the stderr of a verifier that accepts and
// confirms the pod-step schedule and c checks.
const acceptingVerifierStderr = "verify: pod_step_schedule=checked\nverify: c_total=checked\nverify: ACCEPT\n"

// useDefaultVerifyBinName sets DefaultVerifyBinName for one test and puts
// back the previous value when the test ends. Inputs: t, binaryName.
func useDefaultVerifyBinName(t *testing.T, binaryName string) {
	t.Helper()
	previousName := DefaultVerifyBinName
	DefaultVerifyBinName = binaryName
	t.Cleanup(func() { DefaultVerifyBinName = previousName })
}

// konabeansOnPath puts a stub verifier named "konabeans" in a new
// directory and puts that directory first on PATH.
// Input: t. Output: the stub path, and the file where the stub copies
// the envelope it receives.
func konabeansOnPath(t *testing.T) (stubPath, envelopeCopyPath string) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("the stub verifier is a POSIX shell script")
	}
	envelopeCopyPath = filepath.Join(t.TempDir(), "env.json")
	scriptPath := fakeVerifyBin(t, envelopeCopyPath, acceptingVerifierStderr, 0)
	stubDirectory := t.TempDir()
	stubPath = filepath.Join(stubDirectory, "konabeans")
	if err := os.Rename(scriptPath, stubPath); err != nil {
		t.Fatal(err)
	}
	// The stub directory comes first, so the stub wins over any other
	// konabeans; the rest of PATH stays so the stub script can run cp.
	t.Setenv("PATH", stubDirectory+string(os.PathListSeparator)+os.Getenv("PATH"))
	return stubPath, envelopeCopyPath
}

// TestVerifyBin_EnvWinsOverPath: a non-empty KONAREEF_VERIFY_BIN is used
// also when konabeans is on PATH.
func TestVerifyBin_EnvWinsOverPath(t *testing.T) {
	useDefaultVerifyBinName(t, "konabeans")
	konabeansOnPath(t)
	envBinary := filepath.Join(t.TempDir(), "verify-from-env")
	t.Setenv(VerifyBinEnv, envBinary)
	if got := ResolveVerifyBin(); got != envBinary {
		t.Fatalf("ResolveVerifyBin = %q, want the env value %q", got, envBinary)
	}
}

// TestVerifyBin_PathUsedWhenEnvUnset: with KONAREEF_VERIFY_BIN empty,
// konabeans on PATH is found, wired into the options, and run: the proof
// is valid.
func TestVerifyBin_PathUsedWhenEnvUnset(t *testing.T) {
	useDefaultVerifyBinName(t, "konabeans")
	stubPath, envelopeCopyPath := konabeansOnPath(t)
	t.Setenv(VerifyBinEnv, "")
	if got := ResolveVerifyBin(); got != stubPath {
		t.Fatalf("ResolveVerifyBin = %q, want %q", got, stubPath)
	}

	p := newAnchorParts(t, "C")
	t.Setenv(NodeKeyFileEnv, "")
	r := VerifyV2ProductionWithAnchor(p.encode(t), false, AnchorConfig{})
	if r.V2Verdict == nil || !r.V2Verdict.ProofValid {
		t.Fatalf("proof not valid with konabeans on PATH: %v", divergenceStrings(r))
	}
	if _, err := os.Stat(envelopeCopyPath); err != nil {
		t.Fatalf("konabeans was not run: %v", err)
	}
}

// TestVerifyBin_NeitherFailsClosed: with no env value and no konabeans
// on PATH, no verifier is wired and the verdict fails closed exactly as
// before.
func TestVerifyBin_NeitherFailsClosed(t *testing.T) {
	useDefaultVerifyBinName(t, "konabeans")
	t.Setenv("PATH", t.TempDir())
	t.Setenv(VerifyBinEnv, "")
	if got := ResolveVerifyBin(); got != "" {
		t.Fatalf("ResolveVerifyBin = %q, want none", got)
	}

	p := newAnchorParts(t, "C")
	t.Setenv(NodeKeyFileEnv, "")
	r := VerifyV2ProductionWithAnchor(p.encode(t), false, AnchorConfig{})
	if r.OK || r.V2Verdict == nil || r.V2Verdict.ProofValid {
		t.Fatalf("ok=%v, want a fail-closed verdict with proof_valid=false", r.OK)
	}
	found := false
	for _, d := range r.Divergences {
		if errors.Is(d.Err, ErrSnarkVerifierNotConfigured) {
			found = true
		}
	}
	if !found {
		t.Fatalf("no ErrSnarkVerifierNotConfigured divergence: %v", divergenceStrings(r))
	}
}

// TestVerifyBin_EmptyNameTurnsLookupOff: with DefaultVerifyBinName empty
// (as in TestMain), konabeans on PATH is not used.
func TestVerifyBin_EmptyNameTurnsLookupOff(t *testing.T) {
	useDefaultVerifyBinName(t, "")
	konabeansOnPath(t)
	t.Setenv(VerifyBinEnv, "")
	if got := ResolveVerifyBin(); got != "" {
		t.Fatalf("ResolveVerifyBin = %q, want none", got)
	}
}
