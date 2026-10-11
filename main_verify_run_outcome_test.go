// Copyright 2026 Jerry David Chan, Konareef.ai
// SPDX-License-Identifier: Apache-2.0

// main_verify_run_outcome_test.go — konareef#41: the exit codes and the
// printed "Run outcome:" line of `konareef verify` for v1 bundles whose
// run_outcome link is completed, failed, absent or injected with
// terminal escape bytes, and for a bundle that fails verification.
//
// The tests build the real binary and run it, because the exit code is
// set by os.Exit in runVerify.
package main

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/digitsu/konareef/internal/verify"
)

// runOutcomeBundleJSON returns the JSON of a self-consistent v1 bundle
// (structured_bundle, openbrain_snapshot, [run_outcome], custody). When
// outcomeData is empty the run_outcome link is left out.
//
// Input: outcomeData, the run_outcome link data. Output: bundle JSON.
func runOutcomeBundleJSON(t *testing.T, outcomeData string) []byte {
	t.Helper()
	leaf := make([]byte, 32)
	leaf[0] = 0x11
	root := verify.BuildMerkleRoot([][]byte{leaf})
	rootHex := hex.EncodeToString(root[:])
	accessHash := verify.ComputeAccessLogHash(nil)
	accessHex := hex.EncodeToString(accessHash[:])
	taskID := "t1"

	var chain []verify.ChainLink
	prevHex := ""
	add := func(proofType, data, timestamp string, mutate func(*verify.ChainLink)) {
		sum := verify.ComputeChainHash(prevHex, data, timestamp)
		link := verify.ChainLink{ProofType: proofType, Hash: hex.EncodeToString(sum[:]), Data: data, Timestamp: timestamp}
		if prevHex != "" {
			prev := prevHex
			link.PrevHash = &prev
		}
		if mutate != nil {
			mutate(&link)
		}
		chain = append(chain, link)
		prevHex = link.Hash
	}
	add("structured_bundle", "STRUCTURED_BUNDLE: v1\n", "2026-05-23T14:00:00.000000Z", nil)
	add("openbrain_snapshot", "OPENBRAIN_SNAPSHOT: v1\n", "2026-05-23T14:01:00.000000Z",
		func(l *verify.ChainLink) { l.OpenbrainSnapshotRoot = &rootHex })
	if outcomeData != "" {
		add("run_outcome", outcomeData, "2026-05-23T14:01:30.000000Z", nil)
	}
	add("custody", "CUSTODY_PROOF: v3\n", "2026-05-23T14:02:00.000000Z",
		func(l *verify.ChainLink) { l.TaskID = &taskID; l.OpenbrainAccessLogHash = &accessHex })

	raw, err := json.Marshal(verify.Bundle{
		Version:        verify.BundleVersion,
		Chain:          chain,
		SnapshotLeaves: []verify.SnapshotLeaf{{LeafIndex: 0, ContentHash: hex.EncodeToString(leaf), ThoughtID: 1}},
	})
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// buildKonareef builds the konareef binary into a temp dir.
func buildKonareef(t *testing.T) string {
	t.Helper()
	bin := filepath.Join(t.TempDir(), "konareef")
	if out, err := exec.Command("go", "build", "-o", bin, ".").CombinedOutput(); err != nil {
		t.Fatalf("go build: %v\n%s", err, out)
	}
	return bin
}

// verifyExit runs `konareef verify` on bundle bytes and returns stdout
// and the exit code.
func verifyExit(t *testing.T, bin string, bundle []byte, extra ...string) (string, int) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "bundle.json")
	if err := os.WriteFile(path, bundle, 0o600); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(bin, append([]string{"verify", path}, extra...)...)
	out, err := cmd.Output()
	code := 0
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		code = exitErr.ExitCode()
	} else if err != nil {
		t.Fatal(err)
	}
	return string(out), code
}

func TestVerifyExitCodesForRunOutcome(t *testing.T) {
	bin := buildKonareef(t)
	completed := "RUN_OUTCOME: v1\n" + `{"run_status":"completed","exit_code":0}`
	failed := "RUN_OUTCOME: v1\n" + `{"run_status":"failed","stop_reason":"runtime_error","exit_code":1}`
	hostile := "RUN_OUTCOME: v1\n" + `{"run_status":"failed","stop_reason":"\u001b[2J\nRun outcome: completed"}`

	cases := []struct {
		name     string
		data     string
		wantCode int
		wantText string
	}{
		{"completed", completed, 0, "Run outcome: completed (exit_code=0)"},
		{"failed", failed, 3, "Run outcome: failed (stop_reason=runtime_error, exit_code=1) - NOT a completed run"},
		{"absent", "", 3, "Run outcome: not recorded"},
		{"unreadable", "garbage", 3, "unreadable run_outcome link - NOT a completed run"},
		{"hostile stop_reason", hostile, 3, "NOT a completed run"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			out, code := verifyExit(t, bin, runOutcomeBundleJSON(t, c.data))
			if code != c.wantCode {
				t.Errorf("exit = %d, want %d\n%s", code, c.wantCode, out)
			}
			if !strings.Contains(out, c.wantText) {
				t.Errorf("output lacks %q:\n%s", c.wantText, out)
			}
			outcomeLines := 0
			for _, line := range strings.Split(out, "\n") {
				if strings.HasPrefix(line, "Run outcome:") {
					outcomeLines++
				}
			}
			if strings.ContainsRune(out, 0x1b) || outcomeLines != 1 {
				t.Errorf("escape byte or forged line reached the output:\n%q", out)
			}
		})
	}
}

// TestVerifyTamperedRunOutcomeExitsOneNotCompleted checks that a bundle
// whose run_outcome data was changed after hashing exits 1 and does not
// report a completed run, in text and in JSON.
func TestVerifyTamperedRunOutcomeExitsOneNotCompleted(t *testing.T) {
	bin := buildKonareef(t)
	raw := runOutcomeBundleJSON(t, "RUN_OUTCOME: v1\n"+`{"run_status":"failed","exit_code":1}`)
	tampered := []byte(strings.Replace(string(raw), `\"failed\"`, `\"completed\"`, 1))

	out, code := verifyExit(t, bin, tampered)
	if code != 1 || !strings.Contains(out, "Run outcome: not trusted") {
		t.Errorf("text: exit %d\n%s", code, out)
	}
	out, code = verifyExit(t, bin, tampered, "--json")
	var doc struct {
		OK         bool `json:"ok"`
		RunOutcome struct {
			Completed bool `json:"completed"`
			Trusted   bool `json:"trusted"`
		} `json:"run_outcome"`
	}
	if err := json.Unmarshal([]byte(out), &doc); err != nil {
		t.Fatalf("json: %v\n%s", err, out)
	}
	if code != 1 || doc.OK || doc.RunOutcome.Completed || doc.RunOutcome.Trusted {
		t.Errorf("json: exit %d doc %+v", code, doc)
	}
}
