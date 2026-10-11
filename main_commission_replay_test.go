// Copyright 2026 Jerry David Chan, Konareef.ai
// SPDX-License-Identifier: Apache-2.0

// main_commission_replay_test.go — `konareef commission replay` end to end:
// evidence files on disk, the exit codes, both renderings, and the binary's
// subcommand wiring.

package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/digitsu/konareef/internal/canon"
	"github.com/digitsu/konareef/internal/commission"
	"github.com/digitsu/konareef/internal/envelope"
	"github.com/digitsu/konareef/internal/identity"
	"github.com/digitsu/konareef/internal/replay"
)

// replayFiles are the evidence files of one commissioned run.
type replayFiles struct {
	dir, commission, receipt, manifest string
	receiptBody                        map[string]any
}

// writeReplayFiles signs a commission for the IB-00 control pod (mf-ok) with
// the fixture key buyer-a, and writes it, the manifest and the receipt that
// reef-core Claims.receipt/1 returns for it.
func writeReplayFiles(t *testing.T) replayFiles {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("internal", "commission", "testdata", "admission_v1", "vectors.json"))
	if err != nil {
		t.Fatal(err)
	}
	var vectors struct {
		Keys []struct {
			Name          string `json:"name"`
			PrivateKeyHex string `json:"private_key_hex"`
			PublicKeyHex  string `json:"public_key_hex"`
		} `json:"keys"`
		PublishedPods []struct {
			Name     string `json:"name"`
			Manifest string `json:"manifest"`
		} `json:"published_pods"`
	}
	if err := json.Unmarshal(raw, &vectors); err != nil {
		t.Fatal(err)
	}
	var manifest []byte
	for _, p := range vectors.PublishedPods {
		if p.Name == "mf-ok" {
			manifest = []byte(p.Manifest)
		}
	}
	id := &identity.Identity{PrivateKeyHex: vectors.Keys[0].PrivateKeyHex, PublicKeyHex: vectors.Keys[0].PublicKeyHex}
	fr, err := canon.ParseCommitFieldsRoot(manifest)
	if err != nil {
		t.Fatal(err)
	}
	p := commission.Proposal{
		Envelope: envelope.Envelope{
			Models: []string{"anthropic/claude-sonnet-4-5"}, Tools: []string{"bash", "ripgrep"}, CMax: 2500,
			ModelsSet: true, ToolsSet: true, LabelsSet: true, CMaxSet: true,
		},
		Binding: commission.Binding{PodRef: "dave/admit-fixture@1.0.0", HManifest: sha256.Sum256(manifest), FieldsRoot: &fr},
		Prose:   "Private buyer instructions that must never appear in a report.",
	}
	c, err := commission.Sign(p, id)
	if err != nil {
		t.Fatal(err)
	}
	artifact, err := marshalCommission(c)
	if err != nil {
		t.Fatal(err)
	}
	h, _ := c.HCommissionHex()
	body := map[string]any{
		"agent_id": "agent-1", "pod_id": "pod-1",
		"receipt": map[string]any{
			"receipt_id": "0e6f2c1a-4b5d-4e6f-8a9b-0c1d2e3f4a5b", "contract": commission.AdmissionContractV1,
			"assurance_mode": commission.AssuranceModeLimitedV1, "h_commission": h, "signer_pubkey": c.PubKeyHex,
			"signer_key_id": "k-1", "pod_hash": hex.EncodeToString(p.Binding.HManifest[:]), "pod_ref": p.Binding.PodRef,
			"fields_root": hex.EncodeToString(fr[:]), "memory_class": "rinit_v1",
			"derived":   map[string]any{"models": []string{"anthropic/claude-sonnet-4-5"}, "tools": []string{"bash", "ripgrep"}, "c_max_sats": 2500},
			"fees":      map[string]any{"author_fee_sats": 0, "zk_fee_sats": 0, "bounded_by_commission": true},
			"run_state": "started", "effective": map[string]any{"model_id": "anthropic/claude-sonnet-4-5", "budget_sats": 2500},
			"dimensions": map[string]string{"models": "admission_checked", "tools": "admission_checked_declared_only",
				"spend": "admission_checked", "labels": "not_evaluated", "memory": "declares_no_initial_memory_and_commits_empty_root"},
			"inputs": "not_buyer_signed", "verifier_impl": "reef-core/commission-verifier/v1", "admitted_at": "2026-09-25T10:00:00Z",
			"authenticity": "api_session_only",
		},
	}
	dir := t.TempDir()
	f := replayFiles{dir: dir, commission: filepath.Join(dir, "commission.cbor"), receipt: filepath.Join(dir, "receipt.json"),
		manifest: filepath.Join(dir, "manifest.canon"), receiptBody: body}
	for path, data := range map[string][]byte{f.commission: artifact, f.manifest: manifest} {
		if err := os.WriteFile(path, data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	f.writeReceipt(t)
	return f
}

// writeReceipt writes the (possibly edited) receipt body.
func (f replayFiles) writeReceipt(t *testing.T) {
	t.Helper()
	data, err := json.Marshal(f.receiptBody)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(f.receipt, data, 0o600); err != nil {
		t.Fatal(err)
	}
}

// args returns the evidence flags.
func (f replayFiles) args(extra ...string) []string {
	return append([]string{"--commission", f.commission, "--receipt", f.receipt, "--manifest", f.manifest}, extra...)
}

// TestCommissionReplayCLI covers the exit codes and outputs of the command
// for genuine, contradicted, incomplete and malformed invocations.
func TestCommissionReplayCLI(t *testing.T) {
	t.Setenv("KONAREEF_VERIFY_BIN", "")
	files := writeReplayFiles(t)
	prose := "Private buyer instructions"

	run := func(args ...string) (int, string, string) {
		var stdout, stderr bytes.Buffer
		code := runCommissionReplayCore(&stdout, &stderr, args)
		return code, stdout.String(), stderr.String()
	}

	t.Run("genuine evidence", func(t *testing.T) {
		code, out, _ := run(files.args()...)
		if code != 0 || !strings.Contains(out, replay.Headline(replay.VerdictAdmissionReplayed)) {
			t.Fatalf("exit %d:\n%s", code, out)
		}
		if strings.Contains(out, prose) {
			t.Fatal("the report prints the commission prose")
		}
	})

	t.Run("json report", func(t *testing.T) {
		code, out, _ := run(files.args("--json")...)
		var rep replay.Report
		if err := json.Unmarshal([]byte(out), &rep); err != nil {
			t.Fatalf("exit %d, not JSON: %v\n%s", code, err, out)
		}
		if code != 0 || rep.Verdict != replay.VerdictAdmissionReplayed || rep.Format != replay.ReportFormat {
			t.Fatalf("exit %d verdict %s format %s", code, rep.Verdict, rep.Format)
		}
		if strings.Contains(out, prose) {
			t.Fatal("the JSON report carries the commission prose")
		}
	})

	t.Run("tampered receipt", func(t *testing.T) {
		tampered := writeReplayFiles(t)
		tampered.receiptBody["receipt"].(map[string]any)["pod_ref"] = "mallory/admit-fixture@1.0.0\x1b[2J"
		tampered.writeReceipt(t)
		code, out, _ := run(tampered.args()...)
		if code != 4 || !strings.Contains(out, "CONTRADICTED") || !strings.Contains(out, "receipt.pod_ref") {
			t.Fatalf("exit %d:\n%s", code, out)
		}
		if strings.Contains(out, "\x1b") {
			t.Fatal("a raw escape sequence from the receipt reached the output")
		}
	})

	t.Run("unreadable manifest file", func(t *testing.T) {
		code, out, _ := run("--commission", files.commission, "--receipt", files.receipt, "--manifest", filepath.Join(files.dir, "absent"))
		if code != 3 || !strings.Contains(out, "INCOMPLETE") || !strings.Contains(out, "could not be read") {
			t.Fatalf("exit %d:\n%s", code, out)
		}
	})

	t.Run("commission file is not an artifact", func(t *testing.T) {
		junk := filepath.Join(files.dir, "junk.cbor")
		if err := os.WriteFile(junk, []byte("not cbor"), 0o600); err != nil {
			t.Fatal(err)
		}
		code, out, _ := run("--commission", junk, "--receipt", files.receipt, "--manifest", files.manifest)
		if code != 3 || !strings.Contains(out, "not a commission artifact") {
			t.Fatalf("exit %d:\n%s", code, out)
		}
	})

	t.Run("proof supplied without a SNARK verifier", func(t *testing.T) {
		bundle := filepath.Join("internal", "verify", "testdata", "parity-v2-typec.cbor")
		code, out, _ := run(files.args("--proof", bundle)...)
		// The archived bundle proves another manifest: a contradiction.
		if code != 4 || !strings.Contains(out, "proof.manifest") {
			t.Fatalf("exit %d:\n%s", code, out)
		}
	})

	for name, args := range map[string][]string{
		"no arguments":         {},
		"positional argument":  {"commission.cbor"},
		"unknown flag":         {"--commision", "x"},
		"positional and flags": append(files.args(), "extra"),
	} {
		t.Run("usage: "+name, func(t *testing.T) {
			code, _, errOut := run(args...)
			if code != 2 || !strings.Contains(errOut, "usage: konareef commission replay") {
				t.Fatalf("exit %d, stderr %q", code, errOut)
			}
		})
	}
}

// TestCommissionReplayBinary runs the built binary, so the subcommand is
// wired into `konareef commission` and the process exit code is the
// verdict's.
func TestCommissionReplayBinary(t *testing.T) {
	bin := buildGateCLI(t)
	home := commissionCLIHome(t, bin)
	files := writeReplayFiles(t)
	got := runCommissionCLI(t, bin, home, append([]string{"commission", "replay"}, files.args()...)...)
	if got.code != 0 || !strings.Contains(got.stdout, "verdict:   admission_replayed") {
		t.Fatalf("exit %d:\n%s", got.code, got.combined())
	}
	files.receiptBody["receipt"].(map[string]any)["authenticity"] = "server_signed"
	files.writeReceipt(t)
	got = runCommissionCLI(t, bin, home, append([]string{"commission", "replay"}, files.args()...)...)
	if got.code != 4 {
		t.Fatalf("exit %d for a receipt that claims a signature:\n%s", got.code, got.combined())
	}
}
