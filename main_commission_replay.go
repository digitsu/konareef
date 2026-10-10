// Copyright 2026 Jerry David Chan, Konareef.ai
// SPDX-License-Identifier: Apache-2.0

// main_commission_replay.go — `konareef commission replay`: check the
// evidence of one commissioned run offline and print an assurance report
// (docs/design/commission-admission-contract.md §14.4, IB-07).
//
// The command reads local files only and makes no network call. It never
// changes the behaviour of `commission verify` (signature and manifest) or
// `konareef verify` (proof bundles); it combines their evidence with the
// admission receipt in one report.

package main

import (
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/digitsu/konareef/internal/replay"
	"github.com/digitsu/konareef/internal/verify"
)

// The size bounds of the evidence files. A receipt and a manifest are
// small (reef-core's request body limit is 64 KiB); a proof bundle is the
// largest input, and its bound is far above any real one.
const (
	maxReplaySmallEvidenceBytes = 4 << 20
	maxReplayProofBytes         = 256 << 20
)

// runCommissionReplay implements `commission replay`.
func runCommissionReplay(args []string) {
	os.Exit(runCommissionReplayCore(os.Stdout, os.Stderr, args))
}

// readReplayEvidence reads one evidence file of at most limit bytes. An
// empty path means the evidence was not supplied. Output: the bytes, or nil and the reason they
// are missing (an unreadable file is missing evidence, not a crash).
func readReplayEvidence(what, path string, limit int) ([]byte, string) {
	if path == "" {
		return nil, ""
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Sprintf("the %s file could not be read: %v", what, err)
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, int64(limit)+1))
	if err != nil {
		return nil, fmt.Sprintf("the %s file could not be read: %v", what, err)
	}
	if len(data) > limit {
		return nil, fmt.Sprintf("the %s file is over %d bytes and was not read", what, limit)
	}
	return data, ""
}

// runCommissionReplayCore is the testable body of `commission replay`.
//
// Inputs: the output writers and the arguments. Output: the exit code:
// 0 when the evidence is consistent and a run started, 5 when it is
// consistent and no run was launched, 3 when evidence is missing, 4 when
// the evidence is contradicted, and 2 for a usage error.
//
// The commission artifact is decoded with unmarshalCommission, the raw
// loader, and not with loadAndVerifyCommission: replay.Replay verifies the
// signature and ValidateSignable itself, so that a tampered artifact is
// reported as a failed check in the report instead of ending the command
// before the other evidence is examined.
func runCommissionReplayCore(stdout, stderr io.Writer, args []string) int {
	fs := flag.NewFlagSet("commission replay", flag.ContinueOnError)
	fs.SetOutput(stderr)
	commissionPath := fs.String("commission", "", "the signed commission artifact (commission.cbor)")
	receiptPath := fs.String("receipt", "", "the admission receipt JSON, or the POST /api/commissioned-runs response that carries it")
	manifestPath := fs.String("manifest", "", "the pod's canonical manifest bytes (the h_manifest preimage)")
	proofPath := fs.String("proof", "", "optional: the run's konareef-bundle/v2 proof (to check the SNARK, "+verify.VerifierNotConfiguredHint+")")
	asJSON := fs.Bool("json", false, "print the machine-readable report ("+replay.ReportFormat+")")
	allChecks := fs.Bool("all-checks", false, "list every check, not only those that did not pass")
	usage := "usage: konareef commission replay --commission <commission.cbor> --receipt <receipt.json> --manifest <manifest.canon> [--proof <bundle.cbor>] [--json] [--all-checks]"
	if err := fs.Parse(reorderFlagsFirst(args)); err != nil {
		fmt.Fprintln(stderr, usage)
		return 2
	}
	if fs.NArg() != 0 {
		fmt.Fprintln(stderr, usage)
		return 2
	}
	if *commissionPath == "" && *receiptPath == "" && *manifestPath == "" && *proofPath == "" {
		fmt.Fprintln(stderr, usage)
		return 2
	}

	var ev replay.Evidence
	raw, why := readReplayEvidence("commission", *commissionPath, maxReplaySmallEvidenceBytes)
	switch {
	case raw != nil:
		c, err := unmarshalCommission(raw)
		if err != nil {
			ev.CommissionProblem = fmt.Sprintf("the commission file is not a commission artifact: %v", err)
		} else {
			ev.Commission = &c
		}
	case why != "":
		ev.CommissionProblem = why
	}
	ev.Receipt, ev.ReceiptProblem = readReplayEvidence("receipt", *receiptPath, maxReplaySmallEvidenceBytes)
	ev.Manifest, ev.ManifestProblem = readReplayEvidence("manifest", *manifestPath, maxReplaySmallEvidenceBytes)
	ev.Proof, ev.ProofProblem = readReplayEvidence("proof", *proofPath, maxReplayProofBytes)

	rep := replay.Replay(ev)
	if *asJSON {
		if err := replay.RenderJSON(stdout, rep); err != nil {
			fmt.Fprintln(stderr, "commission replay: write report:", err)
			return 1
		}
	} else {
		replay.RenderText(stdout, rep, *allChecks)
	}
	return replay.ExitCode(rep.Verdict)
}
