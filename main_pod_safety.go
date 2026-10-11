// Copyright 2026 Jerry David Chan, Konareef.ai
// SPDX-License-Identifier: Apache-2.0

// main_pod_safety.go — the `konareef pod safety` subcommand and the
// pre-publish gate that shares its logic.
//
// The check itself lives in internal/pod/safety.go. This file is the CLI
// surface: it resolves a pod directory, runs the check, and turns
// findings into exit codes an author and a CI job can both act on.
//
// Exit codes:
//
//	0  no findings
//	1  findings, or the pod could not be read
//	2  usage error
//
// The gate runs before a publish reaches the network. A pod whose own
// files name a host it did not declare should not become something a
// stranger can commission, and telling the author at publish time is
// cheaper for everyone than telling them at review time.
package main

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/digitsu/konareef/internal/pod"
)

// exitSafetyFindings is the exit code for a pod that fails the check.
// Distinct from the usage code so a CI job can tell "your pod has
// undeclared egress" from "you typed the command wrong".
const exitSafetyFindings = 1

// runPodSafety implements `konareef pod safety <pod-dir>`.
func runPodSafety(args []string) {
	if len(args) < 1 {
		fmt.Fprintln(os.Stderr, "usage: konareef pod safety <pod-dir>")
		os.Exit(2)
	}
	podDir := args[0]

	findings, err := podSafetyFindings(podDir)
	if err != nil {
		fmt.Fprintln(os.Stderr, "safety:", err)
		os.Exit(1)
	}

	// Advisory only: `pod publish` and `pod listing publish` refuse.
	warnBundleCredentials(os.Stderr, podDir)

	if len(findings) == 0 {
		fmt.Println("✓ No undeclared egress found in the pod's context files.")
		fmt.Println("  Note: this scans text. A pod can still build a hostname at run time,")
		fmt.Println("  which no static check can see. Runtime egress control is what enforces.")
		printReviewPreview(os.Stdout, podDir)
		return
	}

	reportSafetyFindings(os.Stderr, findings)
	printReviewPreview(os.Stderr, podDir)
	os.Exit(exitSafetyFindings)
}

// printReviewPreview writes the local preview of the server's egress
// review findings that the undeclared-host report above does not already
// show: wildcard, IP-literal and non-TLS declarations, declared hosts no
// text names, and references to the default platform LLM host. Each line
// says whether the server review flags it or only records it.
//
// It never changes the exit code. It prints nothing when there is nothing
// to add, or when a declared source cannot be read (the preview is strict
// and this command is not; `pod validate` and the listing pre-check
// report such a source).
func printReviewPreview(w *os.File, podDir string) {
	podTOML, err := os.ReadFile(filepath.Join(podDir, "pod.toml"))
	if err != nil {
		return
	}
	spec, _, err := pod.ParseAndValidate(podTOML)
	if err != nil {
		return
	}
	preview, err := pod.EgressReviewPreview(podDir, spec, pod.DefaultPlatformHost)
	if err != nil {
		return
	}
	var lines []string
	for _, finding := range preview {
		if finding.Code == pod.ReviewUndeclaredHost {
			continue
		}
		label := "recorded, does not flag"
		if pod.ReviewFlags(finding.Code) {
			label = "flags the review"
		}
		lines = append(lines, fmt.Sprintf("  %s — %s", finding, label))
	}
	if len(lines) == 0 {
		return
	}
	fmt.Fprintln(w, "\nServer egress review preview (local copy of the server's rules; advisory):")
	for _, line := range lines {
		fmt.Fprintln(w, line)
	}
	fmt.Fprintln(w, "  A flagged review needs an operator's approval before a server that requires review lists the pod.")
}

// podSafetyFindings parses the pod at podDir and runs the static egress
// check over it.
func podSafetyFindings(podDir string) ([]pod.SafetyFinding, error) {
	tomlPath := filepath.Join(podDir, "pod.toml")
	podTOML, err := os.ReadFile(tomlPath)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", tomlPath, err)
	}

	// Schema issues are reported by `pod validate` and by publish, both
	// of which give better diagnostics than this command could. Here a
	// spec that parses is enough: the check needs [network] and
	// [context], not a fully valid manifest.
	spec, _, err := pod.ParseAndValidate(podTOML)
	if err != nil {
		return nil, fmt.Errorf("parse %s: %w", tomlPath, err)
	}

	return pod.SafetyCheck(podDir, spec)
}

// reportSafetyFindings writes findings and the remedy to w.
func reportSafetyFindings(w *os.File, findings []pod.SafetyFinding) {
	fmt.Fprintf(w, "✗ %d undeclared egress reference(s):\n\n", len(findings))
	for _, finding := range findings {
		fmt.Fprintf(w, "  %s\n", finding)
	}
	fmt.Fprintln(w, "\nEvery host a context file names must appear in [network].egress:")
	fmt.Fprintln(w, "\n  [network]")
	fmt.Fprintf(w, "  egress = [%s]\n", quotedHosts(findings))
	fmt.Fprintln(w, "\nDeclare only the hosts the pod actually needs. A wildcard such as")
	fmt.Fprintln(w, "\"*.example.com\" is accepted and is treated by review as a much broader claim.")
}

// quotedHosts renders the distinct host:port pairs from findings as a
// TOML array body, so the author can paste the remedy directly.
func quotedHosts(findings []pod.SafetyFinding) string {
	seen := make(map[string]bool)
	var out string
	for _, finding := range findings {
		if finding.Host == "" {
			continue
		}
		entry := finding.Host
		if finding.Port != "443" {
			entry = finding.Host + ":" + finding.Port
		}
		if seen[entry] {
			continue
		}
		seen[entry] = true
		if out != "" {
			out += ", "
		}
		out += fmt.Sprintf("%q", entry)
	}
	return out
}

// warnPodSafety reports undeclared egress at publish time WITHOUT
// halting the publish.
//
// Publishing is not exposure. A published pod is installable and runnable
// by its author and by anyone they hand the reference to; it is listing
// that puts a pod in front of strangers, and that is where the hard gate
// belongs (see listingSafetyGate). Blocking publish would also stop every
// pod that predates [network] from ever shipping a bugfix, which is the
// exact breakage the rollout decision was written to avoid.
//
// A read failure is reported and ignored here. A pod whose files cannot
// be read fails later in Prepare with a better message.
func warnPodSafety(podDir string) {
	findings, err := podSafetyFindings(podDir)
	if err != nil || len(findings) == 0 {
		return
	}
	fmt.Fprintf(os.Stderr,
		"⚠ %d undeclared egress reference(s). This pod cannot be listed until [network].egress covers them:\n",
		len(findings))
	for _, finding := range findings {
		fmt.Fprintf(os.Stderr, "    %s\n", finding)
	}
	fmt.Fprintf(os.Stderr, "  Add:  [network]\n        egress = [%s]\n\n", quotedHosts(findings))
}

// listingSafetyGate is the hard gate, at the point of exposure. It
// returns 0 to continue or a non-zero exit code, matching the
// return-code style of runPodListingImpl rather than calling os.Exit.
//
// Fails closed on three things, not one: a pod directory that cannot be
// read, an undeclared host in a context file, and a declared context
// source that could not be inspected at all. The third is why this uses
// pod.SafetyCheckStrict rather than the advisory pod.SafetyCheck that
// `konareef pod safety` and warnPodSafety run. A missing directive
// template, memory file, prompt, or skill produces no findings from the
// lenient check, and an empty finding list here would mean "listing
// approved" for a manifest whose model-context surface was never
// examined. The leniency stays where it belongs — on the author's own
// half-built pod — and does not follow the pod out to strangers.
//
// This check runs on the author's machine, so it is advice, not a gate a
// server relies on: a client that skips it, or an older binary, is not
// stopped by it. Its refusal message says so, and says that the server
// decides the listing.
func listingSafetyGate(podDir string, spec pod.Spec) int {
	findings, err := pod.SafetyCheckStrict(podDir, spec)
	if err != nil {
		fmt.Fprintln(os.Stderr, "listing: refusing to list — safety check:", err)
		// An uninspectable source comes back alongside whatever the scan
		// did manage to find. Both are printed so an author fixing the
		// manifest sees the whole list in one run rather than uncovering
		// the next problem only after fixing this one.
		if len(findings) > 0 {
			fmt.Fprintln(os.Stderr)
			reportSafetyFindings(os.Stderr, findings)
		}
		fmt.Fprintln(os.Stderr, serverDecidesNote)
		return 1
	}
	if len(findings) == 0 {
		return 0
	}
	fmt.Fprintln(os.Stderr, "listing: refusing to list — safety check failed.")
	fmt.Fprintln(os.Stderr)
	reportSafetyFindings(os.Stderr, findings)
	fmt.Fprintln(os.Stderr, serverDecidesNote)
	return exitSafetyFindings
}

// serverDecidesNote closes a local pre-check refusal. The local check is
// a copy of the server's scan; the server decides, and a server with
// egress review checks the published revision itself.
const serverDecidesNote = "\nThis is a local pre-check; the server decides the listing. " +
	"A server with egress review also scans the published revision, " +
	"so passing here does not by itself list the pod."
