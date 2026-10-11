// Copyright 2026 Jerry David Chan, Konareef.ai
// SPDX-License-Identifier: Apache-2.0

// main_pod_grants.go — CLI glue for sealed closed-pod grants (MCP-C01,
// konareef#13; design MCP-C00, reef-core#42).
//
//   - runPodGrants: `konareef pod grants init <pod-dir>`.
//   - validateSealedGrantsForCLI: the G1–G16 pass `pod validate` adds.
//   - sealedGrantsPublishOptions / checkSealedGrantsBeforeSubmit: the
//     capability read and the refusal `pod publish` performs.
//   - sealedGrantsInspectLine: the one line `install` prints about sealed
//     grants.
//
// Nothing here prints a sealed value. The only fact the CLI states about
// a pod's sealed grants to anyone but its author is "sealed grants:
// present".
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/digitsu/konareef/internal/pod"
	"github.com/digitsu/konareef/internal/publish"
)

// runPodGrants dispatches `konareef pod grants <subcommand>`. Exits 2 on a
// usage error.
func runPodGrants(args []string) {
	if len(args) == 0 || args[0] != "init" {
		fmt.Fprintln(os.Stderr, "usage: konareef pod grants init <pod-dir>")
		os.Exit(2)
	}
	runPodGrantsInit(args[1:])
}

// runPodGrantsInit implements `konareef pod grants init <pod-dir>`: it
// writes an empty sealed/grants.toml with a fresh salt (mode 0600) and
// adds [network].sealed_grants to pod.toml if it is missing. It never
// overwrites an existing grants file. Exits 0 on success, 1 on failure,
// 2 on a usage error.
func runPodGrantsInit(args []string) {
	fs := flag.NewFlagSet("pod grants init", flag.ExitOnError)
	fs.Parse(args)
	if fs.NArg() != 1 {
		fmt.Fprintln(os.Stderr, "usage: konareef pod grants init <pod-dir>")
		os.Exit(2)
	}
	podDir := fs.Arg(0)
	markerAdded, err := publish.InitSealedGrants(podDir)
	if err != nil {
		fmt.Fprintln(os.Stderr, "grants init:", err)
		os.Exit(1)
	}
	fmt.Printf("✓ Created %s with a fresh salt (mode 0600)\n", pod.SealedGrantsBodyPath)
	if markerAdded {
		fmt.Printf("✓ Added sealed_grants = %q to [network] in pod.toml\n", pod.SealedGrantsFormatV1)
	}
	fmt.Println("  Add one [[grant]] table per brokered MCP server. The file is encrypted with")
	fmt.Println("  the pod body; do not list a sealed grant's secret in [dependencies].secrets.")
}

// validateSealedGrantsForCLI runs G1–G16 for `pod validate <pod.toml>`,
// looking for sealed/grants.toml next to the pod.toml. G15 (--zk) is a
// publish-time rule, so it is not checked here.
//
// Inputs: the pod.toml path and bytes. Output: the value-free issues, the
// open-pod warning when it applies, or an error for an I/O failure.
func validateSealedGrantsForCLI(tomlPath string, podTOML []byte) ([]pod.Issue, []pod.Warning, error) {
	issues, _, err := publish.CheckSealedGrants(podTOML, filepath.Dir(tomlPath), false)
	if err != nil {
		return nil, nil, err
	}
	return issues, publish.OpenPodSealedFileWarningsFor(podTOML, filepath.Dir(tomlPath)), nil
}

// sealedGrantsPublishPlan is what `pod publish` decided about sealed
// grants before Prepare.
type sealedGrantsPublishPlan struct {
	// capabilities is the server advertisement; zero for --dry-run.
	capabilities publish.Capabilities
	// fetched reports whether capabilities came from the server.
	fetched bool
}

// planSealedGrantsPublish reads the server's capabilities for a real
// publish of a closed pod. A dry run makes no network call. A fetch
// failure is fatal only when the pod already carries the marker; for a
// legacy closed pod it disables always-emit and the publish goes ahead as
// before.
//
// Inputs: the pod dir, the server URL, and the dry-run flag. Output: the
// plan, or an error that should stop the publish.
func planSealedGrantsPublish(podDir, serverURL string, dryRun bool) (sealedGrantsPublishPlan, error) {
	var plan sealedGrantsPublishPlan
	if dryRun {
		return plan, nil
	}
	head, err := os.ReadFile(filepath.Join(podDir, "pod.toml"))
	if err != nil {
		return plan, nil // Prepare reports the read error.
	}
	spec, err := pod.Parse(head)
	if err != nil || spec.Pod.Visibility != publish.VisibilityClosed {
		return plan, nil
	}
	capabilities, err := publish.FetchCapabilities(context.Background(), serverURL)
	if err != nil {
		if pod.HasSealedGrantsMarker(spec) {
			return plan, fmt.Errorf("%w: %v", publish.ErrSealedGrantsUnsupported, err)
		}
		fmt.Fprintln(os.Stderr, " warning: could not read the server's capabilities; publishing this closed pod without the sealed-grants carrier:", err)
		return plan, nil
	}
	plan.capabilities = capabilities
	plan.fetched = true
	// Refuse before Prepare touches the disk when the server cannot take
	// the carrier at all. The grant-count check waits for Prepare.
	if err := publish.CheckSealedGrantsCapability(publish.SealedGrantsState{Marker: pod.HasSealedGrantsMarker(spec)}, capabilities); err != nil {
		return plan, err
	}
	return plan, nil
}

// prepareOptions returns the Prepare options for this plan. Always-emit
// runs only when the server has closed grants enabled (rollout step 6);
// the salt rotates only on a real publish.
func (plan sealedGrantsPublishPlan) prepareOptions(zk, dryRun bool) publish.PrepareOptions {
	return publish.PrepareOptions{
		ZK:                     zk,
		SealedGrantsAlwaysEmit: plan.fetched && plan.capabilities.SealedGrantsEnabled(),
		RotateSealedSalt:       !dryRun,
	}
}

// reportSealedGrantsPrepared prints what Prepare did to the sealed
// carrier. It states actions only: no content and no grant count.
func reportSealedGrantsPrepared(state publish.SealedGrantsState) {
	if state.Emitted {
		fmt.Printf("✓ Added the sealed-grants carrier (marker in pod.toml, empty %s) — every closed pod carries it\n", pod.SealedGrantsBodyPath)
	}
	if !state.Marker {
		return
	}
	// No grant count: publish output lands in CI logs, and under D3 = a
	// the marker must not say whether the pod uses grants.
	fmt.Printf("✓ Validated %s; it ships only inside the encrypted body\n", pod.SealedGrantsBodyPath)
	if state.SaltRotated {
		fmt.Println("  salt: rotated for this publish")
	} else {
		fmt.Println("  salt: not rotated (--dry-run); a real publish writes a new salt, so its pod_hash differs")
	}
}

// checkSealedGrantsBeforeSubmit refuses a marker-bearing publish to a
// server that cannot keep the grants sealed, and a publish with grants to
// a server that has not enabled them. It never falls back to public
// grants.
func checkSealedGrantsBeforeSubmit(plan sealedGrantsPublishPlan, state publish.SealedGrantsState) error {
	return publish.CheckSealedGrantsCapability(state, plan.capabilities)
}

// sealedGrantsInspectLine returns the line `install` prints for a closed
// pod whose head carries the sealed-grants marker, or "" otherwise. The
// head is all a commissioner holds; the line says nothing about the
// grants beyond their carrier being present.
//
// Input: the canonical manifest bytes. Output: the line or "".
func sealedGrantsInspectLine(manifest []byte) string {
	spec, err := pod.Parse(manifest)
	if err != nil || !pod.HasSealedGrantsMarker(spec) {
		return ""
	}
	return "  sealed grants: present"
}
