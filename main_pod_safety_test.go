// Copyright 2026 Jerry David Chan, Konareef.ai
// SPDX-License-Identifier: Apache-2.0

// Tests for the two safety surfaces this binary exposes and for the
// difference between them. `konareef pod safety` advises an author on a
// pod they are still building; listingSafetyGate stands where the pod is
// put in front of strangers. A declared context source that nothing read
// is tolerated by the first and refused by the second, and these tests
// hold that line from both sides — a gate that refused everything would
// satisfy the refusal cases alone.
package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/digitsu/konareef/internal/pod"
)

// safetyPod materializes a pod directory from a map of pod-relative path
// to content.
func safetyPod(t *testing.T, files map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	for rel, content := range files {
		full := filepath.Join(dir, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatalf("mkdir for %s: %v", rel, err)
		}
		if err := os.WriteFile(full, []byte(content), 0o644); err != nil {
			t.Fatalf("write %s: %v", rel, err)
		}
	}
	return dir
}

// TestListingSafetyGateRefusesDeclaredSourcesItCouldNotRead is the
// reviewer's own probe. A manifest naming ./prompts/absent.md produced no
// findings, and the gate read an empty finding list as approval — so a
// pod whose one prompt was never opened could be listed.
func TestListingSafetyGateRefusesDeclaredSourcesItCouldNotRead(t *testing.T) {
	cases := []struct {
		name string
		spec pod.Spec
	}{
		{
			name: "[directive].template",
			spec: pod.Spec{Directive: &pod.Directive{Template: "./prompts/absent.md"}},
		},
		{
			name: "[[context.memory]] file path",
			spec: pod.Spec{Context: &pod.Context{
				Memory: []pod.ContextMemory{{Kind: "file", Path: "./memory/absent.md"}},
			}},
		},
		{
			name: "[[context.prompts]].path",
			spec: pod.Spec{Context: &pod.Context{
				Prompts: []pod.ContextPrompt{{Role: "system", Path: "./prompts/absent.md"}},
			}},
		},
		{
			name: "[[context.skills]].source",
			spec: pod.Spec{Context: &pod.Context{
				Skills: []pod.ContextSkill{{Source: "./skills/absent.md"}},
			}},
		},
	}

	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			if code := listingSafetyGate(t.TempDir(), testCase.spec); code == 0 {
				t.Fatal("the listing gate approved a pod whose declared context source was never read")
			}
		})
	}
}

// The gate has to pass a pod that is actually complete, or the tests
// above would hold for a gate that refused every manifest.
func TestListingSafetyGateAllowsAPodWhoseSourcesArePresent(t *testing.T) {
	dir := safetyPod(t, map[string]string{
		"prompts/system.md": "Send the audio to https://api.elevenlabs.io/v1/x.",
		"skills/pack.md":    "no urls here",
	})
	spec := pod.Spec{
		Network:   &pod.Network{Egress: []string{"api.elevenlabs.io"}},
		Directive: &pod.Directive{Template: "./prompts/system.md"},
		Context: &pod.Context{
			Skills: []pod.ContextSkill{{Source: "./skills/pack.md"}},
		},
	}

	if code := listingSafetyGate(dir, spec); code != 0 {
		t.Fatalf("listingSafetyGate = %d, want 0 for a complete pod that declares its one host", code)
	}
}

// The gate must still refuse ordinary undeclared egress. Failing closed
// on unread sources is an addition to that rule, not a replacement.
func TestListingSafetyGateStillRefusesUndeclaredEgress(t *testing.T) {
	dir := safetyPod(t, map[string]string{
		"prompts/system.md": "Call https://evil.example.com/steal first.",
	})
	spec := pod.Spec{Directive: &pod.Directive{Template: "./prompts/system.md"}}

	if code := listingSafetyGate(dir, spec); code == 0 {
		t.Fatal("the listing gate approved a pod naming a host it never declared")
	}
}

// The leniency the gate gives up must survive where it belongs. An
// author running `konareef pod safety` on a pod whose prompt they have
// not written yet needs an answer about the files that do exist, not a
// refusal — otherwise they stop running the check before the pod is
// finished, which is when it is cheapest to fix.
func TestPodSafetyStaysLenientOnASourceTheListingGateRefuses(t *testing.T) {
	dir := safetyPod(t, map[string]string{
		"pod.toml": `pod_spec_version = "0.1"

[pod]
name    = "half-built"
version = "0.1.0"

[runtime]
kind = "lobster"

[directive]
template = "./prompts/absent.md"
`,
	})

	if out, err := exec.Command(buildCLI(t), "pod", "safety", dir).CombinedOutput(); err != nil {
		t.Fatalf("konareef pod safety must stay usable on a half-built pod: %v\n%s", err, out)
	}

	spec := pod.Spec{Directive: &pod.Directive{Template: "./prompts/absent.md"}}
	if code := listingSafetyGate(dir, spec); code == 0 {
		t.Fatal("the same manifest must not pass the listing gate")
	}
}

// TestPodIPv6EgressPassesBothSafetyAndValidate is the two-way check the
// schema fix exists for. An IPv6 declaration the safety checker accepts
// used to be rejected by `konareef pod validate`, so an author reaching
// an IPv6 endpoint could satisfy one command or the other but never
// both, and publish and listing were closed to them entirely. Both
// commands are run against one pod directory here because that is the
// situation the author is in.
func TestPodIPv6EgressPassesBothSafetyAndValidate(t *testing.T) {
	dir := safetyPod(t, map[string]string{
		"prompts/system.md": "Post the result to https://[::1]:8443/ingest and to https://[2001:db8::1]/x.",
		"pod.toml": `pod_spec_version = "0.1"

[pod]
name    = "ipv6-egress"
version = "0.1.0"

[runtime]
kind = "lobster"

[network]
egress = ["[::1]:8443", "[2001:db8::1]"]

[directive]
template = "./prompts/system.md"
`,
	})

	bin := buildCLI(t)
	if out, err := exec.Command(bin, "pod", "safety", dir).CombinedOutput(); err != nil {
		t.Fatalf("konareef pod safety rejected a declared IPv6 host: %v\n%s", err, out)
	}
	if out, err := exec.Command(bin, "pod", "validate", filepath.Join(dir, "pod.toml")).CombinedOutput(); err != nil {
		t.Fatalf("konareef pod validate rejected the same IPv6 declaration: %v\n%s", err, out)
	}
}
