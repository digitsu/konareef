// Copyright 2026 Jerry David Chan, Konareef.ai
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// gatewayPodTOMLForPublishTest is a minimal, schema-valid pod.toml with
// one [[network.gateway]] entry. Validating it produces exactly one
// GATEWAY_SECRET_LEAVES_ENV warning and no issues (mirrors the shape
// internal/pod.TestVoiceForgeDemoDeclaresGateway exercises on the real
// demo pod).
const gatewayPodTOMLForPublishTest = `pod_spec_version = "0.1"

[pod]
name = "research-bot"
version = "1.0.0"

[runtime]
kind = "lobster"

[directive]
template = "./prompts/system.md"

[dependencies]
secrets = ["ELEVENLABS_API_KEY"]

[network]

[[network.gateway]]
host = "api.elevenlabs.io"
secret = "ELEVENLABS_API_KEY"
auth = "header:xi-api-key"
max_calls = 2
`

// writePublishTestGatewayPod scaffolds a pod directory with a gateway
// entry, ready for publish.Prepare / runPodPublish.
func writePublishTestGatewayPod(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "pod.toml"), []byte(gatewayPodTOMLForPublishTest), 0o644); err != nil {
		t.Fatalf("write pod.toml: %v", err)
	}
	prompts := filepath.Join(dir, "prompts")
	if err := os.MkdirAll(prompts, 0o755); err != nil {
		t.Fatalf("mkdir prompts: %v", err)
	}
	if err := os.WriteFile(filepath.Join(prompts, "system.md"), []byte("hello"), 0o644); err != nil {
		t.Fatalf("write system.md: %v", err)
	}
	return dir
}

// TestPodPublishPrintsGatewaySecretWarning covers Minor 5 from the
// final review: `pod publish` on a gateway pod must print the
// GATEWAY_SECRET_LEAVES_ENV advisory to stderr, the same way `pod
// validate` does, instead of silently discarding it. Uses --dry-run so
// the test never needs a reef-core stub.
func TestPodPublishPrintsGatewaySecretWarning(t *testing.T) {
	writeListingTestIdentity(t, "alice")
	dir := writePublishTestGatewayPod(t)

	stderr := captureStderr(t)
	runPodPublish([]string{dir, "--dry-run"})
	out := stderr()

	if strings.Count(out, "GATEWAY_SECRET_LEAVES_ENV") != 1 {
		t.Fatalf("stderr =\n%s\nwant exactly one GATEWAY_SECRET_LEAVES_ENV line", out)
	}
}
