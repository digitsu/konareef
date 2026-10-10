// Copyright 2026 Jerry David Chan, Konareef.ai
// SPDX-License-Identifier: Apache-2.0

// main_pod_credentials_test.go — the CLI surfaces of the pod-bundle
// credential scan (SECRET-SCAN). `pod publish` and `pod listing publish`
// refuse with BUNDLE_CREDENTIAL_FOUND; `pod validate` and `pod safety`
// warn and keep their exit codes. No test here reaches the network: the
// publish cases use --dry-run, and the listing refusal returns before any
// request.
package main

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// credentialSecret builds a credential-shaped string at run time so this
// source file holds no whole key for a secret scanner to find.
func credentialSecret() string { return "AKIA" + "FAKEFAKEFAKEFAKE" }

// credentialAllowREADME is an allow file with one entry for the
// credentialSecret on line 1 of README.md. The digest is computed here, on
// its own: the first 16 hex characters of SHA-256 over the string.
func credentialAllowREADME() string {
	sum := sha256.Sum256([]byte(credentialSecret()))
	return "[[allow]]\nfile = \"README.md\"\nclass = \"aws_access_key_id\"\nline = 1\n" +
		"sha256 = \"" + hex.EncodeToString(sum[:])[:16] + "\"\nreason = \"documented example key\"\n"
}

const credentialPodTOML = `pod_spec_version = "0.1"

[pod]
name = "research-bot"
version = "0.1.0"

[runtime]
kind = "lobster"
execution_class = "cloud"

[directive]
task = "Summarize a research question."
`

// credentialPod writes a schema-valid pod with a README holding body.
func credentialPod(t *testing.T, readme string, extra map[string]string) string {
	t.Helper()
	files := map[string]string{"pod.toml": credentialPodTOML, "README.md": readme}
	for name, content := range extra {
		files[name] = content
	}
	return safetyPod(t, files)
}

// runCLI runs the built binary with HOME set to home and returns the exit
// code and combined output.
func runCLI(t *testing.T, bin, home string, args ...string) (int, string) {
	t.Helper()
	cmd := exec.Command(bin, args...)
	cmd.Env = append(os.Environ(), "HOME="+home)
	out, err := cmd.CombinedOutput()
	code := 0
	if exitErr, ok := err.(*exec.ExitError); ok {
		code = exitErr.ExitCode()
	} else if err != nil {
		t.Fatalf("run %v: %v", args, err)
	}
	return code, string(out)
}

// A key in a README is refused at `pod publish`, with the file, the line
// and the class, no value, and the correct path. A near miss publishes.
func TestPodPublishRefusesCredentialInAnyBundleFile(t *testing.T) {
	bin := buildCLI(t)
	home := t.TempDir()
	if code, out := runCLI(t, bin, home, "pod", "identity", "create", "--handle", "alice"); code != 0 {
		t.Fatalf("identity create: %d\n%s", code, out)
	}

	secret := credentialSecret()
	dir := credentialPod(t, "Notes\n\nkey: "+secret+"\n", nil)
	code, out := runCLI(t, bin, home, "pod", "publish", dir, "--dry-run")
	if code != 1 {
		t.Fatalf("exit code = %d, want 1\n%s", code, out)
	}
	for _, want := range []string{"BUNDLE_CREDENTIAL_FOUND", "README.md:3: aws_access_key_id", "konareef pod secret set"} {
		if !strings.Contains(out, want) {
			t.Errorf("output is missing %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, secret) || strings.Contains(out, secret[4:]) {
		t.Fatalf("output contains the secret value:\n%s", out)
	}
	if strings.Contains(out, "Validated pod.toml") {
		t.Errorf("publish went on to prepare the pod after the refusal:\n%s", out)
	}

	nearMiss := credentialPod(t, "Keys start with AKIA and are secret.\n", nil)
	if code, out := runCLI(t, bin, home, "pod", "publish", nearMiss, "--dry-run"); code != 0 {
		t.Fatalf("near miss: exit code = %d, want 0\n%s", code, out)
	}
}

// An allow entry lets `pod publish` through, and says so.
func TestPodPublishAllowsAnAllowedFinding(t *testing.T) {
	bin := buildCLI(t)
	home := t.TempDir()
	if code, out := runCLI(t, bin, home, "pod", "identity", "create", "--handle", "alice"); code != 0 {
		t.Fatalf("identity create: %d\n%s", code, out)
	}
	dir := credentialPod(t, "key: "+credentialSecret()+"\n", map[string]string{
		"credential-allow.toml": credentialAllowREADME(),
	})
	code, out := runCLI(t, bin, home, "pod", "publish", dir, "--dry-run")
	if code != 0 {
		t.Fatalf("exit code = %d, want 0\n%s", code, out)
	}
	if !strings.Contains(out, "README.md:1: aws_access_key_id — documented example key") {
		t.Errorf("the allowed finding is not shown:\n%s", out)
	}
}

// `pod listing publish` refuses on the same finding, before any request.
func TestPodListingPublishRefusesCredential(t *testing.T) {
	dir := credentialPod(t, "key: "+credentialSecret()+"\n", nil)
	writeListingTestIdentity(t, "alice")
	stderr := captureStderr(t)
	code := runPodListingImpl(withFeeConfirmation([]string{
		"publish", dir, "--fee", "500", "--revision", "1", "--category", "research",
		"--description", "Summarizes.", "--server", "http://127.0.0.1:1",
	}))
	out := stderr()
	if code != 1 {
		t.Fatalf("exit code = %d, want 1\n%s", code, out)
	}
	if !strings.Contains(out, "BUNDLE_CREDENTIAL_FOUND") || !strings.Contains(out, "README.md:1: aws_access_key_id") {
		t.Errorf("refusal text:\n%s", out)
	}
	if strings.Contains(out, credentialSecret()) {
		t.Fatalf("output contains the secret value:\n%s", out)
	}
}

// An allowed finding does not refuse the listing, and it is shown in the
// listing diagnostics.
func TestPodListingPublishShowsAllowedFinding(t *testing.T) {
	dir := credentialPod(t, "key: "+credentialSecret()+"\n", map[string]string{
		"credential-allow.toml": credentialAllowREADME(),
	})
	var gotBody map[string]any
	srv := listingCaptureServer(t, &gotBody)
	writeListingTestIdentity(t, "alice")
	stderr := captureStderr(t)
	code := runPodListingImpl(withFeeConfirmation([]string{
		"publish", dir, "--fee", "500", "--revision", "1", "--category", "research",
		"--description", "Summarizes.", "--server", srv.URL,
	}))
	out := stderr()
	if code != 0 {
		t.Fatalf("exit code = %d, want 0\n%s", code, out)
	}
	if !strings.Contains(out, "README.md:1: aws_access_key_id — documented example key") {
		t.Errorf("the allowed finding is not in the listing diagnostics:\n%s", out)
	}
}

// A malformed allow file refuses; it never widens the allowance.
func TestPodPublishRefusesMalformedAllowFile(t *testing.T) {
	dir := credentialPod(t, "clean\n", map[string]string{"credential-allow.toml": "[[allow]]\nfile = \"README.md\"\n"})
	writeListingTestIdentity(t, "alice")
	if code := bundleCredentialGate(dir, "publish"); code != 1 {
		t.Fatalf("gate code = %d, want 1", code)
	}
}

// `pod validate` and `pod safety` warn and keep their exit codes.
func TestPodValidateAndSafetyWarnOnCredential(t *testing.T) {
	bin := buildCLI(t)
	home := t.TempDir()
	dir := credentialPod(t, "key: "+credentialSecret()+"\n", nil)

	code, out := runCLI(t, bin, home, "pod", "validate", filepath.Join(dir, "pod.toml"))
	if code != 0 {
		t.Fatalf("validate exit code = %d, want 0\n%s", code, out)
	}
	if !strings.Contains(out, "warning: BUNDLE_CREDENTIAL_FOUND: README.md:1: aws_access_key_id") ||
		!strings.Contains(out, "valid") {
		t.Errorf("validate output:\n%s", out)
	}
	if strings.Contains(out, credentialSecret()) {
		t.Fatalf("validate output contains the secret value:\n%s", out)
	}

	code, out = runCLI(t, bin, home, "pod", "safety", dir)
	if code != 0 {
		t.Fatalf("safety exit code = %d, want 0\n%s", code, out)
	}
	if !strings.Contains(out, "warning: BUNDLE_CREDENTIAL_FOUND: README.md:1: aws_access_key_id") {
		t.Errorf("safety output:\n%s", out)
	}
}

// A scan that cannot finish fails closed with its own stable code, not the
// found-a-credential code, so automation can tell the two apart (review M4
// on konareef!149). The underlying cause is kept in the message.
func TestBundleCredentialGateReportsScanFailureWithItsOwnCode(t *testing.T) {
	symlinked := credentialPod(t, "clean\n", nil)
	if err := os.Symlink("README.md", filepath.Join(symlinked, "link.md")); err != nil {
		t.Fatal(err)
	}
	malformed := credentialPod(t, "clean\n", map[string]string{"credential-allow.toml": "[[allow]]\nfile = \"README.md\"\n"})
	for name, dir := range map[string]string{"symlink": symlinked, "malformed allow file": malformed} {
		t.Run(name, func(t *testing.T) {
			stderr := captureStderr(t)
			code := bundleCredentialGate(dir, "publish")
			out := stderr()
			if code != 1 {
				t.Fatalf("gate code = %d, want 1\n%s", code, out)
			}
			if !strings.Contains(out, "BUNDLE_CREDENTIAL_SCAN_FAILED") || strings.Contains(out, "BUNDLE_CREDENTIAL_FOUND") {
				t.Fatalf("scan failure is not reported with its own code:\n%s", out)
			}
		})
	}
}
