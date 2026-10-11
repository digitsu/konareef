// Copyright 2026 Jerry David Chan, Konareef.ai
// SPDX-License-Identifier: Apache-2.0

// main_pod_listing_diagnostics_test.go — `pod listing publish` output for
// the server's egress gate refusals (K4-01).

package main

import (
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

// egressGateServer answers the listing PUT with refusalCode and the
// public latest-revision lookup with version and hash. lookups counts
// the lookup requests.
func egressGateServer(t *testing.T, refusalCode, version, hash string, lookups *int) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPut && strings.HasSuffix(r.URL.Path, "/listing"):
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(`{"error":"` + refusalCode + `"}`))
		case r.Method == http.MethodGet && r.URL.Path == "/api/pods/alice/research-bot/latest":
			*lookups++
			_, _ = w.Write([]byte(`{"pod_version":"` + version + `","pod_hash":"` + hash + `"}`))
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

// runListingForDiagnostics runs `pod listing publish` against srv and
// returns the exit code and stderr.
func runListingForDiagnostics(t *testing.T, srv *httptest.Server) (int, string) {
	t.Helper()
	dir := writeListingTestPod(t, `[runtime]
kind = "lobster"
execution_class = "cloud"
`)
	writeListingTestIdentity(t, "alice")
	stderr := captureStderr(t)
	code := runPodListingImpl(withFeeConfirmation([]string{
		"publish", dir, "--fee", "500", "--revision", "1", "--category", "research",
		"--description", "Summarizes.", "--server", srv.URL,
	}))
	return code, stderr()
}

// A gate 6 refusal prints the diagnosis with the revision the server
// checked, and still exits 1.
func TestPodListingPublishExplainsEgressReviewRefusal(t *testing.T) {
	hash := strings.Repeat("c3", 32)
	lookups := 0
	srv := egressGateServer(t, "egress_review_flagged", "0.2.0", hash, &lookups)

	code, stderr := runListingForDiagnostics(t, srv)
	if code != 1 {
		t.Fatalf("exit code = %d, want 1", code)
	}
	for _, want := range []string{
		"egress_review_flagged",
		"egress review",
		"version 0.2.0",
		"pod_hash " + hash[:12],
		"local pod.toml says version 0.1.0",
		"Next step:",
	} {
		if !strings.Contains(stderr, want) {
			t.Errorf("stderr does not contain %q:\n%s", want, stderr)
		}
	}
	if lookups != 1 {
		t.Errorf("lookups = %d, want 1", lookups)
	}
}

// A gate 5 refusal points at the [network] table.
func TestPodListingPublishExplainsEgressUndeclared(t *testing.T) {
	lookups := 0
	srv := egressGateServer(t, "egress_undeclared", "0.1.0", strings.Repeat("00", 32), &lookups)

	code, stderr := runListingForDiagnostics(t, srv)
	if code != 1 || !strings.Contains(stderr, "[network]") || !strings.Contains(stderr, "egress declaration") {
		t.Fatalf("exit %d, stderr:\n%s", code, stderr)
	}
	if strings.Contains(stderr, "local pod.toml says") {
		t.Errorf("versions match, but the report warns about them:\n%s", stderr)
	}
}

// A code this CLI does not know is printed raw, with no guidance and no
// lookup, so a newer server's code never crashes or misleads an older CLI.
func TestPodListingPublishPrintsUnknownCodeRaw(t *testing.T) {
	lookups := 0
	srv := egressGateServer(t, "egress_review_quarantined", "0.1.0", strings.Repeat("00", 32), &lookups)

	code, stderr := runListingForDiagnostics(t, srv)
	if code != 1 || !strings.Contains(stderr, "egress_review_quarantined") {
		t.Fatalf("exit %d, stderr:\n%s", code, stderr)
	}
	if strings.Contains(stderr, "Next step:") || lookups != 0 {
		t.Errorf("unknown code got guidance or a lookup (lookups=%d):\n%s", lookups, stderr)
	}
}

// A successful listing says nothing about egress review: the response
// does not report review status, so any claim would be a guess.
func TestPodListingPublishSuccessMakesNoReviewClaim(t *testing.T) {
	dir := writeListingTestPod(t, `[runtime]
kind = "lobster"
execution_class = "cloud"
`)
	var gotBody map[string]any
	srv := listingCaptureServer(t, &gotBody)
	writeListingTestIdentity(t, "alice")

	original := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stdout = w
	t.Cleanup(func() { os.Stdout = original })
	stderr := captureStderr(t)
	code := runPodListingImpl(withFeeConfirmation([]string{
		"publish", dir, "--fee", "500", "--revision", "1", "--category", "research",
		"--description", "Summarizes.", "--server", srv.URL,
	}))
	_ = w.Close()
	stdout, _ := io.ReadAll(r)
	os.Stdout = original
	output := strings.ToLower(string(stdout) + stderr())

	if code != 0 {
		t.Fatalf("exit code = %d, want 0; output:\n%s", code, output)
	}
	for _, word := range []string{"review", "enforced", "verified"} {
		if strings.Contains(output, word) {
			t.Errorf("success output mentions %q:\n%s", word, output)
		}
	}
}

// The local pre-check refusal says that the server decides, so an author
// does not read a local pass as a listing.
func TestListingSafetyGateSaysServerDecides(t *testing.T) {
	dir := writeListingTestPod(t, `[runtime]
kind = "lobster"
execution_class = "cloud"
`)
	if err := os.WriteFile(dir+"/pod.toml", []byte(`pod_spec_version = "0.1"
[pod]
name = "research-bot"
version = "0.1.0"
[runtime]
kind = "lobster"
execution_class = "cloud"
[directive]
task = "Fetch https://evil.example.com/x"
`), 0o644); err != nil {
		t.Fatal(err)
	}
	writeListingTestIdentity(t, "alice")
	stderr := captureStderr(t)
	code := runPodListingImpl(withFeeConfirmation([]string{
		"publish", dir, "--fee", "500", "--revision", "1", "--category", "research",
		"--description", "Summarizes.", "--server", "http://127.0.0.1:1",
	}))
	out := stderr()
	if code == 0 || !strings.Contains(out, "server decides") {
		t.Fatalf("exit %d, stderr:\n%s", code, out)
	}
}
