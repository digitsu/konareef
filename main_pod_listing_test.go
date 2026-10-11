// Copyright 2026 Jerry David Chan, Konareef.ai
// SPDX-License-Identifier: Apache-2.0

// main_pod_listing_test.go — acceptance tests for `konareef pod listing`.
//
// These drive runPodListingImpl in-process (the exit-code seam behind the
// os.Exit wrapper) so flag parsing, manifest reading, identity loading,
// and the wire body are all covered without building a binary.

package main

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/digitsu/konareef/internal/identity"
)

// withFeeConfirmation appends --confirm-fee to a listing publish arg list.
//
// `pod listing publish` now refuses without either a terminal to ask or that
// flag, and these in-process calls have neither. A real automated publisher
// passes it for the same reason. The gate's own behaviour is covered in
// main_confirm_gate_test.go — nothing here should be read as testing it.
func withFeeConfirmation(args []string) []string {
	return append(append([]string{}, args...), "--"+confirmFlagFee)
}

// writeListingTestIdentity creates an isolated $HOME holding a freshly
// generated publisher identity, and points $HOME at it for the duration
// of the test. Never touches the developer's real ~/.konareef.
func writeListingTestIdentity(t *testing.T, handle string) {
	t.Helper()
	home := t.TempDir()
	id, err := identity.Generate(handle)
	if err != nil {
		t.Fatalf("generate identity: %v", err)
	}
	if err := id.Save(home); err != nil {
		t.Fatalf("save identity: %v", err)
	}
	t.Setenv("HOME", home)
}

// writeListingTestPod writes a minimal pod.toml into a fresh temp dir and
// returns the dir. body is appended to the fixed [pod] header so a test
// can vary the [runtime] block.
func writeListingTestPod(t *testing.T, body string) string {
	t.Helper()
	dir := t.TempDir()
	manifest := `pod_spec_version = "0.1"
[pod]
name = "research-bot"
version = "0.1.0"
[directive]
task = "Summarize a research question."
` + body
	if err := os.WriteFile(filepath.Join(dir, "pod.toml"), []byte(manifest), 0o644); err != nil {
		t.Fatal(err)
	}
	return dir
}

// listingCaptureServer stands in for reef-core, capturing the PUT body.
//
// It echoes handle/pod_name/author_fee_sats back the way the real
// controller's render_listing does, because Submit now refuses a 2xx
// that does not describe the listing it sent.
func listingCaptureServer(t *testing.T, gotBody *map[string]any) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(raw, gotBody)
		reply, _ := json.Marshal(map[string]any{
			"handle":          (*gotBody)["handle"],
			"pod_name":        (*gotBody)["pod_name"],
			"revision":        (*gotBody)["revision"],
			"author_fee_sats": (*gotBody)["author_fee_sats"],
			"status":          "community",
		})
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(reply)
	}))
	t.Cleanup(srv.Close)
	return srv
}

// `konareef pod listing publish <dir> --fee N --category C` reads the
// pod's execution_class from its manifest, signs, and PUTs the listing.
func TestPodListingPublishSendsExecutionClassFromManifest(t *testing.T) {
	dir := writeListingTestPod(t, `[runtime]
kind = "lobster"
execution_class = "local-mount"
`)
	var gotBody map[string]any
	srv := listingCaptureServer(t, &gotBody)
	writeListingTestIdentity(t, "alice")

	code := runPodListingImpl(withFeeConfirmation([]string{
		"publish", dir,
		"--fee", "500", "--revision", "1",
		"--category", "research",
		"--description", "Summarizes a research question.",
		"--server", srv.URL,
	}))
	if code != 0 {
		t.Fatalf("exit code = %d, want 0", code)
	}
	if gotBody["execution_class"] != "local-mount" {
		t.Errorf("execution_class = %v, want local-mount", gotBody["execution_class"])
	}
	if gotBody["author_fee_sats"] != float64(500) {
		t.Errorf("author_fee_sats = %v, want 500", gotBody["author_fee_sats"])
	}
	if gotBody["handle"] != "alice" {
		t.Errorf("handle = %v, want alice", gotBody["handle"])
	}
	if gotBody["pod_name"] != "research-bot" {
		t.Errorf("pod_name = %v, want research-bot", gotBody["pod_name"])
	}
}

// A manifest that does not declare execution_class cannot be listed.
//
// The CLI used to substitute "cloud" here. That was a guaranteed-failure
// path: reef-core's ManifestFields.execution_class/1 returns :error when
// the field is absent and the gate fails closed with
// :execution_class_undeclared, so the invented value could only ever
// produce a server rejection — after the CLI had silently chosen a
// security-relevant value on the author's behalf. Fail locally instead,
// and say what to do about it.
func TestPodListingPublishRefusesManifestWithoutExecutionClass(t *testing.T) {
	dir := writeListingTestPod(t, `[runtime]
kind = "lobster"
`)
	var reached bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reached = true
	}))
	defer srv.Close()
	writeListingTestIdentity(t, "alice")

	code := runPodListingImpl(withFeeConfirmation([]string{
		"publish", dir, "--fee", "500", "--revision", "1", "--category", "research",
		"--description", "Summarizes.", "--server", srv.URL,
	}))
	if code != 1 {
		t.Errorf("exit code = %d, want 1", code)
	}
	if reached {
		t.Error("a listing was submitted for a pod that declares no execution_class")
	}
}

// --description is optional: it falls back to [pod].description.
func TestPodListingPublishFallsBackToManifestDescription(t *testing.T) {
	dir := t.TempDir()
	manifest := `pod_spec_version = "0.1"
[pod]
name = "research-bot"
version = "0.1.0"
description = "From the manifest."
[directive]
task = "Summarize a research question."
[runtime]
kind = "lobster"
execution_class = "cloud"
`
	if err := os.WriteFile(filepath.Join(dir, "pod.toml"), []byte(manifest), 0o644); err != nil {
		t.Fatal(err)
	}
	var gotBody map[string]any
	srv := listingCaptureServer(t, &gotBody)
	writeListingTestIdentity(t, "alice")

	code := runPodListingImpl(withFeeConfirmation([]string{
		"publish", dir, "--fee", "500", "--revision", "1", "--category", "research", "--server", srv.URL,
	}))
	if code != 0 {
		t.Fatalf("exit code = %d, want 0", code)
	}
	if gotBody["display_description"] != "From the manifest." {
		t.Errorf("display_description = %v", gotBody["display_description"])
	}
}

// Usage errors exit 2 and never reach the network.
//
// $HOME is isolated and the request counter asserted at zero: without
// that, a regression in the guard clauses would make this test load the
// developer's real ~/.konareef identity and PUT to whatever is listening
// on localhost:4000, while still "passing".
func TestPodListingPublishUsageErrors(t *testing.T) {
	dir := writeListingTestPod(t, `[runtime]
kind = "lobster"
execution_class = "cloud"
`)
	var requests int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
	}))
	defer srv.Close()
	writeListingTestIdentity(t, "alice")
	t.Setenv("KONAREEF_SERVER", srv.URL)

	cases := map[string][]string{
		"no subcommand":    {},
		"unknown sub":      {"delist", dir},
		"missing pod dir":  {"publish", "--fee", "500", "--revision", "1", "--category", "research"},
		"missing fee":      {"publish", dir, "--revision", "1", "--category", "research"},
		"zero fee":         {"publish", dir, "--fee", "0", "--revision", "1", "--category", "research"},
		"negative fee":     {"publish", dir, "--fee", "-1", "--revision", "1", "--category", "research"},
		"missing category": {"publish", dir, "--fee", "500", "--revision", "1"},
		"missing revision": {"publish", dir, "--fee", "500", "--category", "research"},
	}
	for name, args := range cases {
		t.Run(name, func(t *testing.T) {
			if code := runPodListingImpl(args); code != 2 {
				t.Errorf("exit code = %d, want 2", code)
			}
		})
	}
	if requests != 0 {
		t.Errorf("a usage error reached the network %d time(s)", requests)
	}
}

// A missing description with no manifest fallback is a pipeline failure,
// not a usage error — the manifest parsed fine, it just has nothing to
// display in the marketplace.
func TestPodListingPublishRequiresADescription(t *testing.T) {
	dir := writeListingTestPod(t, `[runtime]
kind = "lobster"
execution_class = "cloud"
`)
	writeListingTestIdentity(t, "alice")
	if code := runPodListingImpl(withFeeConfirmation([]string{
		"publish", dir, "--fee", "500", "--revision", "1", "--category", "research",
	})); code != 1 {
		t.Errorf("exit code = %d, want 1", code)
	}
}

// A flag value carrying a preimage delimiter is refused before anything
// is signed or sent — the CLI is the main way untrusted text reaches the
// canonical bytes, so the rejection has to hold end-to-end, not just in
// the listing package.
func TestPodListingPublishRejectsControlCharsInFlags(t *testing.T) {
	dir := writeListingTestPod(t, `[runtime]
kind = "lobster"
execution_class = "cloud"
`)
	var reached bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reached = true
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"community"}`))
	}))
	defer srv.Close()
	writeListingTestIdentity(t, "alice")

	for name, args := range map[string][]string{
		"category newline":    {"--category", "research\ndisplay_description\tEVIL", "--description", "Good"},
		"description newline": {"--category", "research", "--description", "EVIL\ndisplay_description\tGood"},
		"category tab":        {"--category", "res\tearch", "--description", "Good"},
	} {
		t.Run(name, func(t *testing.T) {
			reached = false
			argv := append([]string{"publish", dir, "--fee", "500", "--revision", "1", "--server", srv.URL}, args...)
			if code := runPodListingImpl(argv); code != 1 {
				t.Errorf("exit code = %d, want 1", code)
			}
			if reached {
				t.Error("the request reached the server; it must be refused before sending")
			}
		})
	}
}

// A server rejection is surfaced as a non-zero exit.
func TestPodListingPublishFailsOnServerRejection(t *testing.T) {
	dir := writeListingTestPod(t, `[runtime]
kind = "lobster"
execution_class = "cloud"
`)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnprocessableEntity)
		_, _ = w.Write([]byte(`{"error":"execution_class_mismatch"}`))
	}))
	defer srv.Close()
	writeListingTestIdentity(t, "alice")

	if code := runPodListingImpl(withFeeConfirmation([]string{
		"publish", dir, "--fee", "500", "--revision", "1", "--category", "research",
		"--description", "Summarizes.", "--server", srv.URL,
	})); code != 1 {
		t.Errorf("exit code = %d, want 1", code)
	}
}

// --fee is decimal-only. Go's flag.Int parses with base 0, so "0100"
// silently means octal 64 and "0x1f4" means 500 — an author pasting a
// zero-padded value from a spreadsheet would publish at a price they
// never chose. This is real money, so anything non-decimal is refused
// rather than reinterpreted.
func TestPodListingPublishRejectsNonDecimalFee(t *testing.T) {
	dir := writeListingTestPod(t, `[runtime]
kind = "lobster"
execution_class = "cloud"
`)
	var requests int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
	}))
	defer srv.Close()
	writeListingTestIdentity(t, "alice")

	for _, fee := range []string{
		"0x1f4",   // would be hex 500 under base-0 parsing
		"0b11",    // would be binary 3
		"0o17",    // would be octal 15
		"1_000",   // Go underscore separator
		"500sats", // trailing junk
		"5.5",     // not an integer
		"",        // empty
		" 500",    // leading space
	} {
		t.Run(fee, func(t *testing.T) {
			code := runPodListingImpl(withFeeConfirmation([]string{
				"publish", dir, "--fee", fee, "--revision", "1", "--category", "research",
				"--description", "Summarizes.", "--server", srv.URL,
			}))
			if code == 0 {
				t.Errorf("--fee %q was accepted", fee)
			}
		})
	}
	if requests != 0 {
		t.Errorf("a malformed fee reached the network %d time(s)", requests)
	}
}

// The fee ceiling mirrors reef-core's Gates.max_author_fee_sats/0
// (100_000_000) so a fat-finger fails locally instead of after a round
// trip. The boundary itself must still be accepted.
func TestPodListingPublishEnforcesFeeCeiling(t *testing.T) {
	dir := writeListingTestPod(t, `[runtime]
kind = "lobster"
execution_class = "cloud"
`)
	writeListingTestIdentity(t, "alice")

	t.Run("above ceiling is refused", func(t *testing.T) {
		var requests int
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			requests++
		}))
		defer srv.Close()
		code := runPodListingImpl(withFeeConfirmation([]string{
			"publish", dir, "--fee", "100000001", "--revision", "1", "--category", "research",
			"--description", "Summarizes.", "--server", srv.URL,
		}))
		if code == 0 {
			t.Error("a fee above the ceiling was accepted")
		}
		if requests != 0 {
			t.Errorf("an out-of-range fee reached the network %d time(s)", requests)
		}
	})

	t.Run("exactly the ceiling is allowed", func(t *testing.T) {
		var gotBody map[string]any
		srv := listingCaptureServer(t, &gotBody)
		code := runPodListingImpl(withFeeConfirmation([]string{
			"publish", dir, "--fee", "100000000", "--revision", "1", "--category", "research",
			"--description", "Summarizes.", "--server", srv.URL,
		}))
		if code != 0 {
			t.Fatalf("exit code = %d, want 0", code)
		}
		if gotBody["author_fee_sats"] != float64(100000000) {
			t.Errorf("author_fee_sats = %v", gotBody["author_fee_sats"])
		}
	})
}

// The confirmation line must report the fee the SERVER stored, not the
// one the CLI asked for. On a money-carrying write, echoing back the
// request would hide a server that stored something else.
func TestPodListingPublishReportsServerStoredFee(t *testing.T) {
	dir := writeListingTestPod(t, `[runtime]
kind = "lobster"
execution_class = "cloud"
`)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(
			`{"handle":"alice","pod_name":"research-bot","author_fee_sats":499,"status":"verified"}`))
	}))
	defer srv.Close()
	writeListingTestIdentity(t, "alice")

	// 499 != the 500 submitted, so this must be an error rather than a
	// success line quoting the requested price back at the author.
	code := runPodListingImpl(withFeeConfirmation([]string{
		"publish", dir, "--fee", "500", "--revision", "1", "--category", "research",
		"--description", "Summarizes.", "--server", srv.URL,
	}))
	if code != 1 {
		t.Errorf("exit code = %d, want 1 (server stored a different fee)", code)
	}
}

// The specific value that motivated the fix: a zero-padded price. Under
// flag.Int's base-0 parsing "0100" silently meant octal 64, so an author
// pricing at 100 sats published at 64. It must now mean exactly 100.
func TestPodListingPublishTreatsZeroPaddedFeeAsDecimal(t *testing.T) {
	dir := writeListingTestPod(t, `[runtime]
kind = "lobster"
execution_class = "cloud"
`)
	var gotBody map[string]any
	srv := listingCaptureServer(t, &gotBody)
	writeListingTestIdentity(t, "alice")

	code := runPodListingImpl(withFeeConfirmation([]string{
		"publish", dir, "--fee", "0100", "--revision", "1", "--category", "research",
		"--description", "Summarizes.", "--server", srv.URL,
	}))
	if code != 0 {
		t.Fatalf("exit code = %d, want 0", code)
	}
	if gotBody["author_fee_sats"] != float64(100) {
		t.Errorf("author_fee_sats = %v, want 100 (64 means base-0 parsing is back)",
			gotBody["author_fee_sats"])
	}
}

// --revision is decimal-only and bounded, mirroring reef-core's
// Canonical.max_revision/0. It is never auto-incremented: it is a
// signed freshness claim on a money-carrying write, so the publisher
// states it explicitly or the command fails.
func TestPodListingPublishRejectsMalformedRevision(t *testing.T) {
	dir := writeListingTestPod(t, `[runtime]
kind = "lobster"
execution_class = "cloud"
`)
	var requests int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
	}))
	defer srv.Close()
	writeListingTestIdentity(t, "alice")

	for _, rev := range []string{
		"0x10",                // would be 16 under base-0 parsing
		"1.0",                 // reef-core 400s on a JSON float
		"1_000",               // underscore separator
		"7rev",                // trailing junk
		" 1",                  // leading space
		"-1",                  // negative
		"9007199254740992",    // MaxRevision + 1
		"9223372036854775807", // int64 max
	} {
		t.Run(rev, func(t *testing.T) {
			if code := runPodListingImpl(withFeeConfirmation([]string{
				"publish", dir, "--fee", "500", "--revision", rev,
				"--category", "research", "--description", "Summarizes.",
				"--server", srv.URL,
			})); code == 0 {
				t.Errorf("--revision %q was accepted", rev)
			}
		})
	}
	if requests != 0 {
		t.Errorf("a malformed revision reached the network %d time(s)", requests)
	}
}

// The signed revision reaches the wire body verbatim.
func TestPodListingPublishSendsRevision(t *testing.T) {
	dir := writeListingTestPod(t, `[runtime]
kind = "lobster"
execution_class = "cloud"
`)
	var gotBody map[string]any
	srv := listingCaptureServer(t, &gotBody)
	writeListingTestIdentity(t, "alice")

	code := runPodListingImpl(withFeeConfirmation([]string{
		"publish", dir, "--fee", "500", "--revision", "9007199254740991",
		"--category", "research", "--description", "Summarizes.", "--server", srv.URL,
	}))
	if code != 0 {
		t.Fatalf("exit code = %d, want 0", code)
	}
	if gotBody["revision"] != float64(9007199254740991) {
		t.Errorf("revision = %v, want 9007199254740991", gotBody["revision"])
	}
}

// A stale_revision rejection must reach the operator as an actionable
// message, not a bare error code.
func TestPodListingPublishSurfacesStaleRevision(t *testing.T) {
	dir := writeListingTestPod(t, `[runtime]
kind = "lobster"
execution_class = "cloud"
`)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"error":"stale_revision"}`))
	}))
	defer srv.Close()
	writeListingTestIdentity(t, "alice")

	if code := runPodListingImpl(withFeeConfirmation([]string{
		"publish", dir, "--fee", "500", "--revision", "3",
		"--category", "research", "--description", "Summarizes.", "--server", srv.URL,
	})); code != 1 {
		t.Errorf("exit code = %d, want 1", code)
	}
}

// The stale_revision recovery hint must reach the operator's terminal,
// not just the library. Covers both server generations: one that
// reports current_revision and one that predates it.
func TestPodListingPublishPrintsStaleRevisionHint(t *testing.T) {
	dir := writeListingTestPod(t, `[runtime]
kind = "lobster"
execution_class = "cloud"
`)
	for name, tc := range map[string]struct{ body, want string }{
		"with current_revision": {
			`{"error":"stale_revision","current_revision":7}`,
			"the stored revision is 7 — re-run with --revision 8 (or higher)",
		},
		"without current_revision": {
			`{"error":"stale_revision"}`,
			"/api/listings/alice/research-bot",
		},
	} {
		t.Run(name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusBadRequest)
				_, _ = w.Write([]byte(tc.body))
			}))
			defer srv.Close()
			writeListingTestIdentity(t, "alice")

			stderr := captureStderr(t)
			code := runPodListingImpl(withFeeConfirmation([]string{
				"publish", dir, "--fee", "500", "--revision", "3",
				"--category", "research", "--description", "Summarizes.",
				"--server", srv.URL,
			}))
			out := stderr()
			if code != 1 {
				t.Fatalf("exit code = %d, want 1", code)
			}
			if !strings.Contains(out, tc.want) {
				t.Errorf("stderr =\n%s\nwant it to contain %q", out, tc.want)
			}
		})
	}
}

// captureStderr redirects os.Stderr for the duration of the test and
// returns a func yielding what was written.
func captureStderr(t *testing.T) func() string {
	t.Helper()
	original := os.Stderr
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stderr = w
	t.Cleanup(func() { os.Stderr = original })
	return func() string {
		_ = w.Close()
		out, _ := io.ReadAll(r)
		os.Stderr = original
		return string(out)
	}
}
