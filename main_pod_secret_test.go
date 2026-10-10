// Copyright 2026 Jerry David Chan, Konareef.ai
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// secretCaptureServer stands in for reef-core's secret endpoints.
func secretCaptureServer(t *testing.T, status int, reply string, got *map[string]any, gotPath *string) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		*gotPath = r.Method + " " + r.URL.Path
		raw, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(raw, got)
		w.WriteHeader(status)
		_, _ = w.Write([]byte(reply))
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestPodSecretSetReadsValueFromStdinAndPosts(t *testing.T) {
	var got map[string]any
	var path string
	srv := secretCaptureServer(t, 201, `{"name":"ELEVENLABS_API_KEY","rotated_at":"2026-09-09T00:00:00Z"}`, &got, &path)
	writeListingTestIdentity(t, "alice")

	code := runPodSecretImpl(
		[]string{"set", "alice/research-bot", "ELEVENLABS_API_KEY", "--server", srv.URL},
		strings.NewReader("xi-test-value\n"),
	)
	if code != 0 {
		t.Fatalf("exit code = %d, want 0", code)
	}
	if path != "POST /api/pods/alice/research-bot/secrets" {
		t.Fatalf("request = %s", path)
	}
	value, _ := base64.StdEncoding.DecodeString(got["value"].(string))
	if string(value) != "xi-test-value" {
		t.Fatalf("value = %q (trailing newline must be trimmed once)", value)
	}
}

func TestPodSecretSetRefusesEmptyValue(t *testing.T) {
	var got map[string]any
	var path string
	srv := secretCaptureServer(t, 201, `{}`, &got, &path)
	writeListingTestIdentity(t, "alice")

	code := runPodSecretImpl([]string{"set", "alice/research-bot", "A_KEY", "--server", srv.URL}, strings.NewReader("\n"))
	if code != 1 || path != "" {
		t.Fatalf("code = %d, request = %q; want 1 and no request", code, path)
	}
}

func TestPodSecretSetRefusesHandleMismatch(t *testing.T) {
	var got map[string]any
	var path string
	srv := secretCaptureServer(t, 201, `{}`, &got, &path)
	writeListingTestIdentity(t, "alice")

	code := runPodSecretImpl([]string{"set", "bob/research-bot", "A_KEY", "--server", srv.URL}, strings.NewReader("v\n"))
	if code != 1 || path != "" {
		t.Fatalf("code = %d, request = %q; want 1 and no request", code, path)
	}
}

func TestPodSecretRmNeedsConfirmation(t *testing.T) {
	var got map[string]any
	var path string
	srv := secretCaptureServer(t, 200, `{"name":"A_KEY","removed":true}`, &got, &path)
	writeListingTestIdentity(t, "alice")

	// No terminal and no flag: refused with the not-confirmed exit code.
	code := runPodSecretImpl([]string{"rm", "alice/research-bot", "A_KEY", "--server", srv.URL}, strings.NewReader(""))
	if code != exitNotConfirmed || path != "" {
		t.Fatalf("code = %d, request = %q", code, path)
	}

	code = runPodSecretImpl([]string{"rm", "alice/research-bot", "A_KEY", "--server", srv.URL, "--" + confirmFlagSecretRm}, strings.NewReader(""))
	if code != 0 || path != "DELETE /api/pods/alice/research-bot/secrets/A_KEY" {
		t.Fatalf("code = %d, request = %q", code, path)
	}
}

func TestPodSecretLs(t *testing.T) {
	var got map[string]any
	var path string
	srv := secretCaptureServer(t, 200, `{"secrets":[{"name":"A_KEY","rotated_at":"2026-09-09T00:00:00Z"}]}`, &got, &path)
	writeListingTestIdentity(t, "alice")

	code := runPodSecretImpl([]string{"ls", "alice/research-bot", "--server", srv.URL}, strings.NewReader(""))
	if code != 0 || path != "POST /api/pods/alice/research-bot/secrets/list" {
		t.Fatalf("code = %d, request = %q", code, path)
	}
}

// TestPodSecretSetRefusesOversizeValue covers Important 2 from the
// final review: a value over the 64 KiB limit must be refused outright,
// not silently truncated and bound as the wrong credential.
func TestPodSecretSetRefusesOversizeValue(t *testing.T) {
	var got map[string]any
	var path string
	srv := secretCaptureServer(t, 201, `{}`, &got, &path)
	writeListingTestIdentity(t, "alice")

	oversize := strings.Repeat("a", 64*1024+1)
	code := runPodSecretImpl([]string{"set", "alice/research-bot", "A_KEY", "--server", srv.URL}, strings.NewReader(oversize))
	if code != 1 || path != "" {
		t.Fatalf("code = %d, request = %q; want 1 and no request", code, path)
	}
}

// TestPodSecretSetRefusesPlainHTTPToRemoteHost covers Important 3 from
// the final review: `pod secret set` must refuse to send a value over
// plain http to anything but a loopback host, so a live third-party API
// key cannot land on the wire in cleartext.
func TestPodSecretSetRefusesPlainHTTPToRemoteHost(t *testing.T) {
	var requestReceived bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestReceived = true
		w.WriteHeader(201)
		_, _ = w.Write([]byte(`{}`))
	}))
	t.Cleanup(srv.Close)
	writeListingTestIdentity(t, "alice")

	code := runPodSecretImpl(
		[]string{"set", "alice/research-bot", "A_KEY", "--server", "http://example.com:4000"},
		strings.NewReader("xi-test-value\n"),
	)
	if code != 2 {
		t.Fatalf("code = %d, want 2", code)
	}
	if requestReceived {
		t.Fatal("request reached the server; a plain-http remote set must be refused before any network call")
	}
}

func TestPodSecretUsageErrors(t *testing.T) {
	writeListingTestIdentity(t, "alice")
	for _, args := range [][]string{
		{},
		{"set"},
		{"set", "alice-research-bot", "A_KEY"},
		{"set", "alice/research-bot", "lower"},
		{"frobnicate", "alice/research-bot"},
	} {
		if code := runPodSecretImpl(args, strings.NewReader("")); code != 2 {
			t.Errorf("args %v: code = %d, want 2", args, code)
		}
	}
}

// TestPodSecretRefusesReservedNames checks that `pod secret set` and `rm`
// refuse every name reef-core reserves, including the two OpenCode flags
// P3-07 sets on the harness, with exit code 2 and before any request.
func TestPodSecretRefusesReservedNames(t *testing.T) {
	writeListingTestIdentity(t, "alice")
	var got map[string]any
	var path string
	srv := secretCaptureServer(t, 201, `{}`, &got, &path)
	for _, name := range []string{
		"OPENCODE_DISABLE_MODELS_FETCH", "OPENCODE_DISABLE_PROJECT_CONFIG",
		"ANTHROPIC_BASE_URL", "ANTHROPIC_AUTH_TOKEN", "REEF_RUN_CREDENTIAL", "ANTHROPIC_API_KEY",
	} {
		for _, args := range [][]string{
			{"set", "alice/research-bot", name, "--server", srv.URL},
			{"rm", "alice/research-bot", name, "--server", srv.URL, "--confirm-secret-rm"},
		} {
			if code := runPodSecretImpl(args, strings.NewReader("value\n")); code != 2 {
				t.Errorf("%v: code = %d, want 2", args, code)
			}
		}
	}
	if path != "" {
		t.Fatalf("a reserved name reached the server: %s", path)
	}
	// Control: the same argument shapes with a plain name reach the
	// server, so the exit code 2 above came from the name.
	for _, args := range [][]string{
		{"set", "alice/research-bot", "ELEVENLABS_API_KEY", "--server", srv.URL},
		{"rm", "alice/research-bot", "ELEVENLABS_API_KEY", "--server", srv.URL, "--confirm-secret-rm"},
	} {
		path = ""
		if code := runPodSecretImpl(args, strings.NewReader("value\n")); code == 2 || path == "" {
			t.Errorf("control %v: code = %d, request = %q", args, code, path)
		}
	}
}
