// Copyright 2026 Jerry David Chan, Konareef.ai
// SPDX-License-Identifier: Apache-2.0

// main_server_url_test.go — MR !58 note 2326 regression at the CLI seam.
//
// resolveServerURL is the single place `--server` / `$KONAREEF_SERVER`
// becomes a reef-core base URL for every signing command. It runs before
// the identity is loaded and before anything is signed, so a malformed
// or misleading value can never turn into a publisher signature sitting
// in a request to a non-reef-core origin.

package main

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/digitsu/konareef/internal/serverurl"
)

// The documented precedence — --server flag → $KONAREEF_SERVER →
// http://localhost:4000 — must survive the added validation.
func TestResolveServerURLPrecedence(t *testing.T) {
	t.Run("flag wins", func(t *testing.T) {
		t.Setenv("KONAREEF_SERVER", "http://env.example:4000")
		got, err := resolveServerURL("http://flag.example:4000")
		if err != nil {
			t.Fatalf("resolveServerURL: %v", err)
		}
		if got != "http://flag.example:4000" {
			t.Errorf("resolved = %q", got)
		}
	})
	t.Run("env when no flag", func(t *testing.T) {
		t.Setenv("KONAREEF_SERVER", "https://beta-api.konareef.ai")
		got, err := resolveServerURL("")
		if err != nil {
			t.Fatalf("resolveServerURL: %v", err)
		}
		if got != "https://beta-api.konareef.ai" {
			t.Errorf("resolved = %q", got)
		}
	})
	t.Run("default when neither", func(t *testing.T) {
		t.Setenv("KONAREEF_SERVER", "")
		got, err := resolveServerURL("")
		if err != nil {
			t.Fatalf("resolveServerURL: %v", err)
		}
		if got != defaultServerURL {
			t.Errorf("resolved = %q, want %q", got, defaultServerURL)
		}
	})
}

// A malformed value is a usage error whichever door it comes through —
// a typo on the command line or a poisoned environment variable.
func TestResolveServerURLRejectsMalformedValues(t *testing.T) {
	malformed := map[string]string{
		"userinfo":           "https://reef-core.konareef.ai@evil.example",
		"query string":       "http://localhost:4000?next=https://evil.example",
		"fragment":           "http://localhost:4000#evil.example",
		"trailing space":     "http://localhost:4000 ",
		"embedded newline":   "http://localhost:4000\nHost: evil.example",
		"no scheme":          "localhost:4000",
		"scheme relative":    "//evil.example",
		"ftp scheme":         "ftp://localhost:4000",
		"no host":            "http://",
		"non-root base path": "http://localhost:4000/reef",
	}
	for name, raw := range malformed {
		t.Run("flag/"+name, func(t *testing.T) {
			t.Setenv("KONAREEF_SERVER", "")
			if got, err := resolveServerURL(raw); err == nil {
				t.Errorf("resolveServerURL(%q) = %q, want an error", raw, got)
			} else if !errors.Is(err, serverurl.ErrInvalidServerURL) {
				t.Errorf("error %v does not wrap serverurl.ErrInvalidServerURL", err)
			}
		})
		t.Run("env/"+name, func(t *testing.T) {
			t.Setenv("KONAREEF_SERVER", raw)
			if got, err := resolveServerURL(""); err == nil {
				t.Errorf("resolveServerURL via env %q = %q, want an error", raw, got)
			}
		})
	}
}

// End-to-end at the CLI seam: `konareef pod listing publish` against a
// malformed --server (or a poisoned $KONAREEF_SERVER) exits 2 and never
// reaches the network. The live capture server proves the second half —
// it is the only reef-core in this test, and it must stay untouched.
func TestPodListingPublishRejectsMalformedServerURL(t *testing.T) {
	dir := writeListingTestPod(t, `[runtime]
kind = "lobster"
execution_class = "cloud"
`)
	var requests int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"community"}`))
	}))
	defer srv.Close()
	writeListingTestIdentity(t, "alice")

	for name, raw := range map[string]string{
		"userinfo":           "https://reef-core.konareef.ai@evil.example",
		"query string":       "http://localhost:4000?next=https://evil.example",
		"fragment":           "http://localhost:4000#evil.example",
		"trailing space":     srv.URL + " ",
		"embedded newline":   srv.URL + "\n",
		"no scheme":          "evil.example:4000",
		"ftp scheme":         "ftp://evil.example",
		"non-root base path": srv.URL + "/reef",
	} {
		t.Run("flag/"+name, func(t *testing.T) {
			code := runPodListingImpl([]string{
				"publish", dir, "--fee", "500", "--revision", "1", "--category", "research",
				"--description", "Summarizes.", "--server", raw,
			})
			if code != 2 {
				t.Errorf("exit code = %d, want 2", code)
			}
		})
		t.Run("env/"+name, func(t *testing.T) {
			t.Setenv("KONAREEF_SERVER", raw)
			code := runPodListingImpl([]string{
				"publish", dir, "--fee", "500", "--revision", "1", "--category", "research",
				"--description", "Summarizes.",
			})
			if code != 2 {
				t.Errorf("exit code = %d, want 2", code)
			}
		})
	}
	if requests != 0 {
		t.Errorf("a malformed server URL reached the network %d time(s)", requests)
	}
}
