// Copyright 2026 Jerry David Chan, Konareef.ai
// SPDX-License-Identifier: Apache-2.0

// Tests for how the verbs treat a validly signed artifact that is over the
// admission contract's size limits (review m4): `verify` and `show` report
// it as valid with a warning, and `submit` refuses to send it.
package main

import (
	"crypto/sha256"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/digitsu/konareef/internal/commission"
	"github.com/digitsu/konareef/internal/envelope"
	"github.com/digitsu/konareef/internal/identity"
)

// writeOverLimitArtifact signs a commission whose prose is one byte over
// the limit, by signing its canonical bytes directly (commission.Sign now
// refuses it), and writes the artifact as `sign` would. It returns the
// path.
func writeOverLimitArtifact(t *testing.T) string {
	t.Helper()
	id, err := identity.Generate("dave")
	if err != nil {
		t.Fatal(err)
	}
	p := commission.Proposal{
		Envelope: envelope.Envelope{Models: []string{"anthropic/claude-sonnet-4-5"}, Tools: []string{"bash"},
			CMax: 100, ModelsSet: true, ToolsSet: true, LabelsSet: true, CMaxSet: true},
		Binding: commission.Binding{PodRef: "dave/pod@1.0.0", HManifest: sha256.Sum256([]byte("m"))},
		Prose:   strings.Repeat("x", commission.MaxProseBytes+1),
	}
	canonical, err := p.Canonical()
	if err != nil {
		t.Fatal(err)
	}
	sig, err := id.Sign(canonical)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := marshalCommission(commission.Reconstruct(p, id.PublicKeyHex, sig))
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "over.cbor")
	if err := os.WriteFile(path, raw, 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

// TestOverLimitArtifactIsReportedNotRefused: verify and show accept the
// valid artifact with a warning; the strict loader and submit refuse it
// and send nothing.
func TestOverLimitArtifactIsReportedNotRefused(t *testing.T) {
	path := writeOverLimitArtifact(t)

	if _, err := loadAndVerifyCommission(path); err == nil {
		t.Fatal("the strict loader accepted an over-limit artifact")
	}
	if _, overLimit, err := loadAndVerifyCommissionForReport(path); err != nil || overLimit == nil {
		t.Fatalf("report loader: overLimit %v err %v", overLimit, err)
	}

	var stdout, stderr strings.Builder
	if code := runCommissionShowCore(&stdout, &stderr, path); code != 0 {
		t.Fatalf("show exit %d\n%s%s", code, stdout.String(), stderr.String())
	}
	if !strings.Contains(stdout.String(), "signature:  VERIFIED") || !strings.Contains(stdout.String(), "reef-core will refuse to admit") {
		t.Fatalf("show output:\n%s", stdout.String())
	}

	bin := buildGateCLI(t)
	home := t.TempDir()
	verify := runCommissionCLI(t, bin, home, "commission", "verify", path)
	if verify.code != 0 || !strings.Contains(verify.stderr, "WARNING") {
		t.Fatalf("verify: exit %d\n%s", verify.code, verify.combined())
	}

	requests := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		http.NotFound(w, r)
	}))
	defer srv.Close()
	submit := runCommissionCLI(t, bin, home, "commission", "submit", path, "--out", t.TempDir(),
		"--server", srv.URL, "--token", "dG9rZW4=", "--confirm-spend")
	if submit.code != 1 || requests != 0 {
		t.Fatalf("submit: exit %d, %d requests\n%s", submit.code, requests, submit.combined())
	}
}
