// Copyright 2026 Jerry David Chan, Konareef.ai
// SPDX-License-Identifier: Apache-2.0

// sealed_grants_test.go — unit tests for the publish side of sealed
// grants: the capability decision, the capability fetch, the [_files]
// cross-check, and Prepare's refusal and salt rotation.
package publish

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/digitsu/konareef/internal/identity"
	"github.com/digitsu/konareef/internal/pod"
)

// TestCheckSealedGrantsCapability covers every row of the decision.
func TestCheckSealedGrantsCapability(t *testing.T) {
	supported := Capabilities{SealedGrantsCarriers: []string{pod.SealedGrantsFormatV1}}
	enabled := Capabilities{SealedGrantsCarriers: []string{pod.SealedGrantsFormatV1}, ClosedGrantsEnabled: true}
	cases := []struct {
		name         string
		state        SealedGrantsState
		capabilities Capabilities
		want         error
	}{
		{"no marker, old server", SealedGrantsState{}, Capabilities{}, nil},
		{"marker, old server", SealedGrantsState{Marker: true}, Capabilities{}, ErrSealedGrantsUnsupported},
		{"marker, other carrier", SealedGrantsState{Marker: true}, Capabilities{SealedGrantsCarriers: []string{"konareef-sealed-grants/v2"}, ClosedGrantsEnabled: true}, ErrSealedGrantsUnsupported},
		{"zero grants, off", SealedGrantsState{Marker: true}, supported, nil},
		{"grants, off", SealedGrantsState{Marker: true, GrantCount: 1}, supported, ErrSealedGrantsNotEnabled},
		{"grants, on", SealedGrantsState{Marker: true, GrantCount: 1}, enabled, nil},
	}
	for _, tc := range cases {
		err := CheckSealedGrantsCapability(tc.state, tc.capabilities)
		if !errors.Is(err, tc.want) || (tc.want == nil && err != nil) {
			t.Errorf("%s: got %v, want %v", tc.name, err, tc.want)
		}
	}
}

// TestFetchCapabilities checks the 404 (old server), success, and
// error paths.
func TestFetchCapabilities(t *testing.T) {
	status := http.StatusNotFound
	body := ""
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/health" {
			http.NotFound(w, r)
			return
		}
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	}))
	defer server.Close()

	capabilities, err := FetchCapabilities(context.Background(), server.URL)
	if err != nil || capabilities.SupportsSealedGrantsV1() {
		t.Fatalf("404: %v %+v", err, capabilities)
	}
	status, body = http.StatusOK, `{"status":"ok","capabilities":{"sealed_grants":["konareef-sealed-grants/v1"],"closed_grants_enabled":true},"other":1}`
	capabilities, err = FetchCapabilities(context.Background(), server.URL)
	if err != nil || !capabilities.SealedGrantsEnabled() {
		t.Fatalf("200: %v %+v", err, capabilities)
	}
	status, body = http.StatusOK, `{"status":"ok","capabilities":{"sealed_grants":["konareef-sealed-grants/v1"]}}`
	capabilities, err = FetchCapabilities(context.Background(), server.URL)
	if err != nil || !capabilities.SupportsSealedGrantsV1() || capabilities.SealedGrantsEnabled() {
		t.Fatalf("200 without closed_grants_enabled: %v %+v", err, capabilities)
	}
	status, body = http.StatusOK, `{"status":"ok"}`
	capabilities, err = FetchCapabilities(context.Background(), server.URL)
	if err != nil || capabilities.SupportsSealedGrantsV1() {
		t.Fatalf("old health body: %v %+v", err, capabilities)
	}
	status, body = http.StatusInternalServerError, ""
	if _, err := FetchCapabilities(context.Background(), server.URL); err == nil {
		t.Fatalf("500 accepted")
	}
	status, body = http.StatusOK, "not json"
	if _, err := FetchCapabilities(context.Background(), server.URL); err == nil {
		t.Fatalf("bad JSON accepted")
	}
}

// TestVerifySealedGrantsCommitted checks the [_files] cross-check.
func TestVerifySealedGrantsCommitted(t *testing.T) {
	grants := []byte("format = \"konareef-sealed-grants/v1\"\n")
	canonical := []byte("[_files]\n\"sealed/grants.toml\" = \"sha256:9f9b1bb9d9fdd6d2e5b2f3c86b6a5b86b41e0d1e2b9a8c0fdd5d7f3b0a1c2d3e\"\n")
	if err := verifySealedGrantsCommitted(canonical, grants); err == nil {
		t.Fatalf("mismatched hash accepted")
	}
}

// TestPrepareSealedGrants checks that Prepare refuses a malformed grants
// file before signing, and that RotateSealedSalt writes a new salt which
// the signed head then commits to.
func TestPrepareSealedGrants(t *testing.T) {
	publisher, err := identity.Generate("sealedprep")
	if err != nil {
		t.Fatal(err)
	}
	badDir, _ := buildSealedGoldenPod(t, "heads/closed-sealed.toml", "grants/reserved-namespace.toml")
	_, err = Prepare(badDir, publisher, PrepareOptions{RotateSealedSalt: true})
	if err == nil || !strings.Contains(err.Error(), pod.CodeGatewayMCPNameReserved) {
		t.Fatalf("malformed grants: %v", err)
	}
	if strings.Contains(strings.ToLower(err.Error()), "cnry") || strings.Contains(err.Error(), "openbrain") {
		t.Fatalf("error quotes a sealed value: %v", err)
	}

	dir, original := buildSealedGoldenPod(t, "heads/closed-sealed.toml", "grants/valid-one.toml")
	prepared, err := Prepare(dir, publisher, PrepareOptions{RotateSealedSalt: true})
	if err != nil {
		t.Fatal(err)
	}
	onDisk, _ := os.ReadFile(filepath.Join(dir, "sealed", "grants.toml"))
	if bytes.Equal(onDisk, original) || !prepared.SealedGrants.SaltRotated || prepared.SealedGrants.GrantCount != 1 || !prepared.SealedGrants.Marker {
		t.Fatalf("state %+v, rotated=%v", prepared.SealedGrants, !bytes.Equal(onDisk, original))
	}
	if err := verifySealedGrantsCommitted(prepared.CanonicalBytes, onDisk); err != nil {
		t.Fatalf("head does not commit to the rotated file: %v", err)
	}
}

// TestPrepareSealedGrantsReviewFixes pins the review follow-ups: the
// rotated file is 0600 whatever its mode was, always-emit leaves a head
// with a public MCP entry untouched, and an open pod with a file at the
// reserved path gets the SEALED_GRANTS_FILE_PUBLIC warning.
func TestPrepareSealedGrantsReviewFixes(t *testing.T) {
	publisher, err := identity.Generate("sealedfix")
	if err != nil {
		t.Fatal(err)
	}

	dir, _ := buildSealedGoldenPod(t, "heads/closed-sealed.toml", "grants/valid-one.toml")
	grantsPath := filepath.Join(dir, "sealed", "grants.toml")
	if err := os.Chmod(grantsPath, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Prepare(dir, publisher, PrepareOptions{RotateSealedSalt: true}); err != nil {
		t.Fatal(err)
	}
	if info, _ := os.Stat(grantsPath); info.Mode().Perm() != 0o600 {
		t.Fatalf("rotated grants file mode %v, want 0600", info.Mode().Perm())
	}

	mixed := t.TempDir()
	head := []byte(`pod_spec_version = "0.1"

[pod]
name = "mixed"
version = "1.0.0"
visibility = "closed"

[runtime]
kind = "lobster"

[directive]
template = "./prompts/task.md"

[dependencies]
secrets = ["PUBLIC_MIXED_TOKEN"]

[network]

[[network.gateway]]
host = "mcp.public-mixed.example"
secret = "PUBLIC_MIXED_TOKEN"
auth = "bearer"
max_calls = 10
protocol = "mcp"
mcp_name = "publicmixed"
mcp_tools = ["lookup"]
`)
	if err := os.WriteFile(filepath.Join(mixed, "pod.toml"), head, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Prepare(mixed, publisher, PrepareOptions{SealedGrantsAlwaysEmit: true}); err != nil {
		t.Fatalf("legacy closed pod with a public grant: %v", err)
	}
	after, _ := os.ReadFile(filepath.Join(mixed, "pod.toml"))
	if !bytes.Equal(after, head) {
		t.Fatalf("always-emit edited a head with a public mcp entry")
	}
	if _, err := os.Stat(filepath.Join(mixed, "sealed")); !os.IsNotExist(err) {
		t.Fatalf("always-emit created sealed/ for a head with a public mcp entry")
	}

	open, _ := buildSealedGoldenPod(t, "heads/closed-no-marker.toml", "grants/valid-one.toml")
	openHead, _ := os.ReadFile(filepath.Join(open, "pod.toml"))
	_ = os.WriteFile(filepath.Join(open, "pod.toml"), bytes.Replace(openHead, []byte(`visibility = "closed"`), []byte(`visibility = "open"`), 1), 0o644)
	prepared, err := Prepare(open, publisher, PrepareOptions{})
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, warning := range prepared.Warnings {
		if warning.Code == OpenPodSealedFileWarning {
			found = true
			if strings.Contains(strings.ToLower(warning.String()), "cnry") {
				t.Fatalf("warning quotes a sealed value: %s", warning)
			}
		}
	}
	if !found {
		t.Fatalf("no %s warning for an open pod with the reserved file", OpenPodSealedFileWarning)
	}
}
