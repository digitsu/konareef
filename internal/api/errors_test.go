// Copyright 2026 Jerry David Chan, Konareef.ai
// SPDX-License-Identifier: Apache-2.0

// Tests for decoding reef-core's structured (object-shaped) error bodies,
// and for rendering the mcp_grant_host_also_declared_egress refusal with
// and without the additive `conflicts` detail (reef-core MR !108).
package api

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"unicode"
)

// spawnPodWithBody runs SpawnPod against a server that answers with the
// given status and raw body, and returns the error SpawnPod gave back.
func spawnPodWithBody(t *testing.T, status int, body string) error {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		w.Write([]byte(body))
	}))
	defer srv.Close()
	_, err := NewClient(srv.URL).WithToken("tok").SpawnPod(SpawnPodRequest{PodToml: "x"})
	if err == nil {
		t.Fatal("SpawnPod succeeded, want an error")
	}
	return err
}

// readTestdata returns the named file under testdata/.
func readTestdata(t *testing.T, name string) string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatalf("read %s: %v", name, err)
	}
	return string(data)
}

// The body is the wildcard case from reef-core's controller test on MR !108
// (egress ["api.unrelated.com", "*.example.com", "mcp.example.com"], grant
// at network.gateway[1]). Both sides of each contradiction must be named,
// and the wildcard must be named as the wildcard.
func TestSpawnPod_MCPEgressConflictNamesBothSides(t *testing.T) {
	err := spawnPodWithBody(t, http.StatusUnprocessableEntity,
		readTestdata(t, "mcp_grant_host_also_declared_egress_422.json"))

	var serverErr *ServerError
	if !errors.As(err, &serverErr) {
		t.Fatalf("error %v (%T) does not wrap *ServerError", err, err)
	}
	if serverErr.Status != 422 || serverErr.Kind != KindMCPGrantHostAlsoDeclaredEgress {
		t.Fatalf("status %d kind %q", serverErr.Status, serverErr.Kind)
	}
	if len(serverErr.Conflicts) != 2 || serverErr.Conflicts[0].Egress != "*.example.com" ||
		serverErr.Conflicts[0].EgressIndex != 1 || serverErr.Conflicts[1].EgressIndex != 2 {
		t.Fatalf("conflicts = %+v", serverErr.Conflicts)
	}

	text := err.Error()
	for _, want := range []string{
		"http 422: mcp_grant_host_also_declared_egress",
		`network.gateway[1].host "mcp.example.com" (mcp.example.com:443) matches network.egress[1] "*.example.com"`,
		`network.gateway[1].host "mcp.example.com" (mcp.example.com:443) matches network.egress[2] "mcp.example.com"`,
		"remove or narrow",
	} {
		if !strings.Contains(text, want) {
			t.Errorf("error text does not contain %q:\n%s", want, text)
		}
	}
	if strings.Contains(text, "truncated") || strings.Contains(text, "does not list") {
		t.Errorf("complete, non-legacy body rendered a truncation or fallback note:\n%s", text)
	}
}

// A reef-core from before MR !108 sends kind, hosts and message only. The
// CLI keeps the stable kind, names the hosts, and says how to get the
// detail locally.
func TestSpawnPod_MCPEgressConflictOlderServerFallsBackToHosts(t *testing.T) {
	err := spawnPodWithBody(t, http.StatusUnprocessableEntity,
		readTestdata(t, "mcp_grant_host_also_declared_egress_422_legacy.json"))

	var serverErr *ServerError
	if !errors.As(err, &serverErr) || serverErr.Conflicts != nil {
		t.Fatalf("error %v: want *ServerError with no conflicts", err)
	}
	text := err.Error()
	for _, want := range []string{
		"http 422: mcp_grant_host_also_declared_egress",
		`"mcp.example.com"`,
		"konareef pod validate",
	} {
		if !strings.Contains(text, want) {
			t.Errorf("error text does not contain %q:\n%s", want, text)
		}
	}
}

// When the server cut the list, the CLI says so instead of implying the
// shown pairs are all of them.
func TestSpawnPod_MCPEgressConflictTruncated(t *testing.T) {
	body := strings.Replace(readTestdata(t, "mcp_grant_host_also_declared_egress_422.json"),
		`"conflicts_truncated": false`, `"conflicts_truncated": true`, 1)
	err := spawnPodWithBody(t, http.StatusUnprocessableEntity, body)
	if !strings.Contains(err.Error(), "truncated") || !strings.Contains(err.Error(), "konareef pod validate") {
		t.Fatalf("truncated body rendered without a truncation note:\n%s", err)
	}
}

// Every string in the body came from the manifest or the server. Control
// characters must reach the terminal only as escapes.
func TestSpawnPod_ServerErrorEscapesControlCharacters(t *testing.T) {
	body := `{"error":{"kind":"mcp_grant_host_also_declared_egress\u001b[2J","hosts":["a\u001b[31m"],` +
		`"conflicts":[{"grant":"m\u001b]0;x\u0007","grant_index":0,"authority":"m:443\r","egress":"*.e\n","egress_index":0}],` +
		`"conflicts_truncated":false,"message":"bad\u001b[0m"}}`
	err := spawnPodWithBody(t, http.StatusUnprocessableEntity, body)
	text := err.Error()
	for _, raw := range []string{"\x1b", "\x07", "\r"} {
		if strings.Contains(text, raw) {
			t.Fatalf("rendered error carries raw %q:\n%q", raw, text)
		}
	}
}

// Other object-shaped errors used to render as a bare "http 422". They now
// carry the stable kind and the server message.
func TestSpawnPod_OtherStructuredErrorShowsKindAndMessage(t *testing.T) {
	err := spawnPodWithBody(t, http.StatusUnprocessableEntity,
		`{"error":{"kind":"toml_decode","message":"line 3: expected '='"}}`)
	var serverErr *ServerError
	if !errors.As(err, &serverErr) || serverErr.Kind != "toml_decode" {
		t.Fatalf("error %v: want *ServerError kind toml_decode", err)
	}
	if !strings.Contains(err.Error(), "http 422: toml_decode: line 3: expected '='") {
		t.Fatalf("error text = %q", err)
	}
}

// The string-shaped body keeps its old rendering.
func TestSpawnPod_StringErrorUnchanged(t *testing.T) {
	err := spawnPodWithBody(t, http.StatusNotFound, `{"error":"not found"}`)
	if !strings.HasSuffix(err.Error(), "http 404: not found") {
		t.Fatalf("error text = %q", err)
	}
	if err := spawnPodWithBody(t, http.StatusBadGateway, `<html>`); !strings.HasSuffix(err.Error(), "http 502") {
		t.Fatalf("error text = %q", err)
	}
}

// A detail field of an unexpected type must not hide the stable kind.
func TestSpawnPod_MalformedDetailKeepsKind(t *testing.T) {
	err := spawnPodWithBody(t, http.StatusUnprocessableEntity,
		`{"error":{"kind":"mcp_grant_host_also_declared_egress","hosts":["mcp.example.com"],"conflicts":[{"grant_index":"one"}]}}`)
	var serverErr *ServerError
	if !errors.As(err, &serverErr) || serverErr.Kind != KindMCPGrantHostAlsoDeclaredEgress {
		t.Fatalf("error %v: want *ServerError keeping the kind", err)
	}
	if serverErr.Conflicts != nil || !strings.Contains(err.Error(), `"mcp.example.com"`) ||
		!strings.Contains(err.Error(), "konareef pod validate") {
		t.Fatalf("error text = %q, want the hosts-only fallback", err)
	}
}

// TestTerminalSafeJSON escapes every non-printable rune, including DEL,
// the C1 CSI and an astral format character, and the result decodes to the
// same value.
func TestTerminalSafeJSON(t *testing.T) {
	value := map[string]string{"k": "a\x1b[2J\x7f\u009b31m \U000E0001ok é \U0001F642"}
	raw, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	safe := TerminalSafeJSON(raw)
	for _, r := range string(safe) {
		if r != '\n' && !unicode.IsPrint(r) {
			t.Fatalf("non-printable rune %U left in %q", r, safe)
		}
	}
	var back map[string]string
	if err := json.Unmarshal(safe, &back); err != nil {
		t.Fatalf("escaped JSON does not decode: %v\n%s", err, safe)
	}
	if back["k"] != value["k"] {
		t.Fatalf("round trip changed the value: %q", back["k"])
	}
	if !strings.Contains(string(safe), `\u009b`) || !strings.Contains(string(safe), `\u`+"db40"+`\u`+"dc01") {
		t.Fatalf("expected escapes missing: %s", safe)
	}
}
