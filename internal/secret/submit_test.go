// Copyright 2026 Jerry David Chan, Konareef.ai
// SPDX-License-Identifier: Apache-2.0

package secret

import (
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/digitsu/konareef/internal/identity"
)

func testIdentity(t *testing.T) *identity.Identity {
	t.Helper()
	id, err := identity.Generate("alice")
	if err != nil {
		t.Fatalf("generate identity: %v", err)
	}
	return id
}

// captureServer records the last request's method, path, and JSON body
// and replies with reply.
func captureServer(t *testing.T, status int, reply any, got *map[string]any, gotMethod, gotPath *string) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		*gotMethod = r.Method
		*gotPath = r.URL.Path
		raw, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(raw, got)
		w.WriteHeader(status)
		_ = json.NewEncoder(w).Encode(reply)
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestSet_PostsSignedEnvelopeAndValue(t *testing.T) {
	id := testIdentity(t)
	var got map[string]any
	var method, path string
	srv := captureServer(t, 201, map[string]any{"name": "ELEVENLABS_API_KEY", "rotated_at": "2026-09-09T00:00:00Z"}, &got, &method, &path)

	envelope := fixedEnvelope()
	resp, err := Set(srv.URL, id, envelope, []byte("foo"))
	if err != nil {
		t.Fatalf("Set: %v", err)
	}
	if resp.Name != "ELEVENLABS_API_KEY" {
		t.Fatalf("resp = %+v", resp)
	}
	if method != http.MethodPost || path != "/api/pods/alice/research-bot/secrets" {
		t.Fatalf("request = %s %s", method, path)
	}
	value, _ := base64.StdEncoding.DecodeString(got["value"].(string))
	if string(value) != "foo" {
		t.Fatalf("value = %q", value)
	}
	if got["value_sha256"] != envelope.ValueSHA256 || got["nonce"] != envelope.Nonce || got["ts"] != float64(envelope.TS) {
		t.Fatalf("body = %v", got)
	}
	sig, _ := base64.StdEncoding.DecodeString(got["signature"].(string))
	if len(sig) < 8 {
		t.Fatalf("signature missing: %v", got["signature"])
	}
	if _, ok := got["publisher_pubkey"].(string); !ok {
		t.Fatal("publisher_pubkey missing")
	}
}

func TestSet_RefusesValueDigestMismatch(t *testing.T) {
	id := testIdentity(t)
	envelope := fixedEnvelope() // sha256("foo")
	if _, err := Set("http://127.0.0.1:1", id, envelope, []byte("bar")); err == nil {
		t.Fatal("digest mismatch accepted before any network call")
	}
}

// TestSet_RefusesEmptyValue covers Minor 10 from the final review:
// wireBody.Value is `omitempty`, so an empty value would otherwise
// marshal to a body with no "value" key at all rather than an explicit
// client-side refusal. Uses an envelope whose digest matches an empty
// value (sha256("")) so the empty-value guard, not the digest check, is
// what is under test, and an unreachable server URL to prove no network
// call happens.
func TestSet_RefusesEmptyValue(t *testing.T) {
	id := testIdentity(t)
	envelope, err := NewEnvelope("alice", "research-bot", "ELEVENLABS_API_KEY", nil, time.Now())
	if err != nil {
		t.Fatalf("NewEnvelope: %v", err)
	}
	if _, err := Set("http://127.0.0.1:1", id, envelope, nil); err == nil {
		t.Fatal("empty value accepted before any network call")
	}
}

func TestRemove_DeletesWithSignedBody(t *testing.T) {
	id := testIdentity(t)
	var got map[string]any
	var method, path string
	srv := captureServer(t, 200, map[string]any{"name": "ELEVENLABS_API_KEY", "removed": true}, &got, &method, &path)

	if err := Remove(srv.URL, id, fixedEnvelope()); err != nil {
		t.Fatalf("Remove: %v", err)
	}
	if method != http.MethodDelete || path != "/api/pods/alice/research-bot/secrets/ELEVENLABS_API_KEY" {
		t.Fatalf("request = %s %s", method, path)
	}
	if _, present := got["value"]; present {
		t.Fatal("rm body carried a value")
	}
}

func TestList_ReturnsEntries(t *testing.T) {
	id := testIdentity(t)
	var got map[string]any
	var method, path string
	srv := captureServer(t, 200, map[string]any{"secrets": []map[string]any{{"name": "A_KEY", "rotated_at": "2026-09-09T00:00:00Z"}}}, &got, &method, &path)

	entries, err := List(srv.URL, id, Envelope{Handle: "alice", PodName: "research-bot", Nonce: fixedEnvelope().Nonce, TS: 1})
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if method != http.MethodPost || path != "/api/pods/alice/research-bot/secrets/list" {
		t.Fatalf("request = %s %s", method, path)
	}
	if len(entries) != 1 || entries[0].Name != "A_KEY" {
		t.Fatalf("entries = %+v", entries)
	}
}

func TestSubmit_SurfacesServerErrorCode(t *testing.T) {
	id := testIdentity(t)
	var got map[string]any
	var method, path string
	srv := captureServer(t, 400, map[string]any{"error": "handle_pubkey_mismatch"}, &got, &method, &path)

	_, err := Set(srv.URL, id, fixedEnvelope(), []byte("foo"))
	if err == nil || err.Error() != "reef-core refused pod secret set: handle_pubkey_mismatch" {
		t.Fatalf("err = %v", err)
	}
}

func TestSubmit_DoesNotFollowRedirects(t *testing.T) {
	id := testIdentity(t)
	reached := false
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { reached = true }))
	defer target.Close()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL, http.StatusTemporaryRedirect)
	}))
	defer srv.Close()

	if _, err := Set(srv.URL, id, fixedEnvelope(), []byte("foo")); err == nil {
		t.Fatal("redirect reported as success")
	}
	if reached {
		t.Fatal("signed body followed a redirect to another host")
	}
}
