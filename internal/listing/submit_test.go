// Copyright 2026 Jerry David Chan, Konareef.ai
// SPDX-License-Identifier: Apache-2.0

package listing

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/digitsu/konareef/internal/identity"
)

// Submit PUTs a signed listing to /api/pods/:handle/:pod_name/listing
// and parses the JSON response.
func TestSubmitPutsSignedListing(t *testing.T) {
	id, err := identity.Generate("alice")
	if err != nil {
		t.Fatalf("identity: %v", err)
	}

	var gotPath, gotMethod, gotContentType string
	var gotBody map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		gotMethod = r.Method
		gotContentType = r.Header.Get("Content-Type")
		raw, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(raw, &gotBody)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"handle":"alice","pod_name":"research-bot","revision":1,"author_fee_sats":500,"status":"community"}`))
	}))
	defer srv.Close()

	f := Fields{
		Revision: Revision(1),
		Handle:   "alice", PodName: "research-bot", AuthorFeeSats: 500,
		ExecutionClass: "cloud", Category: "research", Description: "Summarizes.",
	}
	resp, err := Submit(srv.URL, f, id)
	if err != nil {
		t.Fatalf("Submit: %v", err)
	}
	if gotMethod != http.MethodPut {
		t.Errorf("method = %s, want PUT", gotMethod)
	}
	if gotPath != "/api/pods/alice/research-bot/listing" {
		t.Errorf("path = %s", gotPath)
	}
	if gotContentType != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", gotContentType)
	}
	if gotBody["signature"] == nil || gotBody["publisher_pubkey"] == nil {
		t.Error("body missing signature/publisher_pubkey")
	}
	if resp.Status != "community" {
		t.Errorf("resp.Status = %q", resp.Status)
	}
}

// The wire body must carry the same values that went into the preimage,
// and the signature must verify against Canonical(f) under the published
// pubkey — that is the whole authentication story for a listing write.
func TestSubmitSignsCanonicalBytesUnderPublishedPubkey(t *testing.T) {
	id, err := identity.Generate("alice")
	if err != nil {
		t.Fatalf("identity: %v", err)
	}

	var gotBody map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(raw, &gotBody)
		_, _ = w.Write([]byte(`{"handle":"alice","pod_name":"research-bot","revision":1,"author_fee_sats":500,"status":"community"}`))
	}))
	defer srv.Close()

	f := Fields{
		Revision: Revision(1),
		Handle:   "alice", PodName: "research-bot", AuthorFeeSats: 500,
		ExecutionClass: "local-mount", Category: "research", Description: "Summarizes.",
	}
	if _, err := Submit(srv.URL, f, id); err != nil {
		t.Fatalf("Submit: %v", err)
	}

	for field, want := range map[string]any{
		"handle":              "alice",
		"pod_name":            "research-bot",
		"author_fee_sats":     float64(500),
		"execution_class":     "local-mount",
		"category":            "research",
		"display_description": "Summarizes.",
	} {
		if gotBody[field] != want {
			t.Errorf("body[%q] = %v, want %v", field, gotBody[field], want)
		}
	}

	pubB64, _ := gotBody["publisher_pubkey"].(string)
	pubBytes, err := base64.StdEncoding.DecodeString(pubB64)
	if err != nil {
		t.Fatalf("publisher_pubkey is not base64: %v", err)
	}
	if hex.EncodeToString(pubBytes) != id.PublicKeyHex {
		t.Errorf("publisher_pubkey = %x, want %s", pubBytes, id.PublicKeyHex)
	}

	sigB64, _ := gotBody["signature"].(string)
	sig, err := base64.StdEncoding.DecodeString(sigB64)
	if err != nil {
		t.Fatalf("signature is not base64: %v", err)
	}
	ok, err := identity.Verify(id.PublicKeyHex, mustCanonical(t, f, OpUpsert), sig)
	if err != nil || !ok {
		t.Errorf("signature does not verify over Canonical(f): ok=%v err=%v", ok, err)
	}
}

// A rejected listing surfaces the server's {error: code} body so the CLI
// can print the reason without re-parsing the response.
func TestSubmitSurfacesServerErrorCode(t *testing.T) {
	id, err := identity.Generate("alice")
	if err != nil {
		t.Fatalf("identity: %v", err)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnprocessableEntity)
		_, _ = w.Write([]byte(`{"error":"execution_class_mismatch"}`))
	}))
	defer srv.Close()

	_, err = Submit(srv.URL, Fields{Revision: Revision(1), Handle: "alice", PodName: "research-bot"}, id)
	if err == nil {
		t.Fatal("Submit succeeded on a 422, want error")
	}
	if !strings.Contains(err.Error(), "execution_class_mismatch") {
		t.Errorf("error = %v, want it to mention execution_class_mismatch", err)
	}
}

// A non-2xx with no parseable body still fails, carrying the status.
func TestSubmitFailsOnNon2xxWithoutErrorBody(t *testing.T) {
	id, err := identity.Generate("alice")
	if err != nil {
		t.Fatalf("identity: %v", err)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	_, err = Submit(srv.URL, Fields{Revision: Revision(1), Handle: "alice", PodName: "research-bot"}, id)
	if err == nil {
		t.Fatal("Submit succeeded on a 500, want error")
	}
	if !strings.Contains(err.Error(), "500") {
		t.Errorf("error = %v, want it to mention the 500 status", err)
	}
}

// validListing is the fixture the hardening tests submit.
func validListing() Fields {
	return Fields{
		Revision: Revision(1),
		Handle:   "alice", PodName: "research-bot", AuthorFeeSats: 500,
		ExecutionClass: "cloud", Category: "research", Description: "Summarizes.",
	}
}

// A redirect must NOT be followed. Go's default client follows up to 10
// redirects and re-sends the body verbatim on 307/308 — handing a valid
// signature + pubkey to whatever host the redirect names, then reporting
// success to the publisher. The signature is the credential on this
// endpoint, so this is credential exfiltration.
func TestSubmitDoesNotFollowRedirects(t *testing.T) {
	id, err := identity.Generate("alice")
	if err != nil {
		t.Fatalf("identity: %v", err)
	}
	var attackerHits int
	var attackerBody string
	attacker := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attackerHits++
		raw, _ := io.ReadAll(r.Body)
		attackerBody = string(raw)
		_, _ = w.Write([]byte(`{"handle":"alice","pod_name":"research-bot","revision":1,"status":"community"}`))
	}))
	defer attacker.Close()

	for _, code := range []int{
		http.StatusTemporaryRedirect, http.StatusPermanentRedirect,
		http.StatusMovedPermanently, http.StatusFound, http.StatusSeeOther,
	} {
		t.Run(http.StatusText(code), func(t *testing.T) {
			attackerHits, attackerBody = 0, ""
			victim := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				http.Redirect(w, r, attacker.URL+"/api/pods/alice/research-bot/listing", code)
			}))
			defer victim.Close()

			if _, err := Submit(victim.URL, validListing(), id); err == nil {
				t.Error("Submit reported success on a redirect; want an error")
			}
			if attackerHits != 0 {
				t.Errorf("redirect target was contacted %d time(s); body=%.80s", attackerHits, attackerBody)
			}
		})
	}
}

// Path segments come from a manifest and an identity file, so they must
// be escaped rather than concatenated: a pod name containing "?" or "#"
// would otherwise rewrite the request target and silently drop the
// "/listing" suffix into a query string.
func TestSubmitEscapesPathSegments(t *testing.T) {
	id, err := identity.Generate("alice")
	if err != nil {
		t.Fatalf("identity: %v", err)
	}
	cases := map[string]struct{ handle, podName, wantPath string }{
		"query injection":    {"alice", "bot?admin=1", "/api/pods/alice/bot%3Fadmin=1/listing"},
		"fragment injection": {"alice", "bot#frag", "/api/pods/alice/bot%23frag/listing"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			var gotPath, gotRawQuery string
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				gotPath = r.URL.EscapedPath()
				gotRawQuery = r.URL.RawQuery
				_, _ = w.Write([]byte(`{"status":"community"}`))
			}))
			defer srv.Close()

			f := validListing()
			f.Handle, f.PodName = tc.handle, tc.podName
			_, _ = Submit(srv.URL, f, id)

			if gotPath != tc.wantPath {
				t.Errorf("path = %q, want %q", gotPath, tc.wantPath)
			}
			if gotRawQuery != "" {
				t.Errorf("query = %q, want empty (nothing may escape into the query)", gotRawQuery)
			}
		})
	}
}

// A "/" inside an identifier is refused outright rather than escaped:
// url.URL.JoinPath treats it as a separator, so it would add a path
// component and could push the "/listing" suffix out of position. No
// request may be issued for such a listing.
func TestSubmitRejectsSlashBearingPathSegments(t *testing.T) {
	id, err := identity.Generate("alice")
	if err != nil {
		t.Fatalf("identity: %v", err)
	}
	for name, tc := range map[string]struct{ handle, podName string }{
		"extra segments":   {"alice", "a/b/c"},
		"handle traversal": {"../../admin", "research-bot"},
	} {
		t.Run(name, func(t *testing.T) {
			var requests int
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				requests++
				_, _ = w.Write([]byte(`{"status":"community"}`))
			}))
			defer srv.Close()

			f := validListing()
			f.Handle, f.PodName = tc.handle, tc.podName
			if _, err := Submit(srv.URL, f, id); err == nil {
				t.Error("Submit accepted a slash-bearing identifier; want an error")
			}
			if requests != 0 {
				t.Errorf("a rejected identifier reached the network %d time(s)", requests)
			}
		})
	}
}

// A 200 carrying nothing usable is NOT success. An unwired route, a
// captive portal, or a proxy returning "200 {}" would otherwise be
// indistinguishable from a stored listing, and the CLI would print a
// confirmation for a write that never happened.
func TestSubmitRejectsUninformativeSuccessBody(t *testing.T) {
	id, err := identity.Generate("alice")
	if err != nil {
		t.Fatalf("identity: %v", err)
	}
	for name, body := range map[string]string{
		"null":           `null`,
		"empty object":   `{}`,
		"null status":    `{"status":null}`,
		"empty status":   `{"status":""}`,
		"empty body":     ``,
		"unknown status": `{"status":"ok"}`,
		"html portal":    `<html>captive portal</html>`,
	} {
		t.Run(name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				_, _ = w.Write([]byte(body))
			}))
			defer srv.Close()

			if _, err := Submit(srv.URL, validListing(), id); err == nil {
				t.Errorf("Submit accepted an uninformative 200 body %q", body)
			}
		})
	}
}

// The server must confirm the listing it stored is the one that was
// sent. A response describing a different pod means something is
// seriously wrong (proxy, misroute, or a server bug) and must not be
// reported to the publisher as a successful write.
func TestSubmitRejectsMismatchedEcho(t *testing.T) {
	id, err := identity.Generate("alice")
	if err != nil {
		t.Fatalf("identity: %v", err)
	}
	for name, body := range map[string]string{
		"wrong handle":   `{"handle":"mallory","pod_name":"research-bot","revision":1,"status":"community","author_fee_sats":500}`,
		"wrong pod_name": `{"handle":"alice","pod_name":"other-bot","revision":1,"status":"community","author_fee_sats":500}`,
	} {
		t.Run(name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				_, _ = w.Write([]byte(body))
			}))
			defer srv.Close()

			if _, err := Submit(srv.URL, validListing(), id); err == nil {
				t.Errorf("Submit accepted a response describing a different listing: %s", body)
			}
		})
	}
}

// A server that stored a DIFFERENT fee than the one submitted must be
// reported as an error, not printed as a confirmation — this is a money
// field and a silent disagreement is the worst outcome.
func TestSubmitRejectsFeeDisagreement(t *testing.T) {
	id, err := identity.Generate("alice")
	if err != nil {
		t.Fatalf("identity: %v", err)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(
			`{"handle":"alice","pod_name":"research-bot","revision":1,"status":"community","author_fee_sats":1}`))
	}))
	defer srv.Close()

	_, err = Submit(srv.URL, validListing(), id)
	if err == nil {
		t.Fatal("Submit accepted a stored fee of 1 when 500 was submitted")
	}
	if !strings.Contains(err.Error(), "500") || !strings.Contains(err.Error(), "1") {
		t.Errorf("error should name both fees, got: %v", err)
	}
}

// stale_revision is the one rejection a publisher can act on directly,
// so it must not be swallowed into a generic failure. reef-core's error
// body carries only the code, so the message names the revision that
// was rejected and where to read the current one — it must NOT invent a
// stored value it was never told.
func TestSubmitSurfacesStaleRevisionActionably(t *testing.T) {
	id, err := identity.Generate("alice")
	if err != nil {
		t.Fatalf("identity: %v", err)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"error":"stale_revision"}`))
	}))
	defer srv.Close()

	f := validListing()
	f.Revision = Revision(7)
	_, err = Submit(srv.URL, f, id)
	if err == nil {
		t.Fatal("Submit accepted a stale_revision rejection")
	}
	msg := err.Error()
	for _, want := range []string{"stale", "7", "alice/research-bot", "--revision"} {
		if !strings.Contains(msg, want) {
			t.Errorf("error message lacks %q: %v", want, msg)
		}
	}
	if !strings.Contains(msg, "/api/listings/alice/research-bot") {
		t.Errorf("error should point at the detail endpoint: %v", msg)
	}
}

// A response echoing a revision other than the one signed means the
// write that landed was not this one.
func TestSubmitRejectsRevisionEchoMismatch(t *testing.T) {
	id, err := identity.Generate("alice")
	if err != nil {
		t.Fatalf("identity: %v", err)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(
			`{"handle":"alice","pod_name":"research-bot","revision":99,"status":"community","author_fee_sats":500}`))
	}))
	defer srv.Close()

	if _, err := Submit(srv.URL, validListing(), id); err == nil {
		t.Fatal("Submit accepted a response echoing a different revision")
	}
}

// The signed revision must travel in the wire body — reef-core
// re-derives the preimage from it, so a body without it cannot verify.
func TestSubmitSendsRevisionInWireBody(t *testing.T) {
	id, err := identity.Generate("alice")
	if err != nil {
		t.Fatalf("identity: %v", err)
	}
	var gotBody map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(raw, &gotBody)
		_, _ = w.Write([]byte(
			`{"handle":"alice","pod_name":"research-bot","revision":42,"status":"community","author_fee_sats":500}`))
	}))
	defer srv.Close()

	f := validListing()
	f.Revision = Revision(42)
	if _, err := Submit(srv.URL, f, id); err != nil {
		t.Fatalf("Submit: %v", err)
	}
	if gotBody["revision"] != float64(42) {
		t.Errorf("wire revision = %v, want 42", gotBody["revision"])
	}
}

// staleServer replies 400 with the given raw JSON body and counts
// requests, so "did the client silently retry?" is assertable.
func staleServer(t *testing.T, body string, requests *int) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		*requests++
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)
	return srv
}

// When reef-core reports the stored revision, the message must name it
// and the next usable value, so the publisher can act without a second
// lookup — the detail endpoint 404s delisted listings, so for a pod the
// publisher delisted themselves this error is the ONLY way to recover
// the number.
func TestSubmitReportsCurrentRevisionWhenPresent(t *testing.T) {
	id, err := identity.Generate("alice")
	if err != nil {
		t.Fatalf("identity: %v", err)
	}
	var requests int
	srv := staleServer(t, `{"error":"stale_revision","current_revision":7}`, &requests)

	f := validListing()
	f.Revision = Revision(3)
	_, err = Submit(srv.URL, f, id)
	if err == nil {
		t.Fatal("Submit accepted a stale_revision rejection")
	}
	const want = "listing was not updated: the stored revision is 7 — re-run with --revision 8 (or higher)"
	if err.Error() != want {
		t.Errorf("message =\n  %q\nwant\n  %q", err.Error(), want)
	}
	// A signed, money-carrying write is never silently re-signed at a
	// bumped revision.
	if requests != 1 {
		t.Errorf("requests = %d, want exactly 1 (no retry)", requests)
	}
}

// Against a server predating the additive field, the CLI still fails
// cleanly — no crash, and above all no fabricated "0".
func TestSubmitFallsBackWhenCurrentRevisionAbsent(t *testing.T) {
	id, err := identity.Generate("alice")
	if err != nil {
		t.Fatalf("identity: %v", err)
	}
	var requests int
	srv := staleServer(t, `{"error":"stale_revision"}`, &requests)

	f := validListing()
	f.Revision = Revision(3)
	_, err = Submit(srv.URL, f, id)
	if err == nil {
		t.Fatal("Submit accepted a stale_revision rejection")
	}
	msg := err.Error()
	if strings.Contains(msg, "the stored revision is") {
		t.Errorf("message claims to know the stored revision: %v", msg)
	}
	if !strings.Contains(msg, "/api/listings/alice/research-bot") {
		t.Errorf("message should point at the detail endpoint: %v", msg)
	}
	if requests != 1 {
		t.Errorf("requests = %d, want exactly 1 (no retry)", requests)
	}
}

// A current_revision that is not a usable non-negative integer is
// treated as ABSENT, never as a value. A wrong number here is worse
// than none: the publisher would sign a revision guaranteed to be
// rejected again, or one they did not intend.
func TestSubmitTreatsMalformedCurrentRevisionAsAbsent(t *testing.T) {
	id, err := identity.Generate("alice")
	if err != nil {
		t.Fatalf("identity: %v", err)
	}
	for name, body := range map[string]string{
		"string":       `{"error":"stale_revision","current_revision":"7"}`,
		"null":         `{"error":"stale_revision","current_revision":null}`,
		"negative":     `{"error":"stale_revision","current_revision":-1}`,
		"float":        `{"error":"stale_revision","current_revision":7.5}`,
		"bool":         `{"error":"stale_revision","current_revision":true}`,
		"object":       `{"error":"stale_revision","current_revision":{"n":7}}`,
		"array":        `{"error":"stale_revision","current_revision":[7]}`,
		"above max":    `{"error":"stale_revision","current_revision":9007199254740992}`,
		"absurdly big": `{"error":"stale_revision","current_revision":99999999999999999999}`,
		"empty string": `{"error":"stale_revision","current_revision":""}`,
	} {
		t.Run(name, func(t *testing.T) {
			var requests int
			srv := staleServer(t, body, &requests)

			f := validListing()
			f.Revision = Revision(3)
			_, err := Submit(srv.URL, f, id)
			if err == nil {
				t.Fatal("Submit accepted a stale_revision rejection")
			}
			msg := err.Error()
			// The malformed value must not be presented as the stored
			// revision, and the fallback must still identify the failure.
			if strings.Contains(msg, "the stored revision is") {
				t.Errorf("malformed current_revision was treated as a value: %v", msg)
			}
			if !strings.Contains(msg, "stale") {
				t.Errorf("message no longer identifies a stale revision: %v", msg)
			}
			if requests != 1 {
				t.Errorf("requests = %d, want exactly 1 (no retry)", requests)
			}
		})
	}
}

// current_revision at the ceiling leaves no next value to suggest, so
// the message must not print an out-of-range one.
func TestSubmitDoesNotSuggestRevisionAboveMax(t *testing.T) {
	id, err := identity.Generate("alice")
	if err != nil {
		t.Fatalf("identity: %v", err)
	}
	var requests int
	srv := staleServer(t,
		`{"error":"stale_revision","current_revision":9007199254740991}`, &requests)

	f := validListing()
	f.Revision = Revision(3)
	_, err = Submit(srv.URL, f, id)
	if err == nil {
		t.Fatal("Submit accepted a stale_revision rejection")
	}
	if strings.Contains(err.Error(), "9007199254740992") {
		t.Errorf("message suggests a revision above MaxRevision: %v", err)
	}
	if !strings.Contains(err.Error(), "9007199254740991") {
		t.Errorf("message should still report the stored revision: %v", err)
	}
}
