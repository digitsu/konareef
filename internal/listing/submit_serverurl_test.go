// Copyright 2026 Jerry David Chan, Konareef.ai
// SPDX-License-Identifier: Apache-2.0

// submit_serverurl_test.go — MR !58 note 2326 / 2335 regressions: a
// malformed or misleading `--server` / `$KONAREEF_SERVER` value, and a
// handle or pod name carrying a path separator or traversal token in
// literal or percent-encoded form, must all be refused BEFORE the
// listing is signed, and must never produce an HTTP request.
//
// The publisher's signature is the credential on
// `PUT /api/pods/:handle/:pod_name/listing`, so the base URL decides who
// receives a valid signature plus pubkey. Disabling redirects closes the
// second hop; these tests pin the first-hop origin contract.

package listing

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/digitsu/konareef/internal/identity"
	"github.com/digitsu/konareef/internal/serverurl"
)

// countingTransport records every request handed to the HTTP client and
// refuses to perform it. Installed into submitClient, it turns "a
// request was issued" into a countable, assertable event even when the
// target host does not exist — an httptest server alone cannot prove
// this, because a malformed URL would never reach it either way.
type countingTransport struct{ calls atomic.Int32 }

// RoundTrip counts the call and always fails, so no byte of the signed
// body can leave the process. Input: the outbound request. Output:
// always (nil, error).
func (t *countingTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	t.calls.Add(1)
	return nil, errors.New("test transport: no request may be issued for a malformed server URL")
}

// installCountingTransport swaps a countingTransport into submitClient
// for the duration of the test and restores the original afterwards.
// Input: the test handle. Output: the transport, for call assertions.
func installCountingTransport(t *testing.T) *countingTransport {
	t.Helper()
	ct := &countingTransport{}
	original := submitClient.Transport
	submitClient.Transport = ct
	t.Cleanup(func() { submitClient.Transport = original })
	return ct
}

// malformedServerURLs enumerates the base-URL classes that must be
// refused. Each one could deliver a signed listing to an origin other
// than the reef-core the publisher believes they are talking to.
var malformedServerURLs = map[string]string{
	"userinfo":               "https://reef-core.konareef.ai@evil.example",
	"userinfo with password": "https://alice:hunter2@evil.example",
	"query string":           "http://localhost:4000?next=https://evil.example",
	"fragment":               "http://localhost:4000#evil.example",
	"trailing space":         "http://localhost:4000 ",
	"embedded newline":       "http://localhost:4000\nHost: evil.example",
	"embedded tab":           "http://localhost:4000\t",
	"nul byte":               "http://localhost:4000\x00",
	"no scheme":              "localhost:4000",
	"scheme relative":        "//evil.example",
	"ftp scheme":             "ftp://localhost:4000",
	"file scheme":            "file:///etc/passwd",
	"opaque":                 "http:localhost:4000",
	"no host":                "http://",
	"non-root base path":     "http://localhost:4000/reef",
	"path confusion":         "https://evil.example/reef-core.konareef.ai",
	"empty":                  "",
}

// The core acceptance test: for every malformed base URL, Submit errors
// and issues zero HTTP requests.
func TestSubmitRejectsMalformedServerURLsWithoutRequesting(t *testing.T) {
	id, err := identity.Generate("alice")
	if err != nil {
		t.Fatalf("identity: %v", err)
	}
	for name, raw := range malformedServerURLs {
		t.Run(name, func(t *testing.T) {
			ct := installCountingTransport(t)
			resp, err := Submit(raw, validListing(), id)
			if err == nil {
				t.Fatalf("Submit(%q) = %+v, want an error", raw, resp)
			}
			if !errors.Is(err, serverurl.ErrInvalidServerURL) {
				t.Errorf("error %v does not wrap serverurl.ErrInvalidServerURL", err)
			}
			if got := ct.calls.Load(); got != 0 {
				t.Errorf("a malformed server URL issued %d HTTP request(s)", got)
			}
		})
	}
}

// Nothing may be signed on the malformed path. That is observable
// without a mock signer: Submit is handed a nil *identity.Identity, so
// reaching id.Sign would panic (it dereferences id.PrivateKeyHex). A
// clean error return proves the URL gate runs first and the publisher's
// key was never touched.
func TestSubmitValidatesServerURLBeforeSigning(t *testing.T) {
	for name, raw := range malformedServerURLs {
		t.Run(name, func(t *testing.T) {
			ct := installCountingTransport(t)
			if _, err := Submit(raw, validListing(), nil); err == nil {
				t.Fatalf("Submit(%q) succeeded with a nil identity", raw)
			}
			if got := ct.calls.Load(); got != 0 {
				t.Errorf("a malformed server URL issued %d HTTP request(s)", got)
			}
		})
	}
}

// hostileIdentifiers enumerates the handle / pod-name values that must
// be refused before anything is signed. The literal separators and
// traversal tokens were already covered; the percent-encoded twins are
// the MR !58 note 2335 blocker — url.URL.JoinPath passes an escape
// through verbatim, so an accepted "a%2Fb" would ship as
// PUT /api/pods/a%2Fb/research-bot/listing while the decoded path reads
// /api/pods/a/b/research-bot/listing, and the signed request would no
// longer name the one authenticated route.
var hostileIdentifiers = map[string]string{
	"slash":               "a/b",
	"traversal":           "..",
	"backslash":           `a\b`,
	"backslash traversal": `..\admin`,
	"encoded slash":       "a%2Fb",
	"encoded slash lower": "a%2fb",
	"encoded backslash":   "a%5Cb",
	"encoded traversal":   "%2e%2e",
	"encoded traversal 2": "%2E%2E%2Fadmin",
	"double encoded":      "%252e%252e",
	"empty":               "",
}

// A hostile handle or pod name must fail the URL gate: no signature, no
// HTTP request. Nothing is signed is observable without a mock signer —
// Submit is handed a nil *identity.Identity, so reaching id.Sign would
// panic (it dereferences id.PrivateKeyHex). A clean error return proves
// the segment gate ran first and the publisher's key was never touched.
func TestSubmitRejectsHostileIdentifierSegmentsWithoutSigning(t *testing.T) {
	for name, bad := range hostileIdentifiers {
		for field, mutate := range map[string]func(Fields, string) Fields{
			"handle":   func(f Fields, v string) Fields { f.Handle = v; return f },
			"pod name": func(f Fields, v string) Fields { f.PodName = v; return f },
		} {
			t.Run(name+"/"+field, func(t *testing.T) {
				ct := installCountingTransport(t)
				resp, err := Submit("https://beta-api.konareef.ai", mutate(validListing(), bad), nil)
				if err == nil {
					t.Fatalf("Submit with %s = %q returned %+v, want an error", field, bad, resp)
				}
				if !errors.Is(err, serverurl.ErrInvalidServerURL) {
					t.Errorf("error %v does not wrap serverurl.ErrInvalidServerURL", err)
				}
				if got := ct.calls.Load(); got != 0 {
					t.Errorf("a hostile %s issued %d HTTP request(s)", field, got)
				}
			})
		}
	}
}

// The counterpart to the rejection table: a well-formed base URL — with
// or without a trailing slash — still reaches the real route, so the
// gate cannot pass by rejecting everything.
func TestSubmitAcceptsWellFormedServerURLs(t *testing.T) {
	id, err := identity.Generate("alice")
	if err != nil {
		t.Fatalf("identity: %v", err)
	}
	var gotPath string
	var requests int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		gotPath = r.URL.Path
		_, _ = w.Write([]byte(
			`{"handle":"alice","pod_name":"research-bot","revision":1,"author_fee_sats":500,"status":"community"}`))
	}))
	defer srv.Close()

	for name, base := range map[string]string{
		"bare origin":    srv.URL,
		"trailing slash": srv.URL + "/",
	} {
		t.Run(name, func(t *testing.T) {
			requests, gotPath = 0, ""
			if _, err := Submit(base, validListing(), id); err != nil {
				t.Fatalf("Submit(%q): %v", base, err)
			}
			if requests != 1 {
				t.Errorf("requests = %d, want 1", requests)
			}
			if gotPath != "/api/pods/alice/research-bot/listing" {
				t.Errorf("path = %q", gotPath)
			}
		})
	}
}
