// Copyright 2026 Jerry David Chan, Konareef.ai
// SPDX-License-Identifier: Apache-2.0

// submit_serverurl_test.go — MR !58 note 2326 regression, publish half:
// a malformed or misleading `--server` / `$KONAREEF_SERVER` value must be
// refused before the signed pod body is transmitted, and must never
// produce an HTTP request.
//
// The signed manifest plus publisher pubkey is the credential on
// `POST /api/pods`, so the base URL decides who receives it. The CLI
// applies the same gate before Prepare signs anything
// (resolveServerURL / TestResolveServerURL* in the main package); this
// file pins the library-level backstop.

package publish

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/digitsu/konareef/internal/serverurl"
)

// countingTransport records every request handed to the HTTP client and
// refuses to perform it. Installed into submitClient, it turns "a
// request was issued" into a countable, assertable event even when the
// target host does not exist.
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

// For every malformed base URL, Submit errors and issues zero HTTP
// requests. The classes mirror internal/listing's table — both endpoints
// share one validator, so both must share one contract.
func TestSubmitRejectsMalformedServerURLsWithoutRequesting(t *testing.T) {
	for name, raw := range map[string]string{
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
	} {
		t.Run(name, func(t *testing.T) {
			ct := installCountingTransport(t)
			resp, err := Submit(raw, samplePreparedPod(), SubmitOpts{})
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

// A well-formed base URL — with or without a trailing slash — still
// reaches POST /api/pods, so the gate cannot pass by rejecting
// everything.
func TestSubmitAcceptsWellFormedServerURLs(t *testing.T) {
	var gotPath string
	var requests int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		gotPath = r.URL.Path
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(
			`{"install_url":"https://example.com/i","registered_at":"2026-05-23T10:00:00Z"}`))
	}))
	defer srv.Close()

	for name, base := range map[string]string{
		"bare origin":    srv.URL,
		"trailing slash": srv.URL + "/",
	} {
		t.Run(name, func(t *testing.T) {
			requests, gotPath = 0, ""
			if _, err := Submit(base, samplePreparedPod(), SubmitOpts{}); err != nil {
				t.Fatalf("Submit(%q): %v", base, err)
			}
			if requests != 1 {
				t.Errorf("requests = %d, want 1", requests)
			}
			if gotPath != "/api/pods" {
				t.Errorf("path = %q, want /api/pods", gotPath)
			}
		})
	}
}
