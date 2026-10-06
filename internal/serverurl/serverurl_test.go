// Copyright 2026 Jerry David Chan, Konareef.ai
// SPDX-License-Identifier: Apache-2.0

package serverurl

import (
	"errors"
	"strings"
	"testing"
)

// Every shape the CLI is actually pointed at in the docs, the beta
// onboarding kit and the tests must keep working — a validator that
// rejects `http://localhost:4000` or an httptest address would break
// every publish.
func TestParseAcceptsRealServerURLs(t *testing.T) {
	for _, raw := range []string{
		"http://localhost:4000",
		"http://localhost:4000/",
		"https://beta-api.konareef.ai",
		"https://beta-api.konareef.ai/",
		"http://127.0.0.1:52341",
		"http://reefcore-beta.tail6bed98.ts.net:4000",
		"http://[::1]:4000",
		"HTTP://Localhost:4000", // scheme case is normalised by net/url
	} {
		t.Run(raw, func(t *testing.T) {
			parsed, err := Parse(raw)
			if err != nil {
				t.Fatalf("Parse(%q) = %v, want nil", raw, err)
			}
			if parsed.Path != "" {
				t.Errorf("Path = %q, want normalised to empty", parsed.Path)
			}
			if parsed.Scheme != "http" && parsed.Scheme != "https" {
				t.Errorf("Scheme = %q", parsed.Scheme)
			}
		})
	}
}

// The rejection table. Each case is a class of value that could deliver
// a signed listing / pod to somewhere other than the reef-core the
// operator believes they typed.
func TestParseRejectsMalformedServerURLs(t *testing.T) {
	cases := map[string]string{
		"empty":                      "",
		"userinfo":                   "https://reef-core.konareef.ai@evil.example",
		"userinfo with password":     "https://user:pass@evil.example",
		"doubled userinfo":           "http://a@b@evil.example",
		"query":                      "http://localhost:4000?next=https://evil.example",
		"bare question mark":         "http://localhost:4000?",
		"fragment":                   "http://localhost:4000#frag",
		"leading space":              " http://localhost:4000",
		"trailing space":             "http://localhost:4000 ",
		"inner space":                "http://local host:4000",
		"tab":                        "http://localhost:4000\t",
		"newline":                    "http://localhost:4000\n",
		"carriage return":            "http://localhost:4000\r",
		"nul byte":                   "http://localhost:4000\x00",
		"del byte":                   "http://localhost:4000\x7f",
		"non-breaking space":         "http://localhost:4000 ",
		"no scheme":                  "localhost:4000",
		"scheme relative":            "//localhost:4000",
		"opaque":                     "http:localhost:4000",
		"ftp scheme":                 "ftp://localhost:4000",
		"file scheme":                "file:///etc/passwd",
		"javascript scheme":          "javascript:alert(1)",
		"no host":                    "http://",
		"empty host with path":       "http:///api/pods",
		"bad percent escape":         "http://%zz",
		"out of range port":          "http://localhost:70000",
		"zero port":                  "http://localhost:0",
		"non-root path":              "http://localhost:4000/reef",
		"path confusion":             "https://evil.example/reef-core.konareef.ai",
		"traversal path":             "http://localhost:4000/a/../b",
		"trailing double slash":      "http://localhost:4000//",
		"plain path only":            "/api/pods",
		"relative":                   "localhost",
		"backslash pseudo-authority": `http:\\localhost:4000`,
	}
	for name, raw := range cases {
		t.Run(name, func(t *testing.T) {
			parsed, err := Parse(raw)
			if err == nil {
				t.Fatalf("Parse(%q) = %v, want an error", raw, parsed)
			}
			if !errors.Is(err, ErrInvalidServerURL) {
				t.Errorf("error %v does not wrap ErrInvalidServerURL", err)
			}
		})
	}
}

// A password pasted into the server URL must not be echoed back into an
// error that lands in a terminal, a CI log or a bug report.
func TestParseDoesNotEchoUserinfo(t *testing.T) {
	_, err := Parse("https://alice:hunter2@evil.example")
	if err == nil {
		t.Fatal("Parse accepted a URL with credentials")
	}
	if strings.Contains(err.Error(), "hunter2") || strings.Contains(err.Error(), "alice") {
		t.Errorf("error leaks the credentials: %v", err)
	}
}

// Endpoint is the only URL builder the signing paths may use, so it has
// to produce exactly the routes reef-core serves.
func TestEndpointBuildsExpectedRoutes(t *testing.T) {
	cases := []struct {
		name     string
		base     string
		segments []string
		want     string
	}{
		{"publish", "http://localhost:4000", []string{"api", "pods"},
			"http://localhost:4000/api/pods"},
		{"publish trailing slash", "http://localhost:4000/", []string{"api", "pods"},
			"http://localhost:4000/api/pods"},
		{"listing", "https://beta-api.konareef.ai", []string{"api", "pods", "alice", "research-bot", "listing"},
			"https://beta-api.konareef.ai/api/pods/alice/research-bot/listing"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := Endpoint(tc.base, tc.segments...)
			if err != nil {
				t.Fatalf("Endpoint: %v", err)
			}
			if got != tc.want {
				t.Errorf("Endpoint = %q, want %q", got, tc.want)
			}
		})
	}
}

// Handles and pod names reach Endpoint from a manifest / identity file.
// A segment carrying "?" or "#" must be escaped rather than allowed to
// rewrite the request target, and one carrying "/" — which JoinPath
// would treat as a separator, potentially swallowing the "/listing"
// suffix — must be refused outright.
func TestEndpointNeutralisesHostilePathSegments(t *testing.T) {
	got, err := Endpoint("http://localhost:4000", "api", "pods", "ali?ce", "bot#1", "listing")
	if err != nil {
		t.Fatalf("Endpoint: %v", err)
	}
	const want = "http://localhost:4000/api/pods/ali%3Fce/bot%231/listing"
	if got != want {
		t.Errorf("Endpoint = %q, want %q", got, want)
	}

	for name, seg := range hostileSegments {
		t.Run(name, func(t *testing.T) {
			if url, err := Endpoint("http://localhost:4000", "api", "pods", seg, "listing"); err == nil {
				t.Errorf("Endpoint accepted segment %q -> %s", seg, url)
			} else if !errors.Is(err, ErrInvalidServerURL) {
				t.Errorf("error %v does not wrap ErrInvalidServerURL", err)
			}
		})
	}
}

// hostileSegments enumerates every identifier-segment value that must be
// refused before a URL is returned — the literal separators and
// traversal tokens, and their percent-encoded twins. It is exported to
// the package's tests (and mirrored by the listing/publish submit
// regressions) so one table drives every layer of the gate.
var hostileSegments = map[string]string{
	"slash":                  "alice/../admin",
	"empty":                  "",
	"dot":                    ".",
	"dot dot":                "..",
	"root only":              "/",
	"backslash":              `a\b`,
	"backslash traversal":    `..\admin`,
	"encoded slash":          "a%2Fb",
	"encoded slash lower":    "a%2fb",
	"encoded backslash":      "a%5Cb",
	"encoded dot dot":        "%2e%2e",
	"encoded dot dot upper":  "%2E%2E",
	"encoded traversal":      "%2e%2e%2fadmin",
	"double encoded dot dot": "%252e%252e",
	"encoded nul":            "a%00b",
	"bare percent":           "100%",
}

// The blocker MR !58 note 2335 named: JoinPath passes a percent-escape
// through verbatim, so an accepted "a%2Fb" would ship as
// /api/pods/a%2Fb/pod/listing while the decoded path is
// /api/pods/a/b/pod/listing — the signed request and the route the
// server matches would disagree. This pins the wire form: for every
// hostile segment there is no URL at all, and in particular none whose
// decoded path differs from its escaped form.
func TestEndpointRejectsEncodedSeparatorsAndTraversal(t *testing.T) {
	for name, seg := range hostileSegments {
		t.Run(name, func(t *testing.T) {
			got, err := Endpoint("https://beta-api.konareef.ai", "api", "pods", seg, "research-bot", "listing")
			if err == nil {
				t.Fatalf("Endpoint accepted segment %q -> %s", seg, got)
			}
			if !errors.Is(err, ErrInvalidServerURL) {
				t.Errorf("error %v does not wrap ErrInvalidServerURL", err)
			}
			if got != "" {
				t.Errorf("Endpoint returned %q alongside an error, want the empty string", got)
			}
		})
	}
}

// The counterpart: a real handle and pod name still build the one route
// reef-core serves, so the new rules cannot pass by rejecting
// everything. Identifiers are ^[a-z][a-z0-9_-]*$, and none of those
// characters is escaped by JoinPath — the escaped and decoded paths are
// byte-identical.
func TestEndpointAcceptsRealIdentifierSegments(t *testing.T) {
	for _, handle := range []string{"alice", "a", "bob-2", "carol_x", "d9"} {
		t.Run(handle, func(t *testing.T) {
			got, err := Endpoint("https://beta-api.konareef.ai", "api", "pods", handle, "research-bot", "listing")
			if err != nil {
				t.Fatalf("Endpoint(%q): %v", handle, err)
			}
			want := "https://beta-api.konareef.ai/api/pods/" + handle + "/research-bot/listing"
			if got != want {
				t.Errorf("Endpoint = %q, want %q", got, want)
			}
		})
	}
}

// A malformed base must fail in Endpoint too — callers only ever build
// through it, so the gate cannot be bypassed by skipping Parse.
func TestEndpointRejectsMalformedBase(t *testing.T) {
	if got, err := Endpoint("https://reef-core.konareef.ai@evil.example", "api", "pods"); err == nil {
		t.Errorf("Endpoint accepted a userinfo base -> %s", got)
	}
}
