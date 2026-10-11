// Copyright 2026 Jerry David Chan, Konareef.ai
// SPDX-License-Identifier: Apache-2.0

// Package serverurl validates the operator-supplied reef-core base URL
// (`--server` / `$KONAREEF_SERVER`) and builds endpoint URLs from it.
//
// Why this exists: on `POST /api/pods` and
// `PUT /api/pods/:handle/:pod_name/listing` the publisher's ECDSA
// signature IS the credential — there is no session token to scope the
// request to an origin. So the base URL decides where a valid signature
// plus publisher pubkey is delivered, and it arrives as an arbitrary
// string from a flag or an environment variable. A typo, a pasted
// value, a poisoned env var, or a deliberately misleading authority
// (`https://reef-core.konareef.ai@evil.example/`) would otherwise send
// the signed body to a non-reef-core origin while the command line
// still reads like reef-core.
//
// The contract is therefore fail-closed and deliberately narrow:
//
//   - scheme must be exactly http or https;
//   - the authority must carry a non-empty host and a valid port;
//   - userinfo (`user:pass@`), query, fragment, opaque bodies, and any
//     whitespace / control character anywhere in the input are rejected;
//   - the base path must be root ("" or "/") — see [Parse] for the
//     rationale;
//   - endpoint URLs are assembled with net/url path joining, never by
//     string concatenation.
//
// Callers must validate BEFORE signing, so a malformed server URL means
// no publisher signature is ever produced, let alone transmitted.
package serverurl

import (
	"errors"
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"unicode"
)

// ErrInvalidServerURL is the sentinel every rejection from this package
// wraps, so callers can distinguish "the operator's --server value is
// unusable" (a usage error) from a transport failure. The wrapped text
// always names the specific rule that failed.
var ErrInvalidServerURL = errors.New("invalid reef-core server URL")

// Parse validates rawBase and returns it normalised to a root-path base
// URL suitable for [url.URL.JoinPath].
//
// Input: rawBase — the resolved `--server` / `$KONAREEF_SERVER` value.
// Output: a *url.URL whose Scheme and Host are validated and whose Path,
// RawQuery and Fragment are empty; or an error wrapping
// [ErrInvalidServerURL] naming the rule that failed. Parse never
// performs I/O and never resolves DNS — it is a pure syntactic gate.
//
// Non-root base paths (`https://host/reef/`) are REJECTED, deliberately.
// Nothing in this repo, its docs, or its deployment kits ever configures
// a path-prefixed reef-core base — every documented value is an origin
// (`http://localhost:4000`, `https://beta-api.konareef.ai`) — and a
// silently accepted path prefix is exactly the shape a path-confusion
// bait URL takes (`https://reef-core.konareef.ai.evil.example/api/pods`
// is caught by the host rules, but `https://evil.example/reef-core.konareef.ai`
// reads as legitimate at a glance). Should reef-core ever be deployed
// under a path prefix, lift the restriction here — in one place — rather
// than at each call site.
func Parse(rawBase string) (*url.URL, error) {
	if rawBase == "" {
		return nil, fmt.Errorf("%w: it is empty", ErrInvalidServerURL)
	}
	// Scan before parsing: url.Parse rejects ASCII control characters
	// but tolerates several whitespace forms, and a value carrying a
	// stray space or a non-breaking space is a paste accident, not an
	// address. Rejecting the whole class keeps the error honest.
	for _, r := range rawBase {
		if r == 0x7f || r < 0x20 || unicode.IsSpace(r) {
			return nil, fmt.Errorf(
				"%w: it contains a whitespace or control character (U+%04X)",
				ErrInvalidServerURL, r)
		}
	}

	parsed, err := url.Parse(rawBase)
	if err != nil {
		// url.Parse's error already quotes the input; wrapping it would
		// repeat the URL twice in one line, and its "net/url: invalid
		// userinfo" text can carry a pasted password. Report the shape
		// of the failure, not the value.
		return nil, fmt.Errorf("%w: it is not a well-formed URL", ErrInvalidServerURL)
	}

	// Opaque is non-empty for scheme-relative junk like "http:4000" or
	// "mailto:x@y" — there is no authority to send anything to.
	if parsed.Opaque != "" {
		return nil, fmt.Errorf(
			"%w: %q is not an absolute http(s) URL (did you mean \"http://%s\"?)",
			ErrInvalidServerURL, rawBase, parsed.Opaque)
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return nil, fmt.Errorf("%w: scheme %q is not http or https",
			ErrInvalidServerURL, parsed.Scheme)
	}
	// Userinfo is the classic misleading authority: everything left of
	// the "@" is decoration, and the real origin is whatever follows.
	// The input is NOT echoed here — it may carry a password.
	if parsed.User != nil {
		return nil, fmt.Errorf(
			"%w: it embeds credentials before an \"@\"; the real host would be %q",
			ErrInvalidServerURL, parsed.Host)
	}
	if parsed.Host == "" || parsed.Hostname() == "" {
		return nil, fmt.Errorf("%w: %q has no host", ErrInvalidServerURL, rawBase)
	}
	if port := parsed.Port(); port != "" {
		n, err := strconv.Atoi(port)
		if err != nil || n < 1 || n > 65535 {
			return nil, fmt.Errorf("%w: %q is not a valid port", ErrInvalidServerURL, port)
		}
	}
	if parsed.RawQuery != "" || parsed.ForceQuery {
		return nil, fmt.Errorf("%w: %q carries a query string", ErrInvalidServerURL, rawBase)
	}
	if parsed.Fragment != "" || parsed.RawFragment != "" {
		return nil, fmt.Errorf("%w: %q carries a fragment", ErrInvalidServerURL, rawBase)
	}
	if parsed.Path != "" && parsed.Path != "/" {
		return nil, fmt.Errorf(
			"%w: %q has a base path; pass the reef-core origin only (scheme, host and port)",
			ErrInvalidServerURL, rawBase)
	}

	// Normalise to a bare origin so JoinPath always starts from root and
	// a trailing "/" cannot produce "//api/pods".
	normalised := *parsed
	normalised.Path = ""
	normalised.RawPath = ""
	return &normalised, nil
}

// Endpoint validates rawBase with [Parse] and returns the absolute URL
// for the given path segments.
//
// Input: rawBase — the resolved `--server` / `$KONAREEF_SERVER` value;
// segments — the individual path segments in order, UNESCAPED (e.g.
// "api", "pods", handle, podName, "listing").
// Output: the absolute URL string, or an error wrapping
// [ErrInvalidServerURL].
//
// Segments are joined with [url.URL.JoinPath], which percent-escapes
// each one, so a handle or pod name carrying "?" or "#" cannot rewrite
// the request target. Everything JoinPath does NOT neutralise is
// rejected outright, because the escaped wire form and the decoded path
// must name the same route:
//
//   - "/" is not escaped by JoinPath, so a segment containing one would
//     silently add a path component (and could swallow the "/listing"
//     suffix into an extra segment);
//   - "\" is escaped to "%5C" on the wire, but a proxy or framework that
//     folds backslash to slash before routing sees an extra component;
//   - "%" starts a percent-escape that JoinPath passes through verbatim,
//     so "a%2Fb" ships as /api/pods/a%2Fb/… while the decoded path is
//     /api/pods/a/b/…, and "%2e%2e" decodes to ".." — the encoded twins
//     of the two rules above. No legitimate identifier segment contains
//     one (handles and pod names are ^[a-z][a-z0-9_-]*$), and the
//     literal segments here are "api" / "pods" / "listing", so the whole
//     character is refused rather than a blocklist of escapes that must
//     also cover case folding and double encoding;
//   - empty segments and the "." / ".." traversal tokens path cleaning
//     acts on.
//
// This runs before any publisher signature is produced, so a rejected
// segment means nothing is signed and no request is issued.
func Endpoint(rawBase string, segments ...string) (string, error) {
	base, err := Parse(rawBase)
	if err != nil {
		return "", err
	}
	for _, seg := range segments {
		switch {
		case seg == "":
			return "", fmt.Errorf("%w: empty path segment", ErrInvalidServerURL)
		case strings.Contains(seg, "/"):
			return "", fmt.Errorf("%w: path segment %q contains a slash",
				ErrInvalidServerURL, seg)
		case strings.Contains(seg, `\`):
			return "", fmt.Errorf("%w: path segment %q contains a backslash",
				ErrInvalidServerURL, seg)
		case strings.Contains(seg, "%"):
			return "", fmt.Errorf(
				"%w: path segment %q contains a percent-escape; segments must be unescaped",
				ErrInvalidServerURL, seg)
		case seg == "." || seg == "..":
			return "", fmt.Errorf("%w: path segment %q is a traversal token",
				ErrInvalidServerURL, seg)
		}
	}
	return base.JoinPath(segments...).String(), nil
}
