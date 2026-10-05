// Copyright 2026 Jerry David Chan, Konareef.ai
// SPDX-License-Identifier: Apache-2.0

package vkeystore_test

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/digitsu/konareef/internal/vkeystore"
)

func TestSourceConstantsHaveStableStrings(t *testing.T) {
	cases := map[vkeystore.Source]string{
		vkeystore.SourceCache:         "cache",
		vkeystore.SourceWellKnown:     "well-known-url",
		vkeystore.SourceAnchor:        "on-chain-anchor",
		vkeystore.SourceBundleInline:  "bundle-self-contained",
		vkeystore.SourcePublisherFile: "publisher-file",
	}
	for s, want := range cases {
		if string(s) != want {
			t.Errorf("Source %v string = %q, want %q", s, string(s), want)
		}
	}
}

func TestResolveRequestZeroValueRejected(t *testing.T) {
	r := vkeystore.ResolveRequest{}
	if err := r.Validate(); err == nil {
		t.Fatal("zero ResolveRequest must fail Validate")
	}
}

func TestResolveRequestValidPasses(t *testing.T) {
	r := vkeystore.ResolveRequest{
		CircuitID:       "konareef-pod-step-v1",
		VkeySha256:      "0000000000000000000000000000000000000000000000000000000000000000",
		PublisherDomain: "example.test",
	}
	if err := r.Validate(); err != nil {
		t.Fatalf("valid ResolveRequest rejected: %v", err)
	}
}

func TestVkeyHasResolvedAt(t *testing.T) {
	v := vkeystore.Vkey{ResolvedAt: time.Now()}
	if v.ResolvedAt.IsZero() {
		t.Fatal("ResolvedAt must persist on Vkey value")
	}
}

func TestValidateCircuitIDRejectsTraversalAndSeparators(t *testing.T) {
	// All of these MUST be rejected to prevent path traversal / cache
	// poisoning when circuitID is interpolated into a filesystem path.
	bad := []string{
		"",
		".",
		"..",
		"../../../etc/passwd",
		"foo/bar",
		`..\..\windows\system32`,
		`foo\bar`,
		"foo\x00bar",
		"foo bar", // whitespace
		"foo:bar", // colon (Windows drive)
		"foo/../bar",
		"/abs",
		"a/b",
	}
	for _, id := range bad {
		err := vkeystore.ValidateCircuitID(id)
		if !errors.Is(err, vkeystore.ErrCircuitIDInvalid) {
			t.Errorf("ValidateCircuitID(%q) = %v; want ErrCircuitIDInvalid", id, err)
		}
	}
}

func TestValidateCircuitIDAcceptsSafeTokens(t *testing.T) {
	good := []string{
		"konareef-pod-step-v1",
		"abc123",
		"a.b.c",
		"under_score",
		"ALL-CAPS",
		"con", // Windows reserved name — we don't filter, kernel won't open it anyway
		"v1",
	}
	for _, id := range good {
		if err := vkeystore.ValidateCircuitID(id); err != nil {
			t.Errorf("ValidateCircuitID(%q) = %v; want nil", id, err)
		}
	}
}

func TestValidateVkeySha256Requires64LowerHex(t *testing.T) {
	bad := []struct{ name, in string }{
		{"empty", ""},
		{"short", strings.Repeat("a", 63)},
		{"long", strings.Repeat("a", 65)},
		{"upper", strings.Repeat("A", 64)},
		{"mixed", strings.Repeat("a", 63) + "A"},
		{"non-hex", strings.Repeat("g", 64)},
		{"slash", strings.Repeat("a", 63) + "/"},
		{"dot-dot", strings.Repeat(".", 64)},
	}
	for _, tc := range bad {
		err := vkeystore.ValidateVkeySha256(tc.in)
		if !errors.Is(err, vkeystore.ErrVkeySha256Invalid) {
			t.Errorf("ValidateVkeySha256(%s) = %v; want ErrVkeySha256Invalid", tc.name, err)
		}
	}
	good := strings.Repeat("a", 64)
	if err := vkeystore.ValidateVkeySha256(good); err != nil {
		t.Errorf("ValidateVkeySha256(64 lowercase hex) = %v; want nil", err)
	}
}

func TestValidatePublisherDomainRejectsPaygateZkPrefix(t *testing.T) {
	// Caller passed the full service host instead of the base domain.
	// The Tier-1 backend prepends `paygate-zk.` internally, so accepting
	// this input would produce `paygate-zk.paygate-zk.example.com`.
	bad := []string{
		"paygate-zk.example.com",
		"PAYGATE-ZK.example.com",
		"paygate-zk.foo.bar",
	}
	for _, d := range bad {
		err := vkeystore.ValidatePublisherDomain(d)
		if !errors.Is(err, vkeystore.ErrDomainAlreadyPrefixed) {
			t.Errorf("ValidatePublisherDomain(%q) = %v; want ErrDomainAlreadyPrefixed", d, err)
		}
	}
}

func TestValidatePublisherDomainAcceptsBaseDomain(t *testing.T) {
	good := []string{
		"example.com",
		"example.test",
		"sub.example.com",
		"paygate-zk-not-prefix.example.com", // does not start with the literal prefix
	}
	for _, d := range good {
		if err := vkeystore.ValidatePublisherDomain(d); err != nil {
			t.Errorf("ValidatePublisherDomain(%q) = %v; want nil", d, err)
		}
	}
}

func TestResolveRequestValidateRejectsTraversalInCircuitID(t *testing.T) {
	r := vkeystore.ResolveRequest{
		CircuitID:       "../../../etc/passwd",
		VkeySha256:      strings.Repeat("a", 64),
		PublisherDomain: "example.com",
	}
	if err := r.Validate(); !errors.Is(err, vkeystore.ErrCircuitIDInvalid) {
		t.Fatalf("Validate must reject traversal circuit_id; got %v", err)
	}
}

func TestResolveRequestValidateRejectsAlreadyPrefixedDomain(t *testing.T) {
	r := vkeystore.ResolveRequest{
		CircuitID:       "circ",
		VkeySha256:      strings.Repeat("a", 64),
		PublisherDomain: "paygate-zk.example.com",
	}
	if err := r.Validate(); !errors.Is(err, vkeystore.ErrDomainAlreadyPrefixed) {
		t.Fatalf("Validate must reject paygate-zk.-prefixed domain; got %v", err)
	}
}

// TestValidatePublisherDomainRejectsURLInjection ensures every form of
// URL-authority or path injection is rejected with ErrPublisherDomainInvalid.
// SECURITY-CRITICAL: the publisher domain is interpolated into the Tier-1
// fetch URL host; any character that alters URL parsing must be rejected.
func TestValidatePublisherDomainRejectsURLInjection(t *testing.T) {
	cases := []struct {
		name string
		in   string
	}{
		// Path / query / fragment delimiters.
		{"path-slash", "evil.com/path"},
		{"path-deep", "evil.com/a/b/c"},
		{"query", "evil.com?x=1"},
		{"fragment", "evil.com#frag"},
		{"backslash", `evil.com\path`},
		{"trailing-slash", "evil.com/"},

		// Userinfo injection.
		{"userinfo", "evil.com@target.com"},
		{"userinfo-pass", "u:p@target.com"},
		{"bare-at", "@target.com"},

		// Scheme prefix.
		{"https-scheme", "https://evil.com"},
		{"http-scheme", "http://evil.com"},
		{"ftp-scheme", "ftp://evil.com"},
		{"scheme-only-colon", "https:evil.com"},

		// Port (colon).
		{"port", "evil.com:8080"},
		{"port-empty", "evil.com:"},

		// Whitespace and control characters.
		{"space-in-middle", "evil .com"},
		{"newline", "evil\n.com"},
		{"carriage-return", "evil\r.com"},
		{"tab", "evil\t.com"},
		{"null-byte", "evil\x00.com"},
		{"bell", "evil\x07.com"},
		{"del", "evil\x7f.com"},
		{"non-breaking-space", "evil .com"},

		// Non-ASCII / IDN raw form (must be Punycode-encoded before reaching us).
		{"unicode", "evıl.com"},
		{"emoji", "evil\xf0\x9f\x98\x80.com"},

		// DNS-grammar violations.
		{"single-label", "localhost"},
		{"empty-label-leading-dot", ".example.com"},
		{"empty-label-trailing-dot", "example.com."},
		{"empty-label-double-dot", "foo..example.com"},
		{"leading-hyphen", "-evil.com"},
		{"trailing-hyphen", "evil-.com"},
		{"label-leading-hyphen", "foo.-evil.com"},
		{"label-trailing-hyphen", "foo.evil-.com"},
		{"label-too-long", strings.Repeat("a", 64) + ".com"},

		// IP-looking inputs (numeric TLD).
		{"ipv4", "1.2.3.4"},
		{"ipv4-partial", "10.0.0.1"},
		{"numeric-tld", "example.123"},

		// Other punctuation outside the allow-list.
		{"underscore", "evil_host.com"},
		{"comma", "evil,com"},
		{"semicolon", "evil;com"},
		{"asterisk", "evil*.com"},
		{"square-bracket", "[evil].com"},
		{"percent", "evil%2e.com"},
		{"plus", "evil+.com"},
		{"equals", "evil=.com"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := vkeystore.ValidatePublisherDomain(tc.in)
			if err == nil {
				t.Fatalf("ValidatePublisherDomain(%q) = nil; want rejection", tc.in)
			}
			if !errors.Is(err, vkeystore.ErrPublisherDomainInvalid) {
				t.Errorf("ValidatePublisherDomain(%q) = %v; want ErrPublisherDomainInvalid", tc.in, err)
			}
		})
	}
}

// TestValidatePublisherDomainRejectsLeadingTrailingWhitespace asserts that
// leading/trailing whitespace is rejected outright. Silently trimming would
// allow BuildURL to emit a Host containing %20 / control bytes, producing an
// invalid Tier-1 URL.
func TestValidatePublisherDomainRejectsLeadingTrailingWhitespace(t *testing.T) {
	cases := []string{"  example.com  ", " example.com", "example.com "}
	for _, in := range cases {
		err := vkeystore.ValidatePublisherDomain(in)
		if err == nil {
			t.Errorf("ValidatePublisherDomain(%q) = nil; want ErrPublisherDomainInvalid", in)
			continue
		}
		if !errors.Is(err, vkeystore.ErrPublisherDomainInvalid) {
			t.Errorf("ValidatePublisherDomain(%q) = %v; want ErrPublisherDomainInvalid", in, err)
		}
	}
}

// TestBuildURLRejectsWhitespaceDomain is a regression test for the B1 blocker:
// BuildURL must return ErrPublisherDomainInvalid (not a %20-encoded URL) when
// the publisher domain has surrounding whitespace.
func TestBuildURLRejectsWhitespaceDomain(t *testing.T) {
	be := vkeystore.NewTier1HTTPSBackend(nil)
	_, err := be.BuildURL("circ", "  example.com  ")
	if !errors.Is(err, vkeystore.ErrPublisherDomainInvalid) {
		t.Errorf("BuildURL with whitespace domain = %v; want ErrPublisherDomainInvalid", err)
	}
}

// TestTier1BuildURLRejectsURLInjection asserts the Tier-1 URL constructor
// surfaces ErrPublisherDomainInvalid for the high-value injection vectors,
// proving the validator is wired into URL construction.
func TestTier1BuildURLRejectsURLInjection(t *testing.T) {
	be := vkeystore.NewTier1HTTPSBackend(nil)
	cases := []string{
		"evil.com/path",
		"evil.com@target.com",
		"https://evil.com",
		"evil.com?x=",
		"evil.com#frag",
		"evil .com",
		"evil\n.com",
		"1.2.3.4",
	}
	for _, in := range cases {
		_, err := be.BuildURL("circ", in)
		if !errors.Is(err, vkeystore.ErrPublisherDomainInvalid) {
			t.Errorf("BuildURL(%q) = %v; want ErrPublisherDomainInvalid", in, err)
		}
	}
}
