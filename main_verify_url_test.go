// main_verify_url_test.go — MR !30 regression: the headless
// `konareef verify <src>` dispatch must route a konareef-bundle/v2 CBOR
// bundle to the v2 verifier when src is an http(s) URL, not only when it is
// a local file.
//
// Background: the served-bundle C0 flow is
// `/api/public/proofs/:hash/bundle` (served as application/cbor) +
// `konareef verify <url>`. Before this fix, the headless dispatch only
// peeked at bytes via os.ReadFile, which fails for a URL, so a served v2
// bundle fell through to verify.Load(src) — the legacy v1 JSON loader — and
// never reached VerifyV2Production. These tests pin the corrected routing.
package main

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/digitsu/konareef/internal/verify"
)

// loadV2CBORFixture returns the bytes of a deterministic, in-repo v2 CBOR
// bundle fixture so the regression does not depend on a transient /tmp file.
func loadV2CBORFixture(t *testing.T) []byte {
	t.Helper()
	path := filepath.Join("internal", "verify", "testdata", "parity-v2-typec.cbor")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read v2 CBOR fixture %s: %v", path, err)
	}
	if len(raw) == 0 || raw[0] < 0xA0 || raw[0] > 0xBB {
		t.Fatalf("fixture is not a CBOR map (first byte 0x%02X); test would be vacuous", raw[0])
	}
	return raw
}

// TestVerifyV2ByteSource_RoutesV2CBORURLToV2 is the core MR !30 acceptance
// test: a v2 CBOR bundle served over HTTP must be routed to the v2 verifier
// path (NOT the v1 JSON loader).
//
// It proves routing in two locked-together steps, exactly mirroring the
// production dispatch in runVerify:
//
//  1. verifyV2ByteSource(url) — which fetches via verify.ReadSource (the same
//     http(s)-aware byte source runVerify uses) and applies the first-byte
//     gate — returns isV2 == true with the served bytes. A URL that returned
//     false here would prove the v1-fallthrough bug is still present.
//  2. Feeding those bytes to verify.VerifyV2Production yields the v2
//     fail-closed verdict (no Spartan verifier wired, since the Rust
//     KONAREEF_VERIFY_BIN is absent in unit CI) — and crucially NOT the v1
//     "parse bundle JSON" error that verify.Load would have produced.
//
// This is deterministic and does not require the slow Rust binary: the
// assertion is "reached v2 routing", established by (a) isV2 == true and
// (b) the divergence being the v2 fail-closed path, never a JSON parse error.
func TestVerifyV2ByteSource_RoutesV2CBORURLToV2(t *testing.T) {
	cbor := loadV2CBORFixture(t)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/cbor")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(cbor)
	}))
	defer srv.Close()

	url := srv.URL + "/api/public/proofs/deadbeef/bundle"

	// Step 1 — the shared dispatch helper must route the URL to v2.
	raw, isV2 := verifyV2ByteSource(url)
	if !isV2 {
		t.Fatalf("verifyV2ByteSource(%q) returned isV2=false; v2 CBOR served over HTTP "+
			"fell through to the v1 JSON loader (the MR !30 bug)", url)
	}
	if len(raw) != len(cbor) || raw[0] != cbor[0] {
		t.Fatalf("verifyV2ByteSource returned %d bytes (first 0x%02X); want the served "+
			"%d bytes (first 0x%02X)", len(raw), raw[0], len(cbor), cbor[0])
	}

	// Step 2 — the v2 verifier runs on those bytes and lands on the v2
	// fail-closed path, never the v1 JSON parse error.
	r := verify.VerifyV2Production(raw, false)
	if r.OK {
		// With no KONAREEF_VERIFY_BIN wired, the production path is
		// fail-closed: a green verdict here would mean the v2 verifier
		// was bypassed, which would itself be a soundness regression.
		t.Fatalf("VerifyV2Production unexpectedly OK with no Spartan verifier wired; " +
			"v2 fail-closed semantics broken")
	}
	for _, d := range r.Divergences {
		if strings.Contains(strings.ToLower(d.Msg), "parse bundle json") {
			t.Fatalf("v2 bundle produced a v1 JSON parse divergence (%q); routing "+
				"reached the legacy v1 path, not VerifyV2Production", d.Msg)
		}
	}
	// Positive confirmation we are on the v2 fail-closed path, not some other
	// failure: the production verifier reports the absent-Spartan-verifier
	// divergence. (Substring match keeps this robust to message tweaks.)
	sawV2FailClosed := false
	for _, d := range r.Divergences {
		if strings.Contains(strings.ToLower(d.Msg), "spartan verifier") {
			sawV2FailClosed = true
			break
		}
	}
	if !sawV2FailClosed {
		t.Fatalf("expected the v2 fail-closed (no Spartan verifier) divergence; "+
			"got divergences: %v", divergenceMsgs(r))
	}
}

// TestVerifyV2ByteSource_V1URLFallsThrough confirms the fix did NOT regress
// v1: a v1 JSON bundle served over HTTP must NOT be claimed by the v2 byte
// source (so runVerify falls through to verify.Load), and verify.Load itself
// must still parse that same URL as a v1 bundle.
func TestVerifyV2ByteSource_V1URLFallsThrough(t *testing.T) {
	const v1JSON = `{"version":"konareef-bundle/v1","chain":[]}`

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(v1JSON))
	}))
	defer srv.Close()

	url := srv.URL + "/bundle.json"

	// The v2 byte source must NOT claim a v1 JSON body (first byte '{' = 0x7B).
	if _, isV2 := verifyV2ByteSource(url); isV2 {
		t.Fatalf("verifyV2ByteSource(%q) claimed a v1 JSON body as v2; first-byte gate broken", url)
	}

	// And the v1 URL path itself must still parse — proving the fallthrough
	// target (verify.Load) is unchanged for URLs.
	b, err := verify.Load(url)
	if err != nil {
		t.Fatalf("verify.Load(%q) failed on a v1 JSON URL: %v", url, err)
	}
	if b.Version != verify.BundleVersion {
		t.Fatalf("verify.Load parsed version %q; want %q", b.Version, verify.BundleVersion)
	}
}

// TestVerifyV1URL_FetchesSourceOnce is the MR !30 blocker-2 regression: the
// headless verify path must fetch the source URL EXACTLY ONCE. Previously the
// dispatch fetched once to peek the format and then called verify.Load(src),
// which fetched the URL a SECOND time — a problem for single-use / expiring /
// mutable served-bundle URLs (the same bytes might not come back, or the
// second GET might fail).
//
// This mirrors the production dispatch in runVerify exactly: ReadSource(url)
// for the format peek, then — because the body is v1 JSON, not a CBOR map —
// LoadFromBytes(raw) parsing the SAME already-fetched bytes (NOT a second
// verify.Load(url) that would re-fetch). The request-counting handler asserts
// the server saw a single GET.
func TestVerifyV1URL_FetchesSourceOnce(t *testing.T) {
	const v1JSON = `{"version":"konareef-bundle/v1","chain":[]}`

	var requestCount int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&requestCount, 1)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(v1JSON))
	}))
	defer srv.Close()

	url := srv.URL + "/api/public/proofs/deadbeef/bundle"

	// Step 1 — fetch the raw bytes ONCE (the format peek), exactly as
	// runVerify now does.
	raw, err := verify.ReadSource(url)
	if err != nil {
		t.Fatalf("ReadSource(%q) failed: %v", url, err)
	}

	// First byte is '{' (0x7B), not a CBOR map (0xA0..0xBB), so dispatch
	// falls to the v1 path — which MUST parse the already-fetched bytes,
	// not re-fetch the URL.
	if len(raw) > 0 && raw[0] >= 0xA0 && raw[0] <= 0xBB {
		t.Fatalf("v1 JSON body misclassified as CBOR (first byte 0x%02X)", raw[0])
	}

	b, err := verify.LoadFromBytes(raw)
	if err != nil {
		t.Fatalf("LoadFromBytes failed on v1 JSON bytes: %v", err)
	}
	if b.Version != verify.BundleVersion {
		t.Fatalf("LoadFromBytes parsed version %q; want %q", b.Version, verify.BundleVersion)
	}

	// The headless path must have hit the server exactly once. A count of 2
	// would mean the v1 parse re-fetched the URL (the blocker-2 bug).
	if got := atomic.LoadInt32(&requestCount); got != 1 {
		t.Fatalf("headless v1 URL verify made %d HTTP requests; want exactly 1 "+
			"(double-fetch regression)", got)
	}
}

func divergenceMsgs(r *verify.ResultV2) []string {
	msgs := make([]string, 0, len(r.Divergences))
	for _, d := range r.Divergences {
		msgs = append(msgs, d.Msg)
	}
	return msgs
}
