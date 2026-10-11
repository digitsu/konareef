// Copyright 2026 Jerry David Chan, Konareef.ai
// SPDX-License-Identifier: Apache-2.0

// anchor_offline_test.go: tests for offline mode of the chain-head anchor
// check (--offline, KONAREEF_OFFLINE). They check that offline mode uses
// only a pinned headers file, that without one an anchored bundle reports
// headers_unavailable and no header service gets a request, and that
// offline mode with header URLs is an error. One test runs the
// production entry (VerifyV2ProductionWithAnchor) with KONAREEF_OFFLINE.
package verify

import (
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/digitsu/konareef/internal/spv"
)

// writePinnedHeaders writes the headers of p from the anchor block to the
// tip as a pinned headers file. Inputs: t, p. Output: the file path.
func writePinnedHeaders(t *testing.T, p *anchorParts) string {
	t.Helper()
	var pinned [][spv.HeaderSize]byte
	for height := uint64(anchorBlockHeight); height <= p.chain.Headers.Tip; height++ {
		pinned = append(pinned, p.chain.Headers.Headers[height])
	}
	headersFile := filepath.Join(t.TempDir(), "headers.bin")
	if err := os.WriteFile(headersFile, spv.EncodePinnedFile(anchorBlockHeight, pinned), 0o600); err != nil {
		t.Fatal(err)
	}
	return headersFile
}

// TestOffline_WithFileUsesPinnedFileOnly: in offline mode with a headers
// file, the only header source is the pinned file, the anchor verifies,
// and the default services get no request.
func TestOffline_WithFileUsesPinnedFileOnly(t *testing.T) {
	p := newAnchorParts(t, "C")
	defaultServer, defaultRequests := newHeaderServer(t, p.chain.Headers, headerServerOptions{failOnRequest: true})
	useDefaultHeaderServices(t,
		DefaultHeaderService{BaseURL: defaultServer.URL},
		DefaultHeaderService{BaseURL: defaultServer.URL})

	cfg := AnchorConfig{HeadersFile: writePinnedHeaders(t, p), Offline: true}
	opts, err := cfg.Options()
	if err != nil {
		t.Fatalf("options: %v", err)
	}
	first, ok := opts.Headers.(*spv.First)
	if !ok || len(first.Sources) != 1 {
		t.Fatalf("headers = %#v, want a First over one source", opts.Headers)
	}
	if _, ok := first.Sources[0].(*spv.Memory); !ok {
		t.Fatalf("source = %#v, want the pinned file (*spv.Memory)", first.Sources[0])
	}

	p.opts = liveOptions(t, p, cfg)
	r := p.verify(t)
	if !r.OK || anchorStatus(r) != AnchorVerified || !r.V2Verdict.ChainHeadAnchored {
		t.Fatalf("ok=%v status=%s anchored=%v: %v", r.OK, anchorStatus(r),
			r.V2Verdict.ChainHeadAnchored, divergenceStrings(r))
	}
	if n := defaultRequests.Load(); n != 0 {
		t.Fatalf("default services got %d requests in offline mode", n)
	}
}

// TestOffline_NoFileGivesHeadersUnavailable: in offline mode with no
// headers file, there is no header source. An anchored bundle still
// verifies, reports headers_unavailable, is not anchored, and the
// default services get no request.
func TestOffline_NoFileGivesHeadersUnavailable(t *testing.T) {
	p := newAnchorParts(t, "C")
	defaultServer, defaultRequests := newHeaderServer(t, p.chain.Headers, headerServerOptions{failOnRequest: true})
	useDefaultHeaderServices(t,
		DefaultHeaderService{BaseURL: defaultServer.URL},
		DefaultHeaderService{BaseURL: defaultServer.URL})

	cfg := AnchorConfig{Offline: true}
	opts, err := cfg.Options()
	if err != nil || opts.Headers != nil {
		t.Fatalf("headers %#v, err %v; want no source", opts.Headers, err)
	}

	p.opts = liveOptions(t, p, cfg)
	r := p.verify(t)
	requireAnchorStatus(t, r, AnchorHeadersUnavailable)
	if !r.OK || r.V2Verdict.ChainHeadAnchored {
		t.Fatalf("ok=%v anchored=%v: %v", r.OK, r.V2Verdict.ChainHeadAnchored, divergenceStrings(r))
	}
	if n := defaultRequests.Load(); n != 0 {
		t.Fatalf("default services got %d requests in offline mode", n)
	}
}

// TestOffline_WithHeaderURLsIsError: offline mode with header URLs, from
// the config or from the environment, is ErrOfflineWithHeaderURLs.
func TestOffline_WithHeaderURLsIsError(t *testing.T) {
	cfg := AnchorConfig{Offline: true, HeaderURLs: []string{"https://a.example", "https://b.example"}}
	if err := cfg.CheckOffline(); !errors.Is(err, ErrOfflineWithHeaderURLs) {
		t.Fatalf("CheckOffline: %v, want ErrOfflineWithHeaderURLs", err)
	}
	if _, err := cfg.Options(); !errors.Is(err, ErrOfflineWithHeaderURLs) {
		t.Fatalf("Options: %v, want ErrOfflineWithHeaderURLs", err)
	}

	t.Setenv(HeadersURLsEnv, "https://a.example,https://b.example")
	envCfg, err := AnchorConfigFromEnv()
	if err != nil {
		t.Fatal(err)
	}
	if err := envCfg.Merge(AnchorConfig{Offline: true}).CheckOffline(); !errors.Is(err, ErrOfflineWithHeaderURLs) {
		t.Fatalf("flag offline with env URLs: %v, want ErrOfflineWithHeaderURLs", err)
	}
}

// TestOffline_EnvVar: KONAREEF_OFFLINE accepts 1 and true (any case),
// treats 0, false and empty as off, refuses other values, and offline
// mode from the environment survives a merge with flag config.
func TestOffline_EnvVar(t *testing.T) {
	cases := map[string]bool{"1": true, "true": true, "TRUE": true, "0": false, "false": false, "": false}
	for value, want := range cases {
		t.Setenv(OfflineEnv, value)
		cfg, err := AnchorConfigFromEnv()
		if err != nil || cfg.Offline != want {
			t.Fatalf("%s=%q: offline=%v err=%v, want %v", OfflineEnv, value, cfg.Offline, err, want)
		}
	}

	t.Setenv(OfflineEnv, "yes please")
	if _, err := AnchorConfigFromEnv(); err == nil {
		t.Fatalf("%s=%q was accepted", OfflineEnv, "yes please")
	}

	t.Setenv(OfflineEnv, "1")
	envCfg, err := AnchorConfigFromEnv()
	if err != nil {
		t.Fatal(err)
	}
	if !envCfg.Merge(AnchorConfig{}).Offline {
		t.Fatal("offline mode from the environment was lost in Merge")
	}
	// Set real defaults, so that "no source" below proves that offline
	// mode skipped them, not that an earlier test left them empty.
	useDefaultHeaderServices(t,
		DefaultHeaderService{BaseURL: "https://one.example"},
		DefaultHeaderService{BaseURL: "https://two.example"})
	opts, err := envCfg.Merge(AnchorConfig{}).Options()
	if err != nil || opts.Headers != nil {
		t.Fatalf("env offline: headers %#v, err %v; want no source", opts.Headers, err)
	}
}

// TestOffline_ProductionEntryEnv: with KONAREEF_OFFLINE=1, the production
// entry VerifyV2ProductionWithAnchor checks an anchored bundle with no
// header request to the default services, reports headers_unavailable,
// and does not refuse the anchor configuration.
func TestOffline_ProductionEntryEnv(t *testing.T) {
	p := newAnchorParts(t, "C")
	defaultServer, defaultRequests := newHeaderServer(t, p.chain.Headers, headerServerOptions{failOnRequest: true})
	useDefaultHeaderServices(t,
		DefaultHeaderService{BaseURL: defaultServer.URL},
		DefaultHeaderService{BaseURL: defaultServer.URL})
	t.Setenv(OfflineEnv, "1")
	t.Setenv(HeadersFileEnv, "")
	t.Setenv(HeadersURLsEnv, "")
	t.Setenv(VerifyBinEnv, "")

	extra := AnchorConfig{TrustedNodeKeys: []string{hex.EncodeToString(p.identity)}, MaxTargetBits: "207fffff"}
	r := VerifyV2ProductionWithAnchor(p.encode(t), false, extra)
	// With no Spartan binary the proof check fails closed, so the bundle
	// as a whole is refused. Only the anchor result matters here.
	if got := anchorStatus(r); got != AnchorHeadersUnavailable {
		t.Fatalf("status = %s, want %s: %v", got, AnchorHeadersUnavailable, divergenceStrings(r))
	}
	if r.V2Verdict.ChainHeadAnchored {
		t.Fatal("bundle is anchored with no header source")
	}
	for _, d := range r.Divergences {
		if errors.Is(d.Err, ErrAnchorConfigInvalid) {
			t.Fatalf("anchor config refused: %s", d.Msg)
		}
	}
	if n := defaultRequests.Load(); n != 0 {
		t.Fatalf("default services got %d requests in offline mode", n)
	}
}
