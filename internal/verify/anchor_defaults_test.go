// Copyright 2026 Jerry David Chan, Konareef.ai
// SPDX-License-Identifier: Apache-2.0

// anchor_defaults_test.go: tests for the default header sources of the
// chain-head anchor check (US-007). They check how the default chain is
// built, that it verifies a genuine anchor, that disagreement and
// unreachable services give the correct result, and that an explicit
// headers file or URL replaces the defaults.
//
// No test here reaches the network. TestMain clears
// DefaultHeaderServices for the whole package, and each test that needs
// defaults points them at local httptest servers.
package verify

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"

	"github.com/digitsu/konareef/internal/spv"
	"github.com/digitsu/konareef/internal/spv/spvtest"
)

// shippedDefaultHeaderServices is DefaultHeaderServices as the build
// ships it. Package variables are set before TestMain runs.
var shippedDefaultHeaderServices = DefaultHeaderServices

// TestMain clears the default header services, so that no test in this
// package reaches the public services. It also turns off the node key
// file and the konabeans PATH lookup, so that the files and PATH of a
// developer cannot change a test result. Input: m. Output: the exit code.
func TestMain(m *testing.M) {
	DefaultHeaderServices = nil
	DefaultNodeKeyFile = ""
	DefaultVerifyBinName = ""
	_ = os.Setenv(NodeKeyFileEnv, "")
	os.Exit(m.Run())
}

// useDefaultHeaderServices sets DefaultHeaderServices for one test and
// restores the previous value when the test ends. Inputs: t, services.
func useDefaultHeaderServices(t *testing.T, services ...DefaultHeaderService) {
	t.Helper()
	previous := DefaultHeaderServices
	DefaultHeaderServices = services
	t.Cleanup(func() { DefaultHeaderServices = previous })
}

// headerServerOptions select the JSON shape a test header server uses.
type headerServerOptions struct {
	// tipPath is the tip endpoint path, for example "chain/info".
	tipPath string
	// camelCasePrev writes "previousBlockHash" (Bitails) instead of
	// "previousblockhash" (WhatsOnChain).
	camelCasePrev bool
	// failOnRequest makes any request a test error: the server must not
	// be asked.
	failOnRequest bool
}

// newHeaderServer serves the headers of source in a WhatsOnChain-style
// JSON shape. Inputs: t; source, the headers and tip to serve; options.
// Output: the running server (closed when the test ends) and a counter
// of the requests it received.
func newHeaderServer(t *testing.T, source *spv.Memory, options headerServerOptions) (*httptest.Server, *atomic.Int64) {
	t.Helper()
	requests := &atomic.Int64{}
	prevField := "previousblockhash"
	if options.camelCasePrev {
		prevField = "previousBlockHash"
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		if options.failOnRequest {
			t.Errorf("header server that must not be asked got %s", r.URL.Path)
			http.NotFound(w, r)
			return
		}
		if r.URL.Path == "/"+options.tipPath {
			_ = json.NewEncoder(w).Encode(map[string]any{"blocks": source.Tip})
			return
		}
		var height uint64
		if _, err := fmt.Sscanf(r.URL.Path, "/block/height/%d", &height); err != nil {
			http.NotFound(w, r)
			return
		}
		header, ok := source.Headers[height]
		if !ok {
			http.NotFound(w, r)
			return
		}
		parsed, _ := spv.ParseHeader(header[:])
		hash := spv.Reverse32(parsed.Hash())
		root := spv.Reverse32(parsed.MerkleRoot)
		prev := spv.Reverse32(parsed.PrevBlock)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"hash": hex.EncodeToString(hash[:]), "version": parsed.Version,
			"merkleroot": hex.EncodeToString(root[:]), "time": parsed.Time,
			"bits": fmt.Sprintf("%08x", parsed.Bits), "nonce": parsed.Nonce,
			prevField: hex.EncodeToString(prev[:]),
		})
	}))
	t.Cleanup(server.Close)
	return server, requests
}

// liveOptions builds the anchor options the live path would build from
// cfg, with the test identity key trusted and the test difficulty floor.
// Inputs: t, p (for the identity key), cfg. Output: the options.
func liveOptions(t *testing.T, p *anchorParts, cfg AnchorConfig) AnchorOptions {
	t.Helper()
	cfg.TrustedNodeKeys = append(cfg.TrustedNodeKeys, hex.EncodeToString(p.identity))
	cfg.MaxTargetBits = "207fffff"
	opts, err := cfg.Options()
	if err != nil {
		t.Fatalf("options: %v", err)
	}
	return opts
}

// TestDefaultHeaders_Construction checks the default chain itself: two
// agreeing remotes with their tip paths, none when fewer than two are
// set, and an error for a service that is not https.
func TestDefaultHeaders_Construction(t *testing.T) {
	useDefaultHeaderServices(t,
		DefaultHeaderService{BaseURL: "https://one.example"},
		DefaultHeaderService{BaseURL: "https://two.example", TipPath: "network/info"})
	opts, err := AnchorConfig{}.Options()
	if err != nil {
		t.Fatalf("options: %v", err)
	}
	first, ok := opts.Headers.(*spv.First)
	if !ok || len(first.Sources) != 1 {
		t.Fatalf("headers = %#v, want a First over one default source", opts.Headers)
	}
	agreeing, ok := first.Sources[0].(*spv.Agreeing)
	if !ok || len(agreeing.Sources) != 2 {
		t.Fatalf("default source = %#v, want an Agreeing over two remotes", first.Sources[0])
	}
	second, ok := agreeing.Sources[1].(*spv.Remote)
	if !ok || second.BaseURL != "https://two.example" || second.TipPath != "network/info" {
		t.Fatalf("second remote = %#v", agreeing.Sources[1])
	}

	useDefaultHeaderServices(t, DefaultHeaderService{BaseURL: "https://one.example"})
	if opts, err := (AnchorConfig{}).Options(); err != nil || opts.Headers != nil {
		t.Fatalf("one default service gave headers %#v, err %v; want none", opts.Headers, err)
	}

	useDefaultHeaderServices(t,
		DefaultHeaderService{BaseURL: "http://one.example"},
		DefaultHeaderService{BaseURL: "https://two.example"})
	if _, err := (AnchorConfig{}).Options(); err == nil {
		t.Fatal("a plain http default service was accepted")
	}
}

// TestDefaultHeaders_ShippedServices checks the shipped defaults: two
// https services from different hosts, neither a reef-core node.
func TestDefaultHeaders_ShippedServices(t *testing.T) {
	shipped := shippedDefaultHeaderServices
	if len(shipped) != 2 || shipped[0].BaseURL == shipped[1].BaseURL {
		t.Fatalf("shipped defaults %+v are not two services", shipped)
	}
	for _, service := range shipped {
		if err := checkHeaderURL(service.BaseURL); err != nil {
			t.Fatalf("shipped default: %v", err)
		}
	}
}

// TestDefaultHeaders_VerifyAnchorWithNoConfig: with no file and no URL,
// a genuine anchor verifies through the two default services, one in the
// WhatsOnChain shape and one in the Bitails shape.
func TestDefaultHeaders_VerifyAnchorWithNoConfig(t *testing.T) {
	p := newAnchorParts(t, "C")
	woc, _ := newHeaderServer(t, p.chain.Headers, headerServerOptions{tipPath: "chain/info"})
	bitails, _ := newHeaderServer(t, p.chain.Headers, headerServerOptions{tipPath: "network/info", camelCasePrev: true})
	useDefaultHeaderServices(t,
		DefaultHeaderService{BaseURL: woc.URL},
		DefaultHeaderService{BaseURL: bitails.URL, TipPath: "network/info"})

	p.opts = liveOptions(t, p, AnchorConfig{})
	r := p.verify(t)
	if !r.OK || anchorStatus(r) != AnchorVerified || !r.V2Verdict.ChainHeadAnchored {
		t.Fatalf("ok=%v status=%s anchored=%v: %v", r.OK, anchorStatus(r),
			r.V2Verdict.ChainHeadAnchored, divergenceStrings(r))
	}
	if got := r.V2Verdict.ChainHeadAnchor.Confirmations; got != 3 {
		t.Fatalf("confirmations = %d, want 3", got)
	}
}

// TestDefaultHeaders_DisagreementRefused: when the two default services
// return different headers, the anchor is refused as untrusted.
func TestDefaultHeaders_DisagreementRefused(t *testing.T) {
	p := newAnchorParts(t, "C")
	honestHeader, _ := spv.ParseHeader(p.chain.Header[:])
	other := spvtest.MineHeader(honestHeader.PrevBlock, p.chain.Root, honestHeader.Time+1)
	forged := &spv.Memory{Headers: map[uint64][spv.HeaderSize]byte{anchorBlockHeight: other}, Tip: p.chain.Headers.Tip}
	honest, _ := newHeaderServer(t, p.chain.Headers, headerServerOptions{tipPath: "chain/info"})
	lying, _ := newHeaderServer(t, forged, headerServerOptions{tipPath: "chain/info"})
	useDefaultHeaderServices(t,
		DefaultHeaderService{BaseURL: honest.URL},
		DefaultHeaderService{BaseURL: lying.URL})

	p.opts = liveOptions(t, p, AnchorConfig{})
	requireAnchorError(t, p.verify(t), ErrAnchorHeaderUntrusted)
}

// TestDefaultHeaders_UnreachableGivesHeadersUnavailable: with no
// reachable default service, an anchored bundle still verifies, reports
// headers_unavailable, and is not anchored.
func TestDefaultHeaders_UnreachableGivesHeadersUnavailable(t *testing.T) {
	p := newAnchorParts(t, "C")
	useDefaultHeaderServices(t,
		DefaultHeaderService{BaseURL: "http://127.0.0.1:1"},
		DefaultHeaderService{BaseURL: "http://localhost:1"})
	p.opts = liveOptions(t, p, AnchorConfig{})
	requireAnchorStatus(t, p.verify(t), AnchorHeadersUnavailable)
}

// TestDefaultHeaders_ExplicitSourcesOverride: a headers file, header
// URLs, or the header URL environment variable replace the defaults, and
// the default services are never asked.
func TestDefaultHeaders_ExplicitSourcesOverride(t *testing.T) {
	p := newAnchorParts(t, "C")
	defaultServer, defaultRequests := newHeaderServer(t, p.chain.Headers, headerServerOptions{failOnRequest: true})
	useDefaultHeaderServices(t,
		DefaultHeaderService{BaseURL: defaultServer.URL},
		DefaultHeaderService{BaseURL: defaultServer.URL})

	explicitOne, _ := newHeaderServer(t, p.chain.Headers, headerServerOptions{tipPath: "chain/info"})
	explicitTwo, _ := newHeaderServer(t, p.chain.Headers, headerServerOptions{tipPath: "chain/info"})

	var pinned [][spv.HeaderSize]byte
	for height := uint64(anchorBlockHeight); height <= p.chain.Headers.Tip; height++ {
		pinned = append(pinned, p.chain.Headers.Headers[height])
	}
	headersFile := filepath.Join(t.TempDir(), "headers.bin")
	if err := os.WriteFile(headersFile, spv.EncodePinnedFile(anchorBlockHeight, pinned), 0o600); err != nil {
		t.Fatal(err)
	}

	cases := map[string]func() AnchorConfig{
		"headers file": func() AnchorConfig { return AnchorConfig{HeadersFile: headersFile} },
		"header urls":  func() AnchorConfig { return AnchorConfig{HeaderURLs: []string{explicitOne.URL, explicitTwo.URL}} },
		"header urls env": func() AnchorConfig {
			t.Setenv(HeadersURLsEnv, explicitOne.URL+","+explicitTwo.URL)
			cfg, err := AnchorConfigFromEnv()
			if err != nil {
				t.Fatal(err)
			}
			return cfg
		},
	}
	for name, config := range cases {
		t.Run(name, func(t *testing.T) {
			p.opts = liveOptions(t, p, config())
			r := p.verify(t)
			if !r.OK || anchorStatus(r) != AnchorVerified {
				t.Fatalf("ok=%v status=%s: %v", r.OK, anchorStatus(r), divergenceStrings(r))
			}
		})
	}
	if n := defaultRequests.Load(); n != 0 {
		t.Fatalf("default services got %d requests with explicit sources set", n)
	}
}

// TestDefaultHeaders_NoDefaultsLeavesNoSource: with the defaults cleared
// (as in every other test of this package), the options have no header
// source, so no test reaches the network by accident.
func TestDefaultHeaders_NoDefaultsLeavesNoSource(t *testing.T) {
	opts, err := AnchorConfig{}.Options()
	if err != nil || opts.Headers != nil {
		t.Fatalf("headers %#v, err %v; want none", opts.Headers, err)
	}
	if _, err := (&spv.First{}).HeaderAt(context.Background(), 1); !errors.Is(err, spv.ErrHeaderUnavailable) {
		t.Fatalf("empty chain: %v", err)
	}
}
