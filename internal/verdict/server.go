// Copyright 2026 Jerry David Chan, Konareef.ai
// SPDX-License-Identifier: Apache-2.0

// server.go — the verdict demo HTTP server. It serves one embedded page and a
// single JSON endpoint that fetches a bundle, runs the REAL verifier, and
// returns the decoded evidence + verdict. It is an INDEPENDENT verifier
// (typically run on the presenter's laptop): it trusts reef-core only to hand
// over the 18 KB bundle bytes, and re-derives the verdict itself.
package verdict

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"
	"strings"

	"github.com/digitsu/konareef/internal/verify"
)

//go:embed page.html
var pageHTML []byte

// hashRe bounds the proof-hash query param to a 64-char hex string, so it
// cannot inject path segments into the reef-core bundle URL.
var hashRe = regexp.MustCompile(`^[0-9a-fA-F]{64}$`)

// Server renders live verdicts for konareef-bundle/v2 proofs.
type Server struct {
	// ReefcoreURL is the base URL bundles are fetched from
	// (e.g. http://reefcore-demo.tail6bed98.ts.net:4000).
	ReefcoreURL string
	// DefaultHash is the proof hash used when a request omits ?hash=.
	DefaultHash string
	// Durable threads the verify --durable knob through unchanged.
	Durable bool
}

// Routes returns the server's HTTP handler.
func (s *Server) Routes() *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("/", s.handleIndex)
	mux.HandleFunc("/api/verdict", s.handleVerdict)
	return mux
}

// handleIndex serves the embedded, self-contained verdict page.
func (s *Server) handleIndex(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write(pageHTML)
}

// handleVerdict fetches the bundle, runs the real verifier, decodes the
// disclosed evidence, and returns Evidence JSON. Failures are returned as a
// JSON {error} with an appropriate status so the page can show them.
func (s *Server) handleVerdict(w http.ResponseWriter, r *http.Request) {
	src, hash, label, err := s.resolveSource(r)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	raw, err := verify.ReadSource(src)
	if err != nil {
		writeErr(w, http.StatusBadGateway, fmt.Errorf("fetch bundle from %s: %w", label, err))
		return
	}
	// The real verdict: re-run CompressedSNARK::verify + all out-of-circuit
	// commitment checks. Requires a verifier: KONAREEF_VERIFY_BIN, else
	// konabeans on PATH (else fail-closed).
	res := verify.VerifyV2Production(raw, s.Durable)
	b, err := verify.DecodeBundleV2(raw)
	if err != nil {
		writeErr(w, http.StatusUnprocessableEntity, fmt.Errorf("decode bundle: %w", err))
		return
	}
	ev := BuildEvidence(b, res, hash, label)
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(w).Encode(ev)
}

// resolveSource turns the request into a bundle source (URL or local path),
// the proof hash (for display), and a human source label. A ?bundle= local
// path takes precedence (offline fallback); otherwise ?hash= (or DefaultHash)
// is fetched from ReefcoreURL.
func (s *Server) resolveSource(r *http.Request) (src, hash, label string, err error) {
	if bundle := r.URL.Query().Get("bundle"); bundle != "" {
		return bundle, "", "local file", nil
	}
	hash = r.URL.Query().Get("hash")
	if hash == "" {
		hash = s.DefaultHash
	}
	if hash == "" {
		return "", "", "", fmt.Errorf("no proof hash: pass ?hash=<64-hex> or start the server with --hash")
	}
	if !hashRe.MatchString(hash) {
		return "", "", "", fmt.Errorf("proof hash must be 64 hex chars")
	}
	if s.ReefcoreURL == "" {
		return "", "", "", fmt.Errorf("no reef-core URL configured: start the server with --server")
	}
	base := strings.TrimRight(s.ReefcoreURL, "/")
	return base + "/api/public/proofs/" + hash + "/bundle", hash, s.ReefcoreURL, nil
}

// writeErr emits a JSON error the page can surface.
func writeErr(w http.ResponseWriter, status int, err error) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
}
