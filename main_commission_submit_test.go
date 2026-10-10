// Copyright 2026 Jerry David Chan, Konareef.ai
// SPDX-License-Identifier: Apache-2.0

// Binary-level tests for the commission verbs that talk to reef-core:
// submit (and `pod run --commission`), key register, and revoke. As in
// main_commission_cli_test.go, every step uses the real binary and the
// real artifact `commission sign` writes. The server is an httptest server
// that answers as reef-core does; it records every request, so each test
// can prove that nothing reached an uncommissioned spawn route.
package main

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/digitsu/konareef/internal/commission"
	"github.com/digitsu/konareef/internal/identity"
)

// submitFake is a recording fake reef-core.
type submitFake struct {
	mu       sync.Mutex
	requests []submitRequest
	// commissionRoute answers POST /api/commissioned-runs.
	commissionRoute http.HandlerFunc
}

// submitRequest is one captured request.
type submitRequest struct {
	method, path string
	body         []byte
}

func (f *submitFake) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	f.mu.Lock()
	f.requests = append(f.requests, submitRequest{r.Method, r.URL.Path, body})
	f.mu.Unlock()
	switch {
	case r.Method == http.MethodPost && r.URL.Path == "/api/commissioned-runs":
		f.commissionRoute(w, r)
	case r.URL.Path == "/api/proofs":
		// reef-core#98: the collect step needs a completed run_outcome beside
		// the custody proof, or it fails closed.
		json.NewEncoder(w).Encode(map[string]any{"proofs": []map[string]any{
			{"proof_type": "run_outcome", "hash": "0utc0me", "data": "RUN_OUTCOME: v1\n{\"run_status\":\"completed\"}"},
			{"proof_type": "custody", "hash": "c0ffee"},
		}})
	case r.URL.Path == "/api/agents/agent-1/deliverables":
		json.NewEncoder(w).Encode(map[string]any{"deliverables": []any{}})
	default:
		http.NotFound(w, r)
	}
}

// posts returns the number of requests to path.
func (f *submitFake) posts(path string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	n := 0
	for _, r := range f.requests {
		if r.path == path {
			n++
		}
	}
	return n
}

// assertNoFallback fails if a request reached an uncommissioned spawn route.
func (f *submitFake) assertNoFallback(t *testing.T) {
	t.Helper()
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, r := range f.requests {
		if r.path == "/api/pods/spawn" || (r.method == http.MethodPost && r.path == "/api/agents") {
			t.Fatalf("fell back to %s %s", r.method, r.path)
		}
	}
}

// signedCommissionFixture drives draft → edit → sign through the binary
// and returns the paths of the proposal and the signed artifact.
func signedCommissionFixture(t *testing.T, bin, home string) (proposalPath, commissionPath string) {
	t.Helper()
	work := t.TempDir()
	proposalPath = filepath.Join(work, "proposal.toml")
	commissionPath = filepath.Join(work, "commission.cbor")
	draft := runCommissionCLI(t, bin, home, "commission", "draft", "dave/mybot@0.1.0", "--pod-dir", writeSamplePodDir(t))
	if draft.code != 0 {
		t.Fatalf("draft: %s", draft.combined())
	}
	edited := strings.Replace(draft.stdout, `prose = ""`, `prose = "Summarise the weekly reports."`, 1)
	if err := os.WriteFile(proposalPath, []byte(edited), 0o644); err != nil {
		t.Fatal(err)
	}
	sign := runCommissionCLI(t, bin, home, "commission", "sign", proposalPath, "--confirm-commission", "-o", commissionPath)
	if sign.code != 0 {
		t.Fatalf("sign: %s", sign.combined())
	}
	return proposalPath, commissionPath
}

// receiptForArtifact builds the 201 body reef-core returns for the signed
// artifact at path.
func receiptForArtifact(t *testing.T, path string) map[string]any {
	t.Helper()
	c, err := loadAndVerifyCommission(path)
	if err != nil {
		t.Fatal(err)
	}
	p := c.Proposal()
	h, _ := c.HCommissionHex()
	return map[string]any{
		"agent_id": "agent-1", "pod_id": "pod-1", "task_id": "t", "snapshot_id": "s", "bundle_hash": "b", "bundle_file_count": 1,
		"receipt": map[string]any{
			"receipt_id": "r-1", "contract": commission.AdmissionContractV1, "assurance_mode": commission.AssuranceModeLimitedV1,
			"h_commission": h, "signer_pubkey": c.PubKeyHex, "pod_ref": p.Binding.PodRef,
			"pod_hash": hex.EncodeToString(p.Binding.HManifest[:]), "memory_class": "rinit_v1",
			"derived":    map[string]any{"models": p.Envelope.Models, "tools": p.Envelope.Tools, "c_max_sats": p.Envelope.CMax},
			"effective":  map[string]any{"model_id": p.Envelope.Models[0], "budget_sats": p.Envelope.CMax},
			"dimensions": map[string]string{"labels": "not_evaluated"}, "inputs": "not_buyer_signed",
			"authenticity": "api_session_only", "run_state": "started",
		},
	}
}

// TestCommissionSubmitCLI covers the command end to end: the confirmation
// gate, an unsigned proposal, the accepted run, a refusal, a server without
// the route, and `pod run --commission` with a matching and a conflicting
// pod reference.
func TestCommissionSubmitCLI(t *testing.T) {
	bin := buildGateCLI(t)
	home := commissionCLIHome(t, bin)
	proposalPath, commissionPath := signedCommissionFixture(t, bin, home)
	out := t.TempDir()
	accepted := func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(receiptForArtifact(t, commissionPath))
	}
	start := func(route http.HandlerFunc) (*submitFake, string) {
		fake := &submitFake{commissionRoute: route}
		srv := httptest.NewServer(fake)
		t.Cleanup(srv.Close)
		return fake, srv.URL
	}
	submit := func(url string, args ...string) commissionCLIResult {
		base := []string{"--server", url, "--token", "dG9rZW4=", "--out", out}
		return runCommissionCLI(t, bin, home, append(args, base...)...)
	}

	t.Run("no confirmation, no terminal: refused before any request", func(t *testing.T) {
		fake, url := start(accepted)
		res := submit(url, "commission", "submit", commissionPath)
		if res.code != exitNotConfirmed || fake.posts("/api/commissioned-runs") != 0 {
			t.Fatalf("exit %d, %d posts\n%s", res.code, fake.posts("/api/commissioned-runs"), res.combined())
		}
		if !strings.Contains(res.stderr, "--confirm-spend") || !strings.Contains(res.stderr, "does NOT evaluate labels") {
			t.Fatalf("the refusal must name the flag and the mode's limits:\n%s", res.stderr)
		}
	})

	t.Run("an unsigned proposal is never submitted", func(t *testing.T) {
		fake, url := start(accepted)
		res := submit(url, "commission", "submit", proposalPath, "--confirm-spend")
		if res.code != 1 || len(fake.requests) != 0 {
			t.Fatalf("exit %d, %d requests\n%s", res.code, len(fake.requests), res.combined())
		}
		if !strings.Contains(res.stderr, "not a verified signed commission") {
			t.Fatalf("stderr:\n%s", res.stderr)
		}
	})

	t.Run("accepted", func(t *testing.T) {
		fake, url := start(accepted)
		res := submit(url, "commission", "submit", commissionPath, "--confirm-spend", "--input", "week=38")
		if res.code != 0 {
			t.Fatalf("exit %d\n%s", res.code, res.combined())
		}
		for _, want := range []string{"signature valid:   yes", "locally contained: not_checked", "server admitted:   yes, new run", "executed:          started", "proof verified:    no"} {
			if !strings.Contains(res.stdout, want) {
				t.Errorf("stdout lacks %q:\n%s", want, res.stdout)
			}
		}
		fake.assertNoFallback(t)
		// The body carries the artifact's exact signed bytes.
		c, _ := loadAndVerifyCommission(commissionPath)
		wire, _ := commission.EncodeWireV1(c)
		var body struct {
			Commission string            `json:"commission"`
			Inputs     map[string]string `json:"inputs"`
		}
		for _, r := range fake.requests {
			if r.path == "/api/commissioned-runs" {
				json.Unmarshal(r.body, &body)
			}
		}
		if body.Commission != base64.StdEncoding.EncodeToString(wire) || body.Inputs["week"] != "38" {
			t.Fatalf("body = %+v", body)
		}
	})

	t.Run("a server refusal keeps its code and has its own exit status", func(t *testing.T) {
		fake, url := start(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusForbidden)
			w.Write([]byte(`{"error":{"kind":"commission_signer_unregistered","message":"commission refused: commission_signer_unregistered"}}`))
		})
		res := submit(url, "commission", "submit", commissionPath, "--confirm-spend")
		if res.code != exitServerRefused {
			t.Fatalf("exit %d, want %d\n%s", res.code, exitServerRefused, res.combined())
		}
		if !strings.Contains(res.stderr, "http 403: commission_signer_unregistered") || !strings.Contains(res.stderr, "commission key register") {
			t.Fatalf("stderr:\n%s", res.stderr)
		}
		if fake.posts("/api/commissioned-runs") != 1 {
			t.Fatal("a refusal was retried")
		}
		fake.assertNoFallback(t)
	})

	t.Run("a server without the route fails with its own exit status", func(t *testing.T) {
		fake, url := start(func(w http.ResponseWriter, r *http.Request) { http.NotFound(w, r) })
		res := submit(url, "commission", "submit", commissionPath, "--confirm-spend")
		if res.code != exitServerUnsupported || !strings.Contains(res.stderr, "predates signed commissions") {
			t.Fatalf("exit %d\n%s", res.code, res.combined())
		}
		fake.assertNoFallback(t)
	})

	t.Run("pod run --commission with the signed pod reference", func(t *testing.T) {
		fake, url := start(accepted)
		res := submit(url, "pod", "run", "dave/mybot@0.1.0", "--commission", commissionPath, "--confirm-spend")
		if res.code != 0 || fake.posts("/api/commissioned-runs") != 1 {
			t.Fatalf("exit %d\n%s", res.code, res.combined())
		}
		fake.assertNoFallback(t)
	})

	t.Run("a --commission after -- is not dropped (review B1)", func(t *testing.T) {
		fake, url := start(accepted)
		res := runCommissionCLI(t, bin, home, "pod", "run", "--server", url, "--token", "dG9rZW4=", "--out", out,
			"--confirm-spend", "--", "dave/mybot@0.1.0", "--commission", commissionPath)
		if res.code != 2 || len(fake.requests) != 0 {
			t.Fatalf("exit %d, %d requests\n%s", res.code, len(fake.requests), res.combined())
		}
	})

	t.Run("pod run refuses extra positional words", func(t *testing.T) {
		fake, url := start(accepted)
		res := runCommissionCLI(t, bin, home, "pod", "run", "--server", url, "--token", "dG9rZW4=", "--out", out,
			"--confirm-spend", "--", "dave/mybot@0.1.0", "extra")
		if res.code != 2 || len(fake.requests) != 0 {
			t.Fatalf("exit %d, %d requests\n%s", res.code, len(fake.requests), res.combined())
		}
	})

	t.Run("a 401 without a code is a refusal, not a transport failure (review M1)", func(t *testing.T) {
		fake, url := start(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusUnauthorized)
			w.Write([]byte(`{"error":"invalid_session"}`))
		})
		res := submit(url, "commission", "submit", commissionPath, "--confirm-spend")
		if res.code != exitServerRefused || fake.posts("/api/commissioned-runs") != 1 {
			t.Fatalf("exit %d, %d posts\n%s", res.code, fake.posts("/api/commissioned-runs"), res.combined())
		}
		if !strings.Contains(res.stderr, "invalid_session") || !strings.Contains(res.stderr, "session token was not accepted") {
			t.Fatalf("stderr:\n%s", res.stderr)
		}
	})

	t.Run("pod run --commission cannot retarget the signed pod", func(t *testing.T) {
		fake, url := start(accepted)
		res := submit(url, "pod", "run", "dave/otherbot@0.1.0", "--commission", commissionPath, "--confirm-spend")
		if res.code != 2 || len(fake.requests) != 0 {
			t.Fatalf("exit %d, %d requests\n%s", res.code, len(fake.requests), res.combined())
		}
		if !strings.Contains(res.stderr, "cannot change it") {
			t.Fatalf("stderr:\n%s", res.stderr)
		}
	})
}

// TestCommissionKeyRegisterCLI registers the local identity's key: the
// server receives the §6.1 proof of possession, which verifies over
// SHA-256 of the registration message.
func TestCommissionKeyRegisterCLI(t *testing.T) {
	bin := buildGateCLI(t)
	home := commissionCLIHome(t, bin)
	id, err := identity.Load(home)
	if err != nil {
		t.Fatal(err)
	}
	account := "0f1e2d3c-4b5a-4978-8695-a4b3c2d1e0f9"
	challenge := strings.Repeat("cd", 32)
	var mu sync.Mutex
	var registered struct {
		Pubkey, Challenge, Signature string
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/api/commission-keys/challenge":
			json.NewEncoder(w).Encode(map[string]string{"challenge": challenge, "expires_at": "2026-09-25T00:05:00Z"})
		case r.Method == http.MethodPost && r.URL.Path == "/api/commission-keys":
			mu.Lock()
			defer mu.Unlock()
			json.NewDecoder(r.Body).Decode(&registered)
			w.WriteHeader(http.StatusCreated)
			json.NewEncoder(w).Encode(map[string]any{"key_id": "k-1", "pubkey": registered.Pubkey, "registered_at": "2026-09-25T00:00:00Z", "retired_at": nil})
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	refused := runCommissionCLI(t, bin, home, "commission", "key", "register", "--account", account, "--server", srv.URL, "--token", "dG9rZW4=")
	mu.Lock()
	gotPubkey := registered.Pubkey
	mu.Unlock()
	if refused.code != exitNotConfirmed || gotPubkey != "" {
		t.Fatalf("without --confirm-key-register: exit %d\n%s", refused.code, refused.combined())
	}

	res := runCommissionCLI(t, bin, home, "commission", "key", "register", "--account", account,
		"--server", srv.URL, "--token", "dG9rZW4=", "--confirm-key-register")
	if res.code != 0 || !strings.Contains(res.stdout, "k-1") {
		t.Fatalf("exit %d\n%s", res.code, res.combined())
	}
	mu.Lock()
	defer mu.Unlock()
	if registered.Pubkey != id.PublicKeyHex || registered.Challenge != challenge {
		t.Fatalf("registered %+v", registered)
	}
	msg := "konareef-commission-key-registration/v1\n" + account + "\n" + id.PublicKeyHex + "\n" + challenge
	digest := sha256.Sum256([]byte(msg))
	sig, _ := hex.DecodeString(registered.Signature)
	if ok, err := identity.VerifyDigest(id.PublicKeyHex, digest[:], sig); !ok || err != nil {
		t.Fatalf("the proof of possession does not verify: %v", err)
	}
}

// TestCommissionRevokeCLI sends exactly the signed wire bytes and the
// contract, and nothing else.
func TestCommissionRevokeCLI(t *testing.T) {
	bin := buildGateCLI(t)
	home := commissionCLIHome(t, bin)
	_, commissionPath := signedCommissionFixture(t, bin, home)
	var body map[string]string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/commissions/revoke" || r.Header.Get("Content-Type") != "application/json" {
			http.NotFound(w, r)
			return
		}
		json.NewDecoder(r.Body).Decode(&body)
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(map[string]string{"h_commission": "ab", "state": "revoked"})
	}))
	defer srv.Close()

	res := runCommissionCLI(t, bin, home, "commission", "revoke", commissionPath, "--server", srv.URL, "--token", "dG9rZW4=", "--confirm-revoke")
	if res.code != 0 || !strings.Contains(res.stdout, "revoked") {
		t.Fatalf("exit %d\n%s", res.code, res.combined())
	}
	c, _ := loadAndVerifyCommission(commissionPath)
	wire, _ := commission.EncodeWireV1(c)
	if len(body) != 2 || body["contract"] != commission.AdmissionContractV1 || body["commission"] != base64.StdEncoding.EncodeToString(wire) {
		t.Fatalf("body = %v", body)
	}
}

// TestHasCommissionFlag checks the `pod run` hand-over detection.
func TestHasCommissionFlag(t *testing.T) {
	for args, want := range map[string]bool{
		"dave/x@1 --commission c.cbor": true,
		"--commission=c.cbor":          true,
		"-commission c.cbor":           true,
		"dave/x@1 --out d":             false,
		"--input commission=x":         false,
		"-- --commission c":            true,
	} {
		if got := hasCommissionFlag(strings.Fields(args)); got != want {
			t.Errorf("hasCommissionFlag(%q) = %v, want %v", args, got, want)
		}
	}
}
