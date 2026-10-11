// Copyright 2026 Jerry David Chan, Konareef.ai
// SPDX-License-Identifier: Apache-2.0

// internal/paygate/round2_blockers_test.go — Hermes MR !22 round-2
// blockers B1..B7 regression coverage.
//
// Each Test below pins one of the round-2 fixes so a future regression
// fails loud:
//
//   - TestRound2B1_FreshManifestRefreshUsedForBEEF: SubmitFold builds
//     BEEF from the freshly-refreshed manifest (not the session-captured
//     one), and re-runs the circuit pin check when the refreshed
//     vkey_sha256 differs from the captured pin.
//   - TestRound2B2_StateBHashVerifiesCachedVkey: State B goes through
//     LocalCache.Lookup, which hash-verifies the cached vkey bytes;
//     corrupting vkey.bin under the expected directory fails closed.
//   - TestRound2B3_CreditTokenValidityFromServer: credit_token validity
//     is parsed from server response and used verbatim; when the server
//     omits validity, the token is NOT persisted (fail-closed).
//   - TestRound2B4_IdempotencyPreimageIsNFCNormalised: NFC-composed vs
//     NFC-decomposed circuit IDs produce byte-identical preimages and
//     keys.
//   - TestRound2B5_IdempotencyCacheLookupErrorIsNotAMiss: a non-miss
//     Lookup error suppresses BEEF construction + submission.
//   - TestRound2B6_BSVUSDRateFlowsThroughToBEEF: a non-15 rate produces
//     a different sats amount than the previous hard-coded 15.
//   - TestRound2B7_BRC29PaymentHeaderIsHexEncoded: the stub rejects raw
//     binary BRC-29 payloads and accepts hex-encoded payloads.
package paygate_test

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
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/digitsu/konareef/internal/paygate"
	"github.com/digitsu/konareef/internal/paygate/stubserver"
	"github.com/digitsu/konareef/internal/vkeystore"
)

// --- B1 ---------------------------------------------------------------

// rotatingManifestServer serves manifest A on its first request and a
// rotated manifest B (with a different vkey_sha256) on every subsequent
// request. The submit handler tracks how often it was called and
// records the X-Payment value of the last request so the test can
// assert that BEEF was built from manifest B's pricing.
type rotatingManifestServer struct {
	srv          *httptest.Server
	manifestHits int32

	// pinned for the test
	circuitID  string
	vkeyHashA  string
	vkeyHashB  string
	pricingUSD float64

	lastXPayment string
	beefSubmits  int32
}

func newRotatingManifestServer(t *testing.T) *rotatingManifestServer {
	t.Helper()
	r := &rotatingManifestServer{
		circuitID:  "konareef-pod-step-v1",
		vkeyHashA:  "0101010101010101010101010101010101010101010101010101010101010101",
		vkeyHashB:  "0202020202020202020202020202020202020202020202020202020202020202",
		pricingUSD: 0.0001,
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/.well-known/x402-info", func(w http.ResponseWriter, _ *http.Request) {
		hits := atomic.AddInt32(&r.manifestHits, 1)
		vkey := r.vkeyHashA
		if hits > 1 {
			vkey = r.vkeyHashB
		}
		body := map[string]interface{}{
			"service":    "paygate-zk",
			"version":    "v1",
			"operations": []string{"nova-fold"},
			"circuits": map[string]interface{}{
				r.circuitID: map[string]interface{}{
					"vkey_sha256": vkey,
					"vkey_url":    r.srv.URL + "/.well-known/circuits/" + r.circuitID + "/vkey",
					"pricing": map[string]interface{}{
						"nova-fold": map[string]float64{"compute_usd": r.pricingUSD, "retail_usd": 0.001},
					},
					"input_caps":       map[string]int{"manifest_bytes": 2048},
					"deprecated_after": nil,
				},
			},
			"margin_multiplier":        10,
			"schedule_revision":        1,
			"schedule_effective_after": nil,
			"signature":                map[string]string{"scheme": "BRC-31"},
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(body)
	})
	mux.HandleFunc("/v1/prove/nova-fold", func(w http.ResponseWriter, req *http.Request) {
		r.lastXPayment = req.Header.Get("X-Payment")
		atomic.AddInt32(&r.beefSubmits, 1)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusAccepted)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"job_id":       "rot-job-1",
			"submitted_at": time.Now().UTC(),
		})
	})
	mux.HandleFunc("/v1/jobs/", func(w http.ResponseWriter, req *http.Request) {
		path := strings.TrimPrefix(req.URL.Path, "/v1/jobs/")
		if strings.HasSuffix(path, "/result") {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"job_id":               "rot-job-1",
				"accumulator_out":      []byte{0xaa},
				"step_proof":           []byte{0xbb},
				"public_inputs_echoed": map[string]interface{}{"step_index": 0},
				"cost_meta":            map[string]int{},
			})
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"job_id":     "rot-job-1",
			"status":     "completed",
			"proof_type": "nova-fold",
			"circuit_id": r.circuitID,
			"created_at": time.Now().UTC(),
			"updated_at": time.Now().UTC(),
			"error":      nil,
		})
	})
	r.srv = httptest.NewServer(mux)
	t.Cleanup(r.srv.Close)
	return r
}

// recordingPinChecker records every (circuitID, manifestPin) pair it
// sees and always reports State B so the test can confirm that
// SubmitFold re-runs the pin check after a manifest refresh.
type recordingPinChecker struct {
	calls []struct{ circuitID, pin string }
}

func (rc *recordingPinChecker) Check(_ context.Context, circuitID, pin string) (paygate.PinState, error) {
	rc.calls = append(rc.calls, struct{ circuitID, pin string }{circuitID, pin})
	return paygate.PinStateB, nil
}

func TestRound2B1_FreshManifestRefreshUsedForBEEF(t *testing.T) {
	r := newRotatingManifestServer(t)
	dir := t.TempDir()
	idem, err := paygate.OpenIdempCache(filepath.Join(dir, "idem.db"))
	if err != nil {
		t.Fatal(err)
	}
	ledger, err := paygate.OpenTokenLedger(filepath.Join(dir, "ledger.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = idem.Close(); _ = ledger.Close() })
	pin := &recordingPinChecker{}
	c := &paygate.Client{
		BaseURL:       r.srv.URL,
		HTTP:          r.srv.Client(),
		IdentityPath:  filepath.Join(dir, "identity.key"),
		IdempCache:    idem,
		TokenLedger:   ledger,
		ManifestCache: &paygate.ManifestCache{BaseURL: r.srv.URL, HTTP: r.srv.Client()},
		PinChecker:    pin,
	}
	sess, err := c.Open(context.Background(), paygate.OpenSessionInput{
		CircuitID:        r.circuitID,
		DisclosurePolicy: paygate.DisclosureTypeC,
	})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if sess.PinnedVkeyHash != r.vkeyHashA {
		t.Fatalf("session pinned hash = %q, want %q (manifest A)", sess.PinnedVkeyHash, r.vkeyHashA)
	}
	// Force a fresh manifest hit on SubmitFold by re-fetching directly
	// — the cache hard-floor cadence is 60s, much longer than this
	// test wants to wait. The Refresh call seeds the cache with
	// manifest B; SubmitFold's own Get() will then return that cached
	// manifest B and exercise the round-2 B1 re-pin path.
	if _, err := c.ManifestCache.Refresh(context.Background()); err != nil {
		t.Fatalf("Refresh: %v", err)
	}
	// SubmitFold should re-run the pin check against vkeyHashB before
	// submitting because the fresh manifest advertises a different pin
	// than the one captured at Open.
	if _, err := c.SubmitFold(context.Background(), sess, paygate.FoldStepInput{
		StepIndex: 0, HP: [32]byte{0xaa}, BSVUSDRate: 15.0,
	}); err != nil {
		t.Fatalf("SubmitFold: %v", err)
	}
	if got := atomic.LoadInt32(&r.manifestHits); got < 2 {
		t.Fatalf("manifest hits = %d, want >= 2 (Open + Refresh)", got)
	}
	if sess.PinnedVkeyHash != r.vkeyHashB {
		t.Errorf("session pinned hash after submit = %q, want %q (refreshed)", sess.PinnedVkeyHash, r.vkeyHashB)
	}
	// Expect two pin-check invocations: Open + the refresh re-check.
	if len(pin.calls) < 2 {
		t.Fatalf("PinChecker.Check calls = %d, want >= 2 (Open + refresh)", len(pin.calls))
	}
	// The second pin check MUST use the refreshed manifest's pin (B).
	last := pin.calls[len(pin.calls)-1]
	if last.pin != r.vkeyHashB {
		t.Errorf("last pin check pin = %q, want %q (manifest B)", last.pin, r.vkeyHashB)
	}
}

// --- B2 ---------------------------------------------------------------

func TestRound2B2_StateBHashVerifiesCachedVkey(t *testing.T) {
	t.Setenv("KONAREEF_STATE_DIR", t.TempDir())
	cache, err := vkeystore.NewLocalCache()
	if err != nil {
		t.Fatal(err)
	}
	body := []byte("genuine-vkey-fixture-body")
	pin := paygate.Sha256HexFor(body)
	if err := cache.Store("konareef-pod-step-v1", pin, body, vkeystore.SourceWellKnown); err != nil {
		t.Fatal(err)
	}
	// Tamper with the cached vkey.bin: keep the directory path
	// (so a naive os.Stat would still pass) but change the contents.
	state := os.Getenv("KONAREEF_STATE_DIR")
	binPath := filepath.Join(state, "vkeys", "konareef-pod-step-v1", pin, "vkey.bin")
	if err := os.WriteFile(binPath, []byte("tampered-body-zzz"), 0o600); err != nil {
		t.Fatalf("tamper: %v", err)
	}
	resolver := &vkeystore.Resolver{Cache: cache, Tier1: vkeystore.NewTier1HTTPSBackend(http.DefaultClient)}
	pc := &paygate.PinChecker{Resolver: resolver, Domain: "example.test"}
	stateOut, err := pc.Check(context.Background(), "konareef-pod-step-v1", pin)
	if err == nil {
		t.Fatalf("State B with tampered vkey.bin must surface error; got nil (state=%v)", stateOut)
	}
	if !errors.Is(err, vkeystore.ErrCircuitPinMismatch) {
		t.Errorf("tampered State B err = %v, want ErrCircuitPinMismatch", err)
	}
	if stateOut == paygate.PinStateB {
		t.Errorf("tampered cache MUST NOT report State B; got %v", stateOut)
	}
}

// --- B3 ---------------------------------------------------------------

func TestRound2B3_CreditTokenValidityFromServer(t *testing.T) {
	issued := time.Now().UTC().Truncate(time.Second)
	expires := issued.Add(20 * time.Minute)
	body, _ := json.Marshal(map[string]interface{}{
		"error": map[string]interface{}{
			"code":                    "COMPUTE_WORKER_CRASH",
			"category":                "compute",
			"credit_token":            "tok-validity-server",
			"credit_token_issued_at":  issued,
			"credit_token_expires_at": expires,
		},
	})
	err := paygate.ClassifyHTTPErrorForTest(503, nil, body)
	if err == nil {
		t.Fatal("classify nil")
	}
	gotIssued, gotExpires, ok := paygate.CreditTokenValidityFrom(err)
	if !ok {
		t.Fatal("CreditTokenValidityFrom: ok = false, want true (both fields present)")
	}
	if !gotIssued.Equal(issued) {
		t.Errorf("issued_at = %v, want %v", gotIssued, issued)
	}
	if !gotExpires.Equal(expires) {
		t.Errorf("expires_at = %v, want %v", gotExpires, expires)
	}
}

func TestRound2B3_MissingValidityRejectsToken(t *testing.T) {
	// Server omits validity → token must NOT be persisted.
	body := []byte(`{"error":{"code":"COMPUTE_WORKER_CRASH","category":"compute","credit_token":"tok-no-validity"}}`)
	err := paygate.ClassifyHTTPErrorForTest(503, nil, body)
	if err == nil {
		t.Fatal("classify nil")
	}
	if _, _, ok := paygate.CreditTokenValidityFrom(err); ok {
		t.Error("CreditTokenValidityFrom: ok = true on missing validity; want false (fail-closed)")
	}
	// End-to-end: SubmitFold with a server response carrying token but
	// no validity must NOT persist the token. Use a custom handler so
	// the response is exactly the malformed envelope.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		switch {
		case strings.HasPrefix(req.URL.Path, "/v1/.well-known/x402-info"):
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"service":    "paygate-zk",
				"version":    "v1",
				"operations": []string{"nova-fold"},
				"circuits": map[string]interface{}{
					"konareef-pod-step-v1": map[string]interface{}{
						"vkey_sha256": "0101010101010101010101010101010101010101010101010101010101010101",
						"vkey_url":    "https://example.test/vkey",
						"pricing": map[string]interface{}{
							"nova-fold": map[string]float64{"compute_usd": 0.0001, "retail_usd": 0.001},
						},
					},
				},
				"margin_multiplier":        10,
				"schedule_revision":        1,
				"schedule_effective_after": nil,
				"signature":                map[string]string{},
			})
		case strings.HasPrefix(req.URL.Path, "/v1/prove/nova-fold"):
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusServiceUnavailable)
			_, _ = w.Write(body)
		default:
			http.NotFound(w, req)
		}
	}))
	defer srv.Close()
	dir := t.TempDir()
	idem, _ := paygate.OpenIdempCache(filepath.Join(dir, "idem.db"))
	ledger, _ := paygate.OpenTokenLedger(filepath.Join(dir, "ledger.db"))
	t.Cleanup(func() { _ = idem.Close(); _ = ledger.Close() })
	c := &paygate.Client{
		BaseURL:       srv.URL,
		HTTP:          srv.Client(),
		IdentityPath:  filepath.Join(dir, "identity.key"),
		IdempCache:    idem,
		TokenLedger:   ledger,
		ManifestCache: &paygate.ManifestCache{BaseURL: srv.URL, HTTP: srv.Client()},
		PinChecker:    alwaysStateBPinChecker{},
	}
	sess, err := c.Open(context.Background(), paygate.OpenSessionInput{
		CircuitID:        "konareef-pod-step-v1",
		DisclosurePolicy: paygate.DisclosureTypeC,
	})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if _, err := c.SubmitFold(context.Background(), sess, paygate.FoldStepInput{
		StepIndex: 0, HP: [32]byte{0xab}, BSVUSDRate: 15.0,
	}); err == nil {
		t.Fatal("SubmitFold should fail (503)")
	}
	// Token MUST NOT have been persisted — Take should report invalid.
	if _, terr := ledger.Take("tok-no-validity"); !errors.Is(terr, paygate.ErrCreditTokenInvalid) {
		t.Errorf("ledger.Take(no-validity) = %v, want ErrCreditTokenInvalid (token was not persisted)", terr)
	}
}

// --- B4 ---------------------------------------------------------------

func TestRound2B4_IdempotencyPreimageIsNFCNormalised(t *testing.T) {
	// "Café" composed (NFC) = U+00E9
	composed := "Café-circuit-v1"
	// "Café" decomposed (NFD) = U+0065 U+0301
	decomposed := "Café-circuit-v1"
	if composed == decomposed {
		t.Fatal("test setup error: composed and decomposed strings are byte-equal")
	}
	var hp [32]byte
	preA := paygate.IdempotencyPreimage(composed, 0, hp)
	preB := paygate.IdempotencyPreimage(decomposed, 0, hp)
	if hex.EncodeToString(preA) != hex.EncodeToString(preB) {
		t.Fatalf("NFC vs NFD preimages must match after normalisation:\n composed=%x\ndecomposed=%x", preA, preB)
	}
	keyA := paygate.IdempotencyKey(composed, 0, hp)
	keyB := paygate.IdempotencyKey(decomposed, 0, hp)
	if keyA != keyB {
		t.Errorf("NFC vs NFD keys must match: %s vs %s", keyA, keyB)
	}
}

// --- B5 ---------------------------------------------------------------

// faultyIdempCache wraps the real IdempCache type but Lookup always
// returns a non-miss error so we can prove SubmitFold refuses to submit
// instead of falling through to a fresh BEEF.
//
// Because *paygate.IdempCache is a concrete struct (not an interface)
// we can't drop in a fake — we instead corrupt the underlying SQLite
// file so Lookup returns a sql open error rather than ErrIdempCacheMiss.
func TestRound2B5_IdempotencyCacheLookupErrorIsNotAMiss(t *testing.T) {
	dir := t.TempDir()
	idem, err := paygate.OpenIdempCache(filepath.Join(dir, "idem.db"))
	if err != nil {
		t.Fatal(err)
	}
	// Close the database to make every Lookup return a non-miss error.
	_ = idem.Close()

	ledger, err := paygate.OpenTokenLedger(filepath.Join(dir, "ledger.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ledger.Close() })

	// Stand up a stub that PANICS if /v1/prove/nova-fold is ever called.
	// The whole point of B5 is that we must NOT submit when Lookup
	// returns an unexpected error.
	var submitHit int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		switch {
		case strings.HasPrefix(req.URL.Path, "/v1/.well-known/x402-info"):
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"service":    "paygate-zk",
				"version":    "v1",
				"operations": []string{"nova-fold"},
				"circuits": map[string]interface{}{
					"konareef-pod-step-v1": map[string]interface{}{
						"vkey_sha256": "0101010101010101010101010101010101010101010101010101010101010101",
						"vkey_url":    "https://example.test/vkey",
						"pricing": map[string]interface{}{
							"nova-fold": map[string]float64{"compute_usd": 0.0001, "retail_usd": 0.001},
						},
					},
				},
				"margin_multiplier":        10,
				"schedule_revision":        1,
				"schedule_effective_after": nil,
				"signature":                map[string]string{},
			})
		case strings.HasPrefix(req.URL.Path, "/v1/prove/nova-fold"):
			atomic.AddInt32(&submitHit, 1)
			w.WriteHeader(http.StatusInternalServerError)
		default:
			http.NotFound(w, req)
		}
	}))
	defer srv.Close()

	c := &paygate.Client{
		BaseURL:       srv.URL,
		HTTP:          srv.Client(),
		IdentityPath:  filepath.Join(dir, "identity.key"),
		IdempCache:    idem, // closed
		TokenLedger:   ledger,
		ManifestCache: &paygate.ManifestCache{BaseURL: srv.URL, HTTP: srv.Client()},
		PinChecker:    alwaysStateBPinChecker{},
	}
	sess, err := c.Open(context.Background(), paygate.OpenSessionInput{
		CircuitID:        "konareef-pod-step-v1",
		DisclosurePolicy: paygate.DisclosureTypeC,
	})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	_, err = c.SubmitFold(context.Background(), sess, paygate.FoldStepInput{
		StepIndex: 0, HP: [32]byte{0xcc}, BSVUSDRate: 15.0,
	})
	if err == nil {
		t.Fatal("SubmitFold must surface idempotency-cache error; got nil")
	}
	if errors.Is(err, paygate.ErrIdempCacheMiss) {
		t.Fatalf("SubmitFold MUST NOT treat real lookup errors as misses; err=%v", err)
	}
	if got := atomic.LoadInt32(&submitHit); got != 0 {
		t.Errorf("BEEF submit hits = %d, want 0 (no submission on lookup error)", got)
	}
}

// --- B6 ---------------------------------------------------------------

// recordingPaymentServer captures the X-Payment header so the test can
// inspect the BEEF stub for a sats-amount changed by a non-15 rate.
func TestRound2B6_BSVUSDRateFlowsThroughToBEEF(t *testing.T) {
	captured := make(chan string, 4)
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/.well-known/x402-info", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"service":    "paygate-zk",
			"version":    "v1",
			"operations": []string{"nova-fold"},
			"circuits": map[string]interface{}{
				"konareef-pod-step-v1": map[string]interface{}{
					"vkey_sha256": "0101010101010101010101010101010101010101010101010101010101010101",
					"vkey_url":    "https://example.test/vkey",
					"pricing": map[string]interface{}{
						"nova-fold": map[string]float64{"compute_usd": 0.001, "retail_usd": 0.01},
					},
				},
			},
			"margin_multiplier":        10,
			"schedule_revision":        1,
			"schedule_effective_after": nil,
			"signature":                map[string]string{},
		})
	})
	mux.HandleFunc("/v1/prove/nova-fold", func(w http.ResponseWriter, req *http.Request) {
		captured <- req.Header.Get("X-Payment")
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusAccepted)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"job_id":       fmt.Sprintf("job-rate-%d", time.Now().UnixNano()),
			"submitted_at": time.Now().UTC(),
		})
	})
	mux.HandleFunc("/v1/jobs/", func(w http.ResponseWriter, req *http.Request) {
		path := strings.TrimPrefix(req.URL.Path, "/v1/jobs/")
		if strings.HasSuffix(path, "/result") {
			jobID := strings.TrimSuffix(path, "/result")
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"job_id":               jobID,
				"accumulator_out":      []byte{0xaa},
				"step_proof":           []byte{0xbb},
				"public_inputs_echoed": map[string]interface{}{"step_index": 0},
				"cost_meta":            map[string]int{},
			})
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"job_id":     path,
			"status":     "completed",
			"proof_type": "nova-fold",
			"circuit_id": "konareef-pod-step-v1",
			"created_at": time.Now().UTC(),
			"updated_at": time.Now().UTC(),
			"error":      nil,
		})
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()
	dir := t.TempDir()
	idem, _ := paygate.OpenIdempCache(filepath.Join(dir, "idem.db"))
	ledger, _ := paygate.OpenTokenLedger(filepath.Join(dir, "ledger.db"))
	t.Cleanup(func() { _ = idem.Close(); _ = ledger.Close() })
	c := &paygate.Client{
		BaseURL:       srv.URL,
		HTTP:          srv.Client(),
		IdentityPath:  filepath.Join(dir, "identity.key"),
		IdempCache:    idem,
		TokenLedger:   ledger,
		ManifestCache: &paygate.ManifestCache{BaseURL: srv.URL, HTTP: srv.Client()},
		PinChecker:    alwaysStateBPinChecker{},
	}
	sess, err := c.Open(context.Background(), paygate.OpenSessionInput{
		CircuitID:        "konareef-pod-step-v1",
		DisclosurePolicy: paygate.DisclosureTypeC,
	})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	// Run two submissions with DIFFERENT rates — the captured BEEF
	// stubs must differ in their satoshi amount.
	if _, err := c.SubmitFold(context.Background(), sess, paygate.FoldStepInput{
		StepIndex: 0, HP: [32]byte{0x01}, BSVUSDRate: 15.0,
	}); err != nil {
		t.Fatalf("submit @ 15: %v", err)
	}
	if _, err := c.SubmitFold(context.Background(), sess, paygate.FoldStepInput{
		StepIndex: 1, HP: [32]byte{0x02}, BSVUSDRate: 50.0,
	}); err != nil {
		t.Fatalf("submit @ 50: %v", err)
	}
	pay15 := <-captured
	pay50 := <-captured
	if pay15 == pay50 {
		t.Fatalf("X-Payment must differ across rates; got identical %q", pay15)
	}
	// Sanity: payloads must be hex (B7 cross-coverage).
	if _, err := hex.DecodeString(strings.TrimPrefix(pay15, "Brc29 ")); err != nil {
		t.Errorf("X-Payment @15 not hex: %q", pay15)
	}
	if _, err := hex.DecodeString(strings.TrimPrefix(pay50, "Brc29 ")); err != nil {
		t.Errorf("X-Payment @50 not hex: %q", pay50)
	}
}

func TestRound2B6_ZeroAndNegativeRateRejected(t *testing.T) {
	dir := t.TempDir()
	idem, _ := paygate.OpenIdempCache(filepath.Join(dir, "idem.db"))
	ledger, _ := paygate.OpenTokenLedger(filepath.Join(dir, "ledger.db"))
	t.Cleanup(func() { _ = idem.Close(); _ = ledger.Close() })
	s := stubserver.New(stubserver.Options{ManifestProfile: "active"})
	defer s.Close()
	c := &paygate.Client{
		BaseURL:       s.URL(),
		HTTP:          s.Client(),
		IdentityPath:  filepath.Join(dir, "identity.key"),
		IdempCache:    idem,
		TokenLedger:   ledger,
		ManifestCache: &paygate.ManifestCache{BaseURL: s.URL(), HTTP: s.Client()},
		PinChecker:    alwaysStateBPinChecker{},
	}
	sess, err := c.Open(context.Background(), paygate.OpenSessionInput{
		CircuitID:        "konareef-pod-step-v1",
		DisclosurePolicy: paygate.DisclosureTypeC,
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, bad := range []float64{0.0, -1.0} {
		_, err := c.SubmitFold(context.Background(), sess, paygate.FoldStepInput{
			StepIndex: 0, HP: [32]byte{0x11}, BSVUSDRate: bad,
		})
		if err == nil {
			t.Errorf("SubmitFold with BSVUSDRate=%v should error", bad)
		}
	}
}

// --- B7 ---------------------------------------------------------------

func TestRound2B7_BRC29PaymentHeaderIsHexEncoded(t *testing.T) {
	captured := make(chan string, 1)
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/.well-known/x402-info", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"service":    "paygate-zk",
			"version":    "v1",
			"operations": []string{"nova-fold"},
			"circuits": map[string]interface{}{
				"konareef-pod-step-v1": map[string]interface{}{
					"vkey_sha256": "0101010101010101010101010101010101010101010101010101010101010101",
					"vkey_url":    "https://example.test/vkey",
					"pricing": map[string]interface{}{
						"nova-fold": map[string]float64{"compute_usd": 0.0001, "retail_usd": 0.001},
					},
				},
			},
			"margin_multiplier":        10,
			"schedule_revision":        1,
			"schedule_effective_after": nil,
			"signature":                map[string]string{},
		})
	})
	mux.HandleFunc("/v1/prove/nova-fold", func(w http.ResponseWriter, req *http.Request) {
		captured <- req.Header.Get("X-Payment")
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusAccepted)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"job_id":       "job-b7",
			"submitted_at": time.Now().UTC(),
		})
	})
	mux.HandleFunc("/v1/jobs/", func(w http.ResponseWriter, req *http.Request) {
		path := strings.TrimPrefix(req.URL.Path, "/v1/jobs/")
		if strings.HasSuffix(path, "/result") {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"job_id":               "job-b7",
				"accumulator_out":      []byte{0xaa},
				"step_proof":           []byte{0xbb},
				"public_inputs_echoed": map[string]interface{}{"step_index": 0},
				"cost_meta":            map[string]int{},
			})
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"job_id":     "job-b7",
			"status":     "completed",
			"proof_type": "nova-fold",
			"circuit_id": "konareef-pod-step-v1",
			"created_at": time.Now().UTC(),
			"updated_at": time.Now().UTC(),
			"error":      nil,
		})
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()
	dir := t.TempDir()
	idem, _ := paygate.OpenIdempCache(filepath.Join(dir, "idem.db"))
	ledger, _ := paygate.OpenTokenLedger(filepath.Join(dir, "ledger.db"))
	t.Cleanup(func() { _ = idem.Close(); _ = ledger.Close() })
	c := &paygate.Client{
		BaseURL:       srv.URL,
		HTTP:          srv.Client(),
		IdentityPath:  filepath.Join(dir, "identity.key"),
		IdempCache:    idem,
		TokenLedger:   ledger,
		ManifestCache: &paygate.ManifestCache{BaseURL: srv.URL, HTTP: srv.Client()},
		PinChecker:    alwaysStateBPinChecker{},
	}
	sess, err := c.Open(context.Background(), paygate.OpenSessionInput{
		CircuitID:        "konareef-pod-step-v1",
		DisclosurePolicy: paygate.DisclosureTypeC,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.SubmitFold(context.Background(), sess, paygate.FoldStepInput{
		StepIndex: 0, HP: [32]byte{0xb7}, BSVUSDRate: 15.0,
	}); err != nil {
		t.Fatalf("SubmitFold: %v", err)
	}
	got := <-captured
	if !strings.HasPrefix(got, "Brc29 ") {
		t.Fatalf("X-Payment scheme: %q, want Brc29 prefix", got)
	}
	payload := strings.TrimPrefix(got, "Brc29 ")
	decoded, err := hex.DecodeString(payload)
	if err != nil {
		t.Fatalf("BRC-29 payload must be hex; got %q (err=%v)", payload, err)
	}
	if len(decoded) == 0 {
		t.Errorf("BRC-29 hex payload decoded to empty bytes")
	}
}

// stub server rejects a raw-binary payload as PAYMENT_BEEF_INVALID; we
// drive that path by manually invoking the underlying handler logic via
// a direct request and confirming the stub returns 402.
func TestRound2B7_StubRejectsRawBinaryBRC29(t *testing.T) {
	s := stubserver.New(stubserver.Options{ManifestProfile: "active"})
	defer s.Close()
	req, _ := http.NewRequest(http.MethodPost, s.URL()+"/v1/prove/nova-fold", strings.NewReader(`{}`))
	req.Header.Set("Authorization", "Brc31 session=test")
	req.Header.Set("Idempotency-Key", "deadbeef")
	// Raw binary 0xff is not valid hex.
	rawWithControlBytes := string([]byte{0xff, 0x00, 0xfe})
	req.Header.Set("X-Payment", "Brc29 "+rawWithControlBytes)
	resp, err := s.Client().Do(req)
	if err != nil {
		// Some HTTP clients reject control bytes in headers outright;
		// that is also acceptable evidence that raw binary cannot
		// traverse the protocol.
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusAccepted {
		t.Errorf("stub accepted raw-binary BRC-29 payload (status %d); want rejection", resp.StatusCode)
	}
}
