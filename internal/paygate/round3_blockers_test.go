// Copyright 2026 Jerry David Chan, Konareef.ai
// SPDX-License-Identifier: Apache-2.0

// internal/paygate/round3_blockers_test.go — Hermes MR !22 round-3
// blockers B1..B2 regression coverage.
//
//   - TestRound3B1_CreditTokenInsertFailureIsFatal: when the SQLite
//     idempotency cache returns an error from Insert on the
//     SubmitFoldWithCredit success path, SubmitFoldWithCredit MUST
//     surface it instead of returning success. Symmetric to round-2 B5
//     for the credit-token retry path.
//   - TestRound3B2_CreditTokenRetryRevalidatesPinOnRotation: when the
//     manifest's vkey_sha256 rotates between Open() and a credit-token
//     retry, SubmitFoldWithCredit MUST re-run the State A/B/C pin check
//     and fail closed on a real rotation, just like the primary path.
package paygate_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/digitsu/konareef/internal/paygate"
)

// --- B1 ---------------------------------------------------------------

// TestRound3B1_CreditTokenInsertFailureIsFatal proves that the credit-
// token retry path no longer swallows IdempotencyCache.Insert errors.
//
// Setup: stand up a stub that accepts a credit-token /v1/prove/nova-fold
// submission and reports the subsequent /v1/jobs poll as completed.
// Pre-seed a valid credit_token in the ledger so Take() succeeds. CLOSE
// the IdempCache before calling SubmitFoldWithCredit so Insert returns a
// real "sql: database is closed" error (the exact same fault mode round-2
// B5 used to prove Lookup errors are not silently treated as misses).
//
// Pass criterion: SubmitFoldWithCredit returns a non-nil error that
// wraps the idempotency persist failure. Before the fix, the discarded
// `_ = sess.IdempotencyCache.Insert(...)` made this scenario return
// success with no durable binding — a duplicate-payment opening.
func TestRound3B1_CreditTokenInsertFailureIsFatal(t *testing.T) {
	dir := t.TempDir()
	idem, err := paygate.OpenIdempCache(filepath.Join(dir, "idem.db"))
	if err != nil {
		t.Fatal(err)
	}
	ledger, err := paygate.OpenTokenLedger(filepath.Join(dir, "ledger.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ledger.Close() })

	// Pre-seed a valid credit token so CreditTokens.Take() succeeds.
	now := time.Now().UTC()
	if err := ledger.Persist("tok-round3-b1", now.Add(-time.Minute), now.Add(time.Hour)); err != nil {
		t.Fatalf("ledger.Persist: %v", err)
	}

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
			w.WriteHeader(http.StatusAccepted)
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"job_id":       "round3-b1-job",
				"submitted_at": time.Now().UTC(),
			})
		default:
			http.NotFound(w, req)
		}
	}))
	defer srv.Close()

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

	// Close the idempotency cache AFTER Open() and BEFORE the credit-
	// token retry so Insert fails fatally inside SubmitFoldWithCredit.
	if err := idem.Close(); err != nil {
		t.Fatalf("idem.Close: %v", err)
	}

	rb, err := c.SubmitFoldWithCredit(context.Background(), sess,
		paygate.FoldStepInput{StepIndex: 0, HP: [32]byte{0xb1}, BSVUSDRate: 15.0},
		"tok-round3-b1",
	)
	if err == nil {
		t.Fatalf("SubmitFoldWithCredit MUST surface IdempotencyCache.Insert error; got nil (rb=%+v)", rb)
	}
	if rb != nil {
		t.Errorf("SubmitFoldWithCredit returned non-nil ResultBody on persist failure: %+v", rb)
	}
	// Sanity: the error chain should clearly identify the persist step,
	// not be a generic ctx-cancel or HTTP failure.
	if !strings.Contains(err.Error(), "idempotency") {
		t.Errorf("error should mention idempotency persist; got %v", err)
	}
}

// --- B2 ---------------------------------------------------------------

// rotatingPinChecker reports ErrCircuitPinMismatch (via a sentinel error
// wrapper) when asked to validate any pin other than its "good" pin.
// This is the failure mode a real PinChecker would surface when the
// manifest advertises a fresh vkey hash that the vkeystore does not yet
// trust (State B mismatch / State A miss with refusal).
type rotatingPinChecker struct {
	goodPin string
	calls   []struct{ circuit, pin string }
}

var errRotatingPinReject = errors.New("rotatingPinChecker: refused rotated pin")

func (r *rotatingPinChecker) Check(_ context.Context, circuit, pin string) (paygate.PinState, error) {
	r.calls = append(r.calls, struct{ circuit, pin string }{circuit, pin})
	if pin != r.goodPin {
		return paygate.PinStateB, errRotatingPinReject
	}
	return paygate.PinStateB, nil
}

// TestRound3B2_CreditTokenRetryRevalidatesPinOnRotation proves that the
// credit-token retry path runs the manifest refresh + pin revalidation
// shared with SubmitFold, and fails closed when a rotated vkey_sha256
// is refused.
//
// Setup: a rotating stub serves vkey hash A on the first manifest hit
// (consumed by Open()) and vkey hash B on every subsequent hit. Pre-seed
// a valid credit token. The PinChecker accepts hash A but refuses hash B.
//
// Pass criterion: SubmitFoldWithCredit returns a non-nil error wrapping
// errRotatingPinReject AND DOES NOT submit to /v1/prove/nova-fold (the
// retry path MUST fail closed BEFORE a payment hits the wire). Before
// the fix, SubmitFoldWithCredit only called ManifestCache.Get and
// discarded the result — so a rotated pin slipped past the credit-token
// path entirely.
func TestRound3B2_CreditTokenRetryRevalidatesPinOnRotation(t *testing.T) {
	const (
		circuitID = "konareef-pod-step-v1"
		vkeyA     = "0101010101010101010101010101010101010101010101010101010101010101"
		vkeyB     = "0202020202020202020202020202020202020202020202020202020202020202"
	)
	var manifestHits int32
	var beefSubmits int32

	mux := http.NewServeMux()
	mux.HandleFunc("/v1/.well-known/x402-info", func(w http.ResponseWriter, _ *http.Request) {
		hits := atomic.AddInt32(&manifestHits, 1)
		vk := vkeyA
		if hits > 1 {
			vk = vkeyB
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"service":    "paygate-zk",
			"version":    "v1",
			"operations": []string{"nova-fold"},
			"circuits": map[string]interface{}{
				circuitID: map[string]interface{}{
					"vkey_sha256": vk,
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
	mux.HandleFunc("/v1/prove/nova-fold", func(w http.ResponseWriter, _ *http.Request) {
		atomic.AddInt32(&beefSubmits, 1)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusAccepted)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"job_id":       "round3-b2-job",
			"submitted_at": time.Now().UTC(),
		})
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

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

	// Pre-seed a valid credit token so CreditTokens.Take() succeeds and
	// the retry actually reaches the manifest-refresh + pin-revalidate
	// step under test.
	now := time.Now().UTC()
	if err := ledger.Persist("tok-round3-b2", now.Add(-time.Minute), now.Add(time.Hour)); err != nil {
		t.Fatalf("ledger.Persist: %v", err)
	}

	pin := &rotatingPinChecker{goodPin: vkeyA}
	c := &paygate.Client{
		BaseURL:       srv.URL,
		HTTP:          srv.Client(),
		IdentityPath:  filepath.Join(dir, "identity.key"),
		IdempCache:    idem,
		TokenLedger:   ledger,
		ManifestCache: &paygate.ManifestCache{BaseURL: srv.URL, HTTP: srv.Client()},
		PinChecker:    pin,
	}
	sess, err := c.Open(context.Background(), paygate.OpenSessionInput{
		CircuitID:        circuitID,
		DisclosurePolicy: paygate.DisclosureTypeC,
	})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if sess.PinnedVkeyHash != vkeyA {
		t.Fatalf("session pinned = %q, want vkeyA %q", sess.PinnedVkeyHash, vkeyA)
	}

	// Force the manifest cache to refetch so the SubmitFoldWithCredit
	// call sees the rotated manifest B (the cache hard-floor cadence is
	// far longer than this test wants to wait — identical pattern to
	// round-2 B1).
	if _, err := c.ManifestCache.Refresh(context.Background()); err != nil {
		t.Fatalf("Refresh: %v", err)
	}

	rb, err := c.SubmitFoldWithCredit(context.Background(), sess,
		paygate.FoldStepInput{StepIndex: 0, HP: [32]byte{0xb2}, BSVUSDRate: 15.0},
		"tok-round3-b2",
	)
	if err == nil {
		t.Fatalf("SubmitFoldWithCredit MUST fail closed on rotated pin; got nil (rb=%+v)", rb)
	}
	if !errors.Is(err, errRotatingPinReject) {
		t.Errorf("err should wrap rotating-pin rejection; got %v", err)
	}
	if got := atomic.LoadInt32(&beefSubmits); got != 0 {
		t.Errorf("BEEF submits = %d, want 0 (credit-token path must fail BEFORE network submission)", got)
	}
	// Confirm we actually invoked the pin check against the refreshed
	// pin — proves it's not just a manifest-fetch failure squelching
	// the request.
	if len(pin.calls) < 2 {
		t.Fatalf("PinChecker.Check calls = %d, want >= 2 (Open + credit-retry refresh)", len(pin.calls))
	}
	last := pin.calls[len(pin.calls)-1]
	if last.pin != vkeyB {
		t.Errorf("last pin check pin = %q, want vkeyB %q (refreshed manifest)", last.pin, vkeyB)
	}
}
