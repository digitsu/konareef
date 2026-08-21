// Copyright 2026 Jerry David Chan, Konareef.ai
// SPDX-License-Identifier: Apache-2.0

// internal/paygate/client_test_helpers_test.go — test-only helpers shared
// between client_test.go and the M-test files. Lives in
// package paygate_test so it compiles with the other _test.go files.
package paygate_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/digitsu/konareef/internal/paygate"
	"github.com/digitsu/konareef/internal/saltstore"
)

// stubAlwaysActiveServer returns an httptest.Server serving an
// always-active manifest for "konareef-pod-step-v1". Used by the B2
// Open-path tests that do NOT submit folds (they only exercise the
// salt-handling branch of Open()).
func stubAlwaysActiveServer(t *testing.T) *httptest.Server {
	t.Helper()
	body := []byte(`{
  "service": "paygate-zk",
  "version": "v1",
  "operations": ["nova-fold"],
  "circuits": {
    "konareef-pod-step-v1": {
      "vkey_sha256": "0101010101010101010101010101010101010101010101010101010101010101",
      "vkey_url": "https://example.test/.well-known/circuits/konareef-pod-step-v1/vkey",
      "pricing": {
        "nova-fold": {"compute_usd": 0.0001, "retail_usd": 0.001}
      },
      "input_caps": {"manifest_bytes": 2048},
      "deprecated_after": null
    }
  },
  "margin_multiplier": 10,
  "schedule_revision": 1,
  "schedule_effective_after": null,
  "signature": {"scheme": "BRC-31"}
}`)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/.well-known/x402-info" {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write(body)
			return
		}
		http.NotFound(w, r)
	}))
	t.Cleanup(srv.Close)
	return srv
}

// alwaysStateBPinChecker is a paygate.PinCheck that always returns
// PinStateB with nil error. Suitable for Open() paths that should not
// fail on pin mismatch.
type alwaysStateBPinChecker struct{}

func (alwaysStateBPinChecker) Check(_ context.Context, _, _ string) (paygate.PinState, error) {
	return paygate.PinStateB, nil
}

// newOpenFixtureClient builds a minimal Client wired with a manifest
// cache + pin checker that resolve to a pinned vkey for
// "konareef-pod-step-v1", suitable for exercising Open() without an
// actual nova-fold submission. saltBackend may be nil for Type-C tests.
func newOpenFixtureClient(t *testing.T, dir string, saltBackend saltstore.Backend) *paygate.Client {
	t.Helper()
	srv := stubAlwaysActiveServer(t)
	idem, err := paygate.OpenIdempCache(filepath.Join(dir, "idem.db"))
	if err != nil {
		t.Fatal(err)
	}
	ledger, err := paygate.OpenTokenLedger(filepath.Join(dir, "ledger.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = idem.Close(); _ = ledger.Close() })
	return &paygate.Client{
		BaseURL:       srv.URL,
		HTTP:          srv.Client(),
		IdentityPath:  filepath.Join(dir, "identity.key"),
		IdempCache:    idem,
		TokenLedger:   ledger,
		ManifestCache: &paygate.ManifestCache{BaseURL: srv.URL, HTTP: srv.Client()},
		PinChecker:    alwaysStateBPinChecker{},
		SaltBackend:   saltBackend,
	}
}
