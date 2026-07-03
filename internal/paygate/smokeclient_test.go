// internal/paygate/smokeclient_test.go — shared M-test client helper.
//
// Lives in package paygate_test so the M-1..M-8 test files import
// from the same package.
package paygate_test

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/digitsu/konareef/internal/paygate"
	"github.com/digitsu/konareef/internal/paygate/stubserver"
)

// noopPinChecker satisfies paygate.PinCheck and always reports State B
// (cache hit, pins match) with a nil error. Default for M-1..M-4 and
// M-6..M-8. M-5 overrides via smokeOpts.
type noopPinChecker struct{}

func (noopPinChecker) Check(_ context.Context, _, _ string) (paygate.PinState, error) {
	return paygate.PinStateB, nil
}

// smokeOpts lets individual M-tests override defaults from
// newSmokeClient. M-5 supplies a real PinCheck here.
type smokeOpts struct {
	PinChecker paygate.PinCheck
}

// newSmokeClient wires a paygate.Client against an in-process stub.
// Each M-test (Tasks 14–18) reuses this helper.
func newSmokeClient(t *testing.T, s *stubserver.Server, opts ...smokeOpts) *paygate.Client {
	t.Helper()
	dir := t.TempDir()
	return newSmokeClientWithDirAndOpts(t, s, dir, opts...)
}

// newSmokeClientWithDir builds a Client with explicit state dir (M-2
// uses two of these to produce two distinct BRC-31 identities).
func newSmokeClientWithDir(t *testing.T, s *stubserver.Server, dir string) *paygate.Client {
	t.Helper()
	return newSmokeClientWithDirAndOpts(t, s, dir)
}

func newSmokeClientWithDirAndOpts(t *testing.T, s *stubserver.Server, dir string, opts ...smokeOpts) *paygate.Client {
	t.Helper()
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
		BaseURL:       s.URL(),
		HTTP:          s.Client(),
		IdentityPath:  filepath.Join(dir, "identity.key"),
		IdempCache:    idem,
		TokenLedger:   ledger,
		ManifestCache: &paygate.ManifestCache{BaseURL: s.URL(), HTTP: s.Client()},
		PinChecker:    newPinChecker(opts...),
	}
}

// newPinChecker returns the PinCheck implementation every M-test helper
// shares. The default is noopPinChecker; M-5 overrides via smokeOpts.
func newPinChecker(opts ...smokeOpts) paygate.PinCheck {
	if len(opts) > 0 && opts[0].PinChecker != nil {
		return opts[0].PinChecker
	}
	return noopPinChecker{}
}
