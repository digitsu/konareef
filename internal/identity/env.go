// Package identity — env initializer for feature flags.
//
// LoadEnv reads process environment variables and applies them to
// package-level identity flags. It MUST be called from main() early,
// before any signing or verification operation, so that integration
// tests can cover the env-var path by calling LoadEnv() directly
// without needing to invoke the application binary.
//
// Design note: the initializer lives in the identity package (not in
// main) so that go test ./internal/identity/... exercises it. A bare
// os.Getenv block in main() is untestable from package-level tests,
// which was the Hermes round-3 B2 blocker.
package identity

import "os"

// StrictDerGateEnabled gates the strict-DER + low-S enforcement in Verify
// and VerifyRotationSignature (P1.4). When false (the default), both
// functions accept any signature that dcrec/secp256k1 can parse and verify —
// matching pre-P1.4 behaviour. When true, an additional byte-level DER check
// plus low-S assertion is applied before the ECDSA verification, and any
// non-conforming signature returns ERR_DER_GATE_REJECT.
//
// The flag is set by LoadEnv() from KONAREEF_STRICT_DER_GATE=true or
// directly in tests. It MUST NOT be set in init() — test binaries that
// import this package should not auto-enable the gate without an explicit
// call or env-var.
var StrictDerGateEnabled bool

// LoadEnv reads KONAREEF_STRICT_DER_GATE and enables StrictDerGateEnabled
// when the value is exactly "true". Any other value (unset, "1", "yes",
// etc.) leaves the flag at its current value, which defaults to false.
//
// Idempotent: calling LoadEnv multiple times has the same effect as
// calling it once — the flag is only ever set, never cleared.
func LoadEnv() {
	if os.Getenv("KONAREEF_STRICT_DER_GATE") == "true" {
		StrictDerGateEnabled = true
	}
}
