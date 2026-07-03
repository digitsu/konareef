// internal/tui/verify_test.go
//
// Unit tests for the verify-view presentation layer (Track A.1). These
// drive the pure mapping/render functions (outcomeFromV1, outcomeFromV2,
// plainVerifyLines) without standing up the Bubble Tea event loop, so the
// version-specific verdict→display logic is covered directly.

package tui

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/digitsu/konareef/internal/verify"
)

// joined renders the outcome's plain lines as one string for substring
// assertions.
func joined(o verifyOutcome) string {
	return strings.Join(plainVerifyLines(o), "\n")
}

func mustContain(t *testing.T, haystack, needle string) {
	t.Helper()
	if !strings.Contains(haystack, needle) {
		t.Errorf("expected output to contain %q\n--- got ---\n%s", needle, haystack)
	}
}

func mustNotContain(t *testing.T, haystack, needle string) {
	t.Helper()
	if strings.Contains(haystack, needle) {
		t.Errorf("expected output NOT to contain %q\n--- got ---\n%s", needle, haystack)
	}
}

func TestOutcomeFromV1_AttestedPass(t *testing.T) {
	r := &verify.Result{OK: true, ChainLength: 7, AttestationStatus: "attested"}
	b := &verify.Bundle{Version: "konareef-bundle/v1"}
	o := outcomeFromV1("bundle.json", b, r)

	if !o.OK || o.IsV2 {
		t.Fatalf("expected OK v1 outcome, got OK=%v IsV2=%v", o.OK, o.IsV2)
	}
	out := joined(o)
	mustContain(t, out, "✅ PASS")
	mustContain(t, out, "chain length: 7")
	mustContain(t, out, "publisher attestation")
	mustContain(t, out, "attested")
	mustContain(t, out, "Divergences (0)")
}

func TestOutcomeFromV1_LegacyUnsignedIsInfoNotFail(t *testing.T) {
	r := &verify.Result{OK: true, ChainLength: 2, AttestationStatus: "legacy_unsigned"}
	b := &verify.Bundle{Version: "konareef-bundle/v1"}
	o := outcomeFromV1("legacy.json", b, r)

	out := joined(o)
	mustContain(t, out, "✅ PASS")
	mustContain(t, out, "legacy unsigned")
	// The legacy-unsigned attestation row is a warning (⚠), never a hard ❌.
	if got := o.Checks[0].State; got != checkInfo {
		t.Errorf("expected legacy_unsigned attestation to be checkInfo, got %v", got)
	}
}

func TestOutcomeFromV1_FailListsDivergences(t *testing.T) {
	r := &verify.Result{
		OK:          false,
		ChainLength: 3,
		Divergences: []string{"chain hash mismatch at link 2", "access log hash mismatch"},
	}
	b := &verify.Bundle{Version: "konareef-bundle/v1"}
	o := outcomeFromV1("tampered.json", b, r)

	out := joined(o)
	mustContain(t, out, "❌ FAIL")
	mustContain(t, out, "Divergences (2)")
	mustContain(t, out, "chain hash mismatch at link 2")
	mustContain(t, out, "access log hash mismatch")
}

func TestOutcomeFromV2_PassRendersVerdictAndHeader(t *testing.T) {
	r := &verify.ResultV2{
		OK:          true,
		ChainLength: 3,
		V2Verdict: &verify.Verdict{
			ProofValid:              true,
			DisclosureValid:         true,
			CommitmentsValid:        true,
			ChainPolicyMode:         "redacted",
			ChainPolicyValid:        true,
			SignatureValid:          true,
			PublisherIdentityStatus: verify.PISBound,
		},
	}
	o := outcomeFromV2("bundle.cbor", "konareef-bundle/v2", "konareef-pod-step-v1", "C", r)

	if !o.OK || !o.IsV2 {
		t.Fatalf("expected OK v2 outcome, got OK=%v IsV2=%v", o.OK, o.IsV2)
	}
	out := joined(o)
	mustContain(t, out, "circuit: konareef-pod-step-v1")
	mustContain(t, out, "disclosure: C")
	mustContain(t, out, "SNARK proof")
	mustContain(t, out, "valid")
	mustContain(t, out, "disclosure (Type C)")
	mustContain(t, out, "chain policy (redacted)")
	mustContain(t, out, "publisher attestation")
	mustContain(t, out, string(verify.PISBound))
}

func TestOutcomeFromV2_FailClosedSnarkIsInfo(t *testing.T) {
	// Production default: no Spartan verifier wired → ResultV2 carries the
	// ErrSnarkVerifierNotConfigured divergence. The SNARK row must render
	// as informational (fail-closed), not a tamper-style ❌.
	r := &verify.ResultV2{
		OK:          false,
		ChainLength: 1,
		V2Verdict:   &verify.Verdict{ProofValid: false, DisclosureValid: true, CommitmentsValid: true},
		Divergences: []verify.Divergence{
			{Err: verify.ErrSnarkVerifierNotConfigured, Msg: verify.ErrSnarkVerifierNotConfigured.Error()},
		},
	}
	o := outcomeFromV2("bundle.cbor", "konareef-bundle/v2", "konareef-pod-step-v1", "D", r)

	if !snarkNotConfigured(r) {
		t.Fatal("snarkNotConfigured should detect the fail-closed divergence")
	}
	// Find the SNARK row.
	var snark *checkLine
	for i := range o.Checks {
		if strings.HasPrefix(o.Checks[i].Label, "SNARK") {
			snark = &o.Checks[i]
		}
	}
	if snark == nil {
		t.Fatal("expected a SNARK proof check row")
	}
	if snark.State != checkInfo {
		t.Errorf("fail-closed SNARK row should be checkInfo, got %v", snark.State)
	}
	out := joined(o)
	mustContain(t, out, "verifier not configured")
	mustContain(t, out, "❌ FAIL") // overall result is still a fail
}

func TestOutcomeFromV2_NilVerdictNoPanicNoChecks(t *testing.T) {
	// A malformed bundle diverges before any verdict is built.
	r := &verify.ResultV2{
		OK:          false,
		Divergences: []verify.Divergence{{Err: verify.ErrMalformedCBOR, Msg: "unrecognized first byte 0x09"}},
	}
	o := outcomeFromV2("garbage.bin", "", "", "", r)

	if len(o.Checks) != 0 {
		t.Errorf("expected no check rows for a nil verdict, got %d", len(o.Checks))
	}
	out := joined(o)
	mustContain(t, out, "❌ FAIL")
	mustContain(t, out, "unrecognized first byte 0x09")
	mustContain(t, out, "Divergences (1)")
}

// TestComputeOutcome_DispatchesRealFixtures drives the full load + first-
// byte dispatch path against the real verify testdata bundles, covering
// readBundleBytes and the v1/v2 routing that the synthetic-Result tests
// above do not.
func TestComputeOutcome_DispatchesRealFixtures(t *testing.T) {
	const dir = "../verify/testdata/"

	t.Run("v1 JSON", func(t *testing.T) {
		o, err := computeOutcome(dir+"parity-real-1.bundle.json", false, "")
		if err != nil {
			t.Fatalf("computeOutcome v1: %v", err)
		}
		if o.IsV2 {
			t.Errorf("expected v1 dispatch (IsV2=false), got IsV2=true")
		}
		if !strings.Contains(shortVersion(o.Version), "v1") {
			t.Errorf("expected a v1 version tag, got %q", o.Version)
		}
	})

	for _, tc := range []struct{ file, disclosure string }{
		{"parity-v2-typec.cbor", "C"},
		{"parity-v2-typed.cbor", "D"},
	} {
		t.Run(tc.file, func(t *testing.T) {
			o, err := computeOutcome(dir+tc.file, false, "")
			if err != nil {
				t.Fatalf("computeOutcome v2: %v", err)
			}
			if !o.IsV2 {
				t.Errorf("expected v2 dispatch (IsV2=true), got IsV2=false")
			}
			if o.Disclosure != tc.disclosure {
				t.Errorf("expected disclosure %q from header decode, got %q", tc.disclosure, o.Disclosure)
			}
			// Production default is fail-closed (no Spartan verifier), so a
			// real v2 fixture must surface the SNARK-not-configured notice
			// rather than silently passing.
			out := joined(o)
			mustContain(t, out, "verifier not configured")
			// The parity fixtures carry no pk_pub, so Check 4 now fails closed
			// with a real mismatch (not the pre-P1.4 "pending" stub). The
			// attestation row must render as a hard failure, not "pending (P1.4)".
			mustContain(t, out, "publisher attestation")
			mustContain(t, out, "mismatch")
			mustNotContain(t, out, "pending (P1.4)")
		})
	}
}

func TestOutcomeFromV2_ValidSignatureRendersSelfSigned(t *testing.T) {
	// P1.4 landed: an envelope whose ECDSA signature verifies over
	// h_manifest renders as a passing publisher-attestation row labelled
	// with the self_signed status.
	r := &verify.ResultV2{
		OK:        true,
		V2Verdict: &verify.Verdict{SignatureValid: true, PublisherIdentityStatus: verify.PISSelfSigned},
	}
	o := outcomeFromV2("b.cbor", "", "circ", "C", r)

	var att *checkLine
	for i := range o.Checks {
		if o.Checks[i].Label == "publisher attestation" {
			att = &o.Checks[i]
		}
	}
	if att == nil {
		t.Fatal("expected a publisher attestation row")
	}
	if att.State != checkPass {
		t.Errorf("a valid signature should be checkPass, got %v", att.State)
	}
	if att.Detail != string(verify.PISSelfSigned) {
		t.Errorf("expected self_signed detail, got %q", att.Detail)
	}
}

func TestOutcomeFromV2_GenuinelyInvalidSignatureStaysHardFail(t *testing.T) {
	// P1.4: any envelope-bearing bundle whose ECDSA check fails closed must
	// render a hard ❌ (there is no longer a soft "pending" state).
	r := &verify.ResultV2{
		OK:        false,
		V2Verdict: &verify.Verdict{SignatureValid: false, PublisherIdentityStatus: verify.PISSignatureInvalid},
		Divergences: []verify.Divergence{
			{Err: verify.ErrSignatureInvalid, Msg: "publisher attestation: signature_mismatch: ECDSA verify over h_manifest failed under publisher_pubkey"},
		},
	}
	o := outcomeFromV2("b.cbor", "", "circ", "C", r)

	var att *checkLine
	for i := range o.Checks {
		if o.Checks[i].Label == "publisher attestation" {
			att = &o.Checks[i]
		}
	}
	if att == nil || att.State != checkFail {
		t.Fatalf("a genuinely invalid signature must stay checkFail, got %+v", att)
	}
}

func TestComputeOutcome_MissingFileErrors(t *testing.T) {
	if _, err := computeOutcome("does-not-exist.cbor", false, ""); err == nil {
		t.Fatal("expected an error for a missing bundle file")
	}
}

// TestVerifyExitErr_FailClosedContract is the regression for Hermes
// blocker !27#1461: the --tui path must preserve the headless verify
// exit contract — non-zero on load/parse/disclosure failure or any
// divergence, zero only on a clean pass.
func TestVerifyExitErr_FailClosedContract(t *testing.T) {
	// Clean pass → exit 0.
	if err := verifyExitErr(verifyOutcome{OK: true}, nil); err != nil {
		t.Errorf("passing outcome must map to nil (exit 0); got %v", err)
	}
	// Load/parse/version/disclosure error → exit 1.
	if err := verifyExitErr(verifyOutcome{}, errors.New("unsupported bundle version")); err == nil {
		t.Error("load error must map to non-nil (exit 1)")
	}
	// Verification divergence → exit 1.
	if err := verifyExitErr(verifyOutcome{OK: false, Divergences: []string{"chain hash mismatch"}}, nil); err == nil {
		t.Error("failed verification must map to non-nil (exit 1)")
	}
}

// TestComputeOutcomeToExit_EndToEnd threads real/failing inputs through
// computeOutcome → verifyExitErr to prove rejected bundles are non-zero.
func TestComputeOutcomeToExit_EndToEnd(t *testing.T) {
	const dir = "../verify/testdata/"

	// Disclosure mismatch: computeOutcome returns an error → exit 1.
	_, derr := computeOutcome(dir+"parity-v2-typec.cbor", false, "D")
	if verifyExitErr(verifyOutcome{}, derr) == nil {
		t.Error("disclosure mismatch must be non-zero")
	}

	// v2 fail-closed (no Spartan verifier wired): outcome.OK == false → exit 1.
	o, err := computeOutcome(dir+"parity-v2-typec.cbor", false, "")
	if err != nil {
		t.Fatalf("type-C load: %v", err)
	}
	if o.OK {
		t.Skip("unexpected: v2 verified OK without a verifier")
	}
	if verifyExitErr(o, nil) == nil {
		t.Error("fail-closed v2 outcome must be non-zero")
	}
}

// TestComputeOutcome_RejectsUnsupportedJSONVersion is the regression for
// Hermes blocker !27#1457: the --tui JSON branch must enforce the same
// v1 version gate as verify.Load, rejecting an unsupported bundle version
// instead of feeding it into the v1 verifier/presentation path.
func TestComputeOutcome_RejectsUnsupportedJSONVersion(t *testing.T) {
	dir := t.TempDir()

	bad := filepath.Join(dir, "v999.json")
	if err := os.WriteFile(bad, []byte(`{"version":"konareef-bundle/v999"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := computeOutcome(bad, false, ""); err == nil ||
		!strings.Contains(err.Error(), "unsupported bundle version") {
		t.Fatalf("expected unsupported-version rejection, got %v", err)
	}

	// A valid v1 version still loads (guards against over-rejection).
	ok := filepath.Join(dir, "v1.json")
	if err := os.WriteFile(ok, []byte(`{"version":"`+verify.BundleVersion+`"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := computeOutcome(ok, false, ""); err != nil {
		t.Fatalf("valid v1 version should load, got %v", err)
	}
}

// TestComputeOutcome_DisclosurePolicyCannotBeBypassed is the regression
// for Hermes blocker !27#1447: the --tui path must enforce the
// --disclosure-policy assertion (fail-closed) exactly like the headless
// verify, never render a mismatched bundle.
func TestComputeOutcome_DisclosurePolicyCannotBeBypassed(t *testing.T) {
	const dir = "../verify/testdata/"

	// Type-C bundle asserted as D → hard ERR_DISCLOSURE_POLICY_VIOLATION,
	// no outcome rendered.
	if _, err := computeOutcome(dir+"parity-v2-typec.cbor", false, "D"); !errors.Is(err, verify.ErrDisclosurePolicyViolation) {
		t.Fatalf("type-C asserted D must violate; got %v", err)
	}

	// Case-insensitive match ("c" == "C") → passes, disclosure surfaced.
	o, err := computeOutcome(dir+"parity-v2-typec.cbor", false, "c")
	if err != nil {
		t.Fatalf("type-C asserted c (case-insensitive) should pass; got %v", err)
	}
	if o.Disclosure != "C" {
		t.Errorf("expected disclosure C, got %q", o.Disclosure)
	}

	// Empty policy → no assertion (no-op), bundle loads.
	if _, err := computeOutcome(dir+"parity-v2-typec.cbor", false, ""); err != nil {
		t.Fatalf("empty policy is a no-op; got %v", err)
	}

	// v1 bundle (empty disclosure) asserted as C → violation, proving the
	// assertion is not v2-only.
	if _, err := computeOutcome(dir+"parity-real-1.bundle.json", false, "C"); !errors.Is(err, verify.ErrDisclosurePolicyViolation) {
		t.Fatalf("v1 (no disclosure) asserted C must violate; got %v", err)
	}
}

func TestOutcomeFromV2_NoDisclosureOmitsTypeSuffix(t *testing.T) {
	r := &verify.ResultV2{
		OK:        true,
		V2Verdict: &verify.Verdict{DisclosureValid: true},
	}
	o := outcomeFromV2("b.cbor", "", "circ", "", r)
	out := joined(o)
	mustNotContain(t, out, "disclosure (Type")
	mustContain(t, out, "disclosure")
}
