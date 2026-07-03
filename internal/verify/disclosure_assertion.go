// disclosure_assertion.go — P1.3 verify-side disclosure-policy
// assertion for `konareef verify --disclosure-policy` per PRD 4
// § 4.3.3 verify-side semantics.
package verify

import (
	"errors"
	"fmt"
)

// ErrDisclosurePolicyViolation reports a mismatch between the
// --disclosure-policy assertion and the bundle's embedded
// `disclosure` field. PRD 4 § 6 stable code.
var ErrDisclosurePolicyViolation = errors.New("ERR_DISCLOSURE_POLICY_VIOLATION")

// AssertDisclosurePolicy compares the bundle's disclosure field
// against want. An empty want is a no-op (caller did not supply the
// flag). On mismatch returns ErrDisclosurePolicyViolation.
//
// This is a pure function; the caller invokes it AFTER verify.Load
// and BEFORE verify.Verify so an assertion failure short-circuits
// the structural verification.
func AssertDisclosurePolicy(b *Bundle, want string) error {
	if want == "" {
		return nil
	}
	if b == nil {
		return fmt.Errorf("AssertDisclosurePolicy: bundle is nil")
	}
	if b.Disclosure != want {
		return fmt.Errorf("%w: bundle.disclosure=%q, --disclosure-policy=%q",
			ErrDisclosurePolicyViolation, b.Disclosure, want)
	}
	return nil
}
