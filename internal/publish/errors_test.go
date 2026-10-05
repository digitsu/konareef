// Copyright 2026 Jerry David Chan, Konareef.ai
// SPDX-License-Identifier: Apache-2.0

// errors_test.go — P1.3 sentinel error tests.
package publish

import (
	"errors"
	"fmt"
	"testing"
)

// TestSentinelCodeStrings asserts each sentinel's Error() string
// matches the PRD 4 § 6 stable code so the CLI surface, structured
// logs, and downstream consumers all see the same identifier.
func TestSentinelCodeStrings(t *testing.T) {
	cases := []struct {
		err  error
		want string
	}{
		{ErrZkRequiresCircuitID, "ERR_ZK_REQUIRES_CIRCUIT_ID"},
		{ErrZkRequiresDisclosurePolicy, "ERR_ZK_REQUIRES_DISCLOSURE_POLICY"},
		{ErrInvalidDisclosurePolicy, "ERR_INVALID_DISCLOSURE_POLICY"},
		{ErrDisclosurePolicyViolation, "ERR_DISCLOSURE_POLICY_VIOLATION"},
		{ErrDisclosurePolicySealed, "ERR_DISCLOSURE_POLICY_SEALED"},
		{ErrAnchorBroadcastUnsupported, "ERR_ANCHOR_BROADCAST_UNSUPPORTED"},
		{ErrCircuitIDRequiredForPinCircuitVkey, "ERR_CIRCUIT_ID_REQUIRED_FOR_PIN_CIRCUIT_VKEY"},
	}
	for _, c := range cases {
		if c.err.Error() != c.want {
			t.Errorf("err string = %q, want %q", c.err.Error(), c.want)
		}
		wrapped := fmt.Errorf("publish: %w", c.err)
		if !errors.Is(wrapped, c.err) {
			t.Errorf("errors.Is(wrap, %s) returned false", c.want)
		}
	}
}

// TestSentinelsAreDistinct ensures no sentinel aliases another (which
// would make the CLI's error-code surfacing ambiguous).
func TestSentinelsAreDistinct(t *testing.T) {
	all := []error{
		ErrZkRequiresCircuitID,
		ErrZkRequiresDisclosurePolicy,
		ErrInvalidDisclosurePolicy,
		ErrDisclosurePolicyViolation,
		ErrDisclosurePolicySealed,
		ErrAnchorBroadcastUnsupported,
		ErrCircuitIDRequiredForPinCircuitVkey,
	}
	for i, a := range all {
		for j, b := range all {
			if i != j && errors.Is(a, b) {
				t.Errorf("sentinel %d Is %d — must be distinct", i, j)
			}
		}
	}
}
