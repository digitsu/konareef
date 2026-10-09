// Copyright 2026 Jerry David Chan, Konareef.ai
// SPDX-License-Identifier: Apache-2.0

// smoke_chain_types_test.go — verifyChainTypes accepts the run_outcome
// link that reef-core#98 puts before custody (konareef#41).

package smoke

import (
	"testing"

	"github.com/digitsu/konareef/internal/api"
)

func proofsOfTypes(types ...string) []api.Proof {
	proofs := make([]api.Proof, len(types))
	for i, proofType := range types {
		proofs[i] = api.Proof{ProofType: proofType}
	}
	return proofs
}

func TestVerifyChainTypes(t *testing.T) {
	accept := [][]string{
		{"structured_bundle", "openbrain_snapshot", "custody"},
		{"structured_bundle", "openbrain_snapshot", "capture_commitment", "custody"},
		{"structured_bundle", "openbrain_snapshot", "run_outcome", "custody"},
		{"structured_bundle", "openbrain_snapshot", "capture_commitment", "run_outcome", "custody"},
	}
	for _, types := range accept {
		if err := verifyChainTypes(proofsOfTypes(types...)); err != nil {
			t.Errorf("%v: unexpected error %v", types, err)
		}
	}
	reject := [][]string{
		{"structured_bundle", "custody"},
		{"structured_bundle", "openbrain_snapshot", "run_outcome"},
	}
	for _, types := range reject {
		if err := verifyChainTypes(proofsOfTypes(types...)); err == nil {
			t.Errorf("%v: want an error", types)
		}
	}
}
