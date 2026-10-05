// Copyright 2026 Jerry David Chan, Konareef.ai
// SPDX-License-Identifier: Apache-2.0

// proof.go — the production proof verifier seam of the replay.

package replay

import (
	"errors"

	"github.com/digitsu/konareef/internal/verify"
)

// ProductionProofVerifier verifies a konareef-bundle/v2 proof with the same
// path `konareef verify` uses (verify.VerifyV2Production). The Spartan
// SNARK is checked only when KONAREEF_VERIFY_BIN names the verifier binary;
// without it the result is VerifierMissing, never OK.
//
// Input: the bundle bytes. Output: the decoded facts the replay compares
// and the verifier's verdict.
func ProductionProofVerifier(bundle []byte) ProofCheck {
	b, err := verify.DecodeBundleV2(bundle)
	if err != nil {
		return ProofCheck{DecodeErr: err}
	}
	result := verify.VerifyV2Production(bundle, false)
	pc := ProofCheck{
		Bundle: &BundleFacts{
			Disclosure:        b.Disclosure,
			Manifest:          b.Manifest,
			GenesisFieldsRoot: b.SpartanCompressResult.GenesisFieldsRoot,
		},
		OK: result.OK,
	}
	onlyVerifierMissing := len(result.Divergences) > 0
	for _, d := range result.Divergences {
		pc.Divergences = append(pc.Divergences, d.Msg)
		if !errors.Is(d.Err, verify.ErrSnarkVerifierNotConfigured) {
			onlyVerifierMissing = false
		}
	}
	pc.VerifierMissing = !result.OK && onlyVerifierMissing
	return pc
}
