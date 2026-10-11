// Copyright 2026 Jerry David Chan, Konareef.ai
// SPDX-License-Identifier: Apache-2.0

// model_identity.go — the model identity gate at the feeder boundary
// (IB-03, konareef#21).
//
// reef-core discloses two model fields in step-disclosure.json (IB-02,
// reef-core#50):
//
//	"model"     the bare model name the run was configured with
//	"model_id"  the qualified "<provider>/<name>" ID the runtime was told
//	            to run
//
// The presence of "model_id" marks the newer seam. The manifest commits its
// declared models as qualified IDs (canon.ModelID, konareef-toml-v2 spec
// §4.1, R-V2.5), and PS-1 refuses a witness whose model is not one of them.
// So the witness model must be the disclosed qualified ID, compared exactly
// against the declared set.
//
// This file owns that rule. witnessModelID is the only function that
// decides the witness model; WriteWitness calls it and does nothing else
// with the model fields. requireDeclaredModel is the membership test, also
// applied by AssemblePodRecord to a pre-written witness.
package feeder

import (
	"errors"
	"fmt"
	"slices"
	"strings"
)

// Model identity refusals. Each one stops WriteWitness before it writes a
// witness file. Callers match them with errors.Is.
var (
	// ErrModelIDMissing: the seam has no model_id. The bare model is never
	// used in its place, because a bare name does not say which provider
	// ran it ("openai/gpt-4o" and "azure/gpt-4o" share one bare name).
	ErrModelIDMissing = errors.New("MODEL_ID_MISSING")

	// ErrModelIDMalformed: model_id is not "<provider>/<name>" with both
	// parts non-empty.
	ErrModelIDMalformed = errors.New("MODEL_ID_MALFORMED")

	// ErrModelIDInconsistent: the seam's bare model is set but model_id does
	// not end in "/<bare model>". reef-core derives both from the same
	// config, so a disagreement means the seam file is not what reef-core
	// wrote.
	ErrModelIDInconsistent = errors.New("MODEL_ID_INCONSISTENT")

	// ErrModelNotDeclared: model_id is not byte-for-byte one of the
	// manifest's declared models. There is no case folding, trimming or
	// Unicode normalisation, matching canon.ModelID.
	ErrModelNotDeclared = errors.New("MODEL_NOT_DECLARED")
)

// witnessModelID returns the model the witness commits to for one step.
//
// Input: sd, the parsed step disclosure, and declared, the manifest's
// declared model IDs (ManifestParams.Models). Output: sd.ModelID
// unchanged, or an error wrapping one of the Err* sentinels above.
//
// The rules, in order:
//
//  1. model_id must be present. A seam without it is refused for every
//     manifest version. The declared set is qualified for every version
//     (install.LoadManifestParams), so a bare-name witness cannot pass
//     PS-1's membership check. Refusing here gives the reason early.
//  2. model_id must be "<provider>/<name>" with both parts non-empty. The
//     split is at the first "/"; a name may itself contain "/".
//  3. When the bare model is set, model_id must be "<something>/<bare>".
//     The bare model may be empty: reef-core discloses null for a run on
//     the default model.
//  4. model_id must be an exact member of declared.
//
// The declared set is never used to fill in or correct the witness model.
// Doing so would hide a run of an undeclared model behind a declared name.
func witnessModelID(sd StepDisclosure, declared []string) (string, error) {
	id := sd.ModelID
	if id == "" {
		return "", fmt.Errorf("%w: step-disclosure has no model_id (bare model %q is not a qualified "+
			"identity and is not used in its place); reef-core must disclose model_id (reef-core#50)",
			ErrModelIDMissing, sd.Model)
	}
	provider, name, found := strings.Cut(id, "/")
	if !found || provider == "" || name == "" {
		return "", fmt.Errorf("%w: model_id %q is not \"<provider>/<name>\"", ErrModelIDMalformed, id)
	}
	if sd.Model != "" && !strings.HasSuffix(id, "/"+sd.Model) {
		return "", fmt.Errorf("%w: model_id %q does not name the disclosed bare model %q",
			ErrModelIDInconsistent, id, sd.Model)
	}
	if err := requireDeclaredModel(id, declared); err != nil {
		return "", err
	}
	return id, nil
}

// requireDeclaredModel reports whether model is byte-for-byte one of
// declared.
//
// Input: the witness model and the declared model IDs. Output: nil on a
// match, else an error wrapping ErrModelNotDeclared. It is the same
// membership test PS-1 applies (paygate-zk-prove assemble.rs), run here so
// a mismatch fails before the prover call. AssemblePodRecord calls it for a
// pre-written witness.json that never passed through witnessModelID.
func requireDeclaredModel(model string, declared []string) error {
	if slices.Contains(declared, model) {
		return nil
	}
	return fmt.Errorf("%w: model %q is not in the manifest's declared models %q",
		ErrModelNotDeclared, model, declared)
}
