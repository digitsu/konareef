// Copyright 2026 Jerry David Chan, Konareef.ai
// SPDX-License-Identifier: Apache-2.0

// modelid.go — the one canonical form of a declared model identifier
// (docs/reference/konareef-toml-v2-spec.md §4.1, R-V2.5).
//
// The identifier is a commitment rule, not a schema rule: it decides what
// string `canon.FieldsRoot` folds into a `models_root` leaf. This file is
// therefore the single place the rule is written down, and every Go site
// that derives the models dimension calls it instead of joining the two
// parts itself. Three sites did join it themselves, with two different
// answers, which is the defect this file exists to make impossible.
package canon

// ModelID returns the canonical identifier for one declared model:
// `[model].provider` and `[model].name` joined by a single "/". Both parts
// are REQUIRED; either one empty is a coded COMMIT_MODEL_PROVIDER_MISSING
// rejection (spec §7 has no separate code for an empty name — see the
// message, which names the part that is actually missing).
//
// Callers, all of which MUST agree because they describe the same
// commitment from different sides:
//
//   - internal/publish.DeriveCommitParams — the EMITTER. What it returns
//     here is what `[_commit].fields_root` commits at publish time.
//   - internal/install.LoadManifestParams — the witness feeder. What it
//     returns here reaches feeder.WriteWitness and the circuit, which
//     recomputes models_root and compares.
//   - internal/commission.ModelIDs — the commission envelope. What it
//     returns here is the models dimension a containment check decides on.
//
// Why the provider is required (spec §4.1): the shipped derivation
// committed `[model].name` alone, so `openai/gpt-4o` and `azure/gpt-4o`
// produced an IDENTICAL commitment and the models dimension did not in
// fact constrain which model ran. Joining the provider costs no vkey
// change — only the string folded into leaf_id changes, never the tree
// shape — and no regeneration of
// internal/canon/testdata/fields_root_vectors.json, whose vectors take
// model ids as opaque strings.
//
// This function performs no normalisation. NFC checking of committed
// identifiers is a separate gate applied by the emitter (R-V2.20), and
// commission normalises for set comparison through envelope.Normalise;
// neither belongs to the id-format rule.
func ModelID(provider, name string) (string, error) {
	if provider == "" {
		return "", NewError(ErrCommitModelProviderMissing,
			"[model] declares no provider, so the committed id would be ambiguous")
	}
	if name == "" {
		return "", NewError(ErrCommitModelProviderMissing,
			"[model] declares no name, so the committed id would be ambiguous")
	}
	return provider + "/" + name, nil
}
