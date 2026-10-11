// Copyright 2026 Jerry David Chan, Konareef.ai
// SPDX-License-Identifier: Apache-2.0

// Package pod: schema access.
//
// SchemaJSON exposes the schema that Validate checks against, so tooling and
// coding agents can read the exact shape this binary enforces. Before this,
// the only route to the schema was to reconstruct it from documentation, and
// a reconstruction can disagree with the binary without anything noticing.
package pod

// SchemaJSON returns the embedded pod.toml v0.1 JSON Schema.
//
// The result is a fresh copy on every call. The embedded bytes back every
// validation this process performs, so handing out the original would let one
// caller corrupt validation for the whole program.
func SchemaJSON() []byte {
	out := make([]byte, len(schemaJSON))
	copy(out, schemaJSON)
	return out
}
