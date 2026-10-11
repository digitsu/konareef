// Copyright 2026 Jerry David Chan, Konareef.ai
// SPDX-License-Identifier: Apache-2.0

// internal/saltstore/manifest.go — bridge between the `pod` package's
// in-memory Spec and the saltstore-typed [16]byte lineage_id.
package saltstore

import (
	"encoding/hex"
	"fmt"

	"github.com/digitsu/konareef/internal/pod"
)

// LineageIDFromManifest decodes spec.Pod.LineageID into a [16]byte.
// Returns ErrSaltManifestMissingLineageID when the field is empty
// (Type-D session-start fail-closed gate) and ErrSaltLineageIDInvalid
// when the hex string is malformed or the wrong length.
func LineageIDFromManifest(spec *pod.Spec) ([16]byte, error) {
	if spec == nil || spec.Pod.LineageID == "" {
		return [16]byte{}, ErrSaltManifestMissingLineageID
	}
	raw, err := hex.DecodeString(spec.Pod.LineageID)
	if err != nil {
		return [16]byte{}, fmt.Errorf("%w: %v", ErrSaltLineageIDInvalid, err)
	}
	if len(raw) != 16 {
		return [16]byte{}, fmt.Errorf("%w: want 16 bytes, got %d", ErrSaltLineageIDInvalid, len(raw))
	}
	var lid [16]byte
	copy(lid[:], raw)
	return lid, nil
}

// WriteLineageID sets the 32-char lowercase-hex encoding into the
// spec. Safe to call repeatedly; the field is overwritten.
func WriteLineageID(spec *pod.Spec, lid [16]byte) {
	spec.Pod.LineageID = hex.EncodeToString(lid[:])
}
