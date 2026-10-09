// Copyright 2026 Jerry David Chan, Konareef.ai
// SPDX-License-Identifier: Apache-2.0

// internal/saltstore/manifest_test.go — round-trips lineage_id between
// the pod.Spec manifest and a [16]byte; covers missing-field and
// invalid-hex error paths.
package saltstore

import (
	"errors"
	"testing"

	"github.com/digitsu/konareef/internal/pod"
)

func TestLineageIDRoundTrip(t *testing.T) {
	want := [16]byte{0x0d, 0x8f, 0x4a, 0x2c, 0x3e, 0x1b, 0x5a, 0x76,
		0xd9, 0xc8, 0xf2, 0xa1, 0xb3, 0xe4, 0xd5, 0xf6}
	spec := &pod.Spec{Pod: pod.Identity{Name: "demo", Version: "0.1.0"}}
	WriteLineageID(spec, want)
	got, err := LineageIDFromManifest(spec)
	if err != nil {
		t.Fatalf("LineageIDFromManifest: %v", err)
	}
	if got != want {
		t.Errorf("got %x, want %x", got, want)
	}
}

func TestLineageIDMissingErrors(t *testing.T) {
	spec := &pod.Spec{Pod: pod.Identity{Name: "demo", Version: "0.1.0"}}
	_, err := LineageIDFromManifest(spec)
	if !errors.Is(err, ErrSaltManifestMissingLineageID) {
		t.Fatalf("err = %v, want ErrSaltManifestMissingLineageID", err)
	}
}

func TestLineageIDInvalidHexErrors(t *testing.T) {
	spec := &pod.Spec{Pod: pod.Identity{
		Name:      "demo",
		Version:   "0.1.0",
		LineageID: "not-hex-at-all",
	}}
	_, err := LineageIDFromManifest(spec)
	if !errors.Is(err, ErrSaltLineageIDInvalid) {
		t.Fatalf("err = %v, want ErrSaltLineageIDInvalid", err)
	}
}
