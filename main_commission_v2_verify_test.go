// Copyright 2026 Jerry David Chan, Konareef.ai
// SPDX-License-Identifier: Apache-2.0

// main_commission_v2_verify_test.go — `commission verify --manifest`
// against a konareef-toml/v2 manifest.
//
// readManifestForVerify used to gate acceptance on
// canon.HasSupportedVersionMagic, which (before Task 9's step E) answers
// v1 only — a v2 install cache's manifest.canon, or a v2 server-fetched
// manifest, would be refused with "this build reads konareef-toml/v1
// only" even though this build can by then dispatch on v2 elsewhere
// (canon.CanonicalizeLike, install.verifyContentTarball). This file pins
// that a real v2 manifest, produced by the actual publish pipeline, is
// accepted verbatim by readManifestForVerify once the gate is widened —
// this branch never re-derives the bytes (fix round 2), it only gates on
// the version token and returns raw canonical bytes unchanged.
package main

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/digitsu/konareef/internal/canon"
	"github.com/digitsu/konareef/internal/identity"
	"github.com/digitsu/konareef/internal/publish"
)

// buildV2ManifestFile runs the real publish.Prepare(..., PrepareOptions{ZK:
// true}) pipeline over samplePodTOML (already [model]+[budget]-complete,
// see writeSamplePodDir) and writes the resulting canonical v2 bytes to
// their own scratch directory — mirroring an install cache's
// manifest.canon layout, which is what readManifestForVerify's
// already-canonical branch is for.
func buildV2ManifestFile(t *testing.T) string {
	t.Helper()
	podDir := writeSamplePodDir(t)
	id, err := identity.Generate("dave")
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	prep, err := publish.Prepare(podDir, id, publish.PrepareOptions{ZK: true})
	if err != nil {
		t.Fatalf("Prepare(ZK): %v", err)
	}
	if !bytes.HasPrefix(prep.CanonicalBytes, []byte("#!konareef-toml/v2\n")) {
		t.Fatalf("setup: expected v2 canonicalizer output, got %.32q", prep.CanonicalBytes)
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "manifest.canon")
	if err := os.WriteFile(path, prep.CanonicalBytes, 0o644); err != nil {
		t.Fatalf("write manifest.canon: %v", err)
	}
	return path
}

// TestReadManifestForVerify_AcceptsV2CanonicalBytes is the discriminating
// case for Task 9 step E: this must fail with "unsupported canonical
// manifest version" before HasSupportedVersionMagic is widened, and pass
// (returning the manifest verbatim, unchanged) after.
func TestReadManifestForVerify_AcceptsV2CanonicalBytes(t *testing.T) {
	path := buildV2ManifestFile(t)
	original, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}

	got, err := readManifestForVerify(path)
	if err != nil {
		t.Fatalf("a v2 manifest.canon must be accepted, got %v", err)
	}
	if !bytes.Equal(got, original) {
		t.Fatal("v2 canonicalizer output must be returned byte-identical")
	}
}

// TestReadManifestForVerify_StillRejectsAGenuinelyUnsupportedVersion is the
// control: v999 (a version nothing in this repo ever produces) must still
// be refused after the gate is widened to v1+v2 — the widening must not
// turn into "accept anything with a magic line".
func TestReadManifestForVerify_StillRejectsAGenuinelyUnsupportedVersion(t *testing.T) {
	canonicalV1 := canonicalV1Manifest(t)
	body := bytes.TrimPrefix(canonicalV1, []byte("#!konareef-toml/v1"))
	claimed := append([]byte("#!konareef-toml/v999"), body...)
	path := writeManifestFile(t, "manifest.canon", claimed)

	got, err := readManifestForVerify(path)
	if err == nil {
		t.Fatalf("a v999 manifest must still be refused, got %d bytes back", len(got))
	}
}

// TestCanonHasSupportedVersionMagic_AcceptsV1AndV2 pins the widened gate
// itself (canon.go HasSupportedVersionMagic), independent of the CLI
// plumbing above.
func TestCanonHasSupportedVersionMagic_AcceptsV1AndV2(t *testing.T) {
	if !canon.HasSupportedVersionMagic([]byte("#!konareef-toml/v1\n")) {
		t.Error("v1 magic must be supported")
	}
	if !canon.HasSupportedVersionMagic([]byte("#!konareef-toml/v2\n")) {
		t.Error("v2 magic must be supported")
	}
	if canon.HasSupportedVersionMagic([]byte("#!konareef-toml/v999\n")) {
		t.Error("v999 magic must NOT be supported")
	}
}
