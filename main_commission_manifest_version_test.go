// Copyright 2026 Jerry David Chan, Konareef.ai
// SPDX-License-Identifier: Apache-2.0

// main_commission_manifest_version_test.go — the version gate on the bytes
// `commission verify --manifest` hashes.
//
// readManifestForVerify has to decide whether the file it was handed is an
// author-written pod.toml (canonicalize it) or canonicalizer output (hash it
// verbatim). It asked canon.HasVersionMagic, which answers "have these bytes
// already been canonicalized" and says yes to ANY `#!konareef-toml/vN`. So a
// manifest claiming a version this binary cannot read was passed through as
// though it had been validated, and `verify` would bless a commission
// against it. Nothing here produces a non-v1 manifest, so the honest answer
// to one is refusal — these tests hold that shut.
package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/digitsu/konareef/internal/canon"
)

// canonicalV1Manifest returns genuine canonicalizer output for the sample
// pod, so the cases below vary nothing but the version identifier on the
// magic line. Hand-written bytes would let a case pass for the wrong reason.
func canonicalV1Manifest(t *testing.T) []byte {
	t.Helper()
	manifestBytes, _, err := resolvePodSpecManifest(writeSamplePodDir(t), "", "dave", "mybot", "0.1.0")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.HasPrefix(manifestBytes, []byte("#!konareef-toml/v1\n")) {
		t.Fatalf("setup: expected v1 canonicalizer output, got %.32q", manifestBytes)
	}
	return manifestBytes
}

// writeManifestFile drops bytes into their own directory, because
// readManifestForVerify canonicalizes a non-canonical file against the
// directory it sits in.
func writeManifestFile(t *testing.T, name string, content []byte) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, content, 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

// TestReadManifestForVerify_AcceptsV1CanonicalBytesVerbatim is the control.
// Without it, the refusals below would also be satisfied by a gate that
// refused every already-canonical manifest — which would break `verify`
// against an install cache's manifest.canon, the case the verbatim path
// exists for.
func TestReadManifestForVerify_AcceptsV1CanonicalBytesVerbatim(t *testing.T) {
	canonical := canonicalV1Manifest(t)
	got, err := readManifestForVerify(writeManifestFile(t, "manifest.canon", canonical))
	if err != nil {
		t.Fatalf("v1 canonicalizer output must be accepted, got %v", err)
	}
	if !bytes.Equal(got, canonical) {
		t.Fatal("v1 canonicalizer output must be returned byte-identical; re-canonicalizing it would change the hash")
	}
}

// TestReadManifestForVerify_RejectsUnsupportedCanonicalVersions is the
// discriminating case. Every input is byte-identical to accepted v1 output
// except for the version token, so nothing but the version gate can tell
// them apart — the old code returned all of them verbatim.
//
// "v2" is deliberately NOT in this table (Task 9 step E): once
// canon.HasSupportedVersionMagic accepts v2, a genuine v2 manifest is no
// longer refused here at all — see
// TestReadManifestForVerify_AcceptsV2CanonicalBytes in
// main_commission_v2_verify_test.go for the acceptance case. This branch
// only gates on the version token; it does not validate that a
// v2-claiming file's body is well-formed v2 output (no [_commit] trailer
// check) — see readManifestForVerify's doc comment (fix round 2) for why
// that reproduction/shape check does not belong at this call site.
func TestReadManifestForVerify_RejectsUnsupportedCanonicalVersions(t *testing.T) {
	canonical := canonicalV1Manifest(t)
	body := bytes.TrimPrefix(canonical, []byte("#!konareef-toml/v1"))

	// v10 and v1.1 are the near-misses: they share v1's first two
	// characters, so a prefix test that forgot the line terminator would
	// wave them through.
	for _, version := range []string{"v10", "v999", "v1.1", ""} {
		t.Run("version "+version, func(t *testing.T) {
			claimed := append([]byte("#!konareef-toml/"+version), body...)
			path := writeManifestFile(t, "manifest.canon", claimed)

			got, err := readManifestForVerify(path)
			if err == nil {
				t.Fatalf("a manifest claiming konareef-toml/%s must be refused; this build cannot validate that format, got %d bytes back", version, len(got))
			}
			if !strings.Contains(err.Error(), "unsupported canonical manifest version") {
				t.Fatalf("the refusal must say the version is unsupported, got %q", err)
			}
			if !strings.Contains(err.Error(), version) {
				t.Fatalf("the refusal must name the version it refused (%q), got %q", version, err)
			}
		})
	}
}

// TestReadManifestForVerify_AcceptsCanonicalBytesWithNonEmptyFiles is the
// fix-round-2 regression test. A CANONICAL manifest whose `[_files]`
// section commits real pod files — true of most real pods — must still be
// ACCEPTED here, verbatim, even though this call site has no access to
// those files on disk (the manifest is written to a fresh, unrelated
// directory, nowhere near prompts/system.md).
//
// Before fix round 2, this failed: the branch re-derived the bytes
// against an empty scratch directory, which can never reproduce a
// non-empty `[_files]` section, so a perfectly valid manifest was wrongly
// rejected. That rejection is the regression this test exists to catch if
// it ever comes back.
func TestReadManifestForVerify_AcceptsCanonicalBytesWithNonEmptyFiles(t *testing.T) {
	podDir := t.TempDir()
	podTOML := []byte("pod_spec_version = \"0.1\"\n\n[pod]\nname = \"mybot\"\nversion = \"0.1.0\"\n\n[runtime]\nkind = \"claude-code\"\n\n[directive]\ntemplate = \"./prompts/system.md\"\n")
	if err := os.WriteFile(filepath.Join(podDir, "pod.toml"), podTOML, 0o644); err != nil {
		t.Fatal(err)
	}
	prompts := filepath.Join(podDir, "prompts")
	if err := os.MkdirAll(prompts, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(prompts, "system.md"), []byte("hello"), 0o644); err != nil {
		t.Fatal(err)
	}

	canonical, err := canon.Canonicalize(podTOML, podDir)
	if err != nil {
		t.Fatalf("setup: canonicalize: %v", err)
	}
	if !bytes.Contains(canonical, []byte("[_files]")) {
		t.Fatal("setup: expected a canonical manifest with a [_files] section")
	}
	if bytes.Contains(canonical, []byte("[_files]\n[")) || bytes.HasSuffix(canonical, []byte("[_files]\n")) {
		t.Fatal("setup: expected a NON-EMPTY [_files] section (must list prompts/system.md)")
	}

	// Write the canonical bytes into a directory with NOTHING else in it —
	// no prompts/, no system.md — to prove acceptance does not depend on
	// the real pod tree being reachable from here.
	path := writeManifestFile(t, "manifest.canon", canonical)

	got, err := readManifestForVerify(path)
	if err != nil {
		t.Fatalf("a canonical manifest with a non-empty [_files] section must be accepted without access to the real pod tree, got %v", err)
	}
	if !bytes.Equal(got, canonical) {
		t.Fatal("canonical bytes must be returned byte-identical")
	}
}

// TestReadManifestForVerify_StillCanonicalizesAnAuthorWrittenPodTOML guards
// the other half of the branch. The gate must only apply to files that claim
// a canonical magic line; a plain pod.toml has none and must still be
// canonicalized, which is what makes `verify --manifest pod.toml` work at
// all.
func TestReadManifestForVerify_StillCanonicalizesAnAuthorWrittenPodTOML(t *testing.T) {
	got, err := readManifestForVerify(filepath.Join(writeSamplePodDir(t), "pod.toml"))
	if err != nil {
		t.Fatalf("an author-written pod.toml must still be canonicalized, got %v", err)
	}
	if !bytes.HasPrefix(got, []byte("#!konareef-toml/v1\n")) {
		t.Fatalf("expected canonicalized v1 output, got %.32q", got)
	}
}
