// Copyright 2026 Jerry David Chan, Konareef.ai
// SPDX-License-Identifier: Apache-2.0

// canonlike_test.go — tests for CanonicalizeLike, the read-back helper
// that canonicalizes AUTHOR input at the version (and, for v2, the
// [_commit] trailer) of a separately-authenticated REFERENCE document.
package canon

import (
	"bytes"
	"crypto/sha256"
	"testing"
)

// TestCanonicalizeLike_V1Reference_IsPlainCanonicalize pins that a v1
// reference makes CanonicalizeLike behave exactly like Canonicalize —
// there is no trailer to reuse, and the reference's own bytes play no
// role beyond picking the version.
func TestCanonicalizeLike_V1Reference_IsPlainCanonicalize(t *testing.T) {
	dir := t.TempDir()
	author := []byte("#!konareef-toml/v1\n[pod]\nname = \"x\"\n")
	reference := []byte("#!konareef-toml/v1\n[pod]\nname = \"totally different\"\n")

	got, err := CanonicalizeLike(author, dir, reference)
	if err != nil {
		t.Fatalf("CanonicalizeLike: %v", err)
	}
	want, err := Canonicalize(author, dir)
	if err != nil {
		t.Fatalf("Canonicalize: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("v1 reference must behave exactly like Canonicalize(author, dir):\ngot  %q\nwant %q", got, want)
	}
}

// TestCanonicalizeLike_V2Reference_ReusesReferenceTrailer is the matching
// case: author and reference commit the same author tree, so
// CanonicalizeLike must emit v2 output whose fields_root equals the
// reference's own committed fields_root, and whose hash matches a fully
// re-derived CanonicalizeV2 over the same input.
func TestCanonicalizeLike_V2Reference_ReusesReferenceTrailer(t *testing.T) {
	dir := t.TempDir()
	author := []byte("#!konareef-toml/v1\n[pod]\nname = \"x\"\n")

	reference, err := CanonicalizeV2(author, dir, CommitParams{CMax: 42})
	if err != nil {
		t.Fatalf("CanonicalizeV2 (building reference): %v", err)
	}
	wantRoot, err := ParseCommitFieldsRoot(reference)
	if err != nil {
		t.Fatalf("ParseCommitFieldsRoot (reference): %v", err)
	}

	got, err := CanonicalizeLike(author, dir, reference)
	if err != nil {
		t.Fatalf("CanonicalizeLike: %v", err)
	}
	if !bytes.HasPrefix(got, []byte(magicHeaderV2)) {
		t.Fatalf("expected v2 magic, got %.32q", got)
	}
	gotRoot, err := ParseCommitFieldsRoot(got)
	if err != nil {
		t.Fatalf("ParseCommitFieldsRoot (got): %v", err)
	}
	if gotRoot != wantRoot {
		t.Fatalf("fields_root = %x, want reference's own %x", gotRoot, wantRoot)
	}
	if !bytes.Equal(got, reference) {
		t.Fatalf("author tree identical to reference's own author tree must reproduce reference byte-for-byte:\ngot  %q\nwant %q", got, reference)
	}
}

// TestCanonicalizeLike_V2Reference_TamperedTreeDoesNotMatch is the
// controller-mandated tamper test: when author's tree DIFFERS from what
// reference committed to, CanonicalizeLike must still emit reference's
// trailer verbatim (it recomputes no commitment) — but the resulting
// bytes, and therefore their hash, must NOT match reference's hash. This
// is what lets install.go's sha256(canonBytes) != PodHash check catch a
// tampered tarball: the trailer alone cannot make tampered content pass.
func TestCanonicalizeLike_V2Reference_TamperedTreeDoesNotMatch(t *testing.T) {
	dir := t.TempDir()
	original := []byte("#!konareef-toml/v1\n[pod]\nname = \"x\"\n")
	reference, err := CanonicalizeV2(original, dir, CommitParams{CMax: 42})
	if err != nil {
		t.Fatalf("CanonicalizeV2 (building reference): %v", err)
	}

	tampered := []byte("#!konareef-toml/v1\n[pod]\nname = \"y\"\n")
	got, err := CanonicalizeLike(tampered, dir, reference)
	if err != nil {
		t.Fatalf("CanonicalizeLike: %v", err)
	}

	if bytes.Equal(got, reference) {
		t.Fatal("a tampered author tree must not reproduce reference's bytes")
	}
	if sha256.Sum256(got) == sha256.Sum256(reference) {
		t.Fatal("a tampered author tree must not reproduce reference's hash")
	}
	// The trailer itself is still reference's own, byte for byte — only
	// the body preceding it differs. This pins that CanonicalizeLike
	// really does reuse the trailer rather than, say, silently refusing
	// on mismatch (which would also make the hashes differ, but for the
	// wrong reason, and would defeat the "no CommitParams needed" design
	// goal the doc comment describes).
	gotRoot, err := ParseCommitFieldsRoot(got)
	if err != nil {
		t.Fatalf("ParseCommitFieldsRoot (got): %v", err)
	}
	wantRoot, err := ParseCommitFieldsRoot(reference)
	if err != nil {
		t.Fatalf("ParseCommitFieldsRoot (reference): %v", err)
	}
	if gotRoot != wantRoot {
		t.Fatalf("fields_root = %x, want reference's own %x (trailer must be reused, not recomputed)", gotRoot, wantRoot)
	}
}

// TestCanonicalizeLike_UnrecognisedReference_Errors is the "do not guess"
// case: a reference with no v1 or v2 magic line must be refused, not
// silently treated as v1.
func TestCanonicalizeLike_UnrecognisedReference_Errors(t *testing.T) {
	dir := t.TempDir()
	author := []byte("#!konareef-toml/v1\n[pod]\nname = \"x\"\n")

	cases := map[string][]byte{
		"no magic at all":   []byte("[pod]\nname = \"x\"\n"),
		"unknown version":   []byte("#!konareef-toml/v999\n[pod]\nname = \"x\"\n"),
		"near-miss version": []byte("#!konareef-toml/v1.1\n[pod]\nname = \"x\"\n"),
		"empty reference":   []byte(""),
	}
	for name, reference := range cases {
		t.Run(name, func(t *testing.T) {
			got, err := CanonicalizeLike(author, dir, reference)
			if err == nil {
				t.Fatalf("expected an error for an unrecognised reference, got %d bytes back", len(got))
			}
			if Code(err) != ErrWrongVersion {
				t.Fatalf("Code(err) = %q, want %q", Code(err), ErrWrongVersion)
			}
		})
	}
}
