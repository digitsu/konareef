// Copyright 2026 Jerry David Chan, Konareef.ai
// SPDX-License-Identifier: Apache-2.0

// commit_test.go — tests for CanonicalizeV2, the konareef-toml/v2
// emitter that appends the [_commit] trailer after [_files].
package canon

import (
	"bytes"
	"testing"
)

func TestCanonicalizeV2AppendsCommitAfterFiles(t *testing.T) {
	dir := t.TempDir()
	input := []byte("#!konareef-toml/v1\n[pod]\nname = \"x\"\n")
	out, err := CanonicalizeV2(input, dir, CommitParams{CMax: 7})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.HasPrefix(out, []byte("#!konareef-toml/v2\n")) {
		t.Fatalf("missing v2 magic: %q", out[:20])
	}
	files := bytes.Index(out, []byte("[_files]"))
	commit := bytes.Index(out, []byte("[_commit]"))
	if files == -1 || commit == -1 || commit < files {
		t.Fatalf("[_commit] must follow [_files]; files=%d commit=%d", files, commit)
	}
	want, err := FieldsRoot(nil, nil, 7, [32]byte{})
	if err != nil {
		t.Fatal(err)
	}
	got, err := ParseCommitFieldsRoot(out)
	if err != nil {
		t.Fatalf("emitted trailer does not parse: %v", err)
	}
	if got != want {
		t.Fatalf("fields_root = %x, want %x", got, want)
	}
	if out[len(out)-1] != '\n' {
		t.Fatal("output must end with a newline")
	}
}

func TestCanonicalizeV2BodyMatchesV1Body(t *testing.T) {
	dir := t.TempDir()
	input := []byte("#!konareef-toml/v1\n[pod]\nname = \"x\"\nb = 2\na = 1\n")
	v1, err := Canonicalize(input, dir)
	if err != nil {
		t.Fatal(err)
	}
	v2, err := CanonicalizeV2(input, dir, CommitParams{})
	if err != nil {
		t.Fatal(err)
	}
	// v2 = v1 with the magic line swapped, plus the trailer.
	body1 := bytes.TrimPrefix(v1, []byte(magicHeader))
	body2 := bytes.TrimPrefix(v2, []byte(magicHeaderV2))
	commit := bytes.Index(body2, []byte("[_commit]"))
	if !bytes.Equal(body1, body2[:commit]) {
		t.Fatalf("author tree or [_files] differs between v1 and v2")
	}
}
