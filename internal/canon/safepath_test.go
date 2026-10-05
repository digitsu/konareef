// Copyright 2026 Jerry David Chan, Konareef.ai
// SPDX-License-Identifier: Apache-2.0

// safepath_test.go — SafeRelativePath unit coverage, plus one
// filesystem-integration test proving relSlash actually calls it (SEC-56
// parity with reef-core's Pod.Spec.SafeRelativePath).
package canon

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSafeRelativePath_Accepts(t *testing.T) {
	for _, rel := range []string{
		"a",
		"a/b/c",
		"café/menu.md",
		"prompts/system.md",
		strings.Repeat("a", maxSafePathSegmentBytes),              // exactly at the segment cap
		strings.Repeat("a", 100) + "/" + strings.Repeat("b", 100), // two segments, well under both caps
	} {
		t.Run(rel, func(t *testing.T) {
			if err := SafeRelativePath(rel); err != nil {
				t.Fatalf("SafeRelativePath(%q) = %v, want nil", rel, err)
			}
		})
	}
}

func TestSafeRelativePath_Refuses(t *testing.T) {
	cases := []struct {
		name string
		rel  string
	}{
		{"empty path", ""},
		{"backslash", `a\b`},
		{"NUL byte", "a\x00b"},
		{"drive prefix lowercase", "c:x"},
		{"drive prefix uppercase with slash", "C:/x"},
		{"empty segment (leading slash)", "/a"},
		{"empty segment (trailing slash)", "a/"},
		{"empty segment (doubled slash)", "a//b"},
		{"dot segment", "a/./b"},
		{"dot-dot segment", "a/../b"},
		{"bare dot-dot", ".."},
		{"segment over the 255-byte cap", strings.Repeat("a", maxSafePathSegmentBytes+1)},
		{"path over the 1024-byte cap", strings.Repeat("a", maxSafePathBytes+1)},
		{"invalid UTF-8", "a/\xff\xfe/b"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := SafeRelativePath(tc.rel)
			if err == nil {
				t.Fatalf("SafeRelativePath(%q) = nil, want %s", tc.rel, ErrPathInvalid)
			}
			if Code(err) != ErrPathInvalid {
				t.Fatalf("SafeRelativePath(%q): code = %s, want %s (%v)", tc.rel, Code(err), ErrPathInvalid, err)
			}
		})
	}
}

// TestSafeRelativePath_DrivePrefixIsWholePathNotPerSegment mirrors
// Pod.Spec.SafeRelativePath.drive_prefixed?/1: the check reads the first
// two bytes of the whole path, not of each "/"-separated segment, so a
// drive-shaped string that is not the leading segment is not a drive
// prefix.
func TestSafeRelativePath_DrivePrefixIsWholePathNotPerSegment(t *testing.T) {
	if err := SafeRelativePath("a/c:x"); err != nil {
		t.Fatalf("SafeRelativePath(%q) = %v, want nil: only the whole path's own prefix counts", "a/c:x", err)
	}
}

// TestSafeRelativePath_TwoLetterPrefixIsNotADrive confirms the drive
// check only fires for exactly one letter before ':', matching the
// Elixir guard `letter in ?a..?z or letter in ?A..?Z` applied to a single
// byte, not a run of them.
func TestSafeRelativePath_TwoLetterPrefixIsNotADrive(t *testing.T) {
	if err := SafeRelativePath("ab:x"); err != nil {
		t.Fatalf("SafeRelativePath(%q) = %v, want nil", "ab:x", err)
	}
}

// TestBackslashNamedFileRejected proves the check is actually wired into
// the pod-directory walk (relSlash), not just reachable as a standalone
// function. A backslash is a legal Unix filename byte, so this needs a
// real file on disk rather than a testdata fixture — a backslash in a
// path checked into a git tree round-trips fine on Linux, but committing
// one here would be surprising for anyone browsing the tree.
func TestBackslashNamedFileRejected(t *testing.T) {
	dir := t.TempDir()
	podTOML := []byte("[pod]\nname = \"backslash-test\"\n")
	if err := os.WriteFile(filepath.Join(dir, "pod.toml"), podTOML, 0o644); err != nil {
		t.Fatalf("write pod.toml: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, `a\b`), []byte("x"), 0o644); err != nil {
		t.Fatalf("write backslash-named file: %v", err)
	}

	out, err := Canonicalize(podTOML, dir)
	if err == nil {
		t.Fatalf("expected %s for a backslash-named file, got %d bytes of output", ErrPathInvalid, len(out))
	}
	if Code(err) != ErrPathInvalid {
		t.Fatalf("expected %s, got %s (%v)", ErrPathInvalid, Code(err), err)
	}
}

// TestDrivePrefixedFileRejected is the same proof for a "C:"-prefixed
// filename: legal on Linux, refused by SafeRelativePath.
func TestDrivePrefixedFileRejected(t *testing.T) {
	dir := t.TempDir()
	podTOML := []byte("[pod]\nname = \"drive-prefix-test\"\n")
	if err := os.WriteFile(filepath.Join(dir, "pod.toml"), podTOML, 0o644); err != nil {
		t.Fatalf("write pod.toml: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "c:x"), []byte("x"), 0o644); err != nil {
		t.Fatalf("write drive-prefixed file: %v", err)
	}

	out, err := Canonicalize(podTOML, dir)
	if err == nil {
		t.Fatalf("expected %s for a drive-prefixed file, got %d bytes of output", ErrPathInvalid, len(out))
	}
	if Code(err) != ErrPathInvalid {
		t.Fatalf("expected %s, got %s (%v)", ErrPathInvalid, Code(err), err)
	}
}
