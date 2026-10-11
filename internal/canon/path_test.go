// Copyright 2026 Jerry David Chan, Konareef.ai
// SPDX-License-Identifier: Apache-2.0

// path_test.go — R15 path-handling rejections that cannot be expressed
// as committed golden vectors.
//
// PATH_INVALID needs a path that escapes the pod root, and
// FILE_NOT_READABLE needs an unreadable file — neither is reproducible
// portably as a checked-in fixture, so both are exercised in code.
package canon

import (
	"os"
	"path/filepath"
	"testing"
)

// TestRelSlashRejectsEscape exercises relSlash's PATH_INVALID rejection
// directly: a path that cannot be relativized to a clean in-tree path
// must never be hashed into [_files].
func TestRelSlashRejectsEscape(t *testing.T) {
	cases := []struct{ name, dir, path string }{
		{"parent-escape", "/pods/mypod", "/pods/file.txt"},
		{"sibling-escape", "/pods/mypod", "/pods/other/file.txt"},
		{"absolute-elsewhere", "/pods/mypod", "/etc/passwd"},
		{"unrelatable", "relative-dir", "/absolute/path"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			rel, err := relSlash(c.dir, c.path)
			if err == nil {
				t.Fatalf("expected PATH_INVALID, got rel=%q", rel)
			}
			if Code(err) != ErrPathInvalid {
				t.Fatalf("expected %s, got %s (%v)", ErrPathInvalid, Code(err), err)
			}
		})
	}
}

// TestFileNotReadable confirms an unreadable file in the pod directory
// is a fatal FILE_NOT_READABLE rejection rather than a silent skip —
// a skipped file would drop out of the signed [_files] manifest.
func TestFileNotReadable(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("running as root: mode-0000 files remain readable")
	}
	dir := t.TempDir()
	podTOML := []byte("[pod]\nname = \"unreadable-test\"\n")
	if err := os.WriteFile(filepath.Join(dir, "pod.toml"), podTOML, 0o644); err != nil {
		t.Fatalf("write pod.toml: %v", err)
	}
	secret := filepath.Join(dir, "secret.bin")
	if err := os.WriteFile(secret, []byte("payload"), 0o644); err != nil {
		t.Fatalf("write secret.bin: %v", err)
	}
	if err := os.Chmod(secret, 0o000); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	// Restore read permission so t.TempDir cleanup can remove the file.
	t.Cleanup(func() { _ = os.Chmod(secret, 0o644) })

	out, err := Canonicalize(podTOML, dir)
	if err == nil {
		t.Fatalf("expected FILE_NOT_READABLE, got %d bytes of output", len(out))
	}
	if Code(err) != ErrFileNotReadable {
		t.Fatalf("expected %s, got %s (%v)", ErrFileNotReadable, Code(err), err)
	}
}
