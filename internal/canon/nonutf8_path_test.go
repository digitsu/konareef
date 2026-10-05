// Copyright 2026 Jerry David Chan, Konareef.ai
// SPDX-License-Identifier: Apache-2.0

//go:build linux

// nonutf8_path_test.go — R15 path-UTF-8 rejection on Linux.
//
// On Linux filenames are arbitrary non-zero byte sequences, including
// invalid UTF-8. macOS (APFS/HFS+) normalizes filenames to UTF-8 and
// rejects invalid byte sequences at the syscall, so the test is
// linux-gated; CI runs on Linux and will exercise it.
package canon

import (
	"os"
	"path/filepath"
	"testing"
)

// TestNonUTF8PathRejected confirms a filename whose bytes are not
// valid UTF-8 is a fatal PATH_INVALID rejection. Without this check,
// Go's rune iteration would collapse the bytes to U+FFFD and two
// distinct files could land at the same [_files] key.
func TestNonUTF8PathRejected(t *testing.T) {
	dir := t.TempDir()
	podTOML := []byte("[pod]\nname = \"nonutf8-path\"\n")
	if err := os.WriteFile(filepath.Join(dir, "pod.toml"), podTOML, 0o644); err != nil {
		t.Fatalf("write pod.toml: %v", err)
	}
	badName := "\xff\xfe.bin"
	if err := os.WriteFile(filepath.Join(dir, badName), []byte("payload"), 0o644); err != nil {
		t.Skipf("filesystem rejected non-UTF-8 filename: %v", err)
	}

	out, err := Canonicalize(podTOML, dir)
	if err == nil {
		t.Fatalf("expected PATH_INVALID, got %d bytes of output", len(out))
	}
	if Code(err) != ErrPathInvalid {
		t.Fatalf("expected %s, got %s (%v)", ErrPathInvalid, Code(err), err)
	}
	if out != nil {
		t.Errorf("a rejection must produce no output; got %d bytes", len(out))
	}
}
