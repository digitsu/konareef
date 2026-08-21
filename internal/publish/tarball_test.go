// Copyright 2026 Jerry David Chan, Konareef.ai
// SPDX-License-Identifier: Apache-2.0

package publish

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/rand"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// Round-trip: pack a pod dir, extract it elsewhere, and the extracted
// tree must be file-for-file byte-identical. Determinism: packing the
// same dir twice yields identical bytes (sorted entries, zeroed times).
func TestPackTarballRoundTripAndDeterminism(t *testing.T) {
	dir := t.TempDir()
	mustWrite(t, filepath.Join(dir, "pod.toml"), "pod_spec_version = \"0.1\"\n")
	mustWrite(t, filepath.Join(dir, "prompts", "system.md"), "# directive\n")

	tb1, err := PackTarball(dir)
	if err != nil {
		t.Fatalf("PackTarball: %v", err)
	}
	tb2, err := PackTarball(dir)
	if err != nil {
		t.Fatalf("PackTarball (2nd): %v", err)
	}
	if !bytes.Equal(tb1, tb2) {
		t.Fatal("tarball not deterministic")
	}

	out := t.TempDir()
	if err := ExtractTarball(tb1, out); err != nil {
		t.Fatalf("ExtractTarball: %v", err)
	}
	for _, rel := range []string{"pod.toml", "prompts/system.md"} {
		want, _ := os.ReadFile(filepath.Join(dir, rel))
		got, err := os.ReadFile(filepath.Join(out, rel))
		if err != nil || !bytes.Equal(want, got) {
			t.Fatalf("extracted %s differs or missing: %v", rel, err)
		}
	}
}

func TestPackTarballCapAndTraversalSafety(t *testing.T) {
	dir := t.TempDir()
	mustWrite(t, filepath.Join(dir, "pod.toml"), "x = 1\n")
	// Random bytes so the content is incompressible — the resulting
	// tarball must exceed the 1 MiB compressed cap.
	big := make([]byte, 2*1024*1024) // 2 MiB
	if _, err := rand.Read(big); err != nil {
		t.Fatalf("rand.Read: %v", err)
	}
	mustWrite(t, filepath.Join(dir, "big.bin"), string(big))
	if _, err := PackTarball(dir); err == nil {
		t.Fatal("expected size-cap error for >1MiB compressed tarball")
	}

	// Extraction must reject entries escaping the target dir.
	evil := tarWithEntry(t, "../escape.txt", "boom")
	if err := ExtractTarball(evil, t.TempDir()); err == nil {
		t.Fatal("expected path-traversal rejection")
	}
}

// TestExtractTarballRejectsZipBomb exercises the decompressed-size
// guard directly: a single entry of 9 MiB of zero bytes compresses to
// a tiny gzip stream (gzip.BestCompression eats runs of zeros almost
// for free) but declares a Size past maxDecompressedTarballSize (8
// MiB) — the exact shape the cap exists to catch. Extraction must
// reject it before writing anything to dest.
func TestExtractTarballRejectsZipBomb(t *testing.T) {
	huge := make([]byte, 9*1024*1024) // zero-filled: compresses to almost nothing
	bomb := tarWithEntry(t, "bomb.bin", string(huge))

	dest := t.TempDir()
	if err := ExtractTarball(bomb, dest); err == nil {
		t.Fatal("expected rejection of an entry whose declared size exceeds the decompressed cap")
	}
	entries, err := os.ReadDir(dest)
	if err != nil {
		t.Fatalf("ReadDir(dest): %v", err)
	}
	if len(entries) != 0 {
		t.Fatalf("ExtractTarball wrote %d entries to dest after rejecting the zip bomb", len(entries))
	}
}

// TestPackTarballRejectsSymlink mirrors canon's hard rejection of
// symlinks: PackTarball must fail rather than silently skip or follow
// one, since a symlink inside podDir could smuggle arbitrary host
// content into what's supposed to be a faithful copy of the pod.
func TestPackTarballRejectsSymlink(t *testing.T) {
	dir := t.TempDir()
	mustWrite(t, filepath.Join(dir, "pod.toml"), "x = 1\n")
	mustWrite(t, filepath.Join(dir, "real.txt"), "hello\n")
	if err := os.Symlink(filepath.Join(dir, "real.txt"), filepath.Join(dir, "link.txt")); err != nil {
		t.Fatalf("symlink: %v", err)
	}
	if _, err := PackTarball(dir); err == nil {
		t.Fatal("expected PackTarball to reject a symlink inside the pod directory")
	}
}

// TestPackTarballEmptySubdirectoryRoundTrip confirms an empty
// subdirectory survives pack + extract — PackTarball writes an
// explicit tar.TypeDir entry for every directory (not just the ones
// implied by file paths), so a subtree with no files still exists
// after extraction.
func TestPackTarballEmptySubdirectoryRoundTrip(t *testing.T) {
	dir := t.TempDir()
	mustWrite(t, filepath.Join(dir, "pod.toml"), "x = 1\n")
	if err := os.MkdirAll(filepath.Join(dir, "empty"), 0o755); err != nil {
		t.Fatalf("mkdir empty: %v", err)
	}

	tb, err := PackTarball(dir)
	if err != nil {
		t.Fatalf("PackTarball: %v", err)
	}
	out := t.TempDir()
	if err := ExtractTarball(tb, out); err != nil {
		t.Fatalf("ExtractTarball: %v", err)
	}
	info, err := os.Stat(filepath.Join(out, "empty"))
	if err != nil {
		t.Fatalf("empty subdirectory missing after extraction: %v", err)
	}
	if !info.IsDir() {
		t.Fatalf("empty is not a directory after extraction")
	}
}

// TestExtractTarballRejectsHiddenEntry mirrors PackTarball's hidden-
// entry exclusion on the extract side: a tarball carrying a top-level
// `.evil` entry or a nested `.git/config` was never produced by
// PackTarball (its walk skips both), so ExtractTarball must reject
// them rather than write unverified content — content pod_hash never
// covered — to disk.
func TestExtractTarballRejectsHiddenEntry(t *testing.T) {
	for _, name := range []string{".evil", ".git/config"} {
		evil := tarWithEntry(t, name, "boom")
		dest := t.TempDir()
		err := ExtractTarball(evil, dest)
		if !errors.Is(err, ErrTarballHiddenEntry) {
			t.Fatalf("%s: expected ErrTarballHiddenEntry, got %v", name, err)
		}
		entries, readErr := os.ReadDir(dest)
		if readErr != nil {
			t.Fatalf("%s: ReadDir(dest): %v", name, readErr)
		}
		if len(entries) != 0 {
			t.Fatalf("%s: ExtractTarball wrote %d entries to dest after rejecting a hidden entry", name, len(entries))
		}
	}
}

// TestPackTarballRejectsOversizedDecompressedContent enforces the
// publishable-implies-installable contract at pack time: a pod whose
// content decompresses past ExtractTarball's zip-bomb cap
// (maxDecompressedTarballSize) must be rejected by PackTarball itself,
// not merely accepted and left to fail later on install. The payload
// is random (crypto/rand) so gzip can't compress it away — the
// decompressed-content check fires while packing is still under way,
// before the eventual compressed-size check would even run.
func TestPackTarballRejectsOversizedDecompressedContent(t *testing.T) {
	dir := t.TempDir()
	mustWrite(t, filepath.Join(dir, "pod.toml"), "x = 1\n")
	huge := make([]byte, 9*1024*1024) // 9 MiB > the 8 MiB decompressed cap
	if _, err := rand.Read(huge); err != nil {
		t.Fatalf("rand.Read: %v", err)
	}
	mustWrite(t, filepath.Join(dir, "huge.bin"), string(huge))

	if _, err := PackTarball(dir); !errors.Is(err, ErrTarballContentTooLarge) {
		t.Fatalf("expected ErrTarballContentTooLarge, got %v", err)
	}
}

func mustWrite(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

// tarWithEntry builds a raw gzip tar containing a single crafted entry
// with the given (possibly malicious) name and content, bypassing
// PackTarball entirely — used to exercise ExtractTarball's traversal
// guard against inputs PackTarball itself would never produce.
func tarWithEntry(t *testing.T, name, content string) []byte {
	t.Helper()
	var buf bytes.Buffer
	gw := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gw)
	hdr := &tar.Header{
		Name:     name,
		Typeflag: tar.TypeReg,
		Mode:     0o644,
		Size:     int64(len(content)),
	}
	if err := tw.WriteHeader(hdr); err != nil {
		t.Fatalf("write tar header: %v", err)
	}
	if _, err := tw.Write([]byte(content)); err != nil {
		t.Fatalf("write tar content: %v", err)
	}
	if err := tw.Close(); err != nil {
		t.Fatalf("close tar writer: %v", err)
	}
	if err := gw.Close(); err != nil {
		t.Fatalf("close gzip writer: %v", err)
	}
	return buf.Bytes()
}
