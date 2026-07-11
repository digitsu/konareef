// Copyright 2026 Jerry David Chan, Konareef.ai
// SPDX-License-Identifier: Apache-2.0

// tarball.go — the deterministic pod content tarball packed and
// uploaded alongside the signed manifest.
//
// The signature only covers pod_hash, which is derived from
// canon.Canonicalize(pod.toml, podDir) — the canonical manifest plus a
// `[_files]` section binding every other pod file's SHA-256 into the
// hash. That's enough to *verify* a pod a publisher already has on
// disk, but reef-core's install path (Task B3) needs the actual bytes
// too. PackTarball ships them: a gzip tar of the pod directory that,
// once extracted, reproduces pod_hash bit-for-bit when re-run through
// canon.Canonicalize. That reproduction is the whole feature's
// integrity check — see the Prepare test in publish_test.go.
//
// The walk mirrors internal/canon's buildFilesSection inclusion rules
// (read that file first) with one deliberate difference: canon
// excludes the root pod.toml and pod.lock from its `[_files]` listing
// because pod.toml is the document being hashed (listing it would be
// circular) and pod.lock is excluded from the hash for the same
// reason a lockfile normally is. Neither exclusion means "don't ship
// the file" — install needs pod.toml on disk to recompute the hash at
// all, and pod.lock (once dependency locking lands) needs to travel
// with the pod like any other content. So PackTarball includes both;
// everything else (hidden dotfiles/dirs skipped, symlinks and
// non-regular files hard-rejected) matches canon exactly.
//
// Two guarantees hold across the pack/extract boundary, both enforced
// with the same predicate or constant on both sides so they can never
// drift apart:
//
//   - Hidden exclusion is symmetric. isHiddenName is the one place that
//     decides whether a path component is a hidden dotfile/dir; pack
//     uses it to skip such entries during the walk, extract uses it to
//     reject any tarball entry that carries one. A legitimate
//     PackTarball output never contains a hidden entry, so one showing
//     up on extraction means the tarball was hand-crafted or tampered
//     with after packing — never a case for silently dropping the
//     entry.
//   - Publishable implies installable. maxDecompressedTarballSize caps
//     both ExtractTarball's total decompressed write (the zip-bomb
//     guard) and PackTarball's total uncompressed content (checked
//     while packing, distinct from the 1 MiB *compressed* cap below).
//     Without the pack-time check, a pod could squeeze under the
//     compressed cap while decompressing past what an installer will
//     accept — passing publish but failing install.
package publish

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// maxCompressedTarballSize is the hard cap on the packed, gzip'd
// tarball (spec: "1 MiB compressed"). Enforced here on the client
// side; reef-core (Task B1) enforces the identical cap server-side.
// A pod over this cap is rejected outright — never truncated.
const maxCompressedTarballSize = 1 << 20 // 1 MiB

// maxDecompressedTarballSize is the hard cap on total uncompressed
// content bytes, enforced on BOTH sides of the wire: ExtractTarball
// applies it to bytes actually written (the zip-bomb guard), and
// PackTarball applies it to the sum of entry sizes before anything is
// compressed. One constant, one number, so a tarball that clears
// PackTarball is guaranteed to clear ExtractTarball too. It is
// intentionally larger than maxCompressedTarballSize (a legitimately
// compressible pod can decompress to somewhat more than its packed
// size) but still small enough that a malicious ratio bomb can't
// exhaust disk.
const maxDecompressedTarballSize = 8 << 20 // 8 MiB

// ErrTarballTooLarge is returned by PackTarball when the compressed
// output exceeds maxCompressedTarballSize. Terminal — the publisher
// must trim the pod directory before republishing.
var ErrTarballTooLarge = errors.New("ERR_TARBALL_TOO_LARGE")

// ErrTarballContentTooLarge is returned by PackTarball when the sum of
// uncompressed entry sizes exceeds maxDecompressedTarballSize — the
// same cap ExtractTarball enforces on decompression. Without this
// check a pod could squeeze under the compressed cap yet decompress to
// more than an installer will accept; catching it at pack time means
// nothing PackTarball emits can fail ExtractTarball's zip-bomb guard.
// Terminal — the publisher must trim the pod directory.
var ErrTarballContentTooLarge = errors.New("ERR_TARBALL_CONTENT_TOO_LARGE")

// ErrTarballHiddenEntry is returned by ExtractTarball when an entry's
// path contains a hidden dotfile/dir component (see isHiddenName).
// PackTarball's walk excludes every such entry, so a legitimate
// tarball never carries one — seeing one on extraction means the
// tarball was hand-crafted or tampered with after packing, smuggling
// bytes pod_hash never covered. Terminal — the tarball is treated as
// hostile and nothing further is extracted from it.
var ErrTarballHiddenEntry = errors.New("ERR_TARBALL_HIDDEN_ENTRY")

// ErrTarballUnsafeEntry is returned by ExtractTarball when an entry
// would escape destDir (absolute path or `..` traversal), is a
// symlink/hardlink/device rather than a plain file or directory, or
// would push total decompressed bytes past maxDecompressedTarballSize.
// Terminal — the tarball is treated as hostile and nothing further is
// extracted from it.
var ErrTarballUnsafeEntry = errors.New("ERR_TARBALL_UNSAFE_ENTRY")

// isHiddenName reports whether name — a single path component, not a
// full path — is a hidden dotfile/dir by the same rule internal/canon
// applies: it begins with `.`. This is the ONE predicate both
// walkPodForTarball (which skips such entries) and ExtractTarball
// (which rejects any tarball entry carrying one) call, so pack's
// exclusion and extract's rejection can never drift apart.
func isHiddenName(name string) bool {
	return strings.HasPrefix(name, ".")
}

// pathHasHiddenComponent reports whether any slash-separated component
// of rel — a tar entry name, already `/`-separated per the tar format —
// is hidden per isHiddenName. A directory entry's trailing slash
// yields a harmless empty final component. ExtractTarball uses this to
// reject entries nested arbitrarily deep under a hidden directory
// (e.g. `.git/config`), not just ones hidden at the top level.
func pathHasHiddenComponent(rel string) bool {
	for _, part := range strings.Split(rel, "/") {
		if isHiddenName(part) {
			return true
		}
	}
	return false
}

// tarEntry is one file or directory queued for the tarball, discovered
// during the podDir walk.
type tarEntry struct {
	rel   string // slash-separated path relative to podDir
	abs   string // absolute path for reading (files only)
	isDir bool
}

// PackTarball walks podDir and produces a gzip-compressed tar of its
// contents, suitable for the `content_tarball` wire field. The output
// is fully deterministic for a given directory: entries are sorted by
// relative path, permissions are normalized to 0644 (files) / 0755
// (dirs), and every mod time is zeroed — so re-packing an unchanged
// pod byte-for-byte reproduces the prior tarball, and two publishers
// building the same pod content independently get identical bytes.
//
// The walk mirrors internal/canon's buildFilesSection rules: hidden
// dotfiles and dot-directories (and their subtrees) are skipped;
// symlinks and non-regular files (FIFOs, sockets, devices) are a hard
// error, never a silent skip — the same reasoning applies here as
// there, a symlink could smuggle arbitrary host content into what's
// supposed to be a faithful copy of the pod directory. Unlike canon's
// `[_files]` listing, the root pod.toml (and pod.lock, if present) ARE
// included — they're physical pod content, just excluded from canon's
// hash listing to avoid circularity.
//
// Returns ErrTarballTooLarge if the compressed result exceeds the
// 1 MiB cap, or ErrTarballContentTooLarge if the sum of uncompressed
// entry sizes exceeds maxDecompressedTarballSize (never truncated —
// either way the publisher must trim the pod directory).
func PackTarball(podDir string) ([]byte, error) {
	entries, err := walkPodForTarball(podDir)
	if err != nil {
		return nil, err
	}

	sort.Slice(entries, func(i, j int) bool { return entries[i].rel < entries[j].rel })

	var buf bytes.Buffer
	gw, err := gzip.NewWriterLevel(&buf, gzip.BestCompression)
	if err != nil {
		return nil, fmt.Errorf("create gzip writer: %w", err)
	}
	tw := tar.NewWriter(gw)

	var totalContent int64
	for _, e := range entries {
		if e.isDir {
			hdr := &tar.Header{
				Name:     e.rel + "/",
				Typeflag: tar.TypeDir,
				Mode:     0o755,
				ModTime:  time.Unix(0, 0),
			}
			if err := tw.WriteHeader(hdr); err != nil {
				return nil, fmt.Errorf("write tar header for %s: %w", e.rel, err)
			}
			continue
		}

		content, err := os.ReadFile(e.abs)
		if err != nil {
			return nil, fmt.Errorf("read %s: %w", e.rel, err)
		}
		// Enforced here, at pack time, so publishable implies
		// installable: without this check a pod could clear the 1 MiB
		// *compressed* cap below while decompressing to more than
		// ExtractTarball's zip-bomb guard will accept.
		totalContent += int64(len(content))
		if totalContent > maxDecompressedTarballSize {
			return nil, fmt.Errorf("%w: pod content totals more than %d bytes decompressed",
				ErrTarballContentTooLarge, maxDecompressedTarballSize)
		}
		hdr := &tar.Header{
			Name:     e.rel,
			Typeflag: tar.TypeReg,
			Mode:     0o644,
			Size:     int64(len(content)),
			ModTime:  time.Unix(0, 0),
		}
		if err := tw.WriteHeader(hdr); err != nil {
			return nil, fmt.Errorf("write tar header for %s: %w", e.rel, err)
		}
		if _, err := tw.Write(content); err != nil {
			return nil, fmt.Errorf("write tar content for %s: %w", e.rel, err)
		}
	}

	if err := tw.Close(); err != nil {
		return nil, fmt.Errorf("close tar writer: %w", err)
	}
	if err := gw.Close(); err != nil {
		return nil, fmt.Errorf("close gzip writer: %w", err)
	}

	if buf.Len() > maxCompressedTarballSize {
		return nil, fmt.Errorf("%w: %d bytes exceeds the %d-byte cap", ErrTarballTooLarge, buf.Len(), maxCompressedTarballSize)
	}
	return buf.Bytes(), nil
}

// walkPodForTarball enumerates the files and directories PackTarball
// ships, applying the inclusion/exclusion rules documented on
// PackTarball. It mirrors internal/canon's walkPod (files.go) rather
// than importing it: the two walks serve different purposes (hash
// listing vs. physical copy) and diverge on pod.toml/pod.lock, so a
// shared helper would need the same branching this local copy has.
func walkPodForTarball(podDir string) ([]tarEntry, error) {
	rootInfo, err := os.Lstat(podDir)
	if err != nil {
		return nil, fmt.Errorf("stat pod directory: %w", err)
	}
	if rootInfo.Mode()&fs.ModeSymlink != 0 {
		return nil, fmt.Errorf("pod root directory is a symlink")
	}

	var entries []tarEntry
	walkErr := filepath.WalkDir(podDir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return fmt.Errorf("walk %s: %w", path, err)
		}
		if path == podDir {
			return nil // the pod root itself is never its own entry
		}

		// Hard-rejection gates first, matching canon: these must fire
		// regardless of hidden-name status.
		if d.Type()&fs.ModeSymlink != 0 {
			rel, _ := filepath.Rel(podDir, path)
			return fmt.Errorf("%s is a symlink", filepath.ToSlash(rel))
		}
		if !d.IsDir() && !d.Type().IsRegular() {
			rel, _ := filepath.Rel(podDir, path)
			return fmt.Errorf("%s is not a regular file (mode=%s)", filepath.ToSlash(rel), d.Type())
		}

		// Soft-exclusion: hidden entries (name starts with `.`) are
		// skipped; a hidden directory skips its whole subtree.
		if isHiddenName(d.Name()) {
			if d.IsDir() {
				return fs.SkipDir
			}
			return nil
		}

		rel, relErr := filepath.Rel(podDir, path)
		if relErr != nil {
			return fmt.Errorf("relativize %s: %w", path, relErr)
		}
		entries = append(entries, tarEntry{
			rel:   filepath.ToSlash(rel),
			abs:   path,
			isDir: d.IsDir(),
		})
		return nil
	})
	if walkErr != nil {
		return nil, walkErr
	}
	return entries, nil
}

// ExtractTarball decompresses and unpacks a PackTarball-produced gzip
// tar into destDir, which must already exist. Every entry is checked
// before anything is written:
//
//   - absolute paths and any entry whose cleaned name escapes destDir
//     via a `..` component are rejected (path traversal / zip-slip);
//   - any entry with a hidden dotfile/dir path component (see
//     isHiddenName) is rejected — PackTarball's walk excludes every
//     such entry, so one appearing here means the tarball was
//     hand-crafted or tampered with, carrying content pod_hash never
//     covered;
//   - only regular files and directories are extracted — symlinks,
//     hardlinks, and device/FIFO entries are rejected outright, since
//     a symlink extracted into the caller's workspace could point
//     anywhere on the host;
//   - total decompressed bytes are capped at maxDecompressedTarballSize
//     (a zip-bomb guard: a small compressed input must not be able to
//     inflate into an unbounded write).
//
// Any rejection is ErrTarballUnsafeEntry or ErrTarballHiddenEntry
// (wrapped with detail) and leaves whatever was already written on
// disk — callers extract into a fresh scratch directory, never a
// location shared with anything else, so partial output is inert.
func ExtractTarball(data []byte, destDir string) error {
	gr, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return fmt.Errorf("open gzip stream: %w", err)
	}
	defer gr.Close()

	destAbs, err := filepath.Abs(destDir)
	if err != nil {
		return fmt.Errorf("resolve destination directory: %w", err)
	}

	tr := tar.NewReader(gr)
	var totalWritten int64
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("read tar entry: %w", err)
		}

		target, err := safeExtractPath(destAbs, hdr.Name)
		if err != nil {
			return err
		}
		if pathHasHiddenComponent(hdr.Name) {
			return fmt.Errorf("%w: %s has a hidden path component", ErrTarballHiddenEntry, hdr.Name)
		}

		switch hdr.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(target, 0o755); err != nil {
				return fmt.Errorf("create directory %s: %w", hdr.Name, err)
			}
		case tar.TypeReg:
			if hdr.Size < 0 {
				return fmt.Errorf("%w: %s has a negative size", ErrTarballUnsafeEntry, hdr.Name)
			}
			totalWritten += hdr.Size
			if totalWritten > maxDecompressedTarballSize {
				return fmt.Errorf("%w: decompressed content exceeds the %d-byte cap",
					ErrTarballUnsafeEntry, maxDecompressedTarballSize)
			}
			if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
				return fmt.Errorf("create parent directory for %s: %w", hdr.Name, err)
			}
			if err := writeExtractedFile(target, tr); err != nil {
				return fmt.Errorf("write %s: %w", hdr.Name, err)
			}
		default:
			return fmt.Errorf("%w: %s is not a regular file or directory (type=%v)",
				ErrTarballUnsafeEntry, hdr.Name, hdr.Typeflag)
		}
	}
	return nil
}

// safeExtractPath resolves a tar entry's name against destAbs
// (already an absolute path), rejecting anything that would land
// outside it. It is the zip-slip guard: an absolute entry name or one
// containing a `..` component must never be allowed to write beyond
// the caller's scratch directory.
func safeExtractPath(destAbs, name string) (string, error) {
	if filepath.IsAbs(name) {
		return "", fmt.Errorf("%w: %s is an absolute path", ErrTarballUnsafeEntry, name)
	}
	cleaned := filepath.Clean(filepath.FromSlash(name))
	if cleaned == ".." || strings.HasPrefix(cleaned, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("%w: %s escapes the destination directory", ErrTarballUnsafeEntry, name)
	}
	target := filepath.Join(destAbs, cleaned)
	if target != destAbs && !strings.HasPrefix(target, destAbs+string(filepath.Separator)) {
		return "", fmt.Errorf("%w: %s escapes the destination directory", ErrTarballUnsafeEntry, name)
	}
	return target, nil
}

// writeExtractedFile copies exactly one tar entry's content (the
// current position of tr) to a new regular file at target.
func writeExtractedFile(target string, tr *tar.Reader) error {
	f, err := os.OpenFile(target, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o644)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = io.Copy(f, tr)
	return err
}
