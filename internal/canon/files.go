// Copyright 2026 Jerry David Chan, Konareef.ai
// SPDX-License-Identifier: Apache-2.0

// files.go — the synthetic `[_files]` manifest section (R15).
//
// After the author tree, the canonicalizer appends a `[_files]`
// section binding the manifest hash to every other file in the pod
// directory. This is what defeats the swap-after-signing attack: an
// adversary cannot alter prompts/system.md without changing pod_hash.
//
// The walk is intentionally strict. Symlinks are a hard failure, never
// a silent skip — a symlink can escape the pod directory and pull an
// arbitrary host file into the signed set. `.gitignore` is NOT
// honored: a hidden input that two publishers configure differently
// would let identical content produce different hashes, the exact
// non-determinism the canonicalizer exists to eliminate. The 1 MiB
// size cap is the tripwire for accidental bloat instead.
package canon

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"unicode/utf8"
)

// podSizeHardCap is the inclusive maximum total pod size (R15). The
// sum of every enumerated file plus pod.toml above this is a fatal
// POD_SIZE_EXCEEDED.
const podSizeHardCap = 1 << 20 // 1 MiB = 1,048,576 bytes

// podSizeWarnThreshold is the soft `pod-size-large` warning threshold
// (R15). A total above this but within podSizeHardCap is non-fatal: it
// yields a WarnPodSizeLarge advisory, surfaced through
// CanonicalizeWithWarnings.
const podSizeWarnThreshold = 100 << 10 // 100 KiB

// podFile is one enumerated pod file awaiting hashing.
type podFile struct {
	rel  string // slash-separated path relative to the pod root
	abs  string // absolute path for reading
	size int64  // byte length, for the size-cap sum
}

// buildFilesSection walks dir and renders the `[_files]` section.
// podTOMLSize is the byte length of the pod.toml document, included in
// the size-cap sum but never itself listed (it is the document being
// canonicalized; listing its hash would be circular).
//
// The returned warnings slice carries a WarnPodSizeLarge advisory when
// the total pod size is above the soft threshold but within the hard
// cap; it is nil otherwise.
func buildFilesSection(dir string, podTOMLSize int64) ([]byte, []Warning, error) {
	files, err := walkPod(dir)
	if err != nil {
		return nil, nil, err
	}

	total := podTOMLSize
	for _, f := range files {
		total += f.size
	}
	if total > podSizeHardCap {
		return nil, nil, newErr(ErrPodSizeExceeded,
			fmt.Sprintf("pod totals %d bytes, exceeding the %d-byte cap", total, podSizeHardCap))
	}
	var warnings []Warning
	if total > podSizeWarnThreshold {
		warnings = append(warnings, Warning{
			Code: WarnPodSizeLarge,
			Message: fmt.Sprintf("pod totals %d bytes, above the %d-byte advisory threshold",
				total, podSizeWarnThreshold),
		})
	}

	// R15: paths sorted lexicographically by their UTF-8 bytes. Go
	// string comparison is bytewise, so `<` is exactly that order.
	sort.Slice(files, func(i, j int) bool { return files[i].rel < files[j].rel })

	var b strings.Builder
	b.WriteString("[_files]\n")
	for _, f := range files {
		content, readErr := os.ReadFile(f.abs)
		if readErr != nil {
			return nil, nil, newErr(ErrFileNotReadable, fmt.Sprintf("%s: %v", f.rel, readErr))
		}
		digest := sha256.Sum256(content)
		b.WriteString(serializeString(f.rel))
		b.WriteString(" = ")
		b.WriteString(serializeString("sha256:" + hex.EncodeToString(digest[:])))
		b.WriteByte('\n')
	}
	return []byte(b.String()), warnings, nil
}

// BodyFiles returns the pod-relative paths that the `[_files]` table
// commits to, in the same lexicographic order buildFilesSection emits
// them. It is a thin projection of the SAME walk (walkPod) that builds
// the table, never a second one — a closed pod's encrypted body is
// packed over exactly this set, so if the two walks could diverge, the
// signed commitment and the shipped body would silently disagree and
// nothing would notice until spawn.
//
// Consequently the exclusions are `[_files]`'s exclusions, not "every
// file in the directory": the root pod.toml and pod.lock, and hidden
// dotfiles/dot-directories, are absent because pod_hash does not cover
// them.
//
// Input: dir — the pod root. Output: the sorted relative paths, or the
// same typed canon error walkPod would return (symlink, non-regular
// file, unreadable path, non-UTF-8 name).
func BodyFiles(dir string) ([]string, error) {
	files, err := walkPod(dir)
	if err != nil {
		return nil, err
	}
	paths := make([]string, 0, len(files))
	for _, f := range files {
		paths = append(paths, f.rel)
	}
	// Same comparison buildFilesSection sorts by (R15: lexicographic
	// over UTF-8 bytes, which is Go's bytewise string `<`), so the two
	// orderings are identical by construction.
	sort.Strings(paths)
	return paths, nil
}

// walkPod recursively enumerates the hashable files under dir,
// applying the R15 exclusion and rejection rules.
func walkPod(dir string) ([]podFile, error) {
	// filepath.WalkDir follows a symlinked *root* — "if root itself is
	// a symbolic link, its target will be walked" — and the per-entry
	// symlink check below never sees the root. Reject a symlinked pod
	// root up front, or it escapes SYMLINK_FORBIDDEN and an attacker
	// who controls the pod path could bind arbitrary host files into a
	// signed pod_hash.
	rootInfo, err := os.Lstat(dir)
	if err != nil {
		return nil, newErr(ErrFileNotReadable, fmt.Sprintf("%s: %v", dir, err))
	}
	if rootInfo.Mode()&fs.ModeSymlink != 0 {
		return nil, newErr(ErrSymlinkForbidden, "pod root directory is a symlink")
	}

	var files []podFile

	walkErr := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return newErr(ErrFileNotReadable, fmt.Sprintf("%s: %v", path, err))
		}
		if path == dir {
			return nil // the pod root itself
		}

		// Hard-rejection gates first: they must fire regardless of
		// hidden-name exclusion, because the rules forbid silent
		// skipping for these entry kinds.
		//
		// Symlinks: rejected (file or directory, root or interior).
		if d.Type()&fs.ModeSymlink != 0 {
			rel, _ := relSlash(dir, path) // best-effort path for the message
			return newErr(ErrSymlinkForbidden, fmt.Sprintf("%s is a symlink", rel))
		}
		// Non-regular non-directory entries (FIFOs, sockets, devices,
		// etc.): rejected, even when hidden. Their byte content is
		// not a stable file the way a regular file is, and a silent
		// skip could let a malicious pod hide content from the signed
		// manifest. The strict R15 wording forbids the silent skip
		// regardless of hidden-name status.
		if !d.IsDir() && !d.Type().IsRegular() {
			rel, _ := relSlash(dir, path) // best-effort path for the message
			return newErr(ErrNonRegularFile,
				fmt.Sprintf("%s is not a regular file (mode=%s)", rel, d.Type()))
		}

		// Soft-exclusion gates: hidden entries (name starts with `.`)
		// are excluded. A hidden directory excludes its whole subtree.
		if strings.HasPrefix(d.Name(), ".") {
			if d.IsDir() {
				return fs.SkipDir
			}
			return nil
		}
		if d.IsDir() {
			return nil
		}

		rel, relErr := relSlash(dir, path)
		if relErr != nil {
			return relErr
		}
		// pod.toml and pod.lock are excluded at the pod root only: the
		// root pod.toml is the document being canonicalized, and
		// pod.lock is the reserved dependency-lock filename. A file
		// that merely shares the name deeper in the tree is ordinary
		// content.
		if rel == "pod.toml" || rel == "pod.lock" {
			return nil
		}

		info, infoErr := d.Info()
		if infoErr != nil {
			return newErr(ErrFileNotReadable, fmt.Sprintf("%s: %v", rel, infoErr))
		}
		files = append(files, podFile{rel: rel, abs: path, size: info.Size()})
		return nil
	})

	if walkErr != nil {
		return nil, walkErr
	}
	return files, nil
}

// relSlash returns path relative to dir with `/` separators (R15: `/`
// even on Windows), or a PATH_INVALID error. A relative path that is
// absolute, equal to `..`, or contains a `..` component would escape
// the pod directory and is rejected here rather than hashed into the
// manifest. A failure to relativize is itself PATH_INVALID — never a
// silent fallback to an absolute path.
func relSlash(dir, path string) (string, error) {
	rel, err := filepath.Rel(dir, path)
	if err != nil {
		return "", newErr(ErrPathInvalid, fmt.Sprintf("cannot relativize %s to the pod root", path))
	}
	slashed := filepath.ToSlash(rel)
	if filepath.IsAbs(rel) || rel == ".." ||
		strings.HasPrefix(slashed, "../") || strings.Contains(slashed, "/../") {
		return "", newErr(ErrPathInvalid, fmt.Sprintf("%s escapes the pod directory", slashed))
	}
	// On Linux a filename can be any non-zero byte sequence — including
	// invalid UTF-8. Go's rune iteration turns those bytes into U+FFFD,
	// so two distinct byte-paths could collapse to the same key in
	// `[_files]`. Reject non-UTF-8 paths so the manifest key is always
	// a faithful representation of the on-disk name.
	if !utf8.ValidString(slashed) {
		return "", newErr(ErrPathInvalid, "pod-relative path contains non-UTF-8 bytes")
	}
	// A Unix filename may legally contain bytes reef-core's
	// Pod.Spec.SafeRelativePath refuses — a backslash, a "C:" drive
	// prefix, a segment over 255 bytes (SEC-56). Refuse them here too, so
	// a manifest that hashes cleanly on konareef never fails the server's
	// stricter check afterward.
	if err := SafeRelativePath(slashed); err != nil {
		return "", err
	}
	return slashed, nil
}
