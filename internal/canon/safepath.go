// Copyright 2026 Jerry David Chan, Konareef.ai
// SPDX-License-Identifier: Apache-2.0

// safepath.go — the pod-relative path rule shared with reef-core.
//
// reef-core's Pod.Spec.SafeRelativePath (lib/pod/spec/safe_relative_path.ex)
// is what the server checks on every pod-relative path it stores or joins
// onto a directory it writes to: a closed pod's decrypted body files, and
// an inline spawn request's companion `files` keys. konareef's own walk
// (files.go's walkPod, and publish/tarball.go's mirror of it) is stricter
// than the raw filesystem in some ways already — no symlink, no hidden
// dotfile — but until SEC-56 it did not refuse everything the server
// refuses: a real Unix filename may legally contain a backslash or start
// with "X:", bytes the server's rule treats as unsafe. Publishing such a
// pod passed konareef's own check and then failed on reef-core, after the
// author had already signed and hashed it.
//
// SafeRelativePath closes that gap: it is checked wherever konareef walks
// a pod directory or accepts a caller-supplied relative path for hashing
// or packing, so the local check refuses locally what the server would
// refuse remotely.
package canon

import (
	"fmt"
	"strings"
	"unicode/utf8"
)

// maxSafePathSegmentBytes and maxSafePathBytes are reef-core's bounds
// (Pod.Spec.SafeRelativePath @max_segment_bytes / @max_path_bytes): a
// path within them is one every common filesystem can hold.
const (
	maxSafePathSegmentBytes = 255
	maxSafePathBytes        = 1024
)

// SafeRelativePath reports whether rel is safe to publish or hash, by the
// same rule reef-core enforces server-side. rel must already be a walk's
// clean, slash-separated, non-empty relative path — relSlash and the
// publish package's tarball walk both produce exactly that shape before
// calling this. Unlike the Elixir rule, this does not accept or strip a
// leading "./": no konareef-produced rel ever carries one, so a caller
// that has one is passing something other than a walk result.
//
// A safe path has no NUL byte, no backslash, no Windows drive prefix
// ("C:", "c:x" — checked once against the whole path, matching
// Pod.Spec.SafeRelativePath.drive_prefixed?/1, not per segment), no
// empty, "." or ".." segment, no segment over 255 bytes, and is at most
// 1024 bytes long overall. It must also be valid UTF-8 — every caller
// here already established that for its own reasons, but it is checked
// again so this function is self-contained.
//
// Returns a *Error with code ErrPathInvalid, the same code relSlash
// already uses for a path that escapes the pod directory: both mean
// "this path cannot be trusted," never a silent rewrite or truncation.
func SafeRelativePath(rel string) error {
	if rel == "" {
		return newErr(ErrPathInvalid, "path is empty")
	}
	if len(rel) > maxSafePathBytes {
		return newErr(ErrPathInvalid, fmt.Sprintf("%s exceeds the %d-byte path cap", rel, maxSafePathBytes))
	}
	if !utf8.ValidString(rel) {
		return newErr(ErrPathInvalid, "path contains invalid UTF-8")
	}
	if strings.ContainsAny(rel, "\x00\\") {
		return newErr(ErrPathInvalid, fmt.Sprintf("%s contains a NUL byte or a backslash", rel))
	}
	if drivePrefixed(rel) {
		return newErr(ErrPathInvalid, fmt.Sprintf("%s has a Windows drive prefix", rel))
	}
	for _, segment := range strings.Split(rel, "/") {
		switch segment {
		case "", ".", "..":
			return newErr(ErrPathInvalid, fmt.Sprintf("%s has an empty, \".\" or \"..\" segment", rel))
		}
		if len(segment) > maxSafePathSegmentBytes {
			return newErr(ErrPathInvalid, fmt.Sprintf("%s has a segment over %d bytes", rel, maxSafePathSegmentBytes))
		}
	}
	return nil
}

// drivePrefixed reports whether rel begins with a single ASCII letter
// followed by ':' — "C:/x" and "c:x" are ordinary relative paths on a
// POSIX host but name a drive on Windows, so no pod needs one. Mirrors
// Pod.Spec.SafeRelativePath.drive_prefixed?/1.
func drivePrefixed(rel string) bool {
	if len(rel) < 2 || rel[1] != ':' {
		return false
	}
	c := rel[0]
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
}
