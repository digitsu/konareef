// Copyright 2026 Jerry David Chan, Konareef.ai
// SPDX-License-Identifier: Apache-2.0

// Package version exposes the konareef build version.
//
// The value is injected at release-build time via
//
//	-ldflags "-X github.com/digitsu/konareef/internal/version.version=v0.1.0"
//
// (goreleaser does this automatically). Absent that injection, String()
// falls back to the Go module version recorded in the binary's build info,
// which `go install github.com/digitsu/konareef@vX.Y.Z` populates from the
// VCS tag. A plain `go build` of a working tree reports "dev".
package version

import "runtime/debug"

// SeamVersion is the step-disclosure seam format this binary reads and
// writes. reef-core refuses to spawn a feeder reporting anything else — a
// stale feeder produces a proof over a misinterpreted disclosure, which
// verifies but attests the wrong thing. Bump only when the seam format
// changes.
const SeamVersion = "seam/1"

// version is set via ldflags at release-build time. It is empty for a plain
// `go build` and for `go install` (where build info provides the value).
var version = ""

// String returns the konareef version string.
//
// Precedence:
//  1. the ldflags-injected value (release binaries), else
//  2. the module version from the embedded build info (`go install m@vX.Y.Z`),
//     ignoring the placeholder "(devel)", else
//  3. "dev" (a plain `go build` of a working tree).
//
// It never returns an empty string.
func String() string {
	if version != "" {
		return version
	}
	if info, ok := debug.ReadBuildInfo(); ok {
		if v := info.Main.Version; v != "" && v != "(devel)" {
			return v
		}
	}
	return "dev"
}
