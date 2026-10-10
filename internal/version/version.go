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
//
// seam/2 (MEM-SEAM): step-disclosure.json carries initial_memory for every
// run of a published konareef-toml/v2 or v3 manifest, and the feeder
// fetches the signed memory leaf table for a memory-bearing one
// (--memory-leaf-table-url). A seam/1 feeder would ignore both.
//
// seam/3 (CL-4-live, konareef-rinit/v2 spec R-M24): a memory-bearing run's
// step-disclosure.json also carries touched_cell_id, the leaf table is v2
// (konareef-mem-leaves/v2), and the PS-1 memory lane adds key_tag and
// content_hash. The feeder proves the R-M23 cell (lowest cell_id) and
// never reads the step index as a memory index. reef-core changes its
// @expected_seam_version in lockstep.
const SeamVersion = "seam/3"

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
