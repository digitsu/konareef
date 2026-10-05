// Copyright 2026 Jerry David Chan, Konareef.ai
// SPDX-License-Identifier: Apache-2.0

// magicline.go — the near-miss magic-line gate (KR-MAGIC, konareef#29).
//
// Every other magic-line helper in this package (hasV1Magic, hasV2Magic,
// hasV3Magic, HasVersionMagic, VersionIdentifier, ClaimsCommitTrailer)
// tests exact bytes at offset 0. A first line such as `#!KONAREEF-TOML/V3`,
// ` #!konareef-toml/v3`, or a BOM or blank line before the magic matches
// none of them, so a caller used to read such a manifest as a magic-less
// legacy manifest that commits nothing, and the fields_root checks never
// ran. CheckMagicLine closes that gap: it refuses any first line that
// still claims a konareef-toml magic line after normalization but is not
// an exact v1, v2 or v3 magic line.
//
// The rule is the one paygate-zk PS-1 applies in claims_commit_trailer
// (crates/paygate-zk-prove/src/commit.rs, MCP-Z04), so the two refuse the
// same bytes: PS-1 answers commit_trailer_malformed, konareef answers
// MAGIC_NEAR_MISS.
package canon

import "bytes"

// magicPrefixNormalized is the magic prefix every konareef-toml version
// shares, in lower case with no version token. A first line that
// normalizes to text starting with it claims to be a canonical manifest.
const magicPrefixNormalized = "#!konareef-toml"

// Exact first lines (without the LF) that CheckMagicLine accepts as a
// magic line. v1 also accepts one trailing CR (a CRLF file), as
// hasV1Magic and PS-1 do; v2 and v3 do not, because their canonical
// output is always LF-terminated.
var (
	exactV1MagicLine = []byte(magicPrefix + "v1")
	exactV2MagicLine = []byte(magicPrefix + "v2")
	exactV3MagicLine = []byte(magicPrefix + "v3")
)

// CheckMagicLine refuses a near-miss konareef-toml magic line.
//
// Input: the manifest or author pod.toml bytes.
//
// Output: nil when the first line (the bytes before the first LF) is
// exactly `#!konareef-toml/v1` (optionally followed by one CR),
// `#!konareef-toml/v2` or `#!konareef-toml/v3`, or when the input does not
// claim a konareef-toml magic line at all (a legacy manifest or ordinary
// author input). Otherwise a *Error with code MAGIC_NEAR_MISS.
//
// "Claims a magic line" uses the PS-1 normalization: skip every leading
// byte that is not visible ASCII (0x21-0x7E), which includes blank lines,
// white space, control bytes, a BOM, NBSP and zero-width characters; take
// the rest of that line; drop every byte in it that is not visible ASCII;
// fold ASCII case. The input claims a magic line when the result starts
// with `#!konareef-toml`. So an unknown version such as
// `#!konareef-toml/v4` is also refused here; callers that already refuse
// it with a more specific code may run their own check first.
//
// The message carries no manifest bytes.
func CheckMagicLine(input []byte) error {
	firstLine := input
	if i := bytes.IndexByte(input, '\n'); i >= 0 {
		firstLine = input[:i]
	}
	if bytes.Equal(firstLine, exactV2MagicLine) || bytes.Equal(firstLine, exactV3MagicLine) ||
		bytes.Equal(firstLine, exactV1MagicLine) || bytes.Equal(bytes.TrimSuffix(firstLine, []byte("\r")), exactV1MagicLine) {
		return nil
	}
	if !claimsMagicLine(input) {
		return nil
	}
	return newErr(ErrMagicNearMiss,
		"first line claims a konareef-toml magic line but is not exactly the v1, v2 or v3 magic")
}

// claimsMagicLine reports whether input, after the PS-1 normalization
// described on CheckMagicLine, starts with `#!konareef-toml`.
//
// Input: the manifest bytes. Output: true when the first visible line
// normalizes to text that starts with magicPrefixNormalized.
func claimsMagicLine(input []byte) bool {
	start := 0
	for start < len(input) && !isVisibleASCII(input[start]) {
		start++
	}
	probe := make([]byte, 0, len(magicPrefixNormalized))
	for _, b := range input[start:] {
		if b == '\n' || len(probe) == len(magicPrefixNormalized) {
			break
		}
		if !isVisibleASCII(b) {
			continue
		}
		if 'A' <= b && b <= 'Z' {
			b += 'a' - 'A'
		}
		probe = append(probe, b)
	}
	return string(probe) == magicPrefixNormalized
}

// isVisibleASCII reports whether b is a visible ASCII character
// (0x21-0x7E), the set Rust's u8::is_ascii_graphic accepts.
func isVisibleASCII(b byte) bool { return b >= 0x21 && b <= 0x7E }
