// Copyright 2026 Jerry David Chan, Konareef.ai
// SPDX-License-Identifier: Apache-2.0

// commitparse.go — verifier-side parser for the konareef-toml/v2
// `[_commit]` trailer: the `fields_root` commitment and the optional
// `r_init_scheme` marker (konareef-rinit/v1 spec D2-A).
//
// This is the reverse of fieldsroot.go's producer: where FieldsRoot
// COMPUTES the Poseidon commitment from the four manifest fields, this
// file READS the already-committed value straight out of a canonical-v2
// manifest's final `[_commit]` section. The CL-5(a) verifier needs it to
// bind `[_commit].fields_root` to the proof's carried genesis lane
// (genesis_fields_root) without recomputing canon.FieldsRoot — the
// disclosed manifest is h_manifest-bound, so its committed fields_root is
// itself bound to the proven computation.
package canon

import (
	"bytes"
	"encoding/hex"
	"fmt"
)

// v2Magic is the konareef-toml/v2 first-line magic (konareef-toml/v2
// spec §0). A canonical-v2 manifest MUST begin with these exact bytes.
var v2Magic = []byte("#!konareef-toml/v2")

// maxEchoedFirstLine caps how much of a refused first line
// ParseCommitTrailer copies into its error message.
const maxEchoedFirstLine = 64

// v3Magic is the konareef-toml/v3 first-line magic (konareef-toml/v3 spec
// §0). A v3 manifest carries the same `[_commit]` trailer as v2; only the
// declared_tools set inside fields_root differs.
var v3Magic = []byte("#!konareef-toml/v3")

// commitFieldsRootPrefix is the value prefix the canonicalizer stamps in
// front of the 64-hex Poseidon root (konareef-toml/v2 spec §1).
const commitFieldsRootPrefix = "poseidon:"

// ParseCommitFieldsRoot extracts the 32-byte fields_root commitment from
// a canonical konareef-toml/v2 or v3 manifest's `[_commit]` trailer.
//
// Input:
//
//	manifest — the canonical-v2 or v3 manifest bytes (the same h_manifest-bound
//	bytes the verifier discloses). See ParseCommitTrailer for the exact
//	trailer grammar.
//
// Output:
//
//	[32]byte — the 32 little-endian bytes the 64 hex chars decode to
//	(the same orientation as genesis_fields_root =
//	fq_to_le_bytes(witness.fields_root)), for a byte-for-byte compare.
//	error — non-nil (fail-closed) on every error ParseCommitTrailer
//	returns, including an unknown r_init_scheme. On error the returned
//	array is the zero value and MUST NOT be used.
//
// Callers that need the r_init_scheme marker as well (the canonical
// read-back in CanonicalizeLike, the memory-root classifier) call
// ParseCommitTrailer directly.
func ParseCommitFieldsRoot(manifest []byte) ([32]byte, error) {
	t, err := ParseCommitTrailer(manifest)
	if err != nil {
		return [32]byte{}, err
	}
	return t.FieldsRoot, nil
}

// ParseCommitTrailer parses the `[_commit]` trailer of a canonical
// konareef-toml/v2 or v3 manifest. The two versions share one trailer
// grammar.
//
// Input: the manifest bytes. They MUST start with the exact
// `#!konareef-toml/v2` or `#!konareef-toml/v3` magic line and end with a
// `[_commit]` section whose keys are:
//
//	fields_root   = "poseidon:<64 lowercase hex>"   required, once
//	r_init_scheme = "konareef-rinit/v1"             optional, at most once
//
// The two keys may appear in either order, which matches the PS-1
// preflight parser (paygate-zk crates/paygate-zk-prove/src/commit.rs).
// Order is still load-bearing for the signed bytes: the canonicalizer
// always writes fields_root first, so a reordered trailer does not
// reproduce pod_hash through CanonicalizeLike.
//
// Output: the parsed CommitTrailer, with RInitScheme "" when the marker is
// absent (a legacy manifest). error is non-nil (fail-closed) on any of:
// missing/wrong v2 or v3 magic line; no `[_commit]` section; a line that is not
// `key = "value"`; any key other than the two above; a duplicate key; a
// missing fields_root; a fields_root without the `poseidon:` prefix or not
// exactly 64 lowercase hex characters; and a coded
// COMMIT_RINIT_SCHEME_UNKNOWN *Error for an r_init_scheme other than
// RInitSchemeV1. An unknown scheme is refused here, not left to the
// caller, because every caller binds fields_root to a proof or to a pod
// hash, and a root of unknown derivation has no defined meaning to bind.
//
// The function is deliberately strict and simple: the `[_commit]` section
// is the FINAL section, so a line-oriented scan suffices.
func ParseCommitTrailer(manifest []byte) (CommitTrailer, error) {
	var none CommitTrailer

	// The magic MUST be the EXACT first line (terminated by '\n', or the whole
	// input). A bare prefix check would accept e.g. "#!konareef-toml/v2evil" as
	// v2 — this is the trust boundary for canonical-manifest acceptance, so the
	// first-line delimiter is enforced strictly.
	firstLine := manifest
	if nl := bytes.IndexByte(manifest, '\n'); nl >= 0 {
		firstLine = manifest[:nl]
	}
	if !bytes.Equal(firstLine, v2Magic) && !bytes.Equal(firstLine, v3Magic) {
		// The line is untrusted and may be megabytes long; echo at most
		// maxEchoedFirstLine bytes of it.
		shown := firstLine
		if len(shown) > maxEchoedFirstLine {
			shown = shown[:maxEchoedFirstLine]
		}
		return none, fmt.Errorf("not a konareef-toml/v2 or v3 manifest: first line %q is neither %q nor %q",
			string(shown), string(v2Magic), string(v3Magic))
	}

	// Locate the final `[_commit]` section header. The canonicalizer
	// emits it as the last section, so the trailing key lines belong to
	// it.
	commitIdx := bytes.LastIndex(manifest, []byte("[_commit]"))
	if commitIdx < 0 {
		return none, fmt.Errorf("no [_commit] section in manifest")
	}

	// Scan the lines AFTER the [_commit] header. Reject duplicates (an
	// ambiguous commitment is a soundness hazard) and every key outside the
	// two the trailer grammar permits.
	section := manifest[commitIdx+len("[_commit]"):]
	var hexStr, scheme string
	foundRoot, foundScheme := false, false
	for _, rawLine := range bytes.Split(section, []byte("\n")) {
		line := bytes.TrimSpace(rawLine)
		if len(line) == 0 {
			continue
		}
		// A new section header ends the [_commit] section; the [_commit]
		// trailer is final, but stop scanning to be safe.
		if line[0] == '[' {
			break
		}
		key, val, ok := splitKeyValue(line)
		if !ok {
			// A line that is not `key = value` is non-canonical. Reject
			// rather than skip.
			return none, fmt.Errorf("malformed line in [_commit] (expected `key = value`): %q", string(line))
		}
		switch key {
		case "fields_root":
			if foundRoot {
				return none, fmt.Errorf("duplicate fields_root key in [_commit]")
			}
			unquoted, ok := unquoteBasicString(val)
			if !ok {
				return none, fmt.Errorf("malformed fields_root value (expected a quoted string): %q", string(val))
			}
			hexStr = unquoted
			foundRoot = true
		case "r_init_scheme":
			if foundScheme {
				return none, fmt.Errorf("duplicate r_init_scheme key in [_commit]")
			}
			unquoted, ok := unquoteBasicString(val)
			if !ok {
				return none, fmt.Errorf("malformed r_init_scheme value (expected a quoted string)")
			}
			scheme = unquoted
			foundScheme = true
		default:
			// Extra committed keys would let future or ambiguous [_commit]
			// material ride through the commitment binding. Fail closed.
			return none, fmt.Errorf("unexpected key %q in [_commit] (permitted keys: fields_root, r_init_scheme)", key)
		}
	}
	if !foundRoot {
		return none, fmt.Errorf("missing fields_root key in [_commit] section")
	}

	if len(hexStr) <= len(commitFieldsRootPrefix) || hexStr[:len(commitFieldsRootPrefix)] != commitFieldsRootPrefix {
		return none, fmt.Errorf("fields_root missing %q prefix: %q", commitFieldsRootPrefix, hexStr)
	}
	hexPart := hexStr[len(commitFieldsRootPrefix):]

	if len(hexPart) != 64 {
		return none, fmt.Errorf("fields_root hex length=%d, want 64", len(hexPart))
	}
	for i := 0; i < len(hexPart); i++ {
		c := hexPart[i]
		isLowerHex := (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')
		if !isLowerHex {
			return none, fmt.Errorf("fields_root hex contains non-lowercase-hex char %q at index %d", string(c), i)
		}
	}

	decoded, err := hex.DecodeString(hexPart)
	if err != nil {
		return none, fmt.Errorf("fields_root hex decode: %w", err)
	}
	if len(decoded) != 32 {
		// Unreachable given the len==64 check above, but fail-closed.
		return none, fmt.Errorf("fields_root decoded width=%d, want 32", len(decoded))
	}
	// The scheme is checked after fields_root, in the same order as the
	// PS-1 preflight, so both report the same reason for the same input. A
	// present-but-empty marker is an unknown scheme, not a legacy trailer.
	if foundScheme && scheme != RInitSchemeV1 {
		return none, newErr(ErrCommitRInitSchemeUnknown,
			"[_commit] r_init_scheme names a derivation this build does not support; supported: "+RInitSchemeV1)
	}
	var t CommitTrailer
	copy(t.FieldsRoot[:], decoded)
	t.RInitScheme = scheme
	return t, nil
}

// splitKeyValue splits a trimmed `key = value` TOML line into its key
// and (trimmed) value. The bool is false when the line has no `=`.
func splitKeyValue(line []byte) (key string, val []byte, ok bool) {
	eq := bytes.IndexByte(line, '=')
	if eq < 0 {
		return "", nil, false
	}
	key = string(bytes.TrimSpace(line[:eq]))
	val = bytes.TrimSpace(line[eq+1:])
	return key, val, true
}

// unquoteBasicString strips the surrounding double quotes from a TOML
// basic string. The fields_root value is a fixed ASCII `poseidon:<hex>`
// token, so no escape processing is needed; the bool is false when the
// value is not a `"..."`-quoted string.
func unquoteBasicString(val []byte) (string, bool) {
	if len(val) < 2 || val[0] != '"' || val[len(val)-1] != '"' {
		return "", false
	}
	inner := val[1 : len(val)-1]
	// Reject any embedded quote — the value is a simple flat token.
	if bytes.IndexByte(inner, '"') >= 0 {
		return "", false
	}
	return string(inner), true
}
