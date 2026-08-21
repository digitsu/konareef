// Copyright 2026 Jerry David Chan, Konareef.ai
// SPDX-License-Identifier: Apache-2.0

// commitparse.go — verifier-side parser for the konareef-toml/v2
// `[_commit]` trailer's `fields_root` commitment.
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

// commitFieldsRootPrefix is the value prefix the canonicalizer stamps in
// front of the 64-hex Poseidon root (konareef-toml/v2 spec §1).
const commitFieldsRootPrefix = "poseidon:"

// ParseCommitFieldsRoot extracts the 32-byte fields_root commitment from
// a canonical konareef-toml/v2 manifest's `[_commit]` trailer.
//
// Input:
//
//	manifest — the canonical-v2 manifest bytes (the same h_manifest-bound
//	bytes the verifier discloses). MUST start with the `#!konareef-toml/v2`
//	magic line and end with a `[_commit]` section whose sole key is
//	`fields_root = "poseidon:<64 lowercase hex>"`.
//
// Output:
//
//	[32]byte — the 32 little-endian bytes the 64 hex chars decode to
//	(the same orientation as genesis_fields_root =
//	fq_to_le_bytes(witness.fields_root)), for a byte-for-byte compare.
//	error — non-nil (fail-closed) on any of: missing/wrong v2 magic
//	prefix; no `[_commit]` section; missing/duplicate/malformed
//	`fields_root` line; missing `poseidon:` prefix; hex not exactly 64
//	lowercase-hex chars; bad hex. On error the returned array is the
//	zero value and MUST NOT be used.
//
// The function is deliberately strict and simple: in v1 of the format the
// `[_commit]` section is the FINAL section and `fields_root` is its only
// key, so a line-oriented scan suffices.
func ParseCommitFieldsRoot(manifest []byte) ([32]byte, error) {
	var zero [32]byte

	// The magic MUST be the EXACT first line (terminated by '\n', or the whole
	// input). A bare prefix check would accept e.g. "#!konareef-toml/v2evil" as
	// v2 — this is the trust boundary for canonical-manifest acceptance, so the
	// first-line delimiter is enforced strictly.
	firstLine := manifest
	if nl := bytes.IndexByte(manifest, '\n'); nl >= 0 {
		firstLine = manifest[:nl]
	}
	if !bytes.Equal(firstLine, v2Magic) {
		return zero, fmt.Errorf("not a konareef-toml/v2 manifest: first line %q != %q", string(firstLine), string(v2Magic))
	}

	// Locate the final `[_commit]` section header. The canonicalizer
	// emits it as the last section, so the trailing key lines belong to
	// it.
	commitIdx := bytes.LastIndex(manifest, []byte("[_commit]"))
	if commitIdx < 0 {
		return zero, fmt.Errorf("no [_commit] section in manifest")
	}

	// Scan the lines AFTER the [_commit] header for the fields_root key.
	// Reject duplicates (an ambiguous commitment is a soundness hazard).
	section := manifest[commitIdx+len("[_commit]"):]
	var hexStr string
	found := false
	for _, rawLine := range bytes.Split(section, []byte("\n")) {
		line := bytes.TrimSpace(rawLine)
		if len(line) == 0 {
			continue
		}
		// A new section header ends the [_commit] section; in v1 the
		// [_commit] trailer is final, but stop scanning to be safe.
		if line[0] == '[' {
			break
		}
		key, val, ok := splitKeyValue(line)
		if !ok {
			// `fields_root` is the SOLE key of [_commit] (spec §1); a line that
			// is not `key = value` is non-canonical. Reject rather than skip.
			return zero, fmt.Errorf("malformed line in [_commit] (expected `key = value`): %q", string(line))
		}
		if key != "fields_root" {
			// Extra committed keys violate the sole-key contract; accepting them
			// would let future/ambiguous [_commit] material ride through the
			// commitment binding. Fail closed.
			return zero, fmt.Errorf("unexpected key %q in [_commit] (sole permitted key is fields_root)", key)
		}
		if found {
			return zero, fmt.Errorf("duplicate fields_root key in [_commit]")
		}
		unquoted, ok := unquoteBasicString(val)
		if !ok {
			return zero, fmt.Errorf("malformed fields_root value (expected a quoted string): %q", string(val))
		}
		hexStr = unquoted
		found = true
	}
	if !found {
		return zero, fmt.Errorf("missing fields_root key in [_commit] section")
	}

	if len(hexStr) <= len(commitFieldsRootPrefix) || hexStr[:len(commitFieldsRootPrefix)] != commitFieldsRootPrefix {
		return zero, fmt.Errorf("fields_root missing %q prefix: %q", commitFieldsRootPrefix, hexStr)
	}
	hexPart := hexStr[len(commitFieldsRootPrefix):]

	if len(hexPart) != 64 {
		return zero, fmt.Errorf("fields_root hex length=%d, want 64", len(hexPart))
	}
	for i := 0; i < len(hexPart); i++ {
		c := hexPart[i]
		isLowerHex := (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')
		if !isLowerHex {
			return zero, fmt.Errorf("fields_root hex contains non-lowercase-hex char %q at index %d", string(c), i)
		}
	}

	decoded, err := hex.DecodeString(hexPart)
	if err != nil {
		return zero, fmt.Errorf("fields_root hex decode: %w", err)
	}
	if len(decoded) != 32 {
		// Unreachable given the len==64 check above, but fail-closed.
		return zero, fmt.Errorf("fields_root decoded width=%d, want 32", len(decoded))
	}
	copy(zero[:], decoded)
	return zero, nil
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
