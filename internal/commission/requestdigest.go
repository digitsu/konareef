// Copyright 2026 Jerry David Chan, Konareef.ai
// SPDX-License-Identifier: Apache-2.0

// requestdigest.go — the request_digest of a commissioned-run request
// (docs/design/commission-admission-contract.md §7.2).
//
// reef-core computes request_digest as SHA-256 of the RFC 8785 (JSON
// Canonicalization Scheme, JCS) serialization of the request's `inputs`,
// with an omitted `inputs` read as `{}`. It uses the digest to tell a
// retry of the same request (same run, or 409 in progress) from a changed
// request (409 commission_replay_conflict). The CLI computes the same
// value so it can show the buyer which request a retry repeats.
//
// The CLI sends inputs as a JSON object of strings only (`--input k=v`),
// so this file implements the JCS rules for that subset: members sorted by
// the UTF-16 code units of their keys, no whitespace, and strings escaped
// as ECMAScript JSON.stringify escapes them. The rules match reef-core
// ReefCore.Commission.RequestBody.jcs/1.

package commission

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"sort"
	"strings"
	"unicode/utf16"
	"unicode/utf8"
)

// ErrInputsNotUTF8 means an input key or value is not valid UTF-8. The
// server's JSON decoder refuses such a body, and Go's JSON encoder would
// silently replace the bad bytes, so the request is refused before it is
// sent.
var ErrInputsNotUTF8 = errors.New("commission inputs are not valid UTF-8")

// RequestDigest returns SHA-256(JCS(inputs)), the server's request_digest.
//
// Input: the run inputs; nil and an empty map both mean `{}`. Output: the
// 32-byte digest, or ErrInputsNotUTF8.
func RequestDigest(inputs map[string]string) ([32]byte, error) {
	canonical, err := CanonicalInputsJSON(inputs)
	if err != nil {
		return [32]byte{}, err
	}
	return sha256.Sum256(canonical), nil
}

// CanonicalInputsJSON returns the JCS (RFC 8785) serialization of a JSON
// object of strings.
//
// Input: the run inputs; nil means `{}`. Output: the canonical JSON bytes,
// or ErrInputsNotUTF8 naming the bad key.
func CanonicalInputsJSON(inputs map[string]string) ([]byte, error) {
	keys := make([]string, 0, len(inputs))
	for key, value := range inputs {
		if !utf8.ValidString(key) || !utf8.ValidString(value) {
			return nil, fmt.Errorf("%w: key %q", ErrInputsNotUTF8, key)
		}
		keys = append(keys, key)
	}
	sort.Slice(keys, func(i, j int) bool { return lessUTF16(keys[i], keys[j]) })

	var b strings.Builder
	b.WriteByte('{')
	for i, key := range keys {
		if i > 0 {
			b.WriteByte(',')
		}
		writeJCSString(&b, key)
		b.WriteByte(':')
		writeJCSString(&b, inputs[key])
	}
	b.WriteByte('}')
	return []byte(b.String()), nil
}

// lessUTF16 orders two strings by their UTF-16 code units, as JCS requires.
// UTF-8 byte order differs for characters above U+FFFF, which UTF-16 writes
// as surrogates (0xD800–0xDFFF) and so sorts before U+E000–U+FFFF.
//
// Inputs: two valid UTF-8 strings. Output: whether a sorts before b.
func lessUTF16(a, b string) bool {
	ua := utf16.Encode([]rune(a))
	ub := utf16.Encode([]rune(b))
	for i := 0; i < len(ua) && i < len(ub); i++ {
		if ua[i] != ub[i] {
			return ua[i] < ub[i]
		}
	}
	return len(ua) < len(ub)
}

// writeJCSString writes s as a JSON string with the JSON.stringify escapes:
// `"` and `\` are escaped, U+0008, U+0009, U+000A, U+000C and U+000D use
// their short forms, other characters below U+0020 use \u00xx with
// lowercase hex, and every other character is written as UTF-8.
//
// Inputs: the builder and a valid UTF-8 string. Output: none.
func writeJCSString(b *strings.Builder, s string) {
	b.WriteByte('"')
	for _, r := range s {
		switch r {
		case '"':
			b.WriteString(`\"`)
		case '\\':
			b.WriteString(`\\`)
		case '\b':
			b.WriteString(`\b`)
		case '\t':
			b.WriteString(`\t`)
		case '\n':
			b.WriteString(`\n`)
		case '\f':
			b.WriteString(`\f`)
		case '\r':
			b.WriteString(`\r`)
		default:
			if r < 0x20 {
				fmt.Fprintf(b, `\u%04x`, r)
			} else {
				b.WriteRune(r)
			}
		}
	}
	b.WriteByte('"')
}
