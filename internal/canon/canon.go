// Package canon implements konareef-toml/v1: the canonical TOML
// serializer and the pod-hash construction it feeds.
//
// A pod's pod.toml may be authored in any of TOML's many equivalent
// spellings — key order, comments, whitespace, integer bases, string
// quoting, datetime precision. canon collapses all of them to one
// byte-exact form so that two semantically identical pods always
// produce the same SHA-256 pod_hash, and any later tampering changes
// it. This package is the Go reference implementation of the canonical
// TOML rule set used for pod hashing.
//
// Public surface:
//
//   - Canonicalize             — pod.toml bytes + pod directory → canonical bytes
//   - CanonicalizeWithWarnings — same, plus non-fatal advisories
//   - PodHash                  — the SHA-256 of the canonical bytes
//   - Error / Code             — the stable, machine-readable failure codes
//   - Warning                  — a non-fatal advisory
//
// Every failure is fatal and total: on any rejection the canonicalizer
// returns a *canon.Error and no output. There is no partial or
// best-effort result — a pod either has one canonical form or none.
package canon

import (
	"bytes"
	"crypto/sha256"
	"unicode/utf8"

	"github.com/BurntSushi/toml"
)

// magicHeader is the fixed identifier line that opens every canonical
// output (spec §0). It is part of the hashed bytes and lets a verifier
// dispatch to the correct decoder. The 18-byte identifier plus its
// terminating newline is 19 bytes.
const magicHeader = "#!konareef-toml/v1\n"

// magicPrefix is the 16-byte version-identifier prefix shared by every
// konareef-toml/vN canonical-output magic line. Input that opens with
// this prefix is claiming to be a versioned canonical-toml document
// and MUST identify itself as v1 (§0); any other version identifier is
// rejected with WRONG_VERSION before parsing.
const magicPrefix = "#!konareef-toml/"

// utf8BOM is the UTF-8 byte-order mark. Its presence at the start of
// input is a rejection (R1), not something to strip.
var utf8BOM = []byte{0xEF, 0xBB, 0xBF}

// Canonicalize converts a pod.toml document into its konareef-toml/v1
// canonical byte form. It is the spec §11 entry point and discards any
// non-fatal warnings; use CanonicalizeWithWarnings to receive them.
//
// input is the raw pod.toml bytes. dir is the pod directory whose
// other files are enumerated, hashed, and bound into the synthetic
// `[_files]` section (R15); the root pod.toml within dir is excluded
// from that walk since it is the document being canonicalized.
//
// On success the returned bytes begin with `#!konareef-toml/v1\n` and
// end with exactly one newline. On any rejection the error is a
// *canon.Error whose Code is one of the stable spec §7 identifiers;
// no output is produced.
func Canonicalize(input []byte, dir string) ([]byte, error) {
	output, _, err := CanonicalizeWithWarnings(input, dir)
	return output, err
}

// CanonicalizeWithWarnings is Canonicalize plus the non-fatal advisory
// channel. The byte output and any error are identical to what
// Canonicalize returns for the same arguments; the extra return is the
// slice of Warnings raised during the run (nil when there are none).
// Warnings never affect the canonical bytes or the pod_hash.
func CanonicalizeWithWarnings(input []byte, dir string) ([]byte, []Warning, error) {
	// Step 1 — encoding gate (R1) and version-identifier gate (§0).
	if !utf8.Valid(input) {
		return nil, nil, newErr(ErrEncodingNotUTF8, "input is not valid UTF-8")
	}
	if bytes.HasPrefix(input, utf8BOM) {
		return nil, nil, newErr(ErrEncodingBOMPresent, "input begins with a UTF-8 byte-order mark")
	}
	if bytes.HasPrefix(input, []byte(magicPrefix)) && !hasV1Magic(input) {
		return nil, nil, newErr(ErrWrongVersion,
			"input begins with a konareef-toml version identifier other than v1")
	}
	normalized := normalizeLineEndings(input)

	// Step 2 — parse to a generic tree.
	var root map[string]interface{}
	if _, err := toml.Decode(string(normalized), &root); err != nil {
		return nil, nil, newErr(ErrTOMLParseError, err.Error())
	}

	// Steps 3 & 4 — build the AST (rejecting array-of-inline-tables)
	// and run every domain-rejection gate before any output exists.
	tree, err := buildTree(root, nil)
	if err != nil {
		return nil, nil, err
	}
	if err := validateTree(tree); err != nil {
		return nil, nil, err
	}

	// Step 5 — the file manifest. The pod.toml byte length feeds the
	// R15 size-cap sum but pod.toml is never itself listed.
	filesSection, warnings, err := buildFilesSection(dir, int64(len(input)))
	if err != nil {
		return nil, nil, err
	}

	// Step 6 — serialize: magic header, author tree, `[_files]`.
	var out bytes.Buffer
	out.WriteString(magicHeader)
	out.Write(serializeTree(tree))
	out.Write(filesSection)

	result := out.Bytes()
	if len(result) == 0 || result[len(result)-1] != '\n' {
		result = append(result, '\n')
	}
	return result, warnings, nil
}

// PodHash returns the SHA-256 of the canonical form of input. It is
// the identity bound by a publisher's signature. Any error is the
// *canon.Error that Canonicalize would return for the same arguments.
func PodHash(input []byte, dir string) ([32]byte, error) {
	canonical, err := Canonicalize(input, dir)
	if err != nil {
		return [32]byte{}, err
	}
	return sha256.Sum256(canonical), nil
}

// normalizeLineEndings rewrites every CRLF and lone CR to a bare LF
// (R1). Done before parsing so the normalization reaches inside
// multi-line string content too, not just structural line breaks.
func normalizeLineEndings(input []byte) []byte {
	out := bytes.ReplaceAll(input, []byte("\r\n"), []byte("\n"))
	return bytes.ReplaceAll(out, []byte("\r"), []byte("\n"))
}

// hasV1Magic reports whether input opens with the v1 magic line — the
// `magicPrefix` followed by exactly `v1` and a line terminator (LF or
// CR). The line-terminator check rejects near-misses like
// `#!konareef-toml/v10` or `#!konareef-toml/v1.1`.
func hasV1Magic(input []byte) bool {
	const v1 = magicPrefix + "v1"
	if !bytes.HasPrefix(input, []byte(v1)) {
		return false
	}
	if len(input) == len(v1) {
		return true
	}
	switch input[len(v1)] {
	case '\n', '\r':
		return true
	}
	return false
}
