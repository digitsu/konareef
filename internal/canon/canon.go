// Copyright 2026 Jerry David Chan, Konareef.ai
// SPDX-License-Identifier: Apache-2.0

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

// magicHeaderV2 is the fixed identifier line that opens every
// konareef-toml/v2 canonical output (konareef-toml/v2 spec §0).
const magicHeaderV2 = "#!konareef-toml/v2\n"

// magicHeaderV3 is the fixed identifier line that opens every
// konareef-toml/v3 canonical output (konareef-toml/v3 spec §0). v3 output
// is v2 output with this magic line; only the declared_tools derivation
// inside fields_root differs (declaredtools.go).
const magicHeaderV3 = "#!konareef-toml/v3\n"

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
	// v1 entry-point gate (§0): reject any non-v1 identifier — including
	// v2 — before parsing. canonicalBody's own gate is deliberately
	// widened to also accept v2 (see its doc comment), so that check
	// alone would let a v2-magic document through the v1 entry point.
	// This duplicates checkEncoding + the v1-only predicate ahead of the
	// call so the "rejected before parsing" guarantee (and pinned
	// conformance vector reject/0019-wrong-version) holds exactly as it
	// did before this refactor.
	if err := checkEncoding(input); err != nil {
		return nil, nil, err
	}
	if bytes.HasPrefix(input, []byte(magicPrefix)) && !hasV1Magic(input) {
		return nil, nil, newErr(ErrWrongVersion,
			"input begins with a konareef-toml version identifier other than v1")
	}

	body, warnings, err := canonicalBody(input, dir)
	if err != nil {
		return nil, nil, err
	}

	// Step 6 — serialize: magic header, then the shared author-tree +
	// `[_files]` body.
	var out bytes.Buffer
	out.WriteString(magicHeader)
	out.Write(body)

	result := out.Bytes()
	if len(result) == 0 || result[len(result)-1] != '\n' {
		result = append(result, '\n')
	}
	return result, warnings, nil
}

// checkEncoding applies the encoding gate (R1): input must be valid UTF-8
// and must not open with a UTF-8 byte-order mark. Shared by
// CanonicalizeWithWarnings and canonicalBody so both entry points apply
// the identical check in the identical order.
func checkEncoding(input []byte) error {
	if !utf8.Valid(input) {
		return newErr(ErrEncodingNotUTF8, "input is not valid UTF-8")
	}
	if bytes.HasPrefix(input, utf8BOM) {
		return newErr(ErrEncodingBOMPresent, "input begins with a UTF-8 byte-order mark")
	}
	return nil
}

// canonicalBody runs the version-independent core of canonicalization —
// spec steps 1-5 — and returns the author tree plus `[_files]` section,
// serialized but WITHOUT a magic line. It is shared by
// CanonicalizeWithWarnings (which prepends magicHeader) and CanonicalizeV2
// (which prepends magicHeaderV2 and appends the `[_commit]` trailer), so
// that both versions parse, validate, and serialize the author's document
// identically — v2 differs only in its magic line and trailer, never in
// this body.
//
// After the version-identifier gate, CheckMagicLine refuses a near-miss
// magic line with MAGIC_NEAR_MISS (KR-MAGIC), for every entry point.
//
// The version-identifier gate here is intentionally widened past
// HasSupportedVersionMagic/hasV1Magic: it accepts the v1, v2 or v3
// magic line on input (both are harmless TOML comments to the parser
// below). Any other version identifier is still rejected with
// WRONG_VERSION, exactly as before this refactor.
//
// No current caller feeds this helper a document that carries the v2 magic
// line — CanonicalizeV2 and CanonicalizeLike both pass an AUTHOR tree with
// no magic line at all, and canon.Recanonicalize, the caller the widening
// was written for, was deleted on 2026-09-21 for want of a production
// caller of its own. The widening is kept rather than narrowed because
// narrowing it is a behaviour change on a code path v1 shares, and
// because any future read-back site that re-derives this body from stored
// v2 bytes needs it. It is deliberately permissive, not dead by accident.
//
// This widened acceptance is exactly why CanonicalizeWithWarnings applies
// its OWN stricter, v1-only gate before ever calling this helper: the
// helper alone would let a v2-magic document through, which the v1 entry
// point must still refuse.
func canonicalBody(input []byte, dir string) ([]byte, []Warning, error) {
	// Step 1 — encoding gate (R1) and version-identifier gate (§0).
	if err := checkEncoding(input); err != nil {
		return nil, nil, err
	}
	if bytes.HasPrefix(input, []byte(magicPrefix)) && !hasV1Magic(input) && !hasV2Magic(input) && !hasV3Magic(input) {
		return nil, nil, newErr(ErrWrongVersion,
			"input begins with a konareef-toml version identifier other than v1")
	}
	// Near-miss gate (KR-MAGIC): a first line such as ` #!konareef-toml/v3`
	// or `#!KONAREEF-TOML/V3` is a TOML comment to the parser below, so
	// without this it would canonicalize as ordinary v1 author input.
	if err := CheckMagicLine(input); err != nil {
		return nil, nil, err
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

	var body bytes.Buffer
	body.Write(serializeTree(tree))
	body.Write(filesSection)
	return body.Bytes(), warnings, nil
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

// HasVersionMagic reports whether input already opens with a konareef-toml
// version identifier, i.e. whether it is canonicalizer OUTPUT rather than an
// author-written manifest.
//
// It exists so a caller that must hash canonical bytes can tell which of the
// two it was handed. Canonicalize is not idempotent — it prepends the magic
// header and appends a `[_files]` section, and running it over its own
// output does not reproduce that output — so "canonicalize it anyway" is not
// a safe default. It deliberately accepts ANY version, not just v1: the
// question here is "have these bytes already been canonicalized", and a v2
// manifest answers yes just as a v1 one does.
//
// Because of that, it is NOT an acceptance test. A caller that goes on to
// hash, verify, or otherwise trust the bytes must also ask
// HasSupportedVersionMagic, or it will treat a version this build cannot
// read as though it had validated it.
func HasVersionMagic(input []byte) bool {
	return bytes.HasPrefix(input, []byte(magicPrefix))
}

// HasSupportedVersionMagic reports whether input opens with a canonical
// version identifier this build understands: v1, v2 or v3. Any other version
// identifier (e.g. `#!konareef-toml/v999`) is unimplemented here, so
// nothing in this repository can produce or check one.
//
// It is the companion HasVersionMagic needs. HasVersionMagic answers "are
// these already canonical bytes" and says yes to `#!konareef-toml/v2` or
// `#!konareef-toml/v999` alike; this answers "and can this code actually
// validate them", so a caller can fail closed on a version it does not
// implement rather than passing the bytes through unchecked. Canonicalize
// applies a stricter, v1-only version of this same gate to its own input
// (WRONG_VERSION, §0) — CanonicalizeWithWarnings never accepts v2 magic on
// direct input, even though this predicate now does, because a caller
// asking "can I hash/verify already-canonical bytes of this version" and a
// caller asking "should I treat this document as fresh v1 author input"
// are different questions (see canonicalBody's doc comment).
//
// Widened from v1-only to v1+v2 as the LAST step of wiring up
// konareef-toml/v2 read-back (Task 9 step E): every site that reproduces
// PodHash from already-canonical bytes (canon.CanonicalizeLike, and
// canon.ParseCommitFieldsRoot for the trailer itself) must be able to
// actually read v2 BEFORE this gate says v2 is acceptable, or a caller
// gated on this predicate (`commission verify --manifest`) would wave a v2
// manifest through to code that could not yet validate it.
//
// Widened again to v3 (konareef-toml/v3 spec §0, MCP-Z03) in the same
// change that taught every read-back site to dispatch on v3:
// ParseCommitTrailer, CanonicalizeLike, CommittedTools,
// commission.ManifestFieldsRoot and the verifier's CL-5a gate
// (ClaimsCommitTrailer).
func HasSupportedVersionMagic(input []byte) bool {
	return hasV1Magic(input) || hasV2Magic(input) || hasV3Magic(input)
}

// ClaimsCommitTrailer reports whether manifest opens with the magic prefix
// of a version that carries a `[_commit]` trailer: `#!konareef-toml/v2` or
// `#!konareef-toml/v3`.
//
// It is deliberately a loose PREFIX test, not an exact-line test. It is
// the gate a verifier uses to decide whether the fields_root bindings
// apply, and a near-miss such as `#!konareef-toml/v2evil` must enter the
// gated branch and then fail closed in ParseCommitTrailer, not skip the
// branch as though it were a v1 manifest. The verifier now also runs
// CheckMagicLine first, which refuses such a line before this gate
// (KR-MAGIC); the prefix test stays as a second fail-closed layer.
//
// Input: manifest bytes. Output: true when the bindings must run.
func ClaimsCommitTrailer(manifest []byte) bool {
	return bytes.HasPrefix(manifest, v2Magic) || bytes.HasPrefix(manifest, v3Magic)
}

// VersionIdentifier returns the version token from input's canonical magic
// line — "v1" for `#!konareef-toml/v1`, "v999" for `#!konareef-toml/v999` —
// and reports whether input carried a magic line at all. It exists so a
// caller refusing an unsupported version can name the version it refused.
//
// The token is untrusted input from the file, so it is truncated to
// maxVersionIdentifier bytes: a file whose whole content is one very long
// line must not be able to turn an error message into a byte dump. A caller
// that prints it should still treat it as untrusted text.
func VersionIdentifier(input []byte) (string, bool) {
	if !bytes.HasPrefix(input, []byte(magicPrefix)) {
		return "", false
	}
	rest := input[len(magicPrefix):]
	if i := bytes.IndexAny(rest, "\n\r"); i >= 0 {
		rest = rest[:i]
	}
	if len(rest) > maxVersionIdentifier {
		rest = rest[:maxVersionIdentifier]
	}
	return string(rest), true
}

// maxVersionIdentifier caps how much of an unrecognised magic line
// VersionIdentifier will hand back for an error message.
const maxVersionIdentifier = 32

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

// hasV2Magic reports whether input opens with the v2 identifier.
func hasV2Magic(input []byte) bool { return bytes.HasPrefix(input, []byte(magicHeaderV2)) }

// hasV3Magic reports whether input opens with the v3 identifier line.
func hasV3Magic(input []byte) bool { return bytes.HasPrefix(input, []byte(magicHeaderV3)) }
