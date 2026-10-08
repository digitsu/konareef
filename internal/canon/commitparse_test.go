// Copyright 2026 Jerry David Chan, Konareef.ai
// SPDX-License-Identifier: Apache-2.0

package canon

import (
	"encoding/hex"
	"strings"
	"testing"
)

// makeV2Manifest builds a minimal canonical-v2 manifest whose [_commit]
// trailer carries the given fields_root value verbatim. The caller passes
// the full value token (e.g. "poseidon:<hex>") so negative tests can
// inject malformed prefixes/hex.
func makeV2Manifest(fieldsRootValue string) string {
	return "#!konareef-toml/v2\n" +
		"[pod]\n" +
		"id = \"x\"\n" +
		"[_files]\n" +
		"[_commit]\n" +
		"fields_root = \"" + fieldsRootValue + "\"\n"
}

// TestParseCommitFieldsRoot_Positive asserts a well-formed [_commit]
// fields_root decodes to the exact 32 little-endian bytes.
func TestParseCommitFieldsRoot_Positive(t *testing.T) {
	var fr [32]byte
	for i := range fr {
		fr[i] = byte(i + 1) // 0x01..0x20
	}
	manifest := makeV2Manifest("poseidon:" + hex.EncodeToString(fr[:]))

	got, err := ParseCommitFieldsRoot([]byte(manifest))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != fr {
		t.Errorf("fields_root = %x; want %x", got, fr)
	}
}

// TestParseCommitFieldsRoot_MissingMagic — non-v2 magic prefix rejects.
func TestParseCommitFieldsRoot_MissingMagic(t *testing.T) {
	manifest := strings.TrimPrefix(makeV2Manifest("poseidon:"+strings.Repeat("0", 64)), "#!konareef-toml/v2\n")
	if _, err := ParseCommitFieldsRoot([]byte(manifest)); err == nil {
		t.Fatal("expected error on missing v2 magic prefix; got nil")
	}
}

// TestParseCommitFieldsRoot_NoCommitSection — manifest without
// [_commit] rejects.
func TestParseCommitFieldsRoot_NoCommitSection(t *testing.T) {
	manifest := "#!konareef-toml/v2\n[pod]\nid = \"x\"\n[_files]\n"
	if _, err := ParseCommitFieldsRoot([]byte(manifest)); err == nil {
		t.Fatal("expected error on missing [_commit] section; got nil")
	}
}

// TestParseCommitFieldsRoot_NoCommitSection_IsolatesTheCommitIdxGuard pins
// the SPECIFIC guard that rejects trailerless v2 input at the parser
// level: `commitIdx := bytes.LastIndex(manifest, []byte("[_commit]")); if
// commitIdx < 0 { ... }` in ParseCommitFieldsRoot itself.
//
// TestParseCommitFieldsRoot_NoCommitSection (above) only asserts
// `err == nil` -> Fatal, so it cannot tell this guard apart from a
// DIFFERENT downstream check that happens to also fire on the exact
// same fixture: with the commitIdx<0 guard deleted, commitIdx stays -1,
// and `section := manifest[commitIdx+len("[_commit]"):]` becomes
// `manifest[8:]` — a valid but semantically wrong slice into the middle
// of the manifest. The scan loop over that garbage slice finds no
// `fields_root = ...` line, so `found` stays false and a DIFFERENT
// error ("missing fields_root key in [_commit] section") fires instead,
// which still makes `err != nil` and so still satisfies the
// weaker assertion — this is exactly the "test doesn't discriminate
// which guard fired" gap task-11's mutation table found (Fix round 1;
// see task-11-report.md).
//
// This test closes that gap by asserting the EXACT message only the
// commitIdx<0 guard produces, so it fails if that guard is bypassed even
// though ParseCommitFieldsRoot still returns *some* error.
func TestParseCommitFieldsRoot_NoCommitSection_IsolatesTheCommitIdxGuard(t *testing.T) {
	manifest := "#!konareef-toml/v2\n[pod]\nid = \"x\"\n[_files]\n"
	_, err := ParseCommitFieldsRoot([]byte(manifest))
	if err == nil {
		t.Fatal("expected error on missing [_commit] section; got nil")
	}
	const want = "no [_commit] section in manifest"
	if err.Error() != want {
		t.Fatalf("error = %q, want exactly %q (a different, downstream check fired instead of the commitIdx<0 guard)", err.Error(), want)
	}
}

// TestParseCommitFieldsRoot_MissingKey — [_commit] present but no
// fields_root key rejects.
func TestParseCommitFieldsRoot_MissingKey(t *testing.T) {
	manifest := "#!konareef-toml/v2\n[pod]\nid = \"x\"\n[_files]\n[_commit]\n"
	if _, err := ParseCommitFieldsRoot([]byte(manifest)); err == nil {
		t.Fatal("expected error on missing fields_root key; got nil")
	}
}

// TestParseCommitFieldsRoot_DuplicateKey — two fields_root lines reject.
func TestParseCommitFieldsRoot_DuplicateKey(t *testing.T) {
	val := "poseidon:" + strings.Repeat("0", 64)
	manifest := "#!konareef-toml/v2\n[_commit]\n" +
		"fields_root = \"" + val + "\"\n" +
		"fields_root = \"" + val + "\"\n"
	if _, err := ParseCommitFieldsRoot([]byte(manifest)); err == nil {
		t.Fatal("expected error on duplicate fields_root key; got nil")
	}
}

// TestParseCommitFieldsRoot_MalformedLine — unquoted value rejects.
func TestParseCommitFieldsRoot_MalformedLine(t *testing.T) {
	manifest := "#!konareef-toml/v2\n[_commit]\nfields_root = poseidon:" + strings.Repeat("0", 64) + "\n"
	if _, err := ParseCommitFieldsRoot([]byte(manifest)); err == nil {
		t.Fatal("expected error on unquoted fields_root value; got nil")
	}
}

// TestParseCommitFieldsRoot_MissingPoseidonPrefix — value without the
// poseidon: prefix rejects.
func TestParseCommitFieldsRoot_MissingPoseidonPrefix(t *testing.T) {
	manifest := makeV2Manifest(strings.Repeat("0", 64))
	if _, err := ParseCommitFieldsRoot([]byte(manifest)); err == nil {
		t.Fatal("expected error on missing poseidon: prefix; got nil")
	}
}

// TestParseCommitFieldsRoot_WrongHexLength — 62 hex chars rejects.
func TestParseCommitFieldsRoot_WrongHexLength(t *testing.T) {
	manifest := makeV2Manifest("poseidon:" + strings.Repeat("0", 62))
	if _, err := ParseCommitFieldsRoot([]byte(manifest)); err == nil {
		t.Fatal("expected error on 62-char hex; got nil")
	}
}

// TestParseCommitFieldsRoot_UppercaseHex — uppercase hex rejects (must
// be lowercase per spec §1).
func TestParseCommitFieldsRoot_UppercaseHex(t *testing.T) {
	manifest := makeV2Manifest("poseidon:" + strings.Repeat("A", 64))
	if _, err := ParseCommitFieldsRoot([]byte(manifest)); err == nil {
		t.Fatal("expected error on uppercase hex; got nil")
	}
}

// TestParseCommitFieldsRoot_BadHex — non-hex chars at correct length
// reject.
func TestParseCommitFieldsRoot_BadHex(t *testing.T) {
	manifest := makeV2Manifest("poseidon:" + strings.Repeat("g", 64))
	if _, err := ParseCommitFieldsRoot([]byte(manifest)); err == nil {
		t.Fatal("expected error on non-hex chars; got nil")
	}
}

// TestParseCommitFieldsRoot_MagicSuffix — a first line that merely has the
// magic as a PREFIX (e.g. "#!konareef-toml/v2evil") must reject; the magic is
// an exact first-line delimiter, not a substring (Hermes !29 blocker 1).
func TestParseCommitFieldsRoot_MagicSuffix(t *testing.T) {
	manifest := "#!konareef-toml/v2evil\n[_commit]\nfields_root = \"poseidon:" +
		strings.Repeat("0", 64) + "\"\n"
	if _, err := ParseCommitFieldsRoot([]byte(manifest)); err == nil {
		t.Fatal("expected error on magic-suffix first line; got nil")
	}
}

// TestParseCommitFieldsRoot_ExtraKey — an extra committed key in [_commit]
// beyond the sole `fields_root` key must reject (Hermes !29 blocker 1).
func TestParseCommitFieldsRoot_ExtraKey(t *testing.T) {
	manifest := "#!konareef-toml/v2\n[_commit]\n" +
		"fields_root = \"poseidon:" + strings.Repeat("0", 64) + "\"\n" +
		"extra_key = \"value\"\n"
	if _, err := ParseCommitFieldsRoot([]byte(manifest)); err == nil {
		t.Fatal("expected error on extra key in [_commit]; got nil")
	}
}
