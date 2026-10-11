// Copyright 2026 Jerry David Chan, Konareef.ai
// SPDX-License-Identifier: Apache-2.0

// magicline_test.go — KR-MAGIC (konareef#29): a first line that is a near
// miss of the konareef-toml magic is refused with MAGIC_NEAR_MISS, never
// read as a magic-less legacy manifest. The vectors are the 15 near-miss
// lines of the MCP-Z04 konareef fixture (paygate-zk
// scripts/mcp_z04/konareef_fixture_test.go) plus the extra lines PS-1's
// near_miss_magic_lines_refused test refuses (paygate-zk
// crates/paygate-zk-prove/src/commit.rs).

package canon

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// nearMissMagicLines are first lines (or leading bytes) that normalize to
// `#!konareef-toml` but are not an exact v1, v2 or v3 magic line. The first
// 15 are the MCP-Z04 fixture variants, keyed by the fixture's own ids.
var nearMissMagicLines = []struct{ id, line string }{
	{"magic-upper-case", "#!KONAREEF-TOML/V3\n"},
	{"magic-upper-v", "#!konareef-toml/V3\n"},
	{"magic-title-case", "#!Konareef-Toml/v3\n"},
	{"magic-leading-space", " #!konareef-toml/v3\n"},
	{"magic-trailing-space", "#!konareef-toml/v3 \n"},
	{"magic-trailing-tab", "#!konareef-toml/v3\t\n"},
	{"magic-space-after-shebang", "#! konareef-toml/v3\n"},
	{"magic-space-before-version", "#!konareef-toml/ v3\n"},
	{"magic-crlf", "#!konareef-toml/v3\r\n"},
	{"magic-leading-blank-line", "\n#!konareef-toml/v3\n"},
	{"magic-leading-bom", "\xEF\xBB\xBF#!konareef-toml/v3\n"},
	{"magic-wrong-digit-v4", "#!konareef-toml/v4\n"},
	{"magic-wrong-digit-v30", "#!konareef-toml/v30\n"},
	{"magic-suffix-v3x", "#!konareef-toml/v3x\n"},
	{"magic-leading-zero-v03", "#!konareef-toml/v03\n"},
	// PS-1 extras.
	{"ps1-title-case-v2", "#!Konareef-Toml/v2\n"},
	{"ps1-leading-tab", "\t#!konareef-toml/v3\n"},
	{"ps1-crlf-blank-lines-v2", "\r\n\n#!konareef-toml/v2\n"},
	{"ps1-v10", "#!konareef-toml/v10\n"},
	{"ps1-leading-vt", "\x0B#!konareef-toml/v3\n"},
	{"ps1-leading-nul", "\x00#!konareef-toml/v3\n"},
	{"ps1-leading-nbsp", "\xC2\xA0#!konareef-toml/v3\n"},
	{"ps1-leading-zwsp", "\xE2\x80\x8B#!konareef-toml/v3\n"},
	{"ps1-inner-zwsp", "#!konareef\xE2\x80\x8B-toml/v3\n"},
	{"ps1-trailing-vt", "#!konareef-toml/v3\x0B\n"},
	{"ps1-bare-prefix", "#!konareef-toml\n"},
	// Further near misses of the same rule.
	{"v2-crlf", "#!konareef-toml/v2\r\n"},
	{"v1-lone-cr-then-text", "#!konareef-toml/v1\r[pod]\n"},
	{"v1-trailing-space", "#!konareef-toml/v1 \n"},
	{"v1-upper", "#!KONAREEF-TOML/V1\n"},
	{"v999", "#!konareef-toml/v999\n"},
}

// nearMissBody is the text that follows each near-miss line: a v3-shaped
// body with a `[_commit]` trailer, which is what a publisher hiding a
// commitment would ship.
const nearMissBody = "[pod]\nname = \"x\"\n[_commit]\nfields_root = \"poseidon:" +
	"0000000000000000000000000000000000000000000000000000000000000000\"\n"

// TestCheckMagicLine_RefusesNearMisses pins the MAGIC_NEAR_MISS refusal for
// every near-miss line, alone and followed by a v3-shaped body.
func TestCheckMagicLine_RefusesNearMisses(t *testing.T) {
	for _, nm := range nearMissMagicLines {
		for _, input := range []string{nm.line, nm.line + nearMissBody} {
			err := CheckMagicLine([]byte(input))
			var ce *Error
			if !errors.As(err, &ce) || ce.Code != ErrMagicNearMiss {
				t.Errorf("%s: CheckMagicLine(%q) = %v, want %s", nm.id, input, err, ErrMagicNearMiss)
			}
		}
	}
}

// TestCheckMagicLine_AcceptsControls pins what stays accepted: an exact v1
// (LF, CRLF, end of input), v2 or v3 magic line, and a manifest with no
// konareef-toml magic at all (legacy).
func TestCheckMagicLine_AcceptsControls(t *testing.T) {
	controls := []string{
		"#!konareef-toml/v1\n[pod]\n",
		"#!konareef-toml/v1\r\n[pod]\n",
		"#!konareef-toml/v1",
		"#!konareef-toml/v1\r",
		"#!konareef-toml/v2\n" + nearMissBody,
		"#!konareef-toml/v3\n" + nearMissBody,
		// v2 or v3 at end of input is an exact magic line (as in PS-1);
		// the missing trailer is refused later by the trailer parser.
		"#!konareef-toml/v2",
		"#!konareef-toml/v3",
		// No konareef-toml magic: legacy, not a near miss.
		"",
		"\n\n",
		"[pod]\nname = \"x\"\n",
		"# konareef pod\n[pod]\n",
		"#!/usr/bin/env konareef\n[pod]\n",
		"# konareef-toml/v3 is not a magic line without the bang\n",
		"   \n[pod]\n",
		"[pod]\n#!konareef-toml/v3\n",
		// Known limit shared with PS-1: a non-ASCII look-alike (a Unicode
		// hyphen, a Cyrillic "о") is dropped by the normalization, so the
		// line no longer spells the prefix and reads as legacy. Such a
		// manifest commits nothing on either side, so they still agree.
		"#!konareef\u2010toml/v3\n",
		"#!k\u043enareef-toml/v3\n",
	}
	for _, input := range controls {
		if err := CheckMagicLine([]byte(input)); err != nil {
			t.Errorf("CheckMagicLine(%q) = %v, want nil", input, err)
		}
	}
}

// TestCanonicalizers_RefuseNearMissAuthorInput pins the publish-side
// refusal: every canonicalizer entry point refuses author input whose
// first line is a near miss. A near-miss line that begins with the exact
// `#!konareef-toml/` prefix is refused by the older WRONG_VERSION gate
// (spec §7, pinned by conformance vector reject/0019-wrong-version) and a
// BOM by ENCODING_BOM_PRESENT; every other near miss, which the TOML
// parser would otherwise read as a comment, is refused with
// MAGIC_NEAR_MISS.
func TestCanonicalizers_RefuseNearMissAuthorInput(t *testing.T) {
	dir := t.TempDir()
	author := "[pod]\nname = \"x\"\n"
	entryPoints := map[string]func(in []byte) error{
		"Canonicalize": func(in []byte) error { _, err := Canonicalize(in, dir); return err },
		"CanonicalizeV2": func(in []byte) error {
			_, err := CanonicalizeV2(in, dir, CommitParams{})
			return err
		},
		"CanonicalizeV3": func(in []byte) error {
			_, err := CanonicalizeV3(in, dir, CommitParams{BrokerGrants: []BrokerGrant{{MCPName: "fs", Tools: []string{"read"}}}})
			return err
		},
		"CanonicalizeLike(v2 reference)": func(in []byte) error {
			_, err := CanonicalizeLike(in, dir, []byte("#!konareef-toml/v2\n"+nearMissBody))
			return err
		},
	}
	for name, run := range entryPoints {
		for _, nm := range nearMissMagicLines {
			err := run([]byte(nm.line + author))
			var ce *Error
			if !errors.As(err, &ce) {
				t.Errorf("%s(%s): err = %v, want a *canon.Error", name, nm.id, err)
				continue
			}
			switch ce.Code {
			case ErrMagicNearMiss, ErrWrongVersion, ErrEncodingBOMPresent, ErrEncodingNotUTF8:
			default:
				t.Errorf("%s(%s): code = %s, want a refusal of the magic line", name, nm.id, ce.Code)
			}
			if !startsWithExactPrefix(nm.line) && !startsWithBOM(nm.line) && ce.Code != ErrMagicNearMiss {
				t.Errorf("%s(%s): code = %s, want %s", name, nm.id, ce.Code, ErrMagicNearMiss)
			}
		}
	}
}

// startsWithExactPrefix reports whether line opens with the exact
// `#!konareef-toml/` prefix that the older WRONG_VERSION gate tests.
func startsWithExactPrefix(line string) bool {
	return len(line) >= len(magicPrefix) && line[:len(magicPrefix)] == magicPrefix
}

// startsWithBOM reports whether line opens with a UTF-8 byte-order mark.
func startsWithBOM(line string) bool {
	return len(line) >= 3 && line[:3] == "\xEF\xBB\xBF"
}

// TestCanonicalize_LegacyAuthorInputStillCanonicalizes is the publish-side
// control: author input with no magic line, or an ordinary comment first
// line, still canonicalizes.
func TestCanonicalize_LegacyAuthorInputStillCanonicalizes(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "pod.toml"), nil, 0o644); err != nil {
		t.Fatal(err)
	}
	for _, input := range []string{
		"[pod]\nname = \"x\"\n",
		"# konareef pod\n[pod]\nname = \"x\"\n",
		"\n[pod]\nname = \"x\"\n",
	} {
		if _, err := Canonicalize([]byte(input), dir); err != nil {
			t.Errorf("Canonicalize(%q) = %v, want nil", input, err)
		}
	}
}

// TestCanonicalizeLike_RefusesNearMissReference pins the install-side
// refusal: a reference manifest whose first line is a near miss is
// refused. A line with the exact `#!konareef-toml/` prefix keeps its older
// WRONG_VERSION code (TestCanonicalizeLike_UnrecognisedReference_Errors);
// every other near miss is MAGIC_NEAR_MISS.
func TestCanonicalizeLike_RefusesNearMissReference(t *testing.T) {
	dir := t.TempDir()
	for _, nm := range nearMissMagicLines {
		_, err := CanonicalizeLike([]byte("[pod]\nname = \"x\"\n"), dir, []byte(nm.line+nearMissBody))
		want := ErrMagicNearMiss
		if startsWithExactPrefix(nm.line) && !hasV1Magic([]byte(nm.line)) {
			want = ErrWrongVersion
		}
		var ce *Error
		if !errors.As(err, &ce) || ce.Code != want {
			t.Errorf("%s: CanonicalizeLike = %v, want %s", nm.id, err, want)
		}
	}
}
