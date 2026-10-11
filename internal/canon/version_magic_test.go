// Copyright 2026 Jerry David Chan, Konareef.ai
// SPDX-License-Identifier: Apache-2.0

// version_magic_test.go — the two magic-line questions a caller can ask,
// and the reason they are two questions and not one.
//
// HasVersionMagic answers "have these bytes already been canonicalized" and
// says yes to any `#!konareef-toml/vN`, because that is what a caller
// deciding whether to run Canonicalize needs. A caller that goes on to TRUST
// the bytes needs the second question — "and can this build read that
// version" — and `commission verify --manifest` was asking only the first.
// These tests pin the difference so the two cannot be confused again.

package canon

import "testing"

func TestVersionMagic_SeparatesRecognitionFromSupport(t *testing.T) {
	cases := []struct {
		input       string
		hasMagic    bool
		isSupported bool
		version     string
	}{
		{"#!konareef-toml/v1\nname = \"x\"\n", true, true, "v1"},
		{"#!konareef-toml/v1", true, true, "v1"},
		{"#!konareef-toml/v1\r\n", true, true, "v1"},
		// v2 is recognised AND supported (Task 9 step E widened
		// HasSupportedVersionMagic once every read-back site could
		// actually dispatch on it — canon.CanonicalizeLike and
		// canon.ParseCommitFieldsRoot). Only a version past what this
		// build implements stays "recognised, not supported".
		{"#!konareef-toml/v2\nname = \"x\"\n", true, true, "v2"},
		// v3 (MCP-Z03) was added to HasSupportedVersionMagic in the same
		// change that taught every read-back site to dispatch on it.
		{"#!konareef-toml/v3\nname = \"x\"\n", true, true, "v3"},
		{"#!konareef-toml/v3x\n", true, false, "v3x"},
		{"#!konareef-toml/v4\n", true, false, "v4"},
		{"#!konareef-toml/v999\n", true, false, "v999"},
		{"#!konareef-toml/v10\n", true, false, "v10"},
		{"#!konareef-toml/v1.1\n", true, false, "v1.1"},
		{"#!konareef-toml/\n", true, false, ""},
		// No magic line at all: an author-written pod.toml.
		{"name = \"x\"\n", false, false, ""},
		{"", false, false, ""},
	}
	for _, tc := range cases {
		t.Run(tc.input, func(t *testing.T) {
			if got := HasVersionMagic([]byte(tc.input)); got != tc.hasMagic {
				t.Errorf("HasVersionMagic = %v, want %v", got, tc.hasMagic)
			}
			if got := HasSupportedVersionMagic([]byte(tc.input)); got != tc.isSupported {
				t.Errorf("HasSupportedVersionMagic = %v, want %v", got, tc.isSupported)
			}
			version, ok := VersionIdentifier([]byte(tc.input))
			if ok != tc.hasMagic {
				t.Errorf("VersionIdentifier ok = %v, want %v", ok, tc.hasMagic)
			}
			if version != tc.version {
				t.Errorf("VersionIdentifier = %q, want %q", version, tc.version)
			}
		})
	}
}

// TestVersionIdentifier_TruncatesAnUnterminatedMagicLine keeps an error
// message an error message. The token comes from an untrusted file, and a
// file that is one very long line with no terminator must not be able to
// turn a refusal into a byte dump.
func TestVersionIdentifier_TruncatesAnUnterminatedMagicLine(t *testing.T) {
	long := "#!konareef-toml/"
	for i := 0; i < 500; i++ {
		long += "A"
	}
	version, ok := VersionIdentifier([]byte(long))
	if !ok {
		t.Fatal("a magic prefix must still be recognised")
	}
	if len(version) != maxVersionIdentifier {
		t.Fatalf("version identifier must be truncated to %d bytes, got %d", maxVersionIdentifier, len(version))
	}
}
