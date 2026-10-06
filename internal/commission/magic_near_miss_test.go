// Copyright 2026 Jerry David Chan, Konareef.ai
// SPDX-License-Identifier: Apache-2.0

// magic_near_miss_test.go — KR-MAGIC (konareef#29): a manifest whose first
// line is a near miss of the konareef-toml magic is refused by
// ManifestFieldsRoot, CheckManifestCommitment and ValidateAgainstManifest,
// never read as a legacy manifest that commits nothing. The lines are the
// 15 near-miss variants of the MCP-Z04 konareef fixture (paygate-zk
// scripts/mcp_z04/konareef_fixture_test.go) plus the extra PS-1 vectors.
package commission

import (
	"errors"
	"testing"

	"github.com/digitsu/konareef/internal/canon"
)

// nearMissMagicLines are the near-miss first lines under test. The first
// 15 are the MCP-Z04 fixture variants; six of them
// (upper-case, title-case, leading-space, space-after-shebang,
// leading-blank-line, leading-bom) returned ok from
// CheckManifestCommitment before KR-MAGIC.
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
	{"ps1-leading-tab", "\t#!konareef-toml/v3\n"},
	{"ps1-leading-nbsp", "\xC2\xA0#!konareef-toml/v3\n"},
	{"ps1-leading-zwsp", "\xE2\x80\x8B#!konareef-toml/v3\n"},
	{"ps1-inner-zwsp", "#!konareef\xE2\x80\x8B-toml/v3\n"},
	{"ps1-leading-nul", "\x00#!konareef-toml/v3\n"},
	{"ps1-bare-prefix", "#!konareef-toml\n"},
	{"v1-lone-cr-then-text", "#!konareef-toml/v1\r[pod]\n"},
}

// nearMissManifest swaps the exact v3 magic line of an honest v3 manifest
// (one CheckManifestCommitment accepts) for line.
func nearMissManifest(line string) []byte {
	honest := v3Manifest(frV3)
	return append([]byte(line), honest[len("#!konareef-toml/v3\n"):]...)
}

// isMagicNearMiss reports whether err carries the canon MAGIC_NEAR_MISS
// code.
func isMagicNearMiss(err error) bool {
	var ce *canon.Error
	return errors.As(err, &ce) && ce.Code == canon.ErrMagicNearMiss
}

// TestManifestMagicNearMiss_Refused pins the refusal at every commission
// entry point that decides the magic line: ManifestFieldsRoot,
// CheckManifestCommitment, FromManifest and ValidateAgainstManifest.
func TestManifestMagicNearMiss_Refused(t *testing.T) {
	if err := CheckManifestCommitment(v3Manifest(frV3)); err != nil {
		t.Fatalf("control: honest v3 manifest refused: %v", err)
	}
	root := hexToArr(t, frV3)
	for _, nm := range nearMissMagicLines {
		m := nearMissManifest(nm.line)

		fr, err := ManifestFieldsRoot(m)
		if fr != nil || !errors.Is(err, ErrManifestVersionUnsupported) || !isMagicNearMiss(err) {
			t.Errorf("%s: ManifestFieldsRoot = (%v, %v), want nil and ErrManifestVersionUnsupported with %s",
				nm.id, fr, err, canon.ErrMagicNearMiss)
		}
		if err := CheckManifestCommitment(m); !isMagicNearMiss(err) {
			t.Errorf("%s: CheckManifestCommitment = %v, want %s", nm.id, err, canon.ErrMagicNearMiss)
		}
		if _, err := FromManifest(m, grantSpec()); !isMagicNearMiss(err) {
			t.Errorf("%s: FromManifest = %v, want %s", nm.id, err, canon.ErrMagicNearMiss)
		}
		// Neither an unpinned binding (the "legacy, commits nothing"
		// reading) nor a pinned one may pass.
		for _, pin := range []*[32]byte{nil, root} {
			if err := bindingFor(m, pin).ValidateAgainstManifest(m); !isMagicNearMiss(err) {
				t.Errorf("%s: ValidateAgainstManifest(pin=%v) = %v, want %s", nm.id, pin != nil, err, canon.ErrMagicNearMiss)
			}
		}
	}
}

// TestManifestMagicNearMiss_ControlsAccepted pins what stays accepted: an
// exact v1 manifest (LF or CRLF) and a manifest with no magic line commit
// nothing, and an exact v3 manifest commits its root and derives its
// envelope.
func TestManifestMagicNearMiss_ControlsAccepted(t *testing.T) {
	for _, m := range []string{
		"#!konareef-toml/v1\n[pod]\nname = \"probe\"\n",
		"#!konareef-toml/v1\r\n[pod]\nname = \"probe\"\n",
		"[pod]\nname = \"probe\"\n",
		"# konareef pod\n[pod]\nname = \"probe\"\n",
	} {
		fr, err := ManifestFieldsRoot([]byte(m))
		if fr != nil || err != nil {
			t.Errorf("ManifestFieldsRoot(%q) = (%v, %v), want (nil, nil)", m, fr, err)
		}
		if err := CheckManifestCommitment([]byte(m)); err != nil {
			t.Errorf("CheckManifestCommitment(%q) = %v, want nil", m, err)
		}
	}
	fr, err := ManifestFieldsRoot(v3Manifest(frV3))
	if err != nil || fr == nil || *fr != *hexToArr(t, frV3) {
		t.Errorf("ManifestFieldsRoot(exact v3) = (%v, %v), want the committed root", fr, err)
	}
	if _, err := FromManifest(v3Manifest(frV3), grantSpec()); err != nil {
		t.Errorf("FromManifest(exact v3) = %v, want nil", err)
	}
}
