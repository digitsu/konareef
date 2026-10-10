// Copyright 2026 Jerry David Chan, Konareef.ai
// SPDX-License-Identifier: Apache-2.0

// main_commission_magic_near_miss_test.go — KR-MAGIC (konareef#29):
// `commission verify --manifest` refuses a manifest file whose first line
// is a near miss of the konareef-toml magic, whether it would otherwise be
// read as canonical bytes or canonicalized as an author pod.toml.
package main

import (
	"bytes"
	"errors"
	"os"
	"testing"

	"github.com/digitsu/konareef/internal/canon"
)

// TestReadManifestForVerify_RefusesNearMissMagic swaps the magic line of a
// real canonical v2 manifest for each near-miss line.
func TestReadManifestForVerify_RefusesNearMissMagic(t *testing.T) {
	original, err := os.ReadFile(buildV2ManifestFile(t))
	if err != nil {
		t.Fatal(err)
	}
	body := bytes.TrimPrefix(original, []byte("#!konareef-toml/v2\n"))
	if len(body) == len(original) {
		t.Fatal("fixture is not a v2 manifest")
	}
	for _, line := range []string{
		"#!KONAREEF-TOML/V2\n", "#!konareef-toml/V2\n", "#!Konareef-Toml/v2\n",
		" #!konareef-toml/v2\n", "#!konareef-toml/v2 \n", "#!konareef-toml/v2\t\n",
		"#! konareef-toml/v2\n", "#!konareef-toml/ v2\n", "#!konareef-toml/v2\r\n",
		"\n#!konareef-toml/v2\n", "\xEF\xBB\xBF#!konareef-toml/v2\n", "#!konareef-toml/v4\n",
		"#!konareef-toml/v20\n", "#!konareef-toml/v2x\n", "#!konareef-toml/v02\n",
		"#!konareef-toml/v1\r#!konareef-toml/v2\n",
	} {
		path := writeManifestFile(t, "manifest.canon", append([]byte(line), body...))
		got, err := readManifestForVerify(path)
		if err == nil {
			t.Errorf("%q: readManifestForVerify accepted %d bytes", line, len(got))
			continue
		}
		// A line with the exact prefix of a version this build does not
		// read keeps its older "unsupported version" refusal
		// (main_commission_manifest_version_test.go); every other near miss
		// is MAGIC_NEAR_MISS.
		if canon.HasVersionMagic([]byte(line)) && !canon.HasSupportedVersionMagic([]byte(line)) {
			continue
		}
		var ce *canon.Error
		if !errors.As(err, &ce) || ce.Code != canon.ErrMagicNearMiss {
			t.Errorf("%q: readManifestForVerify = %v, want %s", line, err, canon.ErrMagicNearMiss)
		}
	}
}
