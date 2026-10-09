// Copyright 2026 Jerry David Chan, Konareef.ai
// SPDX-License-Identifier: Apache-2.0

// magic_near_miss_test.go — KR-MAGIC (konareef#29): install.Verify refuses
// a correctly hashed and signed manifest whose first line is a near miss
// of the konareef-toml magic. A closed pod carries no content tarball, so
// before KR-MAGIC nothing on the install path read the magic line at all.
package install

import (
	"crypto/sha256"
	"errors"
	"testing"

	"github.com/digitsu/konareef/internal/canon"
	"github.com/digitsu/konareef/internal/identity"
)

// resignWithFirstLine replaces f's first manifest line with line, then
// re-hashes and re-signs the manifest with a fresh identity, so that only
// the magic line is wrong.
func resignWithFirstLine(t *testing.T, f *FetchedPod, line string) *FetchedPod {
	t.Helper()
	body := f.ManifestCanonical[len("#!konareef-toml/v1\n"):]
	manifest := append([]byte(line), body...)
	id, err := identity.Generate("mallory")
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	sig, err := id.Sign(manifest)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	out := *f
	out.ManifestCanonical = manifest
	out.PodHash = sha256.Sum256(manifest)
	out.Signature = sig
	out.PublisherPubkeyHex = id.PublicKeyHex
	return &out
}

// TestVerify_RefusesNearMissMagic covers the 15 MCP-Z04 near-miss lines
// plus the extra PS-1 vectors, on a closed pod (no content tarball).
func TestVerify_RefusesNearMissMagic(t *testing.T) {
	base := closedPodFetchResponse(t)
	if string(base.ManifestCanonical[:len("#!konareef-toml/v1\n")]) != "#!konareef-toml/v1\n" {
		t.Fatalf("fixture is not a v1 manifest")
	}
	// Control: an exact v1 line, re-signed the same way, still verifies.
	for _, control := range []string{"#!konareef-toml/v1\n", "#!konareef-toml/v1\r\n"} {
		if err := Verify(resignWithFirstLine(t, base, control)); err != nil {
			t.Errorf("control %q: Verify = %v, want nil", control, err)
		}
	}
	for _, line := range []string{
		"#!KONAREEF-TOML/V3\n", "#!konareef-toml/V3\n", "#!Konareef-Toml/v3\n",
		" #!konareef-toml/v3\n", "#!konareef-toml/v3 \n", "#!konareef-toml/v3\t\n",
		"#! konareef-toml/v3\n", "#!konareef-toml/ v3\n", "#!konareef-toml/v3\r\n",
		"\n#!konareef-toml/v3\n", "\xEF\xBB\xBF#!konareef-toml/v3\n", "#!konareef-toml/v4\n",
		"#!konareef-toml/v30\n", "#!konareef-toml/v3x\n", "#!konareef-toml/v03\n",
		"\t#!konareef-toml/v3\n", "\xC2\xA0#!konareef-toml/v3\n", "#!konareef-toml\n",
		"#!KONAREEF-TOML/V1\n",
	} {
		err := Verify(resignWithFirstLine(t, base, line))
		var ce *canon.Error
		if !errors.As(err, &ce) || ce.Code != canon.ErrMagicNearMiss {
			t.Errorf("%q: Verify = %v, want %s", line, err, canon.ErrMagicNearMiss)
		}
	}
}
