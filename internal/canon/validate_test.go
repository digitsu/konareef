// Copyright 2026 Jerry David Chan, Konareef.ai
// SPDX-License-Identifier: Apache-2.0

package canon

import "testing"

func TestHandAuthoredCommitSectionIsRejected(t *testing.T) {
	input := []byte("#!konareef-toml/v1\n[pod]\nname = \"x\"\n\n[_commit]\nfields_root = \"poseidon:00\"\n")
	_, err := Canonicalize(input, t.TempDir())
	if got := Code(err); got != ErrReservedKeyCommit {
		t.Fatalf("code = %q, want %q", got, ErrReservedKeyCommit)
	}
}

func TestOtherUnderscoreKeysKeepTheirCode(t *testing.T) {
	input := []byte("#!konareef-toml/v1\n[pod]\nname = \"x\"\n\n[_other]\nk = 1\n")
	_, err := Canonicalize(input, t.TempDir())
	if got := Code(err); got != ErrReservedKeyUnderscore {
		t.Fatalf("code = %q, want %q", got, ErrReservedKeyUnderscore)
	}
}
