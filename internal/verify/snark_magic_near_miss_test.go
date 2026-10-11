// Copyright 2026 Jerry David Chan, Konareef.ai
// SPDX-License-Identifier: Apache-2.0

// snark_magic_near_miss_test.go — KR-MAGIC (konareef#29): the verifier
// refuses a manifest whose first line is a near miss of the konareef-toml
// magic. Before KR-MAGIC, a line such as `#!KONAREEF-TOML/V3` or
// ` #!konareef-toml/v3` failed canon.ClaimsCommitTrailer and
// canon.HasVersionMagic both, so CL-5(a) was skipped and the bundle was
// verified as a legacy manifest with nothing to bind.
package verify

import (
	"strings"
	"testing"

	"github.com/digitsu/konareef/internal/canon"
)

// TestSnarkPhase_NearMissMagicRefused covers the 15 MCP-Z04 near-miss
// lines plus the extra PS-1 vectors. Each bundle is otherwise
// self-consistent: pod_hash, h_manifest and the genesis lane all agree
// with the disclosed manifest and its trailer.
func TestSnarkPhase_NearMissMagicRefused(t *testing.T) {
	lines := []string{
		"#!KONAREEF-TOML/V3\n",
		"#!konareef-toml/V3\n",
		"#!Konareef-Toml/v3\n",
		" #!konareef-toml/v3\n",
		"#!konareef-toml/v3 \n",
		"#!konareef-toml/v3\t\n",
		"#! konareef-toml/v3\n",
		"#!konareef-toml/ v3\n",
		"#!konareef-toml/v3\r\n",
		"\n#!konareef-toml/v3\n",
		"\xEF\xBB\xBF#!konareef-toml/v3\n",
		"#!konareef-toml/v4\n",
		"#!konareef-toml/v30\n",
		"#!konareef-toml/v3x\n",
		"#!konareef-toml/v03\n",
		"\t#!konareef-toml/v3\n",
		"\xC2\xA0#!konareef-toml/v3\n",
		"\xE2\x80\x8B#!konareef-toml/v3\n",
		"#!konareef\xE2\x80\x8B-toml/v3\n",
		"#!konareef-toml\n",
		"#!konareef-toml/v1\r#!konareef-toml/v3\n",
	}
	for _, line := range lines {
		fr := v2FieldsRoot(t)
		if strings.HasPrefix(line, "#!konareef-toml/v3") {
			fr = v3FieldsRoot(t)
		}
		bundle := buildFieldsRootBundle(t, line, fr, fr[:], true, false, "r_init_scheme = \"konareef-rinit/v1\"\n")
		r := VerifyV2(bundle, WithAcceptingVerifierForTests())
		if r.OK {
			t.Errorf("%q: a near-miss magic line was accepted", line)
			continue
		}
		if r.V2Verdict != nil && r.V2Verdict.CommitmentsValid {
			t.Errorf("%q: CommitmentsValid=true on a near-miss manifest", line)
		}
		named := false
		for _, d := range r.Divergences {
			if d.Err == ErrManifestMagicNearMiss && strings.Contains(d.Msg, canon.ErrMagicNearMiss) {
				named = true
			}
		}
		if !named {
			t.Errorf("%q: no ErrManifestMagicNearMiss divergence names %s; got %v",
				line, canon.ErrMagicNearMiss, divergenceStrings(r))
		}
	}
}
