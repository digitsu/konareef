// Copyright 2026 Jerry David Chan, Konareef.ai
// SPDX-License-Identifier: Apache-2.0

// magic_near_miss_test.go — KR-MAGIC (konareef#29): publish refuses an
// author pod.toml whose first line is a near miss of the konareef-toml
// magic, on both the v1 and the --zk (v2) paths. The TOML parser reads
// such a line as a comment, so only the canonicalizer gate stops it.
package publish

import (
	"errors"
	"testing"

	"github.com/digitsu/konareef/internal/canon"
)

// TestPrepare_RefusesNearMissMagic runs Prepare over a valid memory-free
// pod whose pod.toml opens with each near-miss line. The unprefixed
// control proves the pod itself publishes.
func TestPrepare_RefusesNearMissMagic(t *testing.T) {
	for _, zk := range []bool{false, true} {
		if _, err := Prepare(writePodFixture(t, validMemoryFreePodTOML), testIdentity(t), PrepareOptions{ZK: zk}); err != nil {
			t.Fatalf("control (zk=%v): Prepare = %v", zk, err)
		}
		for _, line := range []string{
			"#!KONAREEF-TOML/V3\n", "#!Konareef-Toml/v3\n", " #!konareef-toml/v3\n",
			"#! konareef-toml/v3\n", "\n#!konareef-toml/v3\n", "\t#!konareef-toml/v2\n",
			"#!konareef-toml\n", "#!konareef-toml/v1\r#!konareef-toml/v2\n",
		} {
			_, err := Prepare(writePodFixture(t, line+validMemoryFreePodTOML), testIdentity(t), PrepareOptions{ZK: zk})
			var ce *canon.Error
			if !errors.As(err, &ce) || ce.Code != canon.ErrMagicNearMiss {
				t.Errorf("zk=%v %q: Prepare = %v, want %s", zk, line, err, canon.ErrMagicNearMiss)
			}
		}
	}
}
