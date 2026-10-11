// Copyright 2026 Jerry David Chan, Konareef.ai
// SPDX-License-Identifier: Apache-2.0

// corpus_memory_class_test.go — pins the memory-root class of the two
// canonical v2 corpus fixtures (MEM-03, konareef#26). They were generated
// while publish committed the provisional r_init = 0, and they are kept
// byte-for-byte as examples of that legacy form (konareef-rinit/v1 R-M16:
// published legacy manifests are never rewritten). This test makes the
// state explicit, so a green suite is not read as "these roots are
// current": both must classify as memory_free_legacy_zero, carry no
// r_init_scheme marker, and would classify as memory_free_rinit_v1 only
// with the E20 root today's publish commits.
package commission

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/digitsu/konareef/internal/canon"
	"github.com/digitsu/konareef/internal/pod"
)

func TestCorpusV2FixturesAreLegacyZero(t *testing.T) {
	for _, name := range []string{"v2_zk_memory_free_pod.toml", "v2_zk_model_bearing_pod.toml"} {
		t.Run(name, func(t *testing.T) {
			raw, err := os.ReadFile(filepath.Join("testdata", "corpus", name))
			if err != nil {
				t.Fatal(err)
			}
			tr, err := canon.ParseCommitTrailer(raw)
			if err != nil {
				t.Fatalf("ParseCommitTrailer: %v", err)
			}
			if tr.RInitScheme != "" {
				t.Fatalf("legacy fixture carries a marker %q", tr.RInitScheme)
			}
			spec, meta, err := pod.ParseWithMeta(raw)
			if err != nil {
				t.Fatal(err)
			}
			var models, tools []string
			if spec.Model != nil {
				id, err := canon.ModelID(spec.Model.Provider, spec.Model.Name)
				if err != nil {
					t.Fatal(err)
				}
				models = []string{id}
			}
			if spec.Context != nil {
				for _, tool := range spec.Context.Tools {
					tools = append(tools, tool.Source)
				}
			}
			if !meta.IsDefined("budget", "max_sats") {
				t.Fatal("fixture has no [budget].max_sats")
			}
			cMax := uint64(spec.Budget.MaxSats)
			class, err := canon.ClassifyMemoryRoot(tr, models, tools, cMax)
			if err != nil || class != canon.MemoryFreeLegacyZero {
				t.Fatalf("class = %s (%v), want %s", class, err, canon.MemoryFreeLegacyZero)
			}
			// Control: the same dimensions over E20 classify as v1.
			v1, _ := canon.FieldsRoot(models, tools, cMax, canon.EmptyMemoryRoot())
			if c, _ := canon.ClassifyMemoryRoot(canon.CommitTrailer{FieldsRoot: v1, RInitScheme: canon.RInitSchemeV1}, models, tools, cMax); c != canon.MemoryFreeRInitV1 {
				t.Fatalf("control class = %s", c)
			}
		})
	}
}
