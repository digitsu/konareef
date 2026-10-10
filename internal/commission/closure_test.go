// Copyright 2026 Jerry David Chan, Konareef.ai
// SPDX-License-Identifier: Apache-2.0

package commission

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/BurntSushi/toml"
	"github.com/digitsu/konareef/internal/envelope"
	"github.com/digitsu/konareef/internal/pod"
	"golang.org/x/text/unicode/norm"
)

// corpusClass names which kind of evidence a closure-corpus fixture is. The
// corpus README counts three kinds separately and the tests must report the
// same three counts, so a reader of `go test -v` output never has to infer
// which fixtures are evidence about real pods and which are evidence about
// rules (IB-09, konareef#24, required-tests item "real vs synthetic corpus
// count reported").
//
// Before the IB-09 follow-up (Hermes review of !122) there were only two
// classes, and the "real" class was "every top-level testdata/corpus/*.toml".
// That counted the two committed v2 fixtures as real pods, so the test logged
// "4 real fixture(s)" while the README said the real corpus is two pods.
type corpusClass int

const (
	// corpusRealPod is a copy of a real, authorized pod manifest a buyer
	// would commission. Only this class is closure evidence.
	corpusRealPod corpusClass = iota
	// corpusCommittedV2 is the byte-exact output of the real publish
	// pipeline for a fixture pod, carrying a genuine [_commit].fields_root.
	// It is evidence that the derivation matches committed roots
	// (TestDerivationMatchesCommittedFieldsRoot), not that real commissions
	// fit the four dimensions: the pods themselves are test fixtures.
	corpusCommittedV2
	// corpusSynthetic is a hand-written manifest under synthetic/ that names
	// one rule the real pods do not exercise. It is never closure evidence.
	corpusSynthetic
)

// String returns the label that collectCorpus logs for the class.
//
// Input: the class. Output: a short human-readable label.
func (c corpusClass) String() string {
	switch c {
	case corpusRealPod:
		return "real pod"
	case corpusCommittedV2:
		return "committed v2 fixture"
	case corpusSynthetic:
		return "synthetic fixture"
	default:
		return fmt.Sprintf("corpusClass(%d)", int(c))
	}
}

// realCorpusPods is the allow-list of real, authorized pods in
// testdata/corpus/. It is the machine-checked form of the README's
// "Two real manifests" claim. Adding a name here is a change to the closure
// evidence, so it needs a third authorized pod and a matching README update;
// it is not a way to make a new fixture pass.
var realCorpusPods = []string{
	"demo_pods_voice-forge_pod.toml",
	"examples_pods_code-reviewer_pod.toml",
}

// committedV2CorpusFixtures is the list of publish-pipeline v2 fixtures in
// testdata/corpus/ (see the README section "The two canonical v2 fixtures").
// They sit beside the real pods because TestDerivationMatchesCommittedFieldsRoot
// and TestCorpusV2FixturesAreLegacyZero read them by that path.
var committedV2CorpusFixtures = []string{
	"v2_zk_memory_free_pod.toml",
	"v2_zk_model_bearing_pod.toml",
}

// corpusFixture pairs a fixture path with its evidence class.
type corpusFixture struct {
	path  string
	class corpusClass
}

// classifyCorpusFile returns the evidence class of one corpus fixture path.
//
// Input: a path as returned by the corpus globs (testdata/corpus/*.toml or
// testdata/corpus/synthetic/*.toml). Output: the class, or an error when a
// top-level file is on neither realCorpusPods nor committedV2CorpusFixtures.
// The error is the point: an unlisted top-level file must not be counted as
// a real pod by default.
func classifyCorpusFile(path string) (corpusClass, error) {
	if filepath.Base(filepath.Dir(path)) == "synthetic" {
		return corpusSynthetic, nil
	}
	name := filepath.Base(path)
	if slices.Contains(realCorpusPods, name) {
		return corpusRealPod, nil
	}
	if slices.Contains(committedV2CorpusFixtures, name) {
		return corpusCommittedV2, nil
	}
	return 0, fmt.Errorf("corpus fixture %s is not classified: add it to realCorpusPods only if it "+
		"is a real, authorized pod (and update testdata/corpus/README.md's count), to "+
		"committedV2CorpusFixtures if it is publish-pipeline output, or move it to "+
		"testdata/corpus/synthetic/ if it is hand-written", path)
}

// collectCorpus globs both corpus levels, classifies every fixture, logs the
// count per class, and fails LOUDLY, never skips, when the corpus is empty,
// when a fixture cannot be classified, or when a listed real pod or committed
// v2 fixture is missing.
//
// Before 2026-09-24 (IB-09) both callers of this glob shape used t.Skip on an
// empty result, the same anti-pattern IB-03 (konareef#21) fixed in
// TestDerivationMatchesCommittedFieldsRoot: a CI change that broke fixture
// discovery (a renamed directory, a build-tag mistake, a testdata exclusion)
// would have made a real regression read as "nothing to test" instead of a
// failure.
//
// Input: the calling test. Output: every fixture with its class, real pods
// first, then committed v2 fixtures, then synthetic fixtures.
func collectCorpus(t *testing.T) []corpusFixture {
	t.Helper()
	top, err := filepath.Glob("testdata/corpus/*.toml")
	if err != nil {
		t.Fatal(err)
	}
	synthetic, err := filepath.Glob("testdata/corpus/synthetic/*.toml")
	if err != nil {
		t.Fatal(err)
	}
	if len(top)+len(synthetic) == 0 {
		t.Fatal("no corpus fixtures found under testdata/corpus/ or testdata/corpus/synthetic/ — " +
			"section 6 item 1 cannot be answered at all, which is a failure, not an empty result " +
			"(IB-09, konareef#24; the same skip-hides-a-regression class IB-03 fixed elsewhere)")
	}

	counts := map[corpusClass]int{}
	fixtures := make([]corpusFixture, 0, len(top)+len(synthetic))
	for _, p := range append(top, synthetic...) {
		class, err := classifyCorpusFile(p)
		if err != nil {
			t.Fatal(err)
		}
		counts[class]++
		fixtures = append(fixtures, corpusFixture{path: p, class: class})
	}
	slices.SortStableFunc(fixtures, func(a, b corpusFixture) int { return int(a.class) - int(b.class) })

	// A listed file that is missing would lower a count without any other
	// signal, so each list is checked against what the glob found.
	if counts[corpusRealPod] != len(realCorpusPods) {
		t.Fatalf("found %d real pod fixture(s), want %d (%v) — a real pod is missing from testdata/corpus/",
			counts[corpusRealPod], len(realCorpusPods), realCorpusPods)
	}
	if counts[corpusCommittedV2] != len(committedV2CorpusFixtures) {
		t.Fatalf("found %d committed v2 fixture(s), want %d (%v) — a committed v2 fixture is missing "+
			"from testdata/corpus/", counts[corpusCommittedV2], len(committedV2CorpusFixtures),
			committedV2CorpusFixtures)
	}

	t.Logf("closure corpus: %d real pod(s), %d committed v2 fixture(s), %d synthetic fixture(s); "+
		"only the real pods are closure evidence",
		counts[corpusRealPod], counts[corpusCommittedV2], counts[corpusSynthetic])
	return fixtures
}

// TestClassifyCorpusFile pins the three-way corpus classification that
// collectCorpus reports (IB-09 follow-up, konareef#24; Hermes review of !122).
// The control cases are every fixture committed today. The refusal case is a
// top-level file that is on neither the real-pod allow-list nor the committed
// v2 fixture list: it must be an error, never a silent "real" count, because
// the corpus README's "two real manifests" claim is only true if a new file
// cannot join the real class by being dropped into the directory.
func TestClassifyCorpusFile(t *testing.T) {
	controls := map[string]corpusClass{
		"testdata/corpus/demo_pods_voice-forge_pod.toml":                         corpusRealPod,
		"testdata/corpus/examples_pods_code-reviewer_pod.toml":                   corpusRealPod,
		"testdata/corpus/v2_zk_memory_free_pod.toml":                             corpusCommittedV2,
		"testdata/corpus/v2_zk_model_bearing_pod.toml":                           corpusCommittedV2,
		"testdata/corpus/synthetic/synthetic_nfc_violation_pod.toml":             corpusSynthetic,
		"testdata/corpus/synthetic/synthetic_declaration_only_denylist_pod.toml": corpusSynthetic,
	}
	for path, want := range controls {
		got, err := classifyCorpusFile(path)
		if err != nil {
			t.Errorf("classifyCorpusFile(%q) returned error %v, want class %s", path, err, want)
			continue
		}
		if got != want {
			t.Errorf("classifyCorpusFile(%q) = %s, want %s", path, got, want)
		}
	}

	for _, path := range []string{
		"testdata/corpus/third_unreviewed_pod.toml",
		"testdata/corpus/v2_zk_unlisted_pod.toml",
	} {
		if class, err := classifyCorpusFile(path); err == nil {
			t.Errorf("classifyCorpusFile(%q) = %s with no error; an unlisted top-level fixture "+
				"must be refused, not counted", path, class)
		}
	}
}

// hasNonNFCDeclaredTool reports whether any [[context.tools]].source in s is
// not NFC-normalized. FromSpec refuses such a manifest with
// ErrToolNameNotNFC (ADR decision D5) before it ever reaches the
// tools_allowed-commitment check, because CheckToolPolicy evaluates the
// declared side's NFC rule first. testdata/corpus/synthetic/synthetic_nfc_violation_pod.toml
// is the fixture that exercises this.
func hasNonNFCDeclaredTool(s pod.Spec) bool {
	if s.Context == nil {
		return false
	}
	for _, tool := range s.Context.Tools {
		if norm.NFC.String(tool.Source) != tool.Source {
			return true
		}
	}
	return false
}

// TestClosureCorpus answers section 6 item 1 of the intent-bridge analysis:
// is the COMMISSION-TIME dimension set closed? Every real manifest must be
// expressible as an envelope with no constraint left over.
//
// A failure here is a finding about the algebra, not a test to relax. The
// corpus is small — see testdata/corpus/README.md for what it contains and
// why — so a pass here is weak evidence of closure, not proof of it.
//
// The tools assertion below deliberately does NOT reuse the field ToolIDs
// reads. A guard built from the same field the derivation reads can only
// confirm "what FromSpec looked at is what FromSpec found" — it can never
// detect a constraint a manifest declares through a route FromSpec does not
// read. This structural independence is what caught the fix-round-1 finding:
// the round-1 ToolIDs read [directive].tools_allowed, which
// demo_pods_voice-forge_pod.toml never sets — it declares tools only via
// [[context.tools]] — so the round-1 guard (built from the same field)
// silently never ran for that manifest. Fix round 2 corrected ToolIDs itself
// to read [[context.tools]].source (the actually-authoritative source; see
// ToolIDs' doc comment), which is what fix round 2 verified against
// internal/install.LoadManifestParams.
//
// That correction surfaced a distinct, schema-level finding:
// examples_pods_code-reviewer_pod.toml declares its tool constraint only via
// [directive].tools_allowed/tools_denied and has no [[context.tools]] table
// at all, so under the now-correct ToolIDs its tool constraint is genuinely
// absent from the derived envelope — not because ToolIDs is wrong, but
// because the manifest uses a field the circuit-feeding derivation was never
// wired to read. See the intent-to-manifest bridge analysis (2026-08-11) §13
// for the full three-round history.
//
// That analysis is named rather than linked by path: it lives under a tree the
// public-mirror export forbids by regex, and a path reference here fails the
// export scan — which is how this comment last broke the mirror.
//
// Fix round 4 (2026-08-31) gave that shape a defined behaviour instead of a
// skip: FromSpec REFUSES it with ErrToolAuthorityNotCommitted. Teaching
// ToolIDs to read tools_allowed was NOT the fix — that would reintroduce the
// divergence fix round 2 closed, and would redefine the committed tool set of
// already-published pods. Refusal is the fail-CLOSED reading: a manifest
// whose tool authority never reaches fields_root cannot participate in a
// containment check that would otherwise report it "contained" while it holds
// authority the envelope does not represent. The assertion below is therefore
// a real, non-skipped regression. Do NOT relax it back into a skip, do NOT
// teach ToolIDs to read tools_allowed, and do NOT edit the corpus fixture to
// add a [[context.tools]] table it does not actually have.
func TestClosureCorpus(t *testing.T) {
	fixtures := collectCorpus(t)
	for _, fx := range fixtures {
		p := fx.path
		t.Run(filepath.Base(p), func(t *testing.T) {
			raw, err := os.ReadFile(p)
			if err != nil {
				t.Fatal(err)
			}
			var s pod.Spec
			if _, err := toml.Decode(string(raw), &s); err != nil {
				// Fatal, not Skip: every corpus fixture is a pod manifest,
				// so a decode failure is a broken fixture or a Spec change,
				// and skipping it would silently remove its coverage.
				t.Fatalf("corpus fixture is not a decodable pod spec: %v", err)
			}
			// Declared-tools guard: read BOTH schema routes the manifest
			// could use ([directive].tools_allowed and [[context.tools]]),
			// not just the one ToolIDs reads, so a mismatch between the two
			// is caught here instead of passing silently. See the function
			// doc comment for why this must not be built from the same field
			// the derivation reads.
			var directiveTools []string
			if s.Directive != nil {
				directiveTools = s.Directive.ToolsAllowed
			}
			hasContextTools := s.Context != nil && len(s.Context.Tools) > 0
			hasDirectiveToolsAllowed := len(directiveTools) > 0
			hasNonNFCDeclared := hasNonNFCDeclaredTool(s)

			e, err := FromSpec(s)

			if hasNonNFCDeclared {
				// CheckToolPolicy evaluates the declared side's NFC rule
				// before anything else (see toolpolicy.go), so a non-NFC
				// [[context.tools]] source is refused ahead of any
				// tools_allowed-commitment question, even if this fixture
				// also happened to have one. ADR decision D5.
				if !errors.Is(err, ErrToolNameNotNFC) {
					t.Fatalf("spec declares a non-NFC [[context.tools]] source; FromSpec must refuse "+
						"it with ErrToolNameNotNFC (tool-policy semantics ADR, decision D5), got err=%v "+
						"envelope=%+v", err, e)
				}
				return
			}

			if hasDirectiveToolsAllowed && !hasContextTools {
				// The uncommittable shape. This manifest states its tool
				// authority only in tools_allowed, which no runtime enforces
				// today and which never reaches fields_root, so
				// deriving an envelope for it at all would let a containment
				// check report "contained" over authority the envelope does
				// not represent. FromSpec must refuse it outright.
				if !errors.Is(err, ErrToolAuthorityNotCommitted) {
					t.Fatalf("spec declares tools only via directive.tools_allowed=%v and has no "+
						"[[context.tools]]; FromSpec must refuse it with ErrToolAuthorityNotCommitted, "+
						"got err=%v envelope=%+v", directiveTools, err, e)
				}
				return
			}

			if err != nil {
				t.Fatalf("cannot derive an envelope: %v", err)
			}
			if s.Model != nil && len(e.Models) == 0 {
				t.Error("spec declares a model the envelope did not capture")
			}
			if hasContextTools && len(e.Tools) == 0 {
				// [[context.tools]] is exactly what ToolIDs reads. If it is
				// set and the envelope is still empty, ToolIDs itself is
				// broken.
				t.Errorf("spec declares [[context.tools]] but the envelope did not capture it — " +
					"this is a ToolIDs regression; see the intent-to-manifest bridge analysis §13")
			}

			if s.Budget != nil && s.Budget.MaxSats > 0 && e.CMax == 0 {
				t.Error("spec declares a budget the envelope did not capture")
			}

			// Unknown-data-scope guard (IB-09, konareef#24): FromSpec's own
			// doc comment says the memory-scope (Labels) dimension is left
			// absent because no pod.toml field carries a provenance-label
			// vocabulary today — this is a named finding, not an oversight
			// (docs/design/tool-policy-semantics-adr.md §5; DATA-00,
			// konareef#27 is the open follow-up). Every corpus manifest,
			// real or synthetic, is asserted against that finding here so a
			// future change that starts deriving Labels from some new field
			// cannot do so silently: it must update this guard, and explain
			// the new derivation, rather than let the corpus report
			// four-dimension closure while a fifth is quietly produced.
			if e.LabelsSet || len(e.Labels) != 0 {
				t.Errorf("FromSpec derived a data-scope (Labels) dimension for this manifest "+
					"(LabelsSet=%v Labels=%v); no pod.toml field is documented to feed it (see "+
					"FromSpec's doc comment) — either this is a regression, or a real derivation now "+
					"exists and this guard, the ADR and the corpus README must all be updated together",
					e.LabelsSet, e.Labels)
			}
		})
	}
}

// expectedManifestParamsFields restates, for test purposes only, the exact
// derivation logic in internal/install.LoadManifestParams
// (internal/install/manifest_params.go): Models is
// []string{"<provider>/<name>"} (spec §4.1, R-V2.5 — the provider prefix is
// REQUIRED and was added on 2026-09-21, when this site still emitted the
// bare name while publish committed the prefixed form), Tools is
// spec.Context.Tools[].Source, and CMax is spec.Budget.MaxSats. That is the
// derivation that actually feeds feeder.ManifestParams into the circuit's
// WitnessWriter, so it is the authority commission.FromSpec must agree
// with.
//
// LoadManifestParams cannot be called directly against a bare pod.toml: it
// reads an install-cache directory (manifest.canon, signature.bin,
// meta.json) that the corpus fixtures here do not have. This helper
// re-states its field-selection logic instead of duplicating the cache
// machinery. If manifest_params.go's derivation changes, this helper (and
// the comment) must change with it, or TestClosureCorpus_AgreesWithInstall
// will pass for the wrong reason.
func expectedManifestParamsFields(s pod.Spec) (models, tools []string, cMax uint64) {
	if s.Model != nil && s.Model.Provider != "" && s.Model.Name != "" {
		models = []string{s.Model.Provider + "/" + s.Model.Name}
	}
	if s.Context != nil {
		for _, t := range s.Context.Tools {
			tools = append(tools, t.Source)
		}
	}
	if s.Budget != nil && s.Budget.MaxSats > 0 {
		cMax = uint64(s.Budget.MaxSats)
	}
	return models, tools, cMax
}

// TestClosureCorpus_AgreesWithInstall guards against exactly the fix-round-1
// class of bug: commission.FromSpec silently deriving a dimension from a
// different manifest field than the one that actually feeds the circuit via
// internal/install.LoadManifestParams. It compares FromSpec's Models, Tools
// and CMax against expectedManifestParamsFields (mirroring
// manifest_params.go) for every corpus manifest, as sets — normalised the
// same way FromSpec normalises — so declaration order is not asserted, only
// which identifiers are present. A divergence here means FromSpec disagrees
// with the field selection the circuit actually depends on and must not be
// shipped.
func TestClosureCorpus_AgreesWithInstall(t *testing.T) {
	fixtures := collectCorpus(t)
	for _, fx := range fixtures {
		p := fx.path
		t.Run(filepath.Base(p), func(t *testing.T) {
			raw, err := os.ReadFile(p)
			if err != nil {
				t.Fatal(err)
			}
			var s pod.Spec
			if _, err := toml.Decode(string(raw), &s); err != nil {
				// Fatal, not Skip: every corpus fixture is a pod manifest,
				// so a decode failure is a broken fixture or a Spec change,
				// and skipping it would silently remove its coverage.
				t.Fatalf("corpus fixture is not a decodable pod spec: %v", err)
			}
			e, err := FromSpec(s)
			if errors.Is(err, ErrToolAuthorityNotCommitted) || errors.Is(err, ErrToolNameNotNFC) {
				// Refused at derivation (see TestClosureCorpus): there is no
				// envelope to compare against LoadManifestParams, and that
				// refusal is the asserted behaviour, not a gap.
				return
			}
			if err != nil {
				t.Fatalf("cannot derive an envelope: %v", err)
			}
			wantModels, wantTools, wantCMax := expectedManifestParamsFields(s)

			gotModels := envelope.Normalise(e.Models)
			wantModelsNorm := envelope.Normalise(wantModels)
			if !slicesEqual(gotModels, wantModelsNorm) {
				t.Errorf("Models = %v, want %v (per internal/install.LoadManifestParams)", gotModels, wantModelsNorm)
			}

			gotTools := envelope.Normalise(e.Tools)
			wantToolsNorm := envelope.Normalise(wantTools)
			if !slicesEqual(gotTools, wantToolsNorm) {
				t.Errorf("Tools = %v, want %v (per internal/install.LoadManifestParams)", gotTools, wantToolsNorm)
			}

			if e.CMax != wantCMax {
				t.Errorf("CMax = %d, want %d (per internal/install.LoadManifestParams)", e.CMax, wantCMax)
			}
		})
	}
}

func slicesEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
