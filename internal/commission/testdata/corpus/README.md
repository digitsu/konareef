# Closure corpus

Collected 2026-08-29 to answer section 6 item 1 of the intent-to-manifest bridge
analysis (2026-08-11): is the
commission-time dimension set (models, tools, spend, memory-scope) closed against real
commissions?

`find . -name "pod.toml"` returns 35 manifests in the repo. Most are canonicalisation
fixtures under `internal/canon/testdata/canon/v1/**` — synthetic TOML built to exercise
the parser (escapes, floats, nested tables, rejects), not pods anyone would commission.
Including those would inflate the corpus with files that answer nothing about closure.
This directory holds only the manifests that represent a real pod a buyer would actually
commission.

## Included

- `demo_pods_voice-forge_pod.toml`, copied from `demo/pods/voice-forge/pod.toml`. A
  working demo pod with a real `[model]`, a `[[context.tools]]` bash allowlist,
  `[directive]`, `[budget]`, dependencies, and output predicates — the ElevenLabs TTS
  demo. Its tool constraint is declared via `[[context.tools]]`, not `[directive]`.
- `examples_pods_code-reviewer_pod.toml`, copied from
  `examples/pods/code-reviewer/pod.toml`. A working example pod with `[model]`,
  `[directive]` (including both `tools_allowed` and `tools_denied`), `[budget]`,
  `[wallet]`, and `[marketplace]` tables — the PR/MR code-review pod. Since
  17d736e it declares its four tools as `[[context.tools]]` entries as well as in
  `[directive].tools_allowed`/`tools_denied`. Before that commit its tool constraint
  lived only in the directive lists.

**These two manifests use different, non-overlapping fields to declare their tool
constraint.** See §13 of the analysis document for why that matters: only
`[[context.tools]]` is read by the circuit-feeding derivation
(`internal/install.LoadManifestParams`). `[directive].tools_allowed` is not captured
in a committed `fields_root`, and no runtime enforces it either: reef-core parses it
and reads it nowhere (spec R-V2.14; see `docs/design/tool-policy-semantics-adr.md`).

As of 2026-08-31 that shape is REFUSED rather than silently derived:
`commission.FromSpec` returns `ErrToolAuthorityNotCommitted` for a manifest declaring
`[directive].tools_allowed` with no `[[context.tools]]`, because an envelope derived
from it would carry an empty `Tools` dimension and let a containment check report the
pod contained while it holds tool authority the envelope does not name.
`examples_pods_code-reviewer_pod.toml` was the corpus fixture for that refusal until
17d736e added its `[[context.tools]]` entries. It now takes the derivation branch of
`TestClosureCorpus`, so no corpus manifest exercises the refusal branch today. The
refusal itself is still asserted by `TestFromSpec_RefusesToolAuthorityOnlyInDirective`
in `derive_test.go` and by fixture TP-09 in `testdata/toolpolicy/cases.json`.

## Considered and excluded

- `internal/publish/testdata/pod-sample-zk/pod.toml` — excluded. It has no `[model]`,
  no `[budget]`, and no `[directive].tools_allowed`; its only directive is a template
  pointing at a prompt file whose entire content is the word "hello". Its own comment
  block says it exists to give `saltstore.LineageIDFromManifest` a deterministic
  16-byte lineage ID for the Type-D salt-provisioning path, and its only referrer in the
  Go source is `main_zk_publish_test.go`. This is a test fixture for the publish/ZK
  code path, not a manifest for a pod anyone would commission, so it does not belong in
  a corpus meant to answer whether real commissions fit the four dimensions.

No other `pod.toml` in the repo has a meaningful `[directive]`, `[model]`, and
`[budget]` combination outside the two included above and the excluded ZK fixture; the
remaining 32 are canonicalisation testdata.

**Recount, 2026-09-24 (IB-09, konareef#24):** `find . -name pod.toml -not -path
"*/testdata/corpus/*"` now returns 49, not 35. The 14 new files are all
`internal/canon/testdata/canon/v2/**` and `internal/publish/testdata/v2/**` —
canonicalizer conformance vectors and v2 publish-refusal fixtures built for the
konareef-toml/v2 work (!106) and the tool-policy semantics ADR (!117), none dated before
2026-09-19. Each is synthetic-by-construction (a `float-nan` or `over-cap` or
`tool-authority-uncommitted` fixture is not a pod a buyer would commission), so this
recount does not change the finding above: konareef still has exactly two real,
authorized pods, and this directory still holds both of them. It also does not change the
count in the next section, which is not a re-derivation of this one.

## Corpus size

**Two real manifests.** This is weak evidence for closure — see the dated subsection
appended to the analysis document for the corpus size, the outcome, and why two pods
cannot settle the question on their own. Adding more files to this directory does not
strengthen that count unless the new file is a third authorized pod; see "Synthetic
additions" below for why the two files under `synthetic/` do not count as evidence toward
closure and must never be cited as if they did.

## The two canonical v2 fixtures

`v2_zk_memory_free_pod.toml` and `v2_zk_model_bearing_pod.toml` are not
hand-written. Each is the byte-exact output of the real publish pipeline
(`publish.Prepare(dir, id, PrepareOptions{ZK: true})`) for a ZK-eligible pod,
so each carries a genuine `[_commit].fields_root`.
`TestDerivationMatchesCommittedFieldsRoot` compares this package's envelope
derivation against those committed roots.

`v2_zk_model_bearing_pod.toml` was added 2026-09-21 because the memory-free
fixture declares no `[model]`, so the models dimension was never compared —
and that was the one dimension where the three Go derivations of the model id
had silently diverged (`internal/publish`, `internal/install` and this package
each derived it, and two of them dropped the provider). The test now also
FAILS when no compared fixture declares a `[model]`, so it cannot go blind
again.

## Synthetic additions (2026-09-24, IB-09, konareef#24)

`synthetic/synthetic_nfc_violation_pod.toml` and
`synthetic/synthetic_declaration_only_denylist_pod.toml` are **not real pods and are not
closure evidence.** No buyer has commissioned either, and the "two real manifests" count
above does not include them. `TestClosureCorpus` and `TestClosureCorpus_AgreesWithInstall`
read them from `testdata/corpus/synthetic/`, a separate subdirectory from the two real
fixtures, and both tests report the count per class so a reader never has to infer which
count backs which claim (see "How the tests classify this directory" below).

They exist because the two real pods, by accident of what they happen to declare, do not
exercise two rules the accepted tool-policy semantics ADR (TA-00 konareef#18, decided;
TA-01 konareef#19, implemented in !117) settled at the commission-derivation layer
(`commission.FromSpec`, as opposed to `pod validate` or v2 publish, which
`internal/pod/toolpolicy_test.go` and `internal/commission/testdata/toolpolicy/cases.json`
already cover at the byte level):

- **`synthetic_nfc_violation_pod.toml`** declares a `[[context.tools]]` source in NFD
  Unicode form. `FromSpec` must refuse it with `ErrToolNameNotNFC` (decision D5) before it
  ever reaches the tools_allowed-commitment question. Neither real pod's tool names need
  normalization, so nothing before this fixture proved the D5 refusal fires through the
  full closure-corpus path (manifest → `toml.Decode` → `FromSpec`), only through the
  narrower `toolpolicy_fixtures_test.go` unit test (fixtures TP-07/TP-08).
- **`synthetic_declaration_only_denylist_pod.toml`** declares
  `[directive].tools_denied = ["secrets_read"]` naming a tool with no `[[context.tools]]`
  entry (an unknown deny referent, D5: a warning under the accepted Option B, never a
  refusal). Neither real pod sets `tools_denied` at all, so nothing before this fixture
  proved that `FromSpec` derives a full envelope — Tools exactly `{bash}`, no error — for a
  manifest carrying a deny list. This is the corpus-level witness for the "declaration
  only" correction: `tools_denied` visibly does nothing to the derived envelope, matching
  `docs/design/tool-policy-semantics-adr.md` §5 and the corrected R-V2.14 in
  `docs/reference/konareef-toml-v2-spec.md`.

Do not add a third file here to "balance" the real corpus, and do not read either fixture
as evidence that a real buyer pod exercises these shapes — they are unit-test material for
two specific rules, dressed as pod manifests because `FromSpec` takes a `pod.Spec`, not a
narrower type.

## How the tests classify this directory

**Corrected 2026-09-25 (IB-09 follow-up, konareef#24).** The first version of this
section's count (added 2026-09-24 in !122) said `go test -v` prints "4 real fixture(s), 2
synthetic fixture(s)". That was the test output, and the test output was wrong: it counted
every top-level `*.toml` here as real, so the two committed v2 fixtures were reported as
real pods. That contradicted the "Two real manifests" count above. Review of !122 found it.

`collectCorpus` in `closure_test.go` now puts every fixture in one of three classes and
prints:

```
closure corpus: 2 real pod(s), 2 committed v2 fixture(s), 2 synthetic fixture(s); only the real pods are closure evidence
```

| Class | Files | Closure evidence? |
|---|---|---|
| Real pod | `demo_pods_voice-forge_pod.toml`, `examples_pods_code-reviewer_pod.toml` | Yes (weak: two pods) |
| Committed v2 fixture | `v2_zk_memory_free_pod.toml`, `v2_zk_model_bearing_pod.toml` | No. Evidence that the derivation matches committed `fields_root` values |
| Synthetic | `synthetic/*.toml` | No. Unit-test material for two ADR rules |

The real-pod and committed-v2 classes are explicit name lists (`realCorpusPods`,
`committedV2CorpusFixtures`), not filename patterns. The test fails when:

- a top-level file is on neither list (it is not counted as real by default),
- a listed file is missing (a count cannot drop without a failure),
- any fixture does not decode as a pod spec (before this change that was a `t.Skip`, which
  could remove a fixture's coverage without a failure).

To add a third real pod, add its name to `realCorpusPods` and update the count in "Corpus
size" above in the same change.

## Data-scope (Labels) coverage

Every fixture in this corpus, real or synthetic, is also asserted against the "unknown
data scope" finding: `commission.FromSpec` never sets `Envelope.LabelsSet` or
`Envelope.Labels`, because no `pod.toml` field carries a provenance-label vocabulary today
(`FromSpec`'s doc comment; `docs/design/tool-policy-semantics-adr.md` §5; DATA-00,
konareef#27 decided attribution-only on 2026-10-08, so no label derivation is planned). `TestClosureCorpus` fails if
any fixture's derived envelope ever sets either, so a future change that starts deriving
labels from some new field cannot do so silently — it must update that guard, this README
and the ADR together, not just add the field.

### Both fixtures embed the LEGACY `r_init = 0` — kept on purpose as legacy examples

**Update 2026-09-24 (MEM-03, konareef#26).** The convention is now settled:
konareef-rinit/v1 (`docs/reference/konareef-memory-root-v1-spec.md`, accepted)
makes a memory-free pod commit `r_init = E₂₀` (the Poseidon empty-tree root)
with `r_init_scheme = "konareef-rinit/v1"` in `[_commit]`, and publish does so.
These two fixtures were deliberately NOT regenerated. They are byte-exact
examples of the legacy form that konareef published from !106 until MEM-03,
and published legacy manifests are never rewritten (R-M16).
`TestCorpusV2FixturesAreLegacyZero` pins that both classify as
`memory_free_legacy_zero` (R-M17), so a green suite cannot be read as "these
roots are current". The history below is kept for context.

#### History (before MEM-03)

Their `fields_root` values were computed with `r_init` set to the all-zero
field element. **That zero is a placeholder, not a settled convention.**
Canonical bytes cannot carry a comment, so this paragraph is the only thing
beside them that says so.

Spec §4.4 says a pod declaring no `[[context.memory]]` "has the empty-tree
root, which `membridge.SparseRoot` already computes". That is not usable as
written. `membridge.SparseRoot` lives in a SHA-256 domain, while
`canon.FieldsRoot`'s `leaf(r_init)` requires a canonical Poseidon-Pallas field
element (R-V2.4: little-endian integer < p). `membridge.SparseRoot(nil)` — the
fixed depth-20 `EmptyRoots[20]` constant — does not land below p, so
`canon.CanonicalizeV2` rejects it with `COMMIT_NONCANONICAL_RINIT` every time,
deterministically, not occasionally. Following the spec literally would make
every `--zk` publish of a memory-free pod fail.

The all-zero element was substituted instead: it is unconditionally canonical
(0 < p) and mirrors the `r_init = 0` convention already used by the "empty"
golden vector in `internal/canon/testdata/fields_root_vectors.json`. The full
reasoning is the comment block at `internal/publish/commitparams.go`, and
`TestFieldsRootRejectsTheRealEmptyMemoryRoot` (`internal/canon`) pins the real
`membridge.SparseRoot(nil)` value as a rejection, so the spec's literal
instruction is documented as unfollowable by a test rather than by prose only.

`r_init`'s real provenance is deferred to the companion spec with reef-core
(spec §4.4 point 2), which is also where a field-canonical empty-memory root
belongs. `membridge.ImportSnapshot` — the function §4.4 says must reproduce
`r_init` — has no production caller yet, so nothing currently cross-checks the
placeholder.

**When that convention is settled, both fixtures must be regenerated** (their
`fields_root` and `[_commit]` lines change) together with whatever wires
`ImportSnapshot` up. `TestDerivationMatchesCommittedFieldsRoot` will NOT catch
a stale fixture: it zeroes `r_init` on the derivation side by design, because
`r_init` is not an envelope dimension. Do not read a green suite as evidence
that these roots are current.
