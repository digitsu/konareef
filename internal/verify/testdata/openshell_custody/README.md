# OpenShell custody golden files (US-109, US-110)

These files are golden custody blobs and `konareef-bundle/v1` bundles of the
OpenShell adapter, phase 2
(reef-core document "OpenShell adapter: phase-2 detailed design", sections 6
and 7). konareef US-111 copies them into its test data. US-114 runs the released
konareef binary against the bundles.

## Files

| File | Content |
|---|---|
| `full.custody.txt` | The custody `data` blob of an OpenShell run with the full form: 16 lines after `AGENT_KEY:`. No trailing newline. |
| `full.bundle.json` | The verifiable bundle (`sanitize: :none`) of that chain, as `Bundle.pack_from_custody/2` gives it. It has the `openshell_evidence` key with every record. |
| `full.public.bundle.json` | The public bundle (`sanitize: :public`) of the same chain. Its `openshell_evidence` key withholds every `HTTP:*` record. |
| `full.public.forged.bundle.json` | `full.public.bundle.json` with forged redaction metadata on two withheld leaves. See "Forged redaction metadata". |
| `unavailable.custody.txt` | The custody `data` blob of an OpenShell run with the unavailable form: 5 lines after `AGENT_KEY:`, reason `records_missing`. No trailing newline. |
| `unavailable.bundle.json` | The verifiable bundle of that chain. It has no `openshell_evidence` key. |

Each chain is `structured_bundle → openbrain_snapshot → openshell_precommit → custody`.
The custody blob is `CUSTODY_PROOF: v4`.

## Inputs

- **Full form.** The evidence is the US-108 real run vector
  (`../reef_ocsf_v1/real_run.records`, 82 records) and its gateway object
  (`../reef_ocsf_v1/real_run.gateway.json`). The listener count is 4. That is the
  `listener_seen` of the vector for the listener `192.0.2.10:4100`, so the listener
  check of design 8.3 has `seen == served`.
- **Unavailable form.** The evidence has the gateway object but no records file (the
  case of the US-114 negative run). The reason is `records_missing`.
- **Policy.** `policy_yaml` is the policy that `OpenShellPolicy.compile/3` makes for
  the listener `192.0.2.10:4100` with no manifest network (`phase1_only: true`), as
  `Spawner.openshell_policy/3` makes it. Its SHA-256 replaces the US-108 placeholder
  `policy_submitted_sha256` of the gateway object. The gateway object is not under the
  root, so the root of the vector does not change. Thus
  `SHA-256(policy_yaml)` = `OPENSHELL_POLICY_SUBMITTED_SHA256` = the precommit's
  `POLICY_SHA256` (design 8.2, rule 11), in both forms.
- **Tool log.** The run has an empty tool log, so `tool_log_records` is `""` and
  `TOOL_LOG_ROOT` is the root of no records.
- Each chain has its own snapshot root. `full` has an empty snapshot: no leaves and
  the all-zero root. `unavailable` has two leaves (32 bytes of `0x0a` and 32 bytes of
  `0x0b`), and its root is the Merkle root of those leaves, so it recomputes from the
  bundle's `snapshot_leaves`. `Bundle` finds the snapshot row by its root, so a shared
  root would put one chain's snapshot block in the other chain's bundle. A test checks
  that the root of every golden bundle recomputes from its leaves. US-111 found that the
  first US-110 `unavailable` bundle had the root `0x0a..0a` with no leaves.
- The ids are fixed (`agent-us109-golden-full`, `agent-us109-golden-unavailable`,
  `task-us109-golden-*`, `pod-us109-golden`). The timestamps and the link hashes come
  from the run that made the files.

## The `openshell_evidence` key (design 7)

| Bundle | `HTTP:*` leaf | every other leaf |
|---|---|---|
| `full.bundle.json` | `{"record": <base64 of tag \|\| JCS>}` | `{"record": ...}` |
| `full.public.bundle.json` | `{"withheld": <hex leaf hash>, "class": ..., "seq": ...}` | `{"record": ...}` |

The real run has 4 `HTTP:POST` records, with `seq` 50, 51, 52 and 53. A withheld
leaf keeps the leaf hash `SHA-256(0x00 || record)`, so the root
`SHA-256(0x13 || ULEB128(82) || top)` recomputes from the leaves of both bundles and
equals `OCSF_LOG_ROOT`. The public bundle is `verifiable: false`. Its custody `data`
went through `Sanitizer.redact/1`, which keeps the OpenShell lines unchanged.

## Forged redaction metadata

`full.public.forged.bundle.json` is `full.public.bundle.json` with two changes:

| Leaf (true values) | Forged field |
|---|---|
| `HTTP:POST`, `seq` 50 | `seq` is `1000` |
| `HTTP:POST`, `seq` 51 | `class` is `NET:OPEN` |

Every leaf hash is unchanged. **The root still recomputes and equals `OCSF_LOG_ROOT`**,
because no hash binds `class` or `seq` (design 7: they are redaction metadata). So
the root check cannot find this forgery. konareef (US-111) must do these checks:

1. **Never grade on `class` or `seq` of a withheld leaf.** A bundle with any
   withheld leaf grades at most `claimed`, with `redacted: true` and the reason
   `evidence withheld in the public bundle; verify the verifiable bundle for
   operator_attested` (design 8.4). The forged bundle must grade exactly as the
   public bundle does.
2. **Recompute the root from the leaves** (a `record` leaf by its hash, a `withheld`
   leaf by its value), and compare it with `OCSF_LOG_ROOT`. Both bundles pass.
3. **Check the metadata for consistency, and report a failure** (the test helper
   `metadata_problems/1` in `test/pod/proofs/open_shell_custody_golden_test.exs`
   does these checks):
   - The `class` of a withheld leaf must match `^HTTP:[A-Z0-9_]+$`. Only `HTTP:*`
     records are withheld. `NET:OPEN` on a withheld leaf is a forgery.
   - The `seq` of a withheld leaf must be an integer, inside
     `[first_seq, last_seq]` of the header, and above the `seq` of every earlier
     leaf that has a `seq` (`seq` is dense and ascending in record order;
     `seq: null` records do not count). `1000` is above `last_seq` (60), so it
     is a forgery.

These checks find the two forgeries of this file. They cannot find a forgery that
stays consistent: for example `HTTP:POST` changed to `HTTP:GET`, or two adjacent
withheld leaves that swap their `seq`. Only the verifiable bundle shows the true
values: its record at the same index has the same leaf hash. This is why rule 1
applies in all cases.

## How the files were made

The test module `test/pod/proofs/open_shell_custody_golden_test.exs` makes the files.
It writes them only when `REEF_WRITE_OPENSHELL_CUSTODY_GOLDEN=1` is set:

```
REEF_WRITE_OPENSHELL_CUSTODY_GOLDEN=1 mix test test/pod/proofs/open_shell_custody_golden_test.exs
```

The module builds each chain in the test database with `Proofs.commit_task_completion/1`,
then packs the verifiable and the public bundle. It makes the forged bundle from the
public bundle. Each new run gives new timestamps and hashes, so konareef must copy
the files again after a change.

Without the variable, the same module checks the committed files: every link hash
recomputes, the bundle's custody `data` is the `.custody.txt` file, the lines are in
their form (`OpenShellCustody.check/1`, `Verifier.check_custody_record/1`), the
`openshell_evidence` key of each bundle (records, withheld leaves, root, policy hash),
the forged fields, and that no file and no record holds an unexpected IPv4 address.

## Notes

- US-110 made these files again. The precommit policy hash changed (see "Policy"),
  so the precommit and custody link hashes changed too.
- A local konareef development build (`konareef verify`, no flags) passed both
  US-109 bundles as legacy unsigned bundles. That build does not read the OpenShell
  lines or the `openshell_evidence` key yet (US-111).
