# reef-ocsf/v1 test vectors (US-108)

These files are the `reef-ocsf/v1` test vectors of the OpenShell adapter, phase 2
(reef-core document "OpenShell adapter: phase-2 detailed design", sections 4.1
and 4.5). konareef copies them into `internal/verify/testdata/reef_ocsf_v1/` (US-111).

## Files

| File | Content |
|---|---|
| `manifest.json` | The name, file, record count and root (hex) of each vector. |
| `real_run.records` | One real run: the US-102 fixture run (reef-core, OpenCode, listener traffic), 82 records. The supervisor marker (`seq` 57) comes after `drain_end_seq` 56, so it is informational. |
| `real_run_marker_before_drain.records` | The same event records, with `drain_end_seq` 58 in the header. The marker then comes before the drain end (possible loss). |
| `real_run.gateway.json` | A gateway object (design 3.4) for the real run. See "Gateway object". |
| `non_ascii.records` | A short complete stream. One `HTTP:GET` record has non-ASCII characters in `msg`. |
| `control_character.records` | A short stream. One `NET:OPEN` record has a C0 control character (BEL) in `msg`, escaped by JCS as `\u0007`. The stream is not gapless. |

Each `.records` file uses the launcher's file format: for each record, a 4-byte
big-endian length, then the record bytes (`tag || JCS(record)`). The root is
`SHA-256(0x13 || ULEB128(n) || top)` over the tree of `ReefCore.Proofs.TLog`.

## How the vectors were made

`launcher/ocsf_vectors_test.go` (build tag `ocsfvectors`) made every vector with the
launcher's own record code (`ocsfEventRecord`, `ocsfRecordBytes`). It computes each root
with its own tree code. The ExUnit test `test/pod/proofs/open_shell_evidence_test.exs`
recomputes each root with `OpenShellEvidence.root/1`, so the check crosses languages.

- **Real run.** The input is the unredacted US-102 fixture stream
  (`/opt/us102/out/fixture/stream.jsonl` on the test VM). It has the received wire bytes
  of every `SandboxStreamEvent`. The committed capture
  (the US-102 `fixture-stream.jsonl` in the reef-core research captures)
  has no raw bytes for 21 frames, so it cannot give the real stub values. The generator
  applies the launcher's node address redaction (design 4.1 item 5) before it hashes or
  encodes. The node addresses came from the environment. No record holds a node address.
- **Drain fields.** The US-102 probe ran no drain, so the generator sets `drain_ms` 1500,
  `drain_quiet` true and `drain_end_seq` (56 or 58) in the header.
- **Stream end.** The probe stream ended with a clean end of stream after delete, after
  both stop markers. The launcher's rule makes this `server_end` with code `OK`.
- **Short vectors.** They use the frame helpers of the launcher tests, with sandbox id
  `fee01160-dfa3-4442-8fa7-0328634b17cc` and listener `192.0.2.10:4100`.

To make the vectors again (on a host that has the unredacted capture):

```
docker run --rm -v "$PWD":/src -v <capture-dir>:/s -w /src/launcher \
  -e OCSF_VECTOR_INPUT=/s/stream.jsonl -e OCSF_VECTOR_OUT=/s/out \
  -e OCSF_VECTOR_LISTENER=192.0.2.10 -e OCSF_VECTOR_NODE_ADDRS=<node addresses> \
  golang:1.26 go test -tags ocsfvectors -run TestGenerateOCSFVectors .
```

## Gateway object

`real_run.gateway.json` has the real values of the US-102 reads where the captures
have them: `run_id`, `sandbox_id`, `gateway_version`, `policy_v1_hash` (revision 1),
`policy_enriched_hash` (revision 2, equal to the `CONFIG:LOADED` hash), the revisions
(create 1, end 2) and `policy_history_sha256` (the SHA-256 of the canonical JSON revision list of
`captures/fixture-reads-stopped.json`, with an absent `loaded_time` as `""`). These values are placeholders, because the US-102
reads do not give them in the launcher's form: `policy_submitted_sha256`,
`settings_digest` and `provider_env_digest`. The placeholders are the SHA-256 of a
`us108 placeholder` text. Create and end are equal, so `policy_changed` is false.
