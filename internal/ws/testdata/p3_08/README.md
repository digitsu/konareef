# reef-core P3-08 LLM billing fixture (vendored)

This file is a byte-for-byte copy of a reef-core file. Do not edit it here.
If reef-core changes it, copy it again. Then update this table and
`llmFixtureSHA256` in `internal/ws/llm_test.go`.

| File here | reef-core path | SHA-256 | Git blob |
|---|---|---|---|
| `llm-billing-v1.json` | `test/support/fixtures/p3_08/llm-billing-v1.json` | `c9d3996ba3677f9c548ee4247ba20f0b2ba1cd2336f11978d4da541ff639e08b` | `bbfa3da2b9a7e950e1ed3b9e450a272690791b64` |

Source: reef-core `main` at `4d100001276bfb1ae6af4aacdf7d8eb8f018dddc`. The
file was last changed by `624a459` (P3-08, reef-core!176, merged as
`7a60c30`). reef-core generates it with
`scripts/gen_p3_08_llm_billing_fixtures.exs` from the production builder
`ReefCore.Llm.Event`, and `test/pod/llm/llm_billing_fixtures_test.exs`
fails on drift.

Consumers (K3-01, konareef#6):

- `internal/ws/llm_test.go` checks the SHA-256, parses every event and
  checks the push names and wire keys.
- `internal/tui/budget_llm_test.go` replays the event kinds and the
  sequences (replayed `call_id`, cumulative overage, custody-off legacy)
  through the Budget tab.
- `internal/verify/llm_proof_totals_test.go` checks the `proof_totals`
  cases against `CustodyTotalSats`.

To copy it again:

```sh
git -C ~/work/reef-core fetch origin
git -C ~/work/reef-core show origin/main:test/support/fixtures/p3_08/llm-billing-v1.json \
  > llm-billing-v1.json
shasum -a 256 llm-billing-v1.json   # then update the table and the test constant
git hash-object llm-billing-v1.json
```
