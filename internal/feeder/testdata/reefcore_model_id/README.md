# reef-core qualified model ID fixtures (vendored)

These three files are copied byte for byte from reef-core. Do not edit them
here. If reef-core changes them, copy them again and update this file.

| File here | reef-core path | Git blob |
|---|---|---|
| `vectors.json` | `test/support/fixtures/model_id/vectors.json` | `712036398ae089a588da035570c0f64f53817f0c` |
| `qualified_model_id.json` | `test/support/fixtures/step_disclosure/qualified_model_id.json` | `2ed5b6231d68ed922bf1d27c71c191ebda9b5301` |
| `legacy_bare_model.json` | `test/support/fixtures/step_disclosure/legacy_bare_model.json` | `a5a2f6a9be2c4c07e2013065b72077317c549293` |

Source: reef-core branch `ib-02/qualified-model-id` (MR !111, reef-core#50),
commit `8331790e7ca363957ddfd744773014a2a7a75e99`. The blobs are identical at
`4e6e9a7`. MR !111 was not merged when these files were copied.

Consumer: `internal/feeder/model_identity_test.go` (IB-03, konareef#21).
The test checks each file against the blob ID above, so an edit made here
fails the test.

To copy them again:

```sh
git -C ~/work/reef-core fetch origin <branch-or-main>
for f in model_id/vectors.json step_disclosure/qualified_model_id.json step_disclosure/legacy_bare_model.json; do
  git -C ~/work/reef-core show "origin/<branch-or-main>:test/support/fixtures/$f" > "$(basename "$f")"
done
git hash-object *.json   # then update the table above and the test constants
```
