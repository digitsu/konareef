# Reference: Pod Definition of Done (`[output]`)

Status: current-behavior reference for `pod_spec_version = "0.1"`.

## Summary

A pod execution has a first-class Definition of Done in the `[output]` table of `pod.toml`.

The author can declare:

- success predicates;
- failure predicates;
- expected deliverables.

reef-core evaluates the supported subset to decide when a pod is done.

## Example

```toml
[output]
format = "markdown"

[[output.success]]
kind = "file_exists"
path = "report.md"

[[output.failure]]
kind = "timeout_seconds"
value = 3600

[[output.deliverables]]
path = "report.md"
description = "Final report"
optional = false
```

Two implicit completion bounds live outside `[output]`:

- `[directive].max_iterations` — hard stop after N agent loops.
- `[budget].max_sats` and related budget caps — spend limits.

## Predicate support: declared does not always mean enforced

The v0.1 predicate vocabulary is broader than what is currently enforced at runtime.

| Predicate `kind` | Shape/parsing support | Runtime-enforced in v0.1 |
| --- | --- | --- |
| `file_exists` | yes | yes |
| `timeout_seconds` | yes | yes |
| `budget_exhausted` | yes | yes |
| `min_words` | forward-compatible | no |
| `contains_regex` | forward-compatible | no |
| `tool_called` | forward-compatible | no |
| `custom_script` | forward-compatible | no |

Practical consequence: a pod may declare forward-compatible predicates, but authors should not rely on them to gate completion until the runtime explicitly supports them.

## Relationship to proof bundles

The Type C proof path attests faithful execution properties such as declared model/tool/budget constraints. It does not by itself prove that a semantic deliverable met the author's success predicate. Treat “the pod executed faithfully” and “the final deliverable satisfied the Definition of Done” as separate claims.
