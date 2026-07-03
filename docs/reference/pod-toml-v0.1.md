# Reference: `pod.toml` v0.1

This is the current public `pod.toml` language surface accepted by `konareef pod validate`.

## Top-level

```toml
pod_spec_version = "0.1"
```

## `[pod]`

```toml
[pod]
name = "hello-world"
version = "0.1.0"
description = "Greets a user by name."
lineage_id = "0123456789abcdef0123456789abcdef"
authors = ["Alice"]
license = "Apache-2.0"
tags = ["demo", "hello-world"]
```

Fields:

- `name`: package name.
- `version`: semantic version string for this release.
- `lineage_id`: stable 32-character lowercase hex identifier for this pod lineage.
- `description`, `authors`, `license`, `tags`: optional metadata.

## `[runtime]`

```toml
[runtime]
kind = "lobster"
version = "^0.1"
```

Fields:

- `kind`: runtime kind expected by the pod.
- `version`: optional runtime version constraint.

## `[model]`

```toml
[model]
provider = "anthropic"
name = "claude-sonnet-4-5"
temperature = 0.2
max_tokens = 4096
```

Fields:

- `provider`: model provider identifier.
- `name`: model name.
- `temperature`, `max_tokens`: optional generation settings.

## `[inputs]`

Inputs are declared as inline tables keyed by input name:

```toml
[inputs]
name = { type = "string", required = true, description = "Name to greet" }
topic = { type = "string", required = false, default = "Konareef" }
```

## `[directive]`

```toml
[directive]
template = "./prompts/system.md"
max_iterations = 5
```

Fields:

- `template`: path to the prompt/directive template relative to the pod directory.
- `max_iterations`: optional execution loop cap.

## `[output]`

`[output]` declares success/failure predicates and expected deliverables.

```toml
[output]
format = "markdown"

[[output.success]]
kind = "file_exists"
path = "report.md"

[[output.failure]]
kind = "timeout_seconds"
value = 600

[[output.deliverables]]
path = "report.md"
description = "Final report"
optional = false
```

Current predicate support is intentionally conservative. `file_exists`, `timeout_seconds`, and `budget_exhausted` are the runtime-enforced v0.1 predicates. Some additional predicate shapes may parse or validate as forward-compatible declarations but should not be treated as runtime gates yet.

## `[budget]`

```toml
[budget]
max_sats = 1000
per_call_cap_sats = 250
daily_cap_sats = 5000
```

Fields:

- `max_sats`: maximum spend for a pod run.
- `per_call_cap_sats`: optional per-call cap.
- `daily_cap_sats`: optional daily cap.

## Minimal complete example

```toml
pod_spec_version = "0.1"

[pod]
name = "hello-world"
version = "0.1.0"
lineage_id = "0123456789abcdef0123456789abcdef"

[runtime]
kind = "lobster"

[model]
provider = "anthropic"
name = "claude-sonnet-4-5"

[inputs]
name = { type = "string", required = true }

[directive]
template = "./prompts/system.md"

[output]
[[output.failure]]
kind = "timeout_seconds"
value = 600

[budget]
max_sats = 1000
```

## Not current syntax

Do not publish or depend on these as current v0.1 manifest sections unless the schema and runtime have been updated:

```toml
[prompt]
[permissions]
[proof]
[package]
[[tools]]
[[tests]]
[outputs]
```
