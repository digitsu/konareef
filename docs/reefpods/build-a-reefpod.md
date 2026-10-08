# Build a reefpod

This guide walks through the public authoring path for a reefpod using `konareef`.

## What a reefpod is

A reefpod is a versioned pod directory anchored by a `pod.toml` manifest, prompt files, and any local assets the pod needs. `konareef` gives you authoring, validation, publishing, installation, and verification tools.

## 1. Scaffold a pod

```sh
konareef pod init hello-world
```

This creates a starter directory containing:

```text
hello-world/
  pod.toml
  prompts/system.md
  README.md
```

## 2. Validate early

```sh
konareef pod validate ./hello-world/pod.toml
```

Validation uses the vendored `pod.toml` v0.1 schema embedded in `konareef`, so authors can work offline.

## 3. Edit the three things that matter first

### `pod.toml`

Start with these fields:

- `[pod]` — name, version, lineage, description, optional authors/license/tags.
- `[runtime]` — runtime kind and optional version constraint.
- `[model]` — provider and model name.
- `[inputs]` — typed user inputs for the pod.
- `[directive]` — prompt template path and iteration cap.
- `[output]` — success/failure predicates and deliverables.
- `[budget]` — spending caps.

### `prompts/system.md`

Replace the scaffold placeholder with the actual role, constraints, and completion standard for the pod.

### `[output]`

Declare what “done” means. The DSL is broader than what reef-core currently evaluates at runtime, so read the Definition of Done reference before relying on advanced predicates.

## 4. Minimal hello-world example

```toml
pod_spec_version = "0.1"

[pod]
name = "hello-world"
version = "0.1.0"
description = "Greets a user by name."
lineage_id = "0123456789abcdef0123456789abcdef"

[runtime]
kind = "lobster"
version = "^0.1"

[model]
provider = "anthropic"
name = "claude-sonnet-4-5"

[inputs]
name = { type = "string", required = true }

[directive]
template = "./prompts/system.md"
max_iterations = 5

[output]
format = "markdown"

[[output.failure]]
kind = "timeout_seconds"
value = 600

[budget]
max_sats = 1000
```

Example `prompts/system.md`:

```md
You are a concise greeting pod.

Input:
- name: the person to greet

Return exactly one friendly sentence greeting the named person.
```

Validate again after editing:

```sh
konareef pod validate ./hello-world/pod.toml
```

## 5. Know the current edges

- `konareef pod validate` is local schema validation.
- reef-core remains the authoritative parser and execution environment.
- A first-class local `konareef run .` flow is not part of the current public CLI. Authors publish to a compatible reef-core deployment and exercise the end-to-end flow there.

## 6. Next steps

Once the pod validates:

1. Create a publisher identity.
2. Publish the pod.
3. Install and verify it as a buyer/user.
4. Run smoke/lifecycle checks against a reef-core deployment.

That flow is covered in `publish-run-verify.md`.
