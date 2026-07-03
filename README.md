# Konareef

Konareef is the developer CLI/TUI for building, publishing, installing, and verifying reefpods.

A reefpod is a versioned agent package anchored by a `pod.toml` manifest. Konareef gives authors a local workflow for scaffolding a pod, validating its manifest, publishing it to a compatible reef-core deployment, installing published pods, and verifying proof bundles offline.

This public repository contains the developer-facing CLI, TUI, tools, schema, tests, and docs. Internal planning, strategy, pitch, and release-planning material is intentionally excluded from the public mirror.

## Current capabilities

- Scaffold a starter reefpod.
- Validate `pod.toml` v0.1 manifests offline.
- Create publisher identities.
- Publish pods to a compatible reef-core server.
- Install signed pod manifests as a buyer/user.
- Run smoke and lifecycle checks against a reef-core deployment.
- Verify exported proof bundles, including strict and disclosure-policy-aware checks.
- Use the terminal UI components for inspection-oriented workflows.

## Install from source

Requirements:

- Go 1.25 or newer.
- Git.

Build the CLI:

```sh
git clone https://github.com/digitsu/konareef.git
cd konareef
go build -o konareef .
./konareef --help
```

Run tests:

```sh
go test ./...
```

## Quick start: build a hello-world reefpod

Create a pod:

```sh
./konareef pod init hello-world
```

Inspect the generated files:

```text
hello-world/
  pod.toml
  prompts/system.md
  README.md
```

Validate the manifest:

```sh
./konareef pod validate ./hello-world/pod.toml
```

A minimal manifest looks like this:

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

## Common commands

```sh
# Create a pod skeleton
./konareef pod init hello-world

# Validate a manifest
./konareef pod validate ./hello-world/pod.toml

# Create a publisher identity
./konareef pod identity create --handle alice

# Publish to a reef-core server
./konareef pod publish ./hello-world --server http://localhost:4000

# Publish and expose a public proof bundle endpoint
./konareef pod publish ./hello-world --server http://localhost:4000 --public-bundle

# Install a published pod
./konareef install alice/hello-world
./konareef install alice/hello-world@0.1.0

# Verify a proof bundle
./konareef verify bundle.json
./konareef verify --strict bundle.json
./konareef verify --disclosure-policy C bundle.cbor

# Run smoke checks against a compatible reef-core deployment
KONAREEF_TOKEN=... ./konareef smoke
KONAREEF_TOKEN=... ./konareef smoke --lifecycle
```

## Documentation

Start here:

- `docs/reefpods/README.md` — reefpod authoring docs index.
- `docs/reefpods/build-a-reefpod.md` — scaffold, edit, validate, and understand a pod.
- `docs/reefpods/publish-run-verify.md` — publish, install, smoke-test, and verify flows.
- `docs/reference/pod-toml-v0.1.md` — current `pod.toml` language reference.
- `docs/reference/pod-definition-of-done.md` — current `[output]` behavior and limitations.
- `docs/integration/paygate-client.md` — PayGate/ZK runtime client reference.

## Repository scope

Konareef owns the developer CLI/TUI, local authoring tools, manifest validation, publishing/install UX, and offline proof verification. reef-core is the compatible server/runtime side that parses and executes pods and serves proof material.

The public mirror is generated from a scrubbed allowlist export and intentionally has a single collapsed release commit. Private project history and non-developer materials are not published.

## License

Apache-2.0. See `LICENSE`.
