# Publish, run, and verify

This guide covers the public lifecycle around a reefpod after authoring.

## 1. Create a publisher identity

```sh
konareef pod identity create --handle alice
```

The identity commands manage the secp256k1 keypair lifecycle used for publisher signing.

## 2. Publish a pod

```sh
konareef pod publish ./hello-world --server http://localhost:4000
```

To opt a publication into the public verifiable bundle endpoint:

```sh
konareef pod publish ./hello-world --server http://localhost:4000 --public-bundle
```

For a dry run:

```sh
konareef pod publish ./hello-world --server http://localhost:4000 --dry-run
```

## 3. Publish with ZK billing rails

```sh
konareef pod publish ./hello-world \
  --zk \
  --circuit-id konareef-pod-step-v1 \
  --disclosure-policy C
```

Optional one-time vkey anchor:

```sh
konareef pod publish ./hello-world \
  --zk \
  --circuit-id konareef-pod-step-v1 \
  --disclosure-policy C \
  --pin-circuit-vkey
```

`--zk` requires both `--circuit-id` and `--disclosure-policy`.

## 4. Install as a buyer/user

```sh
konareef install alice/hello-world
konareef install alice/hello-world@0.1.0
```

The install flow verifies the manifest hash and publisher signature before anything is cached locally.

## 5. Run end-to-end checks against reef-core

The shipped public regression path today is the `smoke` command:

```sh
KONAREEF_TOKEN=... konareef smoke
KONAREEF_TOKEN=... konareef smoke --lifecycle
KONAREEF_TOKEN=... konareef smoke --lifecycle --memory-roundtrip
```

These flows assume a compatible reef-core deployment and a valid session token.

## 6. Verify bundles offline

```sh
curl https://reef-core.example/api/public/proofs/<hash>/bundle > bundle.json
konareef verify bundle.json
konareef verify --strict bundle.json
```

For `konareef-bundle/v2` bundles with the ZK path:

```sh
konareef verify --disclosure-policy C bundle.cbor
```

The verifier automatically runs the additional SNARK verification phase for v2 bundles.

### MCP broker line

`konareef verify` also prints one `MCP broker (server custody)` line. `--json` puts the same data in a `custody` object. The line reads the `CUSTODY_PROOF` version and the `MCP_BROKER` marker in the custody record, and states only what the record proves:

| `assurance` | Meaning |
|---|---|
| `not_verified` | The bundle did not verify, or it is a sanitized copy, or the custody data does not match its link hash. No broker claim is shown. |
| `refused` | The custody record fails a version or marker rule, for example `v5` without `MCP_BROKER: contained`. The bundle fails. |
| `no_marker` | A `v3` or `v4` record with no marker. The record makes no broker claim. A missing marker does not show that a firewall was installed. |
| `proof_incomplete` | The record has `MCP_BROKER: proof_incomplete`. It does not show that MCP calls were contained. |
| `contained_root_not_recomputed` | An unanchored claim: a `v5` record with `MCP_BROKER: contained`. Nothing in a bundle ties its chain to the server, and a bundle does not carry the stored tool-log records, so the verifier cannot recompute the tool-log root. The claim is not verified. |
| `contained` | Every custody rule passed, including the recomputed tool-log root. Only a check that has the stored tool-log records can give this result. |

In `--json`, `version` and `mcp_broker` are set only for `contained`. For the other levels, the record's claim is in `unanchored_claim`.

This is server custody evidence. It is not a ZK spend guarantee, and it does not describe circuit coverage.

## 7. Ownership model

Publicly, the clean mental model is:

- `konareef` owns authoring, publishing, installation, and offline verify UX.
- reef-core is the compatible runtime/parser side that executes pods and serves proof/bundle material.

If you are building a reefpod for external users, document both sides clearly: the pod artifact itself and the compatible reef-core environment it expects.
