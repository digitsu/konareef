# PayGate ZK Runtime Client

Package: `internal/paygate/`.

This package contains the client-side runtime pieces used by the ZK billing/proof path.

## Overview

The client implements these obligations:

| Obligation | Description |
| --- | --- |
| Durable binding before pipelining | Reject speculative folds before durable binding. |
| Discovery-manifest refresh cadence | Clamp refresh cadence to a safe range. |
| Active-schedule BEEF construction | Reject stale schedules before debit. |
| Credit-token persistence | Persist and enforce single-use credit tokens. |
| Idempotency key construction | Build byte-exact idempotency keys. |
| Pre-session pin-check | Resolve or halt on circuit verification-key pin states. |

## Session lifecycle

```text
Open()
  -> refresh manifest
  -> pin-check circuit verification key
  -> load identity
  -> load Type-D salt when policy requires it
  -> return Session

SubmitFold()
  -> ensure fresh manifest
  -> reject speculative folds
  -> build idempotency key
  -> check replay cache
  -> build BEEF against active schedule
  -> submit proof job
  -> persist idempotency result
  -> durably bind result

FetchResult()
  -> fetch result while retention window is active
  -> surface expiry as a typed error
```

## Local state

By default, state lives under:

```text
${KONAREEF_STATE_DIR:-~/.konareef}/paygate/
```

Important files:

| Path | Contents |
| --- | --- |
| `identity.key` | Local secp256k1 private key, mode `0600`. |
| `idem.db` | SQLite idempotency cache. |
| `ledger.db` | SQLite credit-token ledger. |

## Idempotency preimage

```text
preimage = ULEB128(len(circuit_id_bytes))
        || circuit_id_bytes
        || be_u64(step_index)
        || h_p
Idempotency-Key = hex_lower(SHA-256(preimage))
```

## Disclosure-policy handling

`OpenSessionInput.DisclosurePolicy` is required.

| Policy | Behaviour |
| --- | --- |
| Type C | Bundle discloses salt; local salt backend is not consulted. |
| Type D | Runtime must load salt from the salt backend using the pod lineage identifier. Missing salt is fatal. |

## Deferred/non-goals

- Full remote auth handshake persistence.
- Persistent manifest cache across graceful process exit.
- Live-network integration tests in the default suite.
- CLI command for circuit vkey rollover adoption.
