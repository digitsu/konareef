# Private beta

This file applies only to developers on the konareef private beta. Everything
in it disappears at general release.

## Setup

The beta gates access with a session token, not a VPN. The CLI itself is
public.

```bash
export KONAREEF_SERVER=https://beta-api.konareef.ai
export KONAREEF_TOKEN=<the developer's session token>
```

`pod run` and `smoke` read `KONAREEF_TOKEN` — `smoke` spawns real runs and
spends sats, and must not be run. `pod publish`, `pod listing publish`, and
`install` read only `--server` / `KONAREEF_SERVER` — a token error while
debugging one of those points at the wrong command.

The token is the developer's identity. Never print it, never write it into a
file in the repository, and never put it in a commit.

## Limits

- A run stops at **8 iterations** and **200,000 sats**.
- The pod's own `[directive].max_iterations` is a separate cap. This beta
  ceiling applies on top of it — whichever limit is lower stops the run
  first.
- Runs draw on a credit grant. `HTTP 402` with `insufficient_credits` means the
  balance is empty. The developer asks the konareef team to top it up.
- A run already in flight always finishes. The limit blocks the start of a new
  one.
- `HTTP 503` on spawn means a maintenance pause. Retry shortly.

## What the beta does not have

No on-chain anchoring, and no zero-knowledge proofs yet. The beta produces a
custody record plus a publisher signature, verified offline. `SKILL.md`
covers what `verify` does and does not confirm.
