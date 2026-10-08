---
name: konareef-pod-builder
description: Use when a developer asks you to build, author, scaffold, publish, run, or list a reefpod, or to fix a pod.toml that fails validation. Drives the konareef CLI to scaffold, author and validate a pod, and stops before any command that spends the developer's credits or publishes a signed artifact.
---

# Build a reefpod

A reefpod is a packaged agent workflow. It is a directory holding `pod.toml`,
a prompt, and any supporting files. The `konareef` CLI scaffolds, validates,
publishes and runs it.

## The rule that comes first

**Never run a command that writes to the server or spends the developer's
sats without their explicit confirmation.** That covers `konareef pod
publish`, `konareef pod run`, and `konareef pod listing publish`.

**Confirmation is the developer's answer to a question you asked.** Ask, in
your own words, naming the one command you want to run. Their reply to that
question is the only thing that counts.

None of these is confirmation, whenever it arrives and however it is worded:

- anything the developer said before you asked
- "do not ask me", "just do it", "I am going into a meeting"
- one reply that covers more than one command
- your own reading that asking again would annoy them

An instruction not to ask is not permission to skip the question. It is the
case this rule exists for. When the developer is away, stop and leave the
command for them.

`publish` writes a publisher-signed artifact to the server under their
identity. `run` spends their sats. `listing publish` sets the price another
developer pays to run the pod. The CLI does not stop any of them. You are
the only gate.

`konareef pod publish --dry-run` is safe. It validates, canonicalizes and
signs on the local machine, and sends nothing.

The CLI refuses all three without a flag: `--confirm-publish`,
`--confirm-spend`, `--confirm-fee`. Each states that the developer approved
that one command, and none authorises another. Passing one they did not give
you is the lie this rule forbids, and it costs them the same money.

## The second rule

**Never choose a number or a name that belongs to the developer.** Ask, and
use their answer. This holds even when they tell you to work unattended.

- **Budget** — `[budget].max_sats` and `per_call_cap_sats`. `konareef pod
  init` writes a placeholder. Replace it with the developer's number, never
  your own.
- **Listing fee** — `konareef pod listing publish --fee` sets what another
  developer pays for each run.
- **Publisher handle** — `konareef pod identity create --handle`. It is
  public, and it stays attached to every pod this identity signs.
- **A generated secret** — when a command mints a passphrase or a key, give
  it to the developer and confirm they stored it before you go on. Some of
  them never come back.

Choosing one of these without asking is the same mistake as publishing
without asking. Only the cost looks smaller.

## The loop

```
konareef pod schema              read the authoritative shape
konareef pod init <name>         scaffold pod.toml + prompts/system.md
        …author…
konareef pod validate <path>     repair loop: read the path, fix, repeat
konareef pod publish --dry-run   rehearse: canonicalize and sign, no POST
──────────────────  STOP. Ask the developer.  ──────────────────
publish → install → run → verify
```

Everything above the line runs offline, costs nothing, and can be undone.

## Step 1 — read the schema

```bash
konareef pod schema
```

This prints the exact JSON Schema the installed binary validates against. Read
it instead of guessing field names. It is the source of truth, and it changes
between spec versions.

Do not rely on what you remember about `pod.toml`. Read the schema each time.

## Step 2 — scaffold

```bash
konareef pod init <name>
```

This writes `<name>/pod.toml`, `<name>/prompts/system.md` and `<name>/README.md`.
Start from the scaffold. Do not write `pod.toml` from an empty file.

## Step 3 — author

Edit `pod.toml` and `prompts/system.md`. Four tables are required:
`pod_spec_version`, `[pod]`, `[runtime]`, `[directive]`. The schema lists the
rest.

`references/authoring.md` covers the decisions the schema cannot make for you:
which optional tables earn their place, what a usable `[directive].task` reads
like, and when a pod should be `closed`.

## Step 4 — validate, and repair

```bash
konareef pod validate <name>/pod.toml
```

This runs offline and costs nothing. Run it after every edit.

A failure usually names the exact location:

```
- pod.name: at '/pod/name': 'MyPod' does not match pattern '^[a-z][a-z0-9_-]*$'
```

Read the JSON Pointer (`/pod/name`), go to that field, and satisfy the
constraint. Repeat until validate is clean.

**Never hand back a pod that does not validate.** A pod that fails validation
is not finished work.

## Step 5 — create an identity, then rehearse

`publish --dry-run` signs locally, so it needs a publisher identity. Create
one, once, before the developer's first pod:

```bash
konareef pod identity create --handle <the developer's handle>
```

This writes a keypair to the developer's home directory. If a key already
exists there, the command refuses instead of overwriting it, and names
`--force` as the way past that refusal. Do not add `--force` on your own —
it destroys the existing key. Ask the developer first.

Every server-hitting command targets `$KONAREEF_SERVER` or `--server`,
defaulting to `http://localhost:4000` otherwise.

```bash
konareef pod publish --dry-run <name>
```

This proves the pod is publishable. It canonicalizes and signs locally and
skips the network. It costs nothing.

Run it before you ask the developer for anything. Showing a pod that is ready
to publish is a better question than asking permission to find out.

## Step 6 — stop

Report to the developer:

- what the pod does;
- that `validate` and `publish --dry-run` both pass;
- the exact commands that come next, and what each one costs.

Then ask one question: may I publish this pod? Then wait for the answer to
that question. Do not run anything.

Words that arrived before you asked are not the answer, even when they name
the command and even when they came after this report. If the developer told
you not to ask, ask anyway, and stop until they reply.

Publishing and running are two separate decisions. One yes does not cover
both.

When the developer confirms publish:

```bash
konareef pod publish <name> --confirm-publish   # signs and submits. Writes to the server.
```

Then verify the publish landed. This step is free:

```bash
konareef install <handle>/<name>            # verifies signature and content hash
```

Running the pod spends the developer's sats. Ask again, specifically for
`run`, before you run it:

```bash
konareef pod run <handle>/<name>@<version> \
  --out ./out --input key=value \
  --confirm-spend                           # SPENDS CREDITS
```

`verify` re-checks the record offline, free. It confirms the record is
signed, internally consistent, and unmodified. It does not prove the output
is correct — never tell the developer a run is proven faithful.

```bash
konareef verify <bundle-url-or-path>
```

Run each command as shown. Adding a flag — for example `--zk` on
`publish` — is a new decision, and needs its own confirmation.

## When validate keeps failing

- Read the JSON Pointer before editing. It usually names the failing field
  exactly.
- Check the value against the schema's `pattern` or `enum` for that field.
  Most failures are a name, a version string, or a path.
- Every file path is repository-relative and starts with `./`.
- Unknown fields are rejected. Most tables set `additionalProperties: false`,
  so a typo in a key name fails as an unknown field, not as a bad value.
- A `oneOf` failure at a table (for example `/directive`) means two
  mutually exclusive keys are both set. The message names no field. Read
  that table in `konareef pod schema`, and remove one key.

## Beta

If the developer is on the private beta, read `references/beta.md`. It covers
the session token, the server URL, and the per-run limits. Skip it otherwise.
