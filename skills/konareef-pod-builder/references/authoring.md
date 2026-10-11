# Authoring decisions

`konareef pod schema` gives you the field list. This file covers the choices
the schema cannot make for you.

## Add tables when they earn their place

Add an optional table when the pod needs it, not because the schema allows
it.

A first pod usually needs:

```toml
pod_spec_version = "0.1"

[pod]
name    = "invoice-summarizer"
version = "0.1.0"

[runtime]
kind = "lobster"

[directive]
task = "Read each invoice in ./inputs and write a summary to ./out/summary.md."
```

## Write a task that names its output

`[directive].task` tells the runtime what to do. A weak task describes a
subject. A usable task names the input, the action, and the file to produce.

Weak: `"Summarize invoices."`

Usable: `"Read each invoice in ./inputs, extract the payment terms, and write
one markdown table to ./out/terms.md."`

## Set a budget before the developer runs anything

`[budget]` caps spending. Without it the pod inherits whatever the server
allows. `pod init` writes `max_sats = 0`, which spends nothing and fails on
the first run. Get the real number from the developer and put it in.

**Ask the developer for both numbers. Never invent a ceiling for someone
else's money.** The values below are placeholders, not a recommendation:

```toml
[budget]
max_sats          = <ask the developer>
per_call_cap_sats = <ask the developer>
```

## Open or closed

Set `closed` when the prompt is the product. Read the `visibility`
description in `konareef pod schema` before choosing.

Ask before choosing `closed`. It changes who can run the pod.

## Listing a pod

`[runtime].execution_class` is optional for a pod the developer only runs
themselves. It is required to list one. `konareef pod listing publish` refuses
a pod that omits it.

Ask the developer for the per-run fee before you list. Never invent it —
the same rule as the budget.
