# voice-forge

A single-shot ReefCore demo pod: speaks the requested text as an mp3 in a
given (or default) ElevenLabs voice, then writes the synthesized speech and a
run report. The whole workflow runs in **one `bash` call**, which keeps the
tool-log at a single record — well inside the pod-step circuit's limit, and
inside the nominal cost profile too. The run is provable end-to-end.

### Two different `|T_log|` numbers — do not confuse them

| Number | What it is | Effect of exceeding it |
|---|---|---|
| **16** | The v1 **hard cap** (`\|T_log\|` = 16 tool calls, circuit-spec §7 "v1 input caps"). Enforced by the reef-core feeder spawner (its tool-log capacity limit). | The run **declines** with `:tool_log_over_capacity` and falls back to a custody proof — no ZK attestation. |
| **4** | The **nominal cost profile** only (circuit-spec §7, the ~30k–80k constraints/step envelope). | Nothing fails. Tool-log hashing rises from ~4k to ~16k constraints (spec §7 row 7). Purely a cost curve. |

Earlier revisions of this file described **4** as "the cap". That was wrong:
4 is the nominal profile, 16 is the cap. The spec keeps `MAX_TLOG` at 16, and
the accepted vkey-stable worst-case pod-step is already ~545k constraints, so
the original ~30k–80k envelope no longer governs.

> **0.1.5 is TTS-only.** Voice **cloning** (from a YouTube clip via ElevenLabs
> IVC) was deferred on the stated grounds that its `yt-dlp` → `ffmpeg` →
> add-voice → synthesize chain "exceeds the v1 circuit's 4-tool-log-record
> cap". **That rationale does not hold** — the chain is 4 calls, which exceeds
> neither the nominal profile of 4 nor the hard cap of 16. Whether to restore
> clone mode is an open question on its own merits (pre-staged clip cache,
> run time, API cost); it is not blocked by circuit capacity. See earlier
> versions for the clone-mode directive.

## Inputs

| Input | Required | Description |
|---|---|---|
| `speak_text` | yes | Text the voice will speak (≤5000 chars — the budget). |
| `voice_id` | no | An existing ElevenLabs voice id to speak with; defaults to Rachel (`21m00Tcm4TlvDq8ikWAM`). |

### Input handling & safety

Inputs reach the pod as `REEF_INPUT_<NAME>` **environment variables** set by
the runtime (`REEF_INPUT_SPEAK_TEXT`, …) — not as text substituted into the
prompt. The directive uses them only as quoted variables or `jq --arg` data.
Because a shell variable's value is not re-scanned for command substitution, an
input like `` speak_text = "$(id)`whoami`;rm -rf ~" `` is spoken/reported
**literally and never executed**.

Smoke/regression: run the pod with a `speak_text` containing `$()`, backticks,
quotes, and `;`, and confirm the report echoes the literal characters (and the
mp3 speaks them) with no side effects. The runtime-side proof that the value
arrives byte-exact and inert lives in the reef-core runtime tests (the test named "an input value with command
substitution reaches the child literally and does NOT execute"). This env
channel requires a reef-core that exposes `REEF_INPUT_*` (the pod fails closed
— stops with a "missing input" report — against an older runtime rather than
misbehaving).

## Budget

This pod's budget is denominated as **1 sat = 1 ElevenLabs character**.
`max_sats = 5000` caps a run at 5,000 TTS characters; the directive refuses to
call the API and writes a report instead if `speak_text` exceeds that count.

## Declared secret

`ELEVENLABS_API_KEY` is declared under `[dependencies].secrets` and is resolved
by the reef-core secrets vault. The runtime host resolves the value
from its operator-controlled vault at spawn time; the value is never present in
this pod, its prompts, its workspace, or any proof artifact. The demo host's
`REEF_POD_SECRETS_ALLOWLIST` must include `ELEVENLABS_API_KEY` or the spawn
fails closed.
