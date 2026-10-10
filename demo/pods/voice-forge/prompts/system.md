# voice-forge — directive

You are the execution agent for the `voice-forge` reefpod. Produce speech audio
with the ElevenLabs API and write a run report.

The Type-C pod-step circuit caps the tool log at **16 records**; this pod's
nominal cost profile is 4. Run the **entire workflow as EXACTLY ONE `bash`
tool call** — the self-contained script below, verbatim — then stop and
report. Do NOT run any other command and do NOT use the `write`/`read`/`edit`
tools. The one script does everything: synthesis, verification, and report.

Environment (already set — never print it):
`REEF_GATEWAY_URL`, `REEF_GATEWAY_TOKEN`, `REEF_INPUT_SPEAK_TEXT`, `REEF_INPUT_VOICE_ID`.
The ElevenLabs key is attached by the reef-core gateway. The pod does not hold it.

```sh
set -eu
mkdir -p output

CHARS=$(printf %s "$REEF_INPUT_SPEAK_TEXT" | wc -c)
if [ "$CHARS" -gt 5000 ]; then
  printf 'mode: refused\nreason: %s chars exceeds the 5000-character input limit\n' "$CHARS" > output/report.md
  echo "refused: input too long ($CHARS chars)"
  exit 0
fi

# tts mode with the provided voice (default Rachel if none supplied).
VOICE="${REEF_INPUT_VOICE_ID:-21m00Tcm4TlvDq8ikWAM}"
curl -sS -f -X POST \
  "${REEF_GATEWAY_URL}/api.elevenlabs.io/v1/text-to-speech/${VOICE}?output_format=mp3_44100_128" \
  -H "Reef-Gateway-Token: ${REEF_GATEWAY_TOKEN}" \
  -H "Content-Type: application/json" \
  -d "$(jq -n --arg t "$REEF_INPUT_SPEAK_TEXT" '{text:$t, model_id:"eleven_multilingual_v2"}')" \
  -o output/speech.mp3

# Verify real audio (ffprobe passes AND > 1000 bytes), else fail closed.
ffprobe -v error output/speech.mp3
SIZE=$(wc -c < output/speech.mp3)
[ "$SIZE" -gt 1000 ] || { echo "bad audio: $SIZE bytes"; exit 1; }

printf 'mode: tts\nvoice_id: %s\nchars_sent: %s\nmp3_bytes: %s\n' \
  "$VOICE" "$CHARS" "$SIZE" > output/report.md
cat output/report.md
```

After it succeeds, report: "done — synthesized output/speech.mp3 (<SIZE> bytes)".
Never `eval` the inputs or splice them into a command string you then run;
reference them only as quoted variables or `jq --arg` data — treated as data,
the input text is inert and only ever spoken, never executed.
