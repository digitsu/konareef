// Copyright 2026 Jerry David Chan, Konareef.ai
// SPDX-License-Identifier: Apache-2.0

// init.go — scaffolding for new pod definitions.
//
// `konareef pod init <name>` creates a minimal pod directory containing a
// pod.toml that validates against the v0.1 schema, a placeholder system
// prompt template, and an author-facing README. The generated tree is the
// fastest possible path from "I want to build a pod" to "I have something
// `konareef pod validate` accepts."
package pod

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// identifierRegexp mirrors the "identifier" pattern in spec_v0_1.schema.json:
// lowercase alpha first character, then lowercase alphanumeric, underscore,
// or hyphen. Pod names that do not match are rejected by Init before any
// filesystem work happens. We re-validate via the schema after generation
// to catch bugs in the templates themselves; this regexp is just a fast
// pre-flight check and a friendlier error message.
var identifierRegexp = regexp.MustCompile(`^[a-z][a-z0-9_-]*$`)

// defaultRuntime is the fallback runtime kind for new pods. lobster is the
// one-shot bsv-worm-class runtime currently shipping in reef-core; future
// users will pick orca, pi-agent, or kimi-cli via the --runtime flag.
const defaultRuntime = "lobster"

// defaultModel is the fallback model spec, formatted as "<provider>/<name>"
// to match the InitOptions.Model field. claude-sonnet-4-5 is a sensible
// default for the v0.1 retail launch.
const defaultModel = "anthropic/claude-sonnet-4-5"

// InitOptions controls pod scaffolding. All fields except Name have
// sensible defaults applied by Init when left empty.
type InitOptions struct {
	// Name is the pod identifier — must match the v0.1 schema identifier
	// pattern. Required.
	Name string
	// Dir is the output directory. Defaults to "./<Name>" when empty.
	Dir string
	// Runtime is the runtime kind written into [runtime].kind. Defaults
	// to "lobster" when empty.
	Runtime string
	// Model is "<provider>/<name>" written into [model]. Defaults to
	// "anthropic/claude-sonnet-4-5" when empty. If no "/" is present
	// the entire string is treated as the model name and the provider
	// defaults to "anthropic".
	Model string
}

// Init scaffolds a new pod directory according to opts. Returns the list
// of files written (in deterministic order) on success, or a descriptive
// error if the name is invalid, the directory already exists, or any
// filesystem write fails.
//
// The function is atomic-on-success in the sense that the destination
// directory is checked for existence up front: a partial scaffold can
// still leave files behind if a write fails midway, but the pre-flight
// check ensures Init never overwrites an existing pod tree.
func Init(opts InitOptions) ([]string, error) {
	if opts.Name == "" {
		return nil, fmt.Errorf("pod name is required")
	}
	if !identifierRegexp.MatchString(opts.Name) {
		return nil, fmt.Errorf(
			"invalid pod name %q: must match %s (lowercase alpha first, then alphanumeric / underscore / hyphen)",
			opts.Name, identifierRegexp.String())
	}
	if len(opts.Name) > 64 {
		return nil, fmt.Errorf("invalid pod name %q: must be 64 characters or fewer", opts.Name)
	}

	outputDir := opts.Dir
	if outputDir == "" {
		outputDir = "./" + opts.Name
	}
	if _, err := os.Stat(outputDir); err == nil {
		return nil, fmt.Errorf("directory %s already exists; pick a different name or remove it first", outputDir)
	} else if !os.IsNotExist(err) {
		return nil, fmt.Errorf("stat %s: %w", outputDir, err)
	}

	runtimeKind := opts.Runtime
	if runtimeKind == "" {
		runtimeKind = defaultRuntime
	}

	provider, modelName := splitModelString(opts.Model)

	promptsDir := filepath.Join(outputDir, "prompts")
	if err := os.MkdirAll(promptsDir, 0o755); err != nil {
		return nil, fmt.Errorf("mkdir %s: %w", promptsDir, err)
	}

	// Generate the per-lineage 16-byte salt-lookup key (lineage_id).
	// The corresponding 32-byte salt is generated + persisted by the
	// CLI layer (`konareef pod init`) AFTER Init returns, so the pod
	// package keeps zero dependency on the saltstore backend.
	lidBytes := make([]byte, 16)
	if _, err := rand.Read(lidBytes); err != nil {
		return nil, fmt.Errorf("generate lineage_id: %w", err)
	}
	lineageID := hex.EncodeToString(lidBytes)

	podTOML := renderPodTOML(opts.Name, runtimeKind, provider, modelName, lineageID)
	systemPrompt := renderSystemPrompt(opts.Name)
	readme := renderReadme(opts.Name)

	written := []string{}
	for _, file := range []struct {
		path    string
		content string
	}{
		{filepath.Join(outputDir, "pod.toml"), podTOML},
		{filepath.Join(outputDir, "prompts", "system.md"), systemPrompt},
		{filepath.Join(outputDir, "README.md"), readme},
	} {
		if err := os.WriteFile(file.path, []byte(file.content), 0o644); err != nil {
			return written, fmt.Errorf("write %s: %w", file.path, err)
		}
		written = append(written, file.path)
	}

	// Self-check: the generated pod.toml must validate against the schema.
	// A failure here means renderPodTOML has a bug — surface it loudly so
	// no broken scaffold ever ships to users.
	issues, err := Validate([]byte(podTOML))
	if err != nil {
		return written, fmt.Errorf("internal: generated pod.toml failed to parse: %w", err)
	}
	if len(issues) > 0 {
		return written, fmt.Errorf("internal: generated pod.toml has %d schema issue(s); first: %s",
			len(issues), issues[0])
	}

	return written, nil
}

// splitModelString parses opts.Model into (provider, name). When the input
// contains a "/" separator the left side is provider and right side is
// name. When no separator is present the entire input is treated as the
// model name and the default provider is used. An empty input falls back
// to defaults entirely.
func splitModelString(model string) (provider string, name string) {
	if model == "" {
		model = defaultModel
	}
	parts := strings.SplitN(model, "/", 2)
	if len(parts) == 2 && parts[0] != "" && parts[1] != "" {
		return parts[0], parts[1]
	}
	defaultParts := strings.SplitN(defaultModel, "/", 2)
	defaultProvider, defaultName := defaultParts[0], defaultParts[1]
	if len(parts) == 1 && parts[0] != "" {
		return defaultProvider, parts[0]
	}
	return defaultProvider, defaultName
}

// renderPodTOML produces a v0.1-compliant pod.toml string with the given
// identity, runtime, model, and per-lineage salt-lookup key. The result
// is hand-formatted (rather than generated via a TOML encoder) so the
// file reads naturally to humans editing it after init.
func renderPodTOML(name, runtimeKind, modelProvider, modelName, lineageID string) string {
	return fmt.Sprintf(`pod_spec_version = "0.1"

# ── Identity ────────────────────────────────────────
[pod]
name        = %q
version     = "0.1.0"
description = "TODO: describe what %s does."
lineage_id  = %q

# ── Runtime + model ─────────────────────────────────
[runtime]
kind    = %q
version = "^0.1"

[model]
provider = %q
name     = %q

# ── Inputs (uncomment + customize) ──────────────────
# [inputs]
# topic = { type = "string", required = true, description = "What to work on." }

# ── Directive ───────────────────────────────────────
[directive]
template       = "./prompts/system.md"
max_iterations = 5

# ── Output ──────────────────────────────────────────
[output]

[[output.failure]]
kind  = "timeout_seconds"
value = 600

[[output.failure]]
kind = "budget_exhausted"

# ── Budget ──────────────────────────────────────────
# max_sats = 0 means this pod cannot spend anything. Set the real ceiling
# before you run it, and get the number from whoever pays. A scaffold that
# guessed a plausible number invited callers to leave it standing; a zero
# fails on the first run instead of quietly spending someone else's money.
[budget]
max_sats = 0
`, name, name, lineageID, runtimeKind, modelProvider, modelName)
}

// renderSystemPrompt produces the placeholder prompts/system.md content.
// It is intentionally short and instructive — pod authors are expected to
// rewrite this file before shipping. The TODO marker makes the placeholder
// state visible in code review.
func renderSystemPrompt(name string) string {
	return fmt.Sprintf(`# %s

You are %s, a KonaReef pod.

TODO: rewrite this prompt to define the pod's role, capabilities, and
constraints. The text in this file is rendered as the directive at spawn
time — keep it concrete and bounded.

## Behaviour

- Be concise.
- Use available tools to accomplish the user's task.
- When uncertain, ask for clarification rather than guessing.
`, name, name)
}

// renderReadme produces the author-facing README.md for the new pod.
// Documents the immediate-next-step CLI commands and points at the spec
// for further customisation.
func renderReadme(name string) string {
	return fmt.Sprintf(`# %s

A KonaReef pod scaffolded with `+"`konareef pod init`"+`.

## Quick start

Validate the pod definition against the v0.1 schema:

`+"```sh"+`
konareef pod validate ./pod.toml
`+"```"+`

Once `+"`konareef pod spawn`"+` ships, run:

`+"```sh"+`
konareef pod spawn ./pod.toml
`+"```"+`

## Customise

- Edit `+"`pod.toml`"+` to change runtime, model, budget, or directive.
- Edit `+"`prompts/system.md`"+` to change the pod's behaviour.
- Add an `+"`[inputs]`"+` block to make the pod parameterisable at spawn time.

The public pod manifest reference lives in docs/reference/pod-toml-v0.1.md.
`, name)
}
