// Copyright 2026 Jerry David Chan, Konareef.ai
// SPDX-License-Identifier: Apache-2.0

// Package pod provides parsing and validation of konareef pod.toml files.
//
// The canonical JSON Schema lives in the reef-core repo at
// priv/pod/spec_v0_1.schema.json; a vendored copy is embedded here so
// `konareef pod validate` runs offline without a reef-core round-trip.
// reef-core remains the authoritative parser at spawn time — local
// validation is a dev-time UX convenience, not a trust boundary.
//
// Public surface:
//
//   - Issue: a single validation problem with a structured path.
//     Issue.Code carries the cross-field vocabulary (e.g. the
//     [[network.gateway]] codes in gateway.go) alongside the schema
//     failures, which leave Code empty.
//   - Warning: a single advisory that does not fail validation
//   - Validate(podTOML): validate raw TOML bytes
//   - ValidateWithWarnings(podTOML): validate raw TOML bytes and also
//     return advisory warnings
//   - ValidateFile(path): read and validate a file
package pod

import (
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/BurntSushi/toml"
	"github.com/digitsu/konareef/internal/secret"
	"github.com/santhosh-tekuri/jsonschema/v6"
)

// schemaJSON is the vendored copy of reef-core/priv/pod/spec_v0_1.schema.json.
//
// It is a BYTE-FOR-BYTE copy, and must stay one. Update it by copying the
// file, never by editing it here. reef-core has
// scripts/check-schema-parity.py, which takes this file's path and fails
// unless it is identical; run it after any copy, then run this suite.
//
// This used to be a hand-maintained 2020-12 rewrite of reef-core's draft-07
// file, and the two silently diverged: reef-core accepted `pattern` on an int
// input and `min` on a string, which this copy refused, so the CLI rejected
// manifests the server would publish. Nothing caught it, because the tests
// below compare `konareef pod schema` against THIS file — a stale copy is
// self-consistent. The compiler picks the draft from `$schema`, so draft-07
// needs no translation and there is no reason to keep a second dialect.
//
//go:embed spec_v0_1.schema.json
var schemaJSON []byte

// schemaID matches the $id declared in spec_v0_1.schema.json. It is used as
// the resource identifier when registering the embedded schema with the
// jsonschema compiler.
const schemaID = "https://konareef.ai/schemas/pod-toml/v0.1.json"

// Issue describes a single validation problem.
//
// Path is a dotted path into the pod.toml document with bracket notation
// for array indices, e.g. "context.skills[0].source". An empty Path means
// the issue applies to the whole document (e.g. a missing top-level key).
//
// Code is a stable SCREAMING_SNAKE identifier for a cross-field rule, e.g.
// "GATEWAY_SECRET_UNDECLARED". It is empty for a JSON-schema violation.
// A code that mirrors a reef-core refusal code uses reef-core's bytes, so
// CodeSecretReserved is "secret_reserved".
// Callers dispatch on Code; Message may change between releases.
//
// Message is a human-readable description of what went wrong.
type Issue struct {
	Path    string
	Code    string
	Message string
}

// String renders the issue as "path: CODE: message", dropping the path
// when empty and the code when empty. Used for human-facing CLI output.
func (issue Issue) String() string {
	parts := make([]string, 0, 3)
	if issue.Path != "" {
		parts = append(parts, issue.Path)
	}
	if issue.Code != "" {
		parts = append(parts, issue.Code)
	}
	parts = append(parts, issue.Message)
	return strings.Join(parts, ": ")
}

// Warning is a non-fatal advisory raised by a cross-field rule. It never
// fails validation: `pod validate` prints it and exits 0, and `pod
// publish` proceeds. Path and Code follow the Issue conventions.
type Warning struct {
	Path    string
	Code    string
	Message string
}

// String renders the warning as "path: CODE: message".
func (warning Warning) String() string {
	return Issue{Path: warning.Path, Code: warning.Code, Message: warning.Message}.String()
}

// validateSchema checks podTOML against the embedded v0.1 schema only.
//
// It returns a slice of Issues (empty when the document is valid) and a
// non-nil error only when:
//   - podTOML is not parseable as TOML, or
//   - the embedded schema itself fails to compile (a build/programmer bug).
//
// Schema-validation failures are returned as Issues, not as errors, so
// callers can render them as a list to the user rather than aborting.
func validateSchema(podTOML []byte) ([]Issue, error) {
	var rawDoc map[string]interface{}
	if _, err := toml.Decode(string(podTOML), &rawDoc); err != nil {
		return nil, fmt.Errorf("toml parse: %w", err)
	}

	// BurntSushi/toml decodes arrays-of-tables (e.g. [[output.failure]])
	// as []map[string]interface{}, but jsonschema/v6 expects standard
	// JSON-style []interface{}. A JSON round-trip normalizes the types.
	// pod.toml has no TOML datetimes / inf / NaN so the round-trip is
	// lossless for our purposes.
	jsonBytes, err := json.Marshal(rawDoc)
	if err != nil {
		return nil, fmt.Errorf("toml-to-json normalize (marshal): %w", err)
	}
	var document interface{}
	if err := json.Unmarshal(jsonBytes, &document); err != nil {
		return nil, fmt.Errorf("toml-to-json normalize (unmarshal): %w", err)
	}

	schema, err := compileSchema()
	if err != nil {
		return nil, err
	}

	if err := schema.Validate(document); err != nil {
		var validationErr *jsonschema.ValidationError
		if errors.As(err, &validationErr) {
			return flattenIssues(validationErr), nil
		}
		return nil, fmt.Errorf("schema validation: %w", err)
	}
	return nil, nil
}

// ValidateWithWarnings validates podTOML against the embedded v0.1 schema
// and then applies the cross-field rules a schema cannot express (today:
// the [[network.gateway]] rules in gateway.go, the brokered-MCP runtime and
// tool-name rules in mcp_broker.go, the tool-policy rules below, the
// advisory egress warnings in egress_review.go, the egress breadth rules
// in egress_breadth.go, and the reserved [dependencies].secrets warning).
//
// It returns the issues (empty when valid), the advisory warnings, and a
// non-nil error only when the TOML is unparseable or the embedded schema
// fails to compile. The cross-field pass runs only when the schema pass
// found nothing, because a Spec decoded from a document the schema
// rejects is not trustworthy.
func ValidateWithWarnings(podTOML []byte) ([]Issue, []Warning, error) {
	issues, err := validateSchema(podTOML)
	if err != nil {
		return nil, nil, err
	}
	if len(issues) > 0 {
		return issues, nil, nil
	}
	spec, meta, err := ParseWithMeta(podTOML)
	if err != nil {
		return nil, nil, err
	}
	gatewayIssues, gatewayWarnings := gatewayRules(*spec)
	gatewayIssues = append(gatewayIssues, mcpBrokerRules(*spec)...)
	toolsIssues, toolsWarnings := toolsPolicyRules(*spec, meta)

	// Merge issues and warnings from all cross-field rules.
	// gatewayRules currently returns only issues (no issues returned),
	// but we prepare for both.
	allIssues := append(gatewayIssues, toolsIssues...)
	allWarnings := append(gatewayWarnings, toolsWarnings...)
	// Egress warnings (egress_review.go) name the declarations a server
	// egress review flags. They are advice only and never become issues.
	allWarnings = append(allWarnings, EgressWarnings(*spec)...)
	// Egress breadth (egress_breadth.go, reef-core#87): a public-suffix
	// wildcard is an issue, because reef-core refuses it in every mode; a
	// rule count above the unreviewed-run limit is a warning, because
	// only the server knows whether a run is reviewed.
	breadthIssues, breadthWarnings := egressBreadthRules(*spec)
	allIssues = append(allIssues, breadthIssues...)
	allWarnings = append(allWarnings, breadthWarnings...)
	// Reserved harness secret names are refused only by a hosted node.
	allWarnings = append(allWarnings, reservedSecretWarnings(*spec)...)

	return allIssues, allWarnings, nil
}

// toolsPolicyRules applies the cross-field rules for [directive].
// tools_allowed and [directive].tools_denied against [[context.tools]], per
// the tool-policy semantics ADR (docs/design/tool-policy-semantics-adr.md,
// TA-00 konareef#18 / TA-01 konareef#19, decisions D3-D5). The accepted
// contract (D1 = Option B) is declaration-only: reef-core enforces neither
// field at runtime today, so every rule below is advisory (a Warning) with
// one exception the ADR calls an outright authoring mistake (a name in both
// tools_allowed and tools_denied — D5 "refuse at validate and publish").
//
//   - non-NFC name (D5): warns. A v2 publish, and commission
//     draft/check/sign/verify, both refuse this outright
//     (COMMIT_NON_NFC_ID / ErrToolNameNotNFC).
//   - tools_allowed name absent from declared (D3, spec R-V2.14): warns.
//     A v2 publish refuses (COMMIT_TOOL_AUTHORITY_UNCOMMITTED); commission
//     check/sign/verify now apply the same per-name rule.
//   - tools_denied name also in tools_allowed (D5): an Issue, not a
//     Warning — the one case this function fails validation for, since a
//     manifest cannot mean "deny wins" and "narrow the runtime set" for
//     the same name at once. A v2 publish also refuses this
//     (COMMIT_TOOL_DENY_OVERLAP).
//   - tools_denied name absent from declared, and not overlapping
//     tools_allowed (D5, Option B): warns. Nothing refuses this — the
//     accepted contract has no S1-to-runtime-name map to check the name
//     against, so it may simply be a label with no committed referent
//     (the code-reviewer example's tools_denied entries are exactly this
//     shape).
//
// D4 (presence): [directive].tools_allowed explicitly set to `[]` reads as
// "this pod uses no tools" (an intentional declaration), distinct from an
// omitted key ("no directive policy stated"). A `[]` beside a non-empty
// declared set is therefore a contradiction under Option B and warns here;
// a v2 publish refuses it (COMMIT_TOOL_AUTHORITY_CONTRADICTION). This
// needs toml.MetaData, because ToolsAllowed alone cannot tell "omitted"
// from "explicit empty" apart (both decode to len == 0 — see
// ParseWithMeta's doc comment); it is checked directly here rather than in
// CheckToolPolicy, whose other three rules don't need presence at all.
//
// A nil Directive yields nothing: CheckToolPolicy's declared-side NFC rule
// still fires without one, but there is no [directive] table for an
// author to fix, so nothing is reported.
func toolsPolicyRules(spec Spec, meta toml.MetaData) ([]Issue, []Warning) {
	if spec.Directive == nil {
		return nil, nil
	}

	var issues []Issue
	var warnings []Warning

	for _, problem := range CheckToolPolicy(spec) {
		switch problem.Code {
		case ToolPolicyNonNFC:
			var location string
			switch problem.Field {
			case ToolPolicyFieldDeclared:
				location = "[[context.tools]] declares source"
			case ToolPolicyFieldAllowed:
				location = "[directive].tools_allowed names"
			case ToolPolicyFieldDenied:
				location = "[directive].tools_denied names"
			}
			warnings = append(warnings, Warning{
				Path:    string(problem.Field),
				Code:    "tools-non-nfc",
				Message: fmt.Sprintf("%s %q, which is not NFC-normalized; a --zk publish or a commission derivation will refuse this pod rather than rewrite the bytes", location, problem.Name),
			})
		case ToolPolicyUncommitted:
			warnings = append(warnings, Warning{
				Path:    "directive.tools_allowed",
				Code:    "tools-allowed-uncommitted",
				Message: fmt.Sprintf("%q is not declared as a [[context.tools]] entry, so the manifest commitment does not cover it; a --zk publish will refuse this pod", problem.Name),
			})
		case ToolPolicyDenyOverlap:
			issues = append(issues, Issue{
				Path:    "directive.tools_denied",
				Code:    "tools-denied-overlap-allowed",
				Message: fmt.Sprintf("%q is named in both tools_allowed and tools_denied; deny wins, but naming a tool in both is almost always a mistake", problem.Name),
			})
		case ToolPolicyDenyUnknown:
			warnings = append(warnings, Warning{
				Path:    "directive.tools_denied",
				Code:    "tools-denied-unknown",
				Message: fmt.Sprintf("%q names no [[context.tools]] entry; tools_denied is a declaration only — no runtime enforces it today — so this name has no committed referent", problem.Name),
			})
		}
	}

	if meta.IsDefined("directive", "tools_allowed") && len(spec.Directive.ToolsAllowed) == 0 && len(DeclaredToolSources(spec)) > 0 {
		warnings = append(warnings, Warning{
			Path:    "directive.tools_allowed",
			Code:    "tools-allowed-empty-contradicts-declared",
			Message: "tools_allowed is explicitly empty, which reads as \"this pod uses no tools\", but [[context.tools]] declares tools; a --zk publish will refuse this pod (COMMIT_TOOL_AUTHORITY_CONTRADICTION)",
		})
	}

	return issues, warnings
}

// CodeSecretReserved is the code for a reserved harness secret name. It
// is the same bytes as the `secret_reserved` code a hosted reef-core
// returns when it refuses the name.
const CodeSecretReserved = secret.CodeReserved

// reservedSecretWarnings warns about each [dependencies].secrets name that
// is reserved for the runtime harness (secret.IsReserved: the reef-core
// SecretsVault list).
//
// It is a Warning, not an Issue, because reef-core does not refuse the name
// in every mode. A hosted reef-core refuses it with secret_reserved at every
// spawn. A self-host reef-core resolves it from REEF_SECRET_<NAME>, so an
// operator can bring their own provider key on purpose. A sealed grant's
// secret is refused in every mode; sealedGrantSchemaIssues reports that one as
// an Issue. Input: the parsed spec. Output: one Warning per reserved name,
// in declaration order, or nil.
func reservedSecretWarnings(spec Spec) []Warning {
	if spec.Dependencies == nil {
		return nil
	}
	var warnings []Warning
	for index, name := range spec.Dependencies.Secrets {
		if secret.IsReserved(name) {
			warnings = append(warnings, Warning{
				Path:    fmt.Sprintf("dependencies.secrets[%d]", index),
				Code:    CodeSecretReserved,
				Message: fmt.Sprintf("secret name %q is reserved for the runtime harness; a hosted reef-core refuses this pod at spawn, and only a self-host node supplies it (REEF_SECRET_%s)", name, name),
			})
		}
	}
	return warnings
}

// Validate is ValidateWithWarnings without the warnings. Every existing
// caller (publish, listing, spawn) keeps its signature and gains the
// cross-field issues.
func Validate(podTOML []byte) ([]Issue, error) {
	issues, _, err := ValidateWithWarnings(podTOML)
	return issues, err
}

// ValidateFile reads the file at path and validates it. The path argument
// is included in any I/O error returned for context.
func ValidateFile(path string) ([]Issue, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	return Validate(data)
}

// compileSchema unmarshals the embedded schema bytes and registers them
// with a fresh jsonschema compiler keyed by schemaID. The compiler is
// constructed per call rather than cached because compilation is fast
// relative to anything users do interactively, and per-call construction
// avoids any subtle global-state surprises.
func compileSchema() (*jsonschema.Schema, error) {
	var schemaDocument interface{}
	if err := json.Unmarshal(schemaJSON, &schemaDocument); err != nil {
		return nil, fmt.Errorf("embedded schema unmarshal: %w", err)
	}
	compiler := jsonschema.NewCompiler()
	if err := compiler.AddResource(schemaID, schemaDocument); err != nil {
		return nil, fmt.Errorf("embedded schema add: %w", err)
	}
	schema, err := compiler.Compile(schemaID)
	if err != nil {
		return nil, fmt.Errorf("embedded schema compile: %w", err)
	}
	return schema, nil
}

// flattenIssues walks a jsonschema validation error tree and returns only
// the leaf-level issues. Branch nodes group their children by keyword
// (allOf/oneOf/anyOf branching) and would produce noisy "schema does not
// validate" pseudo-messages without context, so we surface only the leaves
// where a concrete constraint failed.
func flattenIssues(validationErr *jsonschema.ValidationError) []Issue {
	var issues []Issue
	walkValidationError(validationErr, &issues)
	return issues
}

// walkValidationError recursively descends into causes, accumulating leaf
// errors into issues. Each leaf becomes one Issue with its instance path
// rendered in dotted form.
func walkValidationError(node *jsonschema.ValidationError, issues *[]Issue) {
	if len(node.Causes) == 0 {
		*issues = append(*issues, Issue{
			Path:    formatInstancePath(node.InstanceLocation),
			Message: node.Error(),
		})
		return
	}
	for _, cause := range node.Causes {
		walkValidationError(cause, issues)
	}
}

// formatInstancePath converts a jsonschema InstanceLocation slice (a list
// of strings where numeric strings represent array indices) into a
// dotted-path representation with bracket notation for indices.
//
// Examples:
//
//	[]                                -> ""
//	["pod", "name"]                   -> "pod.name"
//	["context", "skills", "0", "source"] -> "context.skills[0].source"
//	["output", "success", "2", "kind"] -> "output.success[2].kind"
func formatInstancePath(location []string) string {
	if len(location) == 0 {
		return ""
	}
	var builder strings.Builder
	for index, segment := range location {
		if isAllDigits(segment) {
			builder.WriteByte('[')
			builder.WriteString(segment)
			builder.WriteByte(']')
			continue
		}
		if index > 0 && builder.Len() > 0 && builder.String()[builder.Len()-1] != ']' {
			builder.WriteByte('.')
		} else if index > 0 {
			builder.WriteByte('.')
		}
		builder.WriteString(segment)
	}
	return builder.String()
}

// isAllDigits reports whether s consists entirely of ASCII digit characters.
// Used to distinguish array indices (encoded as numeric strings in
// jsonschema InstanceLocation) from object keys.
func isAllDigits(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}
