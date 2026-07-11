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
//   - Issue: a single validation problem with a structured path
//   - Validate(podTOML): validate raw TOML bytes
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
	"github.com/santhosh-tekuri/jsonschema/v6"
)

// schemaJSON is the vendored copy of reef-core/priv/pod/spec_v0_1.schema.json.
// Keep this file in sync with the canonical schema; a future build-time
// check or sync script should enforce that.
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
// Message is a human-readable description of what went wrong.
type Issue struct {
	Path    string
	Message string
}

// String renders the issue in "path: message" form, or just "message" when
// no specific path is associated. Used for human-facing CLI output.
func (issue Issue) String() string {
	if issue.Path == "" {
		return issue.Message
	}
	return fmt.Sprintf("%s: %s", issue.Path, issue.Message)
}

// Validate parses podTOML as a pod.toml document and checks the result
// against the embedded v0.1 schema.
//
// It returns a slice of Issues (empty when the document is valid) and a
// non-nil error only when:
//   - podTOML is not parseable as TOML, or
//   - the embedded schema itself fails to compile (a build/programmer bug).
//
// Schema-validation failures are returned as Issues, not as errors, so
// callers can render them as a list to the user rather than aborting.
func Validate(podTOML []byte) ([]Issue, error) {
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
