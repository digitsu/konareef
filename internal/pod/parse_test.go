// Tests for the pod.toml parser. Coverage targets:
//   - All major struct fields populate correctly from a realistic pod.toml
//   - Optional sub-tables decode to nil when absent (so callers can
//     distinguish "not set" from "set to zero")
//   - ParseAndValidate combines parsing and schema-checking with the
//     expected three-state return shape
//   - Malformed TOML surfaces as a parse error, not a schema issue
package pod

import (
	"strings"
	"testing"
)

func TestParse_HelloWorldExample(t *testing.T) {
	source := `
pod_spec_version = "0.1"

[pod]
name        = "hello-world"
version     = "0.1.0"
authors     = ["jerry@konareef.ai"]
license     = "MIT"
description = "Smallest pod that exercises the v0.1 spec end-to-end."
tags        = ["example", "smoke-test"]

[runtime]
kind    = "lobster"
version = "^0.1"

[model]
provider   = "anthropic"
name       = "claude-sonnet-4-5"
max_tokens = 1024

[inputs]
name = { type = "string", required = true, description = "Person to greet." }

[directive]
template       = "./prompts/greeting.md"
max_iterations = 1

[output]
[[output.failure]]
kind  = "timeout_seconds"
value = 60

[[output.failure]]
kind = "budget_exhausted"

[budget]
max_sats = 200
`
	spec, err := Parse([]byte(source))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if spec.PodSpecVersion != "0.1" {
		t.Errorf("PodSpecVersion = %q, want %q", spec.PodSpecVersion, "0.1")
	}
	if spec.Pod.Name != "hello-world" {
		t.Errorf("Pod.Name = %q, want %q", spec.Pod.Name, "hello-world")
	}
	if spec.Pod.Version != "0.1.0" {
		t.Errorf("Pod.Version = %q, want %q", spec.Pod.Version, "0.1.0")
	}
	if got := len(spec.Pod.Authors); got != 1 || spec.Pod.Authors[0] != "jerry@konareef.ai" {
		t.Errorf("Pod.Authors = %v, want one author", spec.Pod.Authors)
	}
	if got := len(spec.Pod.Tags); got != 2 {
		t.Errorf("Pod.Tags length = %d, want 2", got)
	}

	if spec.Runtime.Kind != "lobster" {
		t.Errorf("Runtime.Kind = %q, want %q", spec.Runtime.Kind, "lobster")
	}
	if spec.Runtime.Version != "^0.1" {
		t.Errorf("Runtime.Version = %q, want %q", spec.Runtime.Version, "^0.1")
	}

	if spec.Model == nil {
		t.Fatalf("Model should not be nil")
	}
	if spec.Model.Provider != "anthropic" {
		t.Errorf("Model.Provider = %q, want %q", spec.Model.Provider, "anthropic")
	}
	if spec.Model.MaxTokens != 1024 {
		t.Errorf("Model.MaxTokens = %d, want 1024", spec.Model.MaxTokens)
	}

	if spec.Inputs == nil {
		t.Fatal("Inputs should not be nil")
	}
	nameInput, ok := spec.Inputs["name"]
	if !ok {
		t.Fatal("Inputs[\"name\"] missing")
	}
	if nameInput.Type != "string" {
		t.Errorf("Inputs[name].Type = %q, want %q", nameInput.Type, "string")
	}
	if !nameInput.Required {
		t.Errorf("Inputs[name].Required = false, want true")
	}

	if spec.Directive == nil {
		t.Fatal("Directive should not be nil")
	}
	if spec.Directive.Template != "./prompts/greeting.md" {
		t.Errorf("Directive.Template = %q, want %q", spec.Directive.Template, "./prompts/greeting.md")
	}
	if spec.Directive.MaxIterations != 1 {
		t.Errorf("Directive.MaxIterations = %d, want 1", spec.Directive.MaxIterations)
	}
	if spec.Directive.Task != "" {
		t.Errorf("Directive.Task = %q, want empty", spec.Directive.Task)
	}

	if spec.Output == nil {
		t.Fatal("Output should not be nil")
	}
	if got := len(spec.Output.Failure); got != 2 {
		t.Errorf("Output.Failure length = %d, want 2", got)
	} else {
		if spec.Output.Failure[0].Kind != "timeout_seconds" {
			t.Errorf("Failure[0].Kind = %q, want %q", spec.Output.Failure[0].Kind, "timeout_seconds")
		}
		if spec.Output.Failure[0].Value != 60 {
			t.Errorf("Failure[0].Value = %d, want 60", spec.Output.Failure[0].Value)
		}
		if spec.Output.Failure[1].Kind != "budget_exhausted" {
			t.Errorf("Failure[1].Kind = %q, want %q", spec.Output.Failure[1].Kind, "budget_exhausted")
		}
	}

	if spec.Budget == nil {
		t.Fatal("Budget should not be nil")
	}
	if spec.Budget.MaxSats != 200 {
		t.Errorf("Budget.MaxSats = %d, want 200", spec.Budget.MaxSats)
	}
}

func TestParse_OptionalSectionsAreNil(t *testing.T) {
	source := `
pod_spec_version = "0.1"

[pod]
name    = "minimal"
version = "0.1.0"

[runtime]
kind = "lobster"

[directive]
task = "Say hello."
`
	spec, err := Parse([]byte(source))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if spec.Model != nil {
		t.Errorf("Model should be nil for minimal pod, got %+v", spec.Model)
	}
	if spec.Hardware != nil {
		t.Errorf("Hardware should be nil, got %+v", spec.Hardware)
	}
	if spec.Dependencies != nil {
		t.Errorf("Dependencies should be nil, got %+v", spec.Dependencies)
	}
	if spec.Context != nil {
		t.Errorf("Context should be nil, got %+v", spec.Context)
	}
	if spec.Output != nil {
		t.Errorf("Output should be nil, got %+v", spec.Output)
	}
	if spec.Budget != nil {
		t.Errorf("Budget should be nil, got %+v", spec.Budget)
	}
	if spec.Wallet != nil {
		t.Errorf("Wallet should be nil, got %+v", spec.Wallet)
	}
	if spec.Hooks != nil {
		t.Errorf("Hooks should be nil, got %+v", spec.Hooks)
	}
	if spec.Marketplace != nil {
		t.Errorf("Marketplace should be nil, got %+v", spec.Marketplace)
	}

	if spec.Directive == nil {
		t.Fatal("Directive should not be nil — it was set in the source")
	}
	if spec.Directive.Task != "Say hello." {
		t.Errorf("Directive.Task = %q, want %q", spec.Directive.Task, "Say hello.")
	}
}

func TestParse_ContextSubtables(t *testing.T) {
	source := `
pod_spec_version = "0.1"

[pod]
name    = "ctx-test"
version = "0.1.0"

[runtime]
kind = "lobster"

[directive]
task = "x"

[[context.skills]]
source  = "./skills/research-writer"
version = "^1.2"

[[context.skills]]
source = "./skills/summariser"

[[context.tools]]
source = "./tools/web-search"
config = { provider = "brave", max_results = 10 }

[[context.prompts]]
role = "system"
path = "./prompts/system.md"
`
	spec, err := Parse([]byte(source))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if spec.Context == nil {
		t.Fatal("Context should not be nil")
	}
	if got := len(spec.Context.Skills); got != 2 {
		t.Errorf("Skills length = %d, want 2", got)
	}
	if spec.Context.Skills[0].Source != "./skills/research-writer" {
		t.Errorf("Skills[0].Source = %q, want %q",
			spec.Context.Skills[0].Source, "./skills/research-writer")
	}
	if spec.Context.Skills[0].Version != "^1.2" {
		t.Errorf("Skills[0].Version = %q, want %q", spec.Context.Skills[0].Version, "^1.2")
	}
	// Second skill has no version constraint
	if spec.Context.Skills[1].Version != "" {
		t.Errorf("Skills[1].Version = %q, want empty", spec.Context.Skills[1].Version)
	}

	if got := len(spec.Context.Tools); got != 1 {
		t.Errorf("Tools length = %d, want 1", got)
	}
	if spec.Context.Tools[0].Config["provider"] != "brave" {
		t.Errorf("Tools[0].Config[provider] = %v, want %q",
			spec.Context.Tools[0].Config["provider"], "brave")
	}

	if got := len(spec.Context.Prompts); got != 1 {
		t.Errorf("Prompts length = %d, want 1", got)
	}
	if spec.Context.Prompts[0].Role != "system" {
		t.Errorf("Prompts[0].Role = %q, want %q", spec.Context.Prompts[0].Role, "system")
	}
}

func TestParse_TemperatureZeroDistinguishedFromAbsent(t *testing.T) {
	withTemp := `
pod_spec_version = "0.1"
[pod]
name = "t"
version = "0.1.0"
[runtime]
kind = "lobster"
[directive]
task = "x"
[model]
provider    = "anthropic"
name        = "claude-sonnet-4-5"
temperature = 0.0
`
	withoutTemp := `
pod_spec_version = "0.1"
[pod]
name = "t"
version = "0.1.0"
[runtime]
kind = "lobster"
[directive]
task = "x"
[model]
provider = "anthropic"
name     = "claude-sonnet-4-5"
`
	specWith, err := Parse([]byte(withTemp))
	if err != nil {
		t.Fatalf("withTemp: %v", err)
	}
	if specWith.Model == nil || specWith.Model.Temperature == nil {
		t.Fatal("Temperature should be non-nil when explicitly set, even at 0.0")
	}
	if *specWith.Model.Temperature != 0.0 {
		t.Errorf("Temperature = %f, want 0.0", *specWith.Model.Temperature)
	}

	specWithout, err := Parse([]byte(withoutTemp))
	if err != nil {
		t.Fatalf("withoutTemp: %v", err)
	}
	if specWithout.Model == nil {
		t.Fatal("Model should not be nil")
	}
	if specWithout.Model.Temperature != nil {
		t.Errorf("Temperature should be nil when absent, got %f", *specWithout.Model.Temperature)
	}
}

func TestParse_MalformedTOML(t *testing.T) {
	_, err := Parse([]byte("not = = valid = toml"))
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !strings.Contains(err.Error(), "toml parse") {
		t.Errorf("expected 'toml parse' in error, got: %v", err)
	}
}

func TestParseAndValidate_ValidDocument(t *testing.T) {
	source := `
pod_spec_version = "0.1"
[pod]
name    = "ok"
version = "0.1.0"
[runtime]
kind = "lobster"
[directive]
task = "Do the thing."
`
	spec, issues, err := ParseAndValidate([]byte(source))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(issues) > 0 {
		t.Fatalf("expected no issues, got %d:\n%s", len(issues), formatIssues(issues))
	}
	if spec.Pod.Name != "ok" {
		t.Errorf("Pod.Name = %q, want %q", spec.Pod.Name, "ok")
	}
}

func TestParseAndValidate_SchemaIssues(t *testing.T) {
	// Valid TOML, schema-invalid (pod.name violates identifier pattern).
	source := `
pod_spec_version = "0.1"
[pod]
name    = "Has Capitals"
version = "0.1.0"
[runtime]
kind = "lobster"
[directive]
task = "x"
`
	spec, issues, err := ParseAndValidate([]byte(source))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(issues) == 0 {
		t.Fatal("expected schema issues, got none")
	}
	// Spec is still returned with the populated (but invalid) name.
	if spec.Pod.Name != "Has Capitals" {
		t.Errorf("Pod.Name should be returned even on validation failure, got %q", spec.Pod.Name)
	}
}

func TestParseAndValidate_MalformedTOML(t *testing.T) {
	spec, issues, err := ParseAndValidate([]byte("[[[ not toml"))
	if err == nil {
		t.Fatal("expected error for malformed TOML")
	}
	// On parse error, spec is empty and issues is nil — neither is meaningful.
	_ = spec
	if issues != nil {
		t.Errorf("issues should be nil on parse error, got %v", issues)
	}
}
