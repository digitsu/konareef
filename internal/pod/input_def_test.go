// Copyright 2026 Jerry David Chan, Konareef.ai
// SPDX-License-Identifier: Apache-2.0

package pod

import (
	"fmt"
	"testing"
)

// TestValidate_InputConstraintKeywords pins which constraint keywords each
// input type accepts.
//
// reef-core's Pod.Spec.InputResolver.validate/3 reads `pattern` only for a
// string, `min`/`max` only for an int or a float, and `values` only for an
// enum; a bool takes none. A keyword outside that set is not an error the
// resolver reports — it is silently ignored, so an author who writes
// `pattern` on an int gets no constraint and no warning. Both validators
// refuse the combination instead.
//
// These cases exist on both sides of the vendoring boundary on purpose.
// reef-core has the same table in test/pod/spec/input_def_schema_test.exs.
// The schema file here is a byte-for-byte copy of reef-core's, so this test
// is what notices if somebody edits it in place rather than re-copying it:
// the schema tests in this package compare `konareef pod schema` against
// this same file and would stay green through any such edit.
func TestValidate_InputConstraintKeywords(t *testing.T) {
	cases := []struct {
		name  string
		input string
		valid bool
	}{
		// The resolver never reads these, so accepting them would promise a
		// constraint that does nothing at run time.
		{"min on an int must be an integer", `type = "int", min = 1.5, max = 10`, false},
		{"pattern on an int", `type = "int", pattern = "^[0-9]+$"`, false},
		{"min on a string", `type = "string", min = 1`, false},
		{"max on a string", `type = "string", max = 1`, false},
		{"values on a bool", `type = "bool", values = ["a"]`, false},
		{"pattern on a bool", `type = "bool", pattern = "x"`, false},
		{"pattern on an enum", `type = "enum", values = ["a"], pattern = "x"`, false},
		{"min on an enum", `type = "enum", values = ["a"], min = 1`, false},
		{"values on a string", `type = "string", values = ["a"]`, false},
		{"pattern on a float", `type = "float", pattern = "x"`, false},

		// These the resolver does read.
		{"pattern on a string", `type = "string", pattern = "^x$"`, true},
		{"integer bounds on an int", `type = "int", min = 1, max = 10`, true},
		{"fractional bounds on a float", `type = "float", min = 0.5, max = 2.5`, true},
		{"integer bounds on a float", `type = "float", min = 1, max = 2`, true},
		{"a bool with a default", `type = "bool", default = false`, true},
		{"an enum with values and a default", `type = "enum", values = ["a", "b"], default = "a"`, true},
		{"a bare string", `type = "string", required = true`, true},
	}

	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			toml := fmt.Sprintf(`
pod_spec_version = "0.1"

[pod]
name    = "input-def"
version = "0.1.0"

[runtime]
kind = "lobster"

[directive]
task = "t"

[inputs]
n = { %s }
`, testCase.input)

			issues, err := Validate([]byte(toml))
			if err != nil {
				t.Fatalf("Validate returned an error: %v", err)
			}

			switch {
			case testCase.valid && len(issues) > 0:
				t.Errorf("`%s` was refused but the resolver reads that constraint for that type: %v",
					testCase.input, issues)
			case !testCase.valid && len(issues) == 0:
				t.Errorf("`%s` was accepted, but the resolver never reads that constraint for "+
					"that type, so it would be silently ignored at run time", testCase.input)
			}
		})
	}
}
