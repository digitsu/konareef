// parse.go — typed-struct decoding for pod.toml documents.
//
// Parse is intentionally permissive: it only catches TOML syntax errors.
// Missing required fields show up as zero values; conditional constraints
// (directive.task XOR template, wallet.reuse when strategy=reuse) are
// the schema's job and surface only via Validate or ParseAndValidate.
//
// Callers that want both typed access AND schema-validation should use
// ParseAndValidate, which combines the two operations and gives a single
// place to handle each failure mode.
package pod

import (
	"fmt"
	"os"

	"github.com/BurntSushi/toml"
)

// Parse decodes podTOML into a Spec. Returns a non-nil error only when
// the input is not parseable as TOML; missing required fields and other
// schema violations are NOT caught here — use Validate for those.
func Parse(podTOML []byte) (Spec, error) {
	var spec Spec
	if _, err := toml.Decode(string(podTOML), &spec); err != nil {
		return Spec{}, fmt.Errorf("toml parse: %w", err)
	}
	return spec, nil
}

// ParseFile reads a pod.toml file and parses it. The path argument is
// included in any I/O error returned for context.
func ParseFile(path string) (Spec, error) {
	bytes, err := os.ReadFile(path)
	if err != nil {
		return Spec{}, fmt.Errorf("read %s: %w", path, err)
	}
	return Parse(bytes)
}

// ParseAndValidate decodes podTOML into a Spec AND validates the original
// bytes against the embedded v0.1 schema. Returns the parsed Spec, any
// schema issues (empty when valid), and a non-nil error only when the
// TOML is malformed or the embedded schema fails to compile.
//
// The parsed Spec is returned even when issues is non-empty — the caller
// can choose to surface a partial typed view alongside the issue list.
//
// Typical usage in spawn-flow callers:
//
//	spec, issues, err := pod.ParseAndValidate(podTOML)
//	if err != nil {
//	    // malformed TOML or programmer error in the embedded schema
//	}
//	if len(issues) > 0 {
//	    // render issues to user; refuse to spawn
//	}
//	// spec is well-formed AND validated; proceed.
func ParseAndValidate(podTOML []byte) (Spec, []Issue, error) {
	spec, err := Parse(podTOML)
	if err != nil {
		return Spec{}, nil, err
	}
	issues, err := Validate(podTOML)
	if err != nil {
		return spec, nil, err
	}
	return spec, issues, nil
}
