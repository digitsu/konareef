// Copyright 2026 Jerry David Chan, Konareef.ai
// SPDX-License-Identifier: Apache-2.0

// Tests for the reserved harness secret names (secret_reserved) in pod
// validation: a warning for [dependencies].secrets, which only a hosted
// reef-core refuses, and an issue for a sealed grant's secret, which
// reef-core refuses in every mode.
package pod

import (
	"bytes"
	"fmt"
	"strings"
	"testing"
)

// reservedSecretsPodTOML returns a schema-valid pod whose
// [dependencies].secrets is the given TOML array literal.
func reservedSecretsPodTOML(secrets string) string {
	return `pod_spec_version = "0.1"

[pod]
name    = "voice"
version = "0.1.0"

[runtime]
kind = "lobster"

[dependencies]
secrets = ` + secrets + `

[directive]
task = "Speak."
`
}

// TestReservedDependencySecretsWarn checks that every name reef-core
// reserves, including the two OpenCode flags P3-07 sets on the harness,
// gets a secret_reserved warning at its own index, and that a plain
// secret beside them gets none. It is a warning, not an issue, because a
// self-host reef-core resolves these names from REEF_SECRET_<NAME>.
func TestReservedDependencySecretsWarn(t *testing.T) {
	body := reservedSecretsPodTOML(`["ELEVENLABS_API_KEY", "OPENCODE_DISABLE_MODELS_FETCH", "OPENCODE_DISABLE_PROJECT_CONFIG", "ANTHROPIC_BASE_URL", "ANTHROPIC_AUTH_TOKEN", "REEF_RUN_CREDENTIAL", "ANTHROPIC_API_KEY"]`)
	issues, warnings, err := ValidateWithWarnings([]byte(body))
	if err != nil || len(issues) != 0 {
		t.Fatalf("a reserved dependency secret must not fail validation: err=%v issues=%v", err, issues)
	}
	var reserved []Warning
	for _, warning := range warnings {
		if warning.Code == CodeSecretReserved {
			reserved = append(reserved, warning)
		}
	}
	if len(reserved) != 6 {
		t.Fatalf("secret_reserved warnings = %v, want 6", reserved)
	}
	for position, warning := range reserved {
		wantPath := fmt.Sprintf("dependencies.secrets[%d]", position+1)
		if warning.Code != "secret_reserved" || warning.Path != wantPath {
			t.Errorf("warning %d = %+v, want code secret_reserved at %s", position, warning, wantPath)
		}
		if !strings.Contains(warning.Message, "hosted reef-core refuses") {
			t.Errorf("warning %d message = %q", position, warning.Message)
		}
	}
}

// TestReservedDependencySecretsControl is the control: near-miss names
// get no secret_reserved warning.
func TestReservedDependencySecretsControl(t *testing.T) {
	_, warnings, err := ValidateWithWarnings([]byte(reservedSecretsPodTOML(`["ELEVENLABS_API_KEY", "ANTHROPIC_MODEL", "OPENCODE"]`)))
	if err != nil {
		t.Fatal(err)
	}
	for _, warning := range warnings {
		if warning.Code == CodeSecretReserved {
			t.Fatalf("unexpected warning %v", warning)
		}
	}
}

// TestValidateSealedGrants_ReservedSecret checks that a sealed grant whose
// secret is a reserved harness name is refused with secret_reserved, since
// reef-core refuses it at every spawn, self-host included, and that the
// issue does not quote the name. valid-one.toml is the control.
func TestValidateSealedGrants_ReservedSecret(t *testing.T) {
	head := readSealedFixture(t, "heads/closed-sealed.toml")
	valid := readSealedFixture(t, "grants/valid-one.toml")
	for _, name := range []string{"OPENCODE_DISABLE_PROJECT_CONFIG", "REEF_RUN_CREDENTIAL", "ANTHROPIC_API_KEY"} {
		grants := bytes.Replace(valid, []byte(`secret = "CNRY_C00K7Q_TOKEN"`), []byte(`secret = "`+name+`"`), 1)
		issues := runSealedFixtureCase(t, head, grants, true, false)
		if codes := SortedIssueCodes(issues); strings.Join(codes, ",") != CodeSecretReserved {
			t.Fatalf("%s: codes %v, want %s", name, codes, CodeSecretReserved)
		}
		if issues[0].Path != "sealed/grants.toml:grant[0].secret" || strings.Contains(issues[0].String(), name) {
			t.Fatalf("%s: issue %q has the wrong path or quotes the name", name, issues[0])
		}
	}
	if issues := runSealedFixtureCase(t, head, valid, true, false); len(issues) != 0 {
		t.Fatalf("control: %v", issues)
	}
}
