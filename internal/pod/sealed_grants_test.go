// Copyright 2026 Jerry David Chan, Konareef.ai
// SPDX-License-Identifier: Apache-2.0

// sealed_grants_test.go — unit tests for the sealed-grants helpers that
// the shared fixtures do not cover: file creation, salt rotation, the
// head-marker edit, and the rules' edge cases.
package pod

import (
	"bytes"
	"strings"
	"testing"
)

// TestNewSealedGrantsFile_IsValidAndSalted checks that a fresh file passes
// every rule on a closed marker head, and that two files get different
// salts.
func TestNewSealedGrantsFile_IsValidAndSalted(t *testing.T) {
	head := readSealedFixture(t, "heads/closed-sealed.toml")
	first, err := NewSealedGrantsFile()
	if err != nil {
		t.Fatal(err)
	}
	second, err := NewSealedGrantsFile()
	if err != nil {
		t.Fatal(err)
	}
	if issues := runSealedFixtureCase(t, head, first, true, false); len(issues) != 0 {
		t.Fatalf("fresh file refused: %v", issues)
	}
	parsedFirst, err := ParseSealedGrantsFile(first)
	if err != nil {
		t.Fatal(err)
	}
	parsedSecond, _ := ParseSealedGrantsFile(second)
	if parsedFirst.Salt == parsedSecond.Salt || !sealedSaltPattern.MatchString(parsedFirst.Salt) {
		t.Fatalf("salts not fresh 64-hex values: %q %q", parsedFirst.Salt, parsedSecond.Salt)
	}
	if len(parsedFirst.Grants) != 0 || parsedFirst.Format != SealedGrantsFormatV1 {
		t.Fatalf("unexpected content: %+v", parsedFirst)
	}
}

// TestRotateSealedGrantsSalt_ChangesOnlyTheSalt checks D14: the rotated
// file differs from the input only on the salt line and still validates.
func TestRotateSealedGrantsSalt_ChangesOnlyTheSalt(t *testing.T) {
	original := readSealedFixture(t, "grants/valid-one.toml")
	rotated, err := RotateSealedGrantsSalt(original)
	if err != nil {
		t.Fatal(err)
	}
	originalLines := strings.Split(string(original), "\n")
	rotatedLines := strings.Split(string(rotated), "\n")
	if len(originalLines) != len(rotatedLines) {
		t.Fatalf("line count changed")
	}
	changed := 0
	for index := range originalLines {
		if originalLines[index] != rotatedLines[index] {
			changed++
			if !strings.HasPrefix(rotatedLines[index], "salt = ") {
				t.Fatalf("line %d changed and is not the salt", index)
			}
		}
	}
	if changed != 1 {
		t.Fatalf("%d lines changed, want 1", changed)
	}
	head := readSealedFixture(t, "heads/closed-sealed.toml")
	if issues := runSealedFixtureCase(t, head, rotated, true, false); len(issues) != 0 {
		t.Fatalf("rotated file refused: %v", issues)
	}
}

// TestRotateSealedGrantsSalt_RefusesAmbiguousFiles checks that a file
// without exactly one valid top-level salt line is not rewritten.
func TestRotateSealedGrantsSalt_RefusesAmbiguousFiles(t *testing.T) {
	for name, content := range map[string][]byte{
		"missing":   readSealedFixture(t, "grants/salt-missing.toml"),
		"short":     readSealedFixture(t, "grants/salt-short.toml"),
		"uppercase": readSealedFixture(t, "grants/salt-uppercase.toml"),
		"two lines": []byte("format = \"konareef-sealed-grants/v1\"\nsalt = \"" + strings.Repeat("a", 64) + "\"\nsalt = \"" + strings.Repeat("b", 64) + "\"\n"),
		"in grant":  []byte("format = \"konareef-sealed-grants/v1\"\n[[grant]]\nsalt = \"" + strings.Repeat("a", 64) + "\"\n"),
	} {
		if _, err := RotateSealedGrantsSalt(content); err == nil {
			t.Errorf("%s: rotated, want refusal", name)
		} else if strings.Contains(err.Error(), "cnry") {
			t.Errorf("%s: error quotes file content: %v", name, err)
		}
	}
}

// TestAddSealedGrantsMarker covers the three head layouts: an existing
// [network] table, none at all, and a layout the edit refuses.
func TestAddSealedGrantsMarker(t *testing.T) {
	withNetwork := readSealedFixture(t, "heads/closed-no-marker.toml")
	edited, err := AddSealedGrantsMarker(withNetwork)
	if err != nil {
		t.Fatal(err)
	}
	spec, err := Parse(edited)
	if err != nil || spec.Network.SealedGrants != SealedGrantsFormatV1 {
		t.Fatalf("marker not added: %v %+v", err, spec.Network)
	}
	if len(spec.Network.Egress) != 3 || len(spec.Network.Gateway) != 1 {
		t.Fatalf("network table changed: %+v", spec.Network)
	}
	if !bytes.HasPrefix(edited, withNetwork[:bytes.Index(withNetwork, []byte("[network]"))]) {
		t.Fatalf("bytes before [network] changed")
	}

	noNetwork := []byte("pod_spec_version = \"0.1\"\n\n[pod]\nname = \"x\"\nversion = \"1.0.0\"\nvisibility = \"closed\"\n\n[runtime]\nkind = \"lobster\"\n\n[directive]\ntemplate = \"./prompts/task.md\"")
	edited, err = AddSealedGrantsMarker(noNetwork)
	if err != nil {
		t.Fatal(err)
	}
	if issues, _, err := ValidateWithWarnings(edited); err != nil || len(issues) != 0 {
		t.Fatalf("edited head invalid: %v %v\n%s", err, issues, edited)
	}

	headerLast := []byte("pod_spec_version = \"0.1\"\n[pod]\nname = \"x\"\nversion = \"1.0.0\"\n[runtime]\nkind = \"lobster\"\n[network]")
	edited, err = AddSealedGrantsMarker(headerLast)
	if err != nil {
		t.Fatal(err)
	}
	if spec, err := Parse(edited); err != nil || !HasSealedGrantsMarker(spec) {
		t.Fatalf("header-last edit failed: %v\n%s", err, edited)
	}

	// An inline [network] table cannot be extended by a later header, so
	// the verified edit must refuse rather than write a broken file.
	inline := []byte("pod_spec_version = \"0.1\"\nnetwork = { egress = [\"a.example\"] }\n[pod]\nname = \"x\"\nversion = \"1.0.0\"\n[runtime]\nkind = \"lobster\"\n")
	if _, err := AddSealedGrantsMarker(inline); err == nil {
		t.Fatalf("inline network table edited; want a refusal")
	}
	if _, err := AddSealedGrantsMarker(edited); err == nil {
		t.Fatalf("second marker added; want a refusal")
	}
}

// TestValidateSealedGrants_OpenPodFileIsOrdinary checks section 4.2: on an
// open pod without the marker, a file at the reserved path is ordinary
// public content and no rule fires.
func TestValidateSealedGrants_OpenPodFileIsOrdinary(t *testing.T) {
	head := bytes.Replace(readSealedFixture(t, "heads/closed-no-marker.toml"), []byte(`visibility = "closed"`), []byte(`visibility = "open"`), 1)
	issues := runSealedFixtureCase(t, head, []byte("not toml at all ["), true, false)
	if len(issues) != 0 {
		t.Fatalf("open pod refused: %v", issues)
	}
}

// TestValidateSealedGrants_SecretUndeclaredExempt checks C1: a sealed
// grant's secret is absent from [dependencies].secrets and that is not
// GATEWAY_SECRET_UNDECLARED, while a public entry still gets the code.
func TestValidateSealedGrants_SecretUndeclaredExempt(t *testing.T) {
	head := readSealedFixture(t, "heads/closed-sealed.toml")
	grants := readSealedFixture(t, "grants/valid-one.toml")
	for _, issue := range runSealedFixtureCase(t, head, grants, true, false) {
		t.Errorf("unexpected issue %v", issue)
	}
	publicUndeclared := bytes.Replace(head, []byte(`secrets = ["PUBLIC_DEP_TOKEN"]`), []byte(`secrets = []`), 1)
	codes := SortedIssueCodes(runSealedFixtureCase(t, publicUndeclared, grants, true, false))
	if strings.Join(codes, ",") != CodeGatewaySecretUndeclared {
		t.Fatalf("codes %v, want only %s for the public entry", codes, CodeGatewaySecretUndeclared)
	}
}

// TestValidateSealedGrants_ToolCap checks the total-tool half of G16.
func TestValidateSealedGrants_ToolCap(t *testing.T) {
	head := readSealedFixture(t, "heads/closed-sealed.toml")
	var tools []string
	for index := 0; index < SealedGrantsMaxTools+1; index++ {
		tools = append(tools, `"t`+strings.Repeat("x", index%5)+string(rune('a'+index%26))+`_`+itoa(index)+`"`)
	}
	grants := []byte("format = \"konareef-sealed-grants/v1\"\nsalt = \"" + strings.Repeat("0", 64) + "\"\n\n[[grant]]\nhost = \"mcp.example.test\"\nsecret = \"SEALED_T\"\nauth = \"bearer\"\nmax_calls = 1\nprotocol = \"mcp\"\nmcp_name = \"many\"\nmcp_tools = [" + strings.Join(tools, ", ") + "]\n")
	codes := SortedIssueCodes(runSealedFixtureCase(t, head, grants, true, false))
	if strings.Join(codes, ",") != CodeSealedGrantsOverCap {
		t.Fatalf("codes %v, want %s", codes, CodeSealedGrantsOverCap)
	}
}

// TestValidateSealedGrants_WildcardAndTypeErrorsAreValueFree checks two
// paths the fixtures miss: a wildcard sealed host, and a wrong-typed
// field, both reported without the value.
func TestValidateSealedGrants_WildcardAndTypeErrorsAreValueFree(t *testing.T) {
	head := readSealedFixture(t, "heads/closed-sealed.toml")
	wildcard := bytes.Replace(readSealedFixture(t, "grants/valid-one.toml"), []byte(`host = "mcp.cnry-c00k7q.example"`), []byte(`host = "*.cnry-c00k7q.example"`), 1)
	issues := runSealedFixtureCase(t, head, wildcard, true, false)
	if codes := SortedIssueCodes(issues); strings.Join(codes, ",") != CodeGatewayHostWildcard {
		t.Fatalf("codes %v, want %s", codes, CodeGatewayHostWildcard)
	}
	wrongType := bytes.Replace(readSealedFixture(t, "grants/valid-one.toml"), []byte(`max_calls = 50`), []byte(`max_calls = "cnry-c00k7q"`), 1)
	issues = append(issues, runSealedFixtureCase(t, head, wrongType, true, false)...)
	for _, issue := range issues {
		if strings.Contains(strings.ToLower(issue.String()), "cnry") {
			t.Errorf("issue quotes a sealed value: %s", issue)
		}
	}
}

// itoa is strconv.Itoa without the import, for the tool-name builder.
func itoa(value int) string {
	if value == 0 {
		return "0"
	}
	var digits []byte
	for value > 0 {
		digits = append([]byte{byte('0' + value%10)}, digits...)
		value /= 10
	}
	return string(digits)
}

// g17Paths returns the paths of the SEALED_GRANTS_FILE_REFERENCED issues
// ValidateSealedGrants reports for head, with no grants file.
func g17Paths(t *testing.T, head string) []string {
	t.Helper()
	issues, err := ValidateSealedGrants(SealedGrantsInput{Head: []byte(head)})
	if err != nil {
		t.Fatalf("validate: %v", err)
	}
	var paths []string
	for _, issue := range issues {
		if issue.Code == CodeSealedGrantsFileReferenced {
			paths = append(paths, issue.Path)
		}
	}
	return paths
}

// g17Head is a closed head without the marker whose extra TOML is body.
func g17Head(visibility, directiveTemplate, body string) string {
	return "pod_spec_version = \"0.1\"\n[pod]\nname = \"g17\"\nversion = \"1.0.0\"\nvisibility = \"" + visibility +
		"\"\n[runtime]\nkind = \"lobster\"\nexecution_class = \"cloud\"\n[directive]\ntemplate = \"" + directiveTemplate +
		"\"\n" + body
}

// TestSealedGrantsFileReferenced_EveryField checks G17 (reef-core#63): each
// field that names sealed/grants.toml is reported.
func TestSealedGrantsFileReferenced_EveryField(t *testing.T) {
	body := `[[context.memory]]
kind = "openbrain"
[[context.memory]]
kind = "file"
path = "./sealed/grants.toml"
[[context.skills]]
source = "./sealed/grants.toml"
[[context.tools]]
source = "bash"
[[context.tools]]
source = "./sealed/grants.toml"
[[context.prompts]]
role = "system"
path = "./sealed/grants.toml"
`
	got := strings.Join(g17Paths(t, g17Head("closed", "./sealed/grants.toml", body)), ",")
	want := "context.memory[1].path,context.skills[0].source,context.tools[1].source,context.prompts[0].path,directive.template"
	if got != want {
		t.Fatalf("G17 paths = %s, want %s", got, want)
	}
}

// TestSealedGrantsFileReferenced_OpenPodAndNearMisses checks the controls:
// an open head is not refused, and paths that do not reach the grants file
// are not refused.
func TestSealedGrantsFileReferenced_OpenPodAndNearMisses(t *testing.T) {
	prompt := "[[context.prompts]]\nrole = \"system\"\npath = \"./sealed/grants.toml\"\n"
	if paths := g17Paths(t, g17Head("open", "./prompts/task.md", prompt)); len(paths) != 0 {
		t.Fatalf("open head refused: %v", paths)
	}
	for _, path := range []string{
		"./sealed/grants.toml.bak", "./sealed/other.toml", "./sealed-grants.toml",
		"./sealedx", "./sealed", "./grants.toml", "./prompts/task.md", "./sealed/../sealed/grants.toml",
	} {
		body := "[[context.prompts]]\nrole = \"system\"\npath = \"" + path + "\"\n"
		if paths := g17Paths(t, g17Head("closed", "./prompts/task.md", body)); len(paths) != 0 {
			t.Errorf("%s: refused as %v", path, paths)
		}
	}
	body := "[[context.skills]]\nsource = \"sealed/grants.toml\"\n"
	if got := g17Paths(t, g17Head("closed", "./prompts/task.md", body)); len(got) != 1 || got[0] != "context.skills[0].source" {
		t.Fatalf("reference without ./ prefix: got %v", got)
	}
}

// TestSealedGrantsFileReferenced_FoldsASCIICaseOnly checks that G17 folds
// ASCII letter case, as reef-core does, and does not apply full Unicode
// case folding.
func TestSealedGrantsFileReferenced_FoldsASCIICaseOnly(t *testing.T) {
	for _, path := range []string{"./Sealed/Grants.toml", "./SEALED/GRANTS.TOML", "sealed/Grants.toml"} {
		body := "[[context.prompts]]\nrole = \"system\"\npath = \"" + path + "\"\n"
		if got := g17Paths(t, g17Head("closed", "./prompts/task.md", body)); len(got) != 1 {
			t.Errorf("%s: want one G17 issue, got %v", path, got)
		}
	}
	for _, path := range []string{"./\u017fealed/grants.toml", "./sealed/grant\u017f.toml"} {
		body := "[[context.prompts]]\nrole = \"system\"\npath = \"" + path + "\"\n"
		if got := g17Paths(t, g17Head("closed", "./prompts/task.md", body)); len(got) != 0 {
			t.Errorf("%q: refused as %v", path, got)
		}
	}
}
