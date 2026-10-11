// Copyright 2026 Jerry David Chan, Konareef.ai
// SPDX-License-Identifier: Apache-2.0

// credentials_test.go — tests for the pod-bundle credential scan.
//
// The shared vector file (testdata/credential-patterns/vectors.json) is the
// contract with the reef-core scanner, so the vector test is the one that
// must never be weakened. The bundle tests hold the other half of the
// acceptance: every file in the bundle is read, the finding text never
// carries the value, and an allow entry lets exactly one finding through.
package pod

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// credentialVectorFile mirrors testdata/credential-patterns/vectors.json.
type credentialVectorFile struct {
	Format         string             `json:"format"`
	ScannerVersion string             `json:"scanner_version"`
	Classes        []string           `json:"classes"`
	Vectors        []credentialVector `json:"vectors"`
}

// credentialVector is one case: the text is the concatenation of Parts, and
// Findings is the exact set of (line, class) pairs the scanner must return.
type credentialVector struct {
	ID       string   `json:"id"`
	Class    string   `json:"class"`
	Parts    []string `json:"parts"`
	Note     string   `json:"note"`
	Rule     string   `json:"rule"`
	Findings []struct {
		Line   int      `json:"line"`
		Class  string   `json:"class"`
		SHA256 []string `json:"sha256"`
	} `json:"findings"`
}

func loadCredentialVectors(t *testing.T) credentialVectorFile {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", "credential-patterns", "vectors.json"))
	if err != nil {
		t.Fatalf("read vectors: %v", err)
	}
	var file credentialVectorFile
	if err := json.Unmarshal(raw, &file); err != nil {
		t.Fatalf("parse vectors: %v", err)
	}
	return file
}

// TestCredentialVectors runs the scanner over every shared vector and
// compares the findings as an exact set.
func TestCredentialVectors(t *testing.T) {
	file := loadCredentialVectors(t)
	if file.Format != "konareef-credential-vectors/v2" {
		t.Fatalf("format = %q", file.Format)
	}
	for _, vector := range file.Vectors {
		t.Run(vector.ID, func(t *testing.T) {
			var want []string
			for _, finding := range vector.Findings {
				if len(finding.SHA256) == 0 {
					t.Errorf("finding %s@%d lists no sha256 digest", finding.Class, finding.Line)
				}
				want = append(want, formatVectorFinding(finding.Line, finding.Class)+"="+strings.Join(finding.SHA256, "+"))
			}
			var got []string
			for _, finding := range ScanCredentialText(strings.Join(vector.Parts, "")) {
				got = append(got, formatVectorFinding(finding.Line, finding.Class)+"="+strings.Join(finding.Matches, "+"))
			}
			sort.Strings(want)
			sort.Strings(got)
			if strings.Join(got, ",") != strings.Join(want, ",") {
				t.Fatalf("findings = %v, want %v", got, want)
			}
		})
	}
}

func formatVectorFinding(line int, class string) string {
	return class + "@" + strconv.Itoa(line)
}

// TestCredentialVectorsCoverEveryClassBothWays keeps the vector file honest:
// each class the scanner knows needs a positive and a near-miss vector, and
// the file must not name a class the scanner does not have.
func TestCredentialVectorsCoverEveryClassBothWays(t *testing.T) {
	file := loadCredentialVectors(t)
	known := CredentialClassNames()
	if strings.Join(file.Classes, ",") != strings.Join(known, ",") {
		t.Fatalf("vector file classes = %v, scanner classes = %v", file.Classes, known)
	}
	positive := map[string]bool{}
	nearMiss := map[string]bool{}
	for _, vector := range file.Vectors {
		if vector.Class == "" {
			continue
		}
		if len(vector.Findings) > 0 {
			positive[vector.Class] = true
		} else {
			nearMiss[vector.Class] = true
		}
	}
	for _, class := range known {
		if !positive[class] || !nearMiss[class] {
			t.Errorf("class %s: positive=%v near-miss=%v", class, positive[class], nearMiss[class])
		}
	}
}

// ruleOneFindingPerLineAndClass names the vector rule that a line with
// several matches of one class yields one finding.
const ruleOneFindingPerLineAndClass = "one-finding-per-line-and-class"

// TestCredentialVectorRulesAreExercised fails when a vector that claims to
// test a rule has an expectation that holds even without the rule. A
// vector for ruleOneFindingPerLineAndClass must have a line on which its
// class matches two or more times; otherwise a scanner that reports one
// finding per match passes it too (review M5 on konareef!149).
func TestCredentialVectorRulesAreExercised(t *testing.T) {
	file := loadCredentialVectors(t)
	exercised := 0
	for _, vector := range file.Vectors {
		switch vector.Rule {
		case "":
			continue
		case ruleOneFindingPerLineAndClass:
		default:
			t.Errorf("vector %s: unknown rule %q", vector.ID, vector.Rule)
			continue
		}
		lines := strings.Split(strings.Join(vector.Parts, ""), "\n")
		repeated := false
		for _, finding := range vector.Findings {
			if finding.Line < 1 || finding.Line > len(lines) {
				t.Errorf("vector %s: finding line %d is outside the text", vector.ID, finding.Line)
				continue
			}
			if credentialMatchCount(lines[finding.Line-1], finding.Class) >= 2 {
				repeated = true
			}
		}
		if !repeated {
			t.Errorf("vector %s claims rule %s, but no expected finding has two or more matches on its line, so the vector does not test the rule",
				vector.ID, vector.Rule)
		}
		exercised++
	}
	if exercised == 0 {
		t.Fatalf("no vector exercises rule %s", ruleOneFindingPerLineAndClass)
	}
}

// credentialNearMissPrefixes holds, for each class, the literal prefixes a
// near-miss vector must contain. A near miss without its class's prefix is
// clean for every scanner, so it tests nothing about the pattern edge.
var credentialNearMissPrefixes = map[string][]string{
	"anthropic_api_key": {"sk-ant-"},
	"openai_api_key":    {"sk-"},
	"aws_access_key_id": {"AKIA", "ASIA"},
	"github_token":      {"gh", "github_pat_"},
	"gitlab_token":      {"glpat-"},
	"slack_token":       {"xox"},
	"private_key_block": {"BEGIN", "PRIVATE KEY"},
	"jwt":               {"eyJ"},
}

// TestCredentialNearMissVectorsAreNearTheEdge fails when a near-miss
// vector does not hold its class's prefix, which makes its empty
// expectation vacuous.
func TestCredentialNearMissVectorsAreNearTheEdge(t *testing.T) {
	file := loadCredentialVectors(t)
	for _, vector := range file.Vectors {
		if vector.Class == "" || len(vector.Findings) > 0 {
			continue
		}
		prefixes, ok := credentialNearMissPrefixes[vector.Class]
		if !ok {
			t.Errorf("vector %s: no near-miss prefixes for class %s", vector.ID, vector.Class)
			continue
		}
		text := strings.Join(vector.Parts, "")
		near := false
		for _, prefix := range prefixes {
			if strings.Contains(text, prefix) {
				near = true
			}
		}
		if !near {
			t.Errorf("vector %s: near miss holds none of %v, so it does not test the %s pattern", vector.ID, prefixes, vector.Class)
		}
	}
}

// credentialMatchCount returns how many non-overlapping matches of the
// named class the scanner sees on one line.
func credentialMatchCount(line, className string) int {
	for _, class := range credentialClasses {
		if class.name == className {
			return len(class.pattern.FindAllString(scanLine(line), -1))
		}
	}
	return 0
}

// fakeAWSKey builds a credential-shaped string at run time, so this source
// file holds no whole key for a secret scanner to find.
func fakeAWSKey() string { return "AKIA" + "FAKEFAKEFAKEFAKE" }

// The scan reads every file in the bundle, not only the context files a
// prompt names: a key in a README is still published.
func TestScanBundleCredentialsReadsEveryFile(t *testing.T) {
	dir := writePod(t, map[string]string{
		"pod.toml":             "[pod]\nname = \"x\"\n",
		"README.md":            "See the notes.\n" + fakeAWSKey() + "\n",
		"scripts/run.sh":       "export T=" + "glpat-" + "FAKEFAKEFAKEFAKE-_12\n",
		"prompts/system.md":    "Nothing here.\n",
		".hidden/secret.txt":   fakeAWSKey(),
		"nested/deep/file.txt": "line one\nline two\n" + "xoxb-" + "1234567890-FAKEFAKEFAKE\n",
	})

	scan, err := ScanBundleCredentials(dir)
	if err != nil {
		t.Fatalf("ScanBundleCredentials: %v", err)
	}
	var got []string
	for _, finding := range scan.Refused {
		got = append(got, finding.File+":"+finding.Class)
	}
	want := []string{
		"README.md:aws_access_key_id",
		"nested/deep/file.txt:slack_token",
		"scripts/run.sh:gitlab_token",
	}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("refused = %v, want %v (hidden paths are not in the bundle)", got, want)
	}
	if scan.Refused[0].Line != 2 {
		t.Errorf("README.md line = %d, want 2", scan.Refused[0].Line)
	}
}

// pod.toml is published too, so a key in it is a finding.
func TestScanBundleCredentialsReadsPodToml(t *testing.T) {
	dir := writePod(t, map[string]string{
		"pod.toml": "[pod]\nname = \"x\"\nnote = \"" + fakeAWSKey() + "\"\n",
	})
	scan, err := ScanBundleCredentials(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(scan.Refused) != 1 || scan.Refused[0].File != "pod.toml" || scan.Refused[0].Line != 3 {
		t.Fatalf("refused = %+v", scan.Refused)
	}
}

// The finding text is a file, a line and a class. It never carries the
// value, and neither does the rendered refusal.
func TestCredentialFindingTextDoesNotContainTheSecret(t *testing.T) {
	secret := fakeAWSKey()
	dir := writePod(t, map[string]string{
		"pod.toml":  "[pod]\nname = \"x\"\n",
		"notes.txt": "key " + secret + " end\n",
	})
	scan, err := ScanBundleCredentials(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(scan.Refused) != 1 {
		t.Fatalf("refused = %+v", scan.Refused)
	}
	rendered := scan.Refused[0].String() + "\n" + scan.RefusalMessage("publish")
	if strings.Contains(rendered, secret) || strings.Contains(rendered, secret[4:]) {
		t.Fatalf("the finding text contains the secret value:\n%s", rendered)
	}
	for _, want := range []string{CodeBundleCredentialFound, "notes.txt:1", "aws_access_key_id", "konareef pod secret set",
		`sha256 = "` + testMatchDigest(secret) + `"`} {
		if !strings.Contains(rendered, want) {
			t.Errorf("refusal is missing %q:\n%s", want, rendered)
		}
	}
}

// testMatchDigest is the allow-file digest of a matched string, computed
// here on its own so the test does not trust the scanner's helper: the
// first 16 lowercase hex characters of SHA-256 over the bytes.
func testMatchDigest(match string) string {
	sum := sha256.Sum256([]byte(match))
	return hex.EncodeToString(sum[:])[:16]
}

var fixtureAllowEntry = `[[allow]]
file = "notes.txt"
class = "aws_access_key_id"
line = 1
sha256 = "` + testMatchDigest(fakeAWSKey()) + `"
reason = "documented example key used by a test"
`

// fakeJWT builds a JWT-shaped string with a chosen signature, at run time.
func fakeJWT(signature string) string {
	return "eyJ" + "hbGciOiJIUzI1NiJ9" + "." + "eyJ" + "zdWIiOiJmYWtlMSJ9" + "." + signature
}

// One allow entry covers one matched string, not every match of its class
// on the line. A minified fixture with two JWTs on one line, one allowed,
// still refuses the other (review M1 on konareef!149).
func TestAllowEntryCoversOneMatchedStringNotTheLine(t *testing.T) {
	fixture := fakeJWT("FAKEFAKEFAKEsig1")
	real := fakeJWT("FAKEFAKEFAKEsig2")
	dir := writePod(t, map[string]string{
		"pod.toml": "[pod]\nname = \"x\"\n",
		"fx.json":  `{"a":"` + fixture + `","b":"` + real + `"}`,
		CredentialAllowFile: "[[allow]]\nfile = \"fx.json\"\nclass = \"jwt\"\nline = 1\nsha256 = \"" +
			testMatchDigest(fixture) + "\"\nreason = \"the fixture token\"\n",
	})
	scan, err := ScanBundleCredentials(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(scan.Allowed) != 1 || scan.Allowed[0].SHA256 != testMatchDigest(fixture) {
		t.Fatalf("allowed = %+v, want the fixture only", scan.Allowed)
	}
	if len(scan.Refused) != 1 || scan.Refused[0].SHA256 != testMatchDigest(real) {
		t.Fatalf("refused = %+v, want the second token", scan.Refused)
	}
	if message := scan.RefusalMessage("publish"); !strings.Contains(message, `fx.json:1: jwt (sha256 = "`+testMatchDigest(real)+`")`) {
		t.Errorf("refusal does not name the digest to allow:\n%s", message)
	}
}

// An allow entry lets one finding through and the finding is still
// reported, as allowed, with its reason.
func TestAllowEntryLetsExactlyOneFindingThrough(t *testing.T) {
	dir := writePod(t, map[string]string{
		"pod.toml":          "[pod]\nname = \"x\"\n",
		"notes.txt":         fakeAWSKey() + "\n",
		CredentialAllowFile: fixtureAllowEntry,
		"other.txt":         "x\n" + fakeAWSKey() + "\n",
	})
	scan, err := ScanBundleCredentials(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(scan.Allowed) != 1 || scan.Allowed[0].File != "notes.txt" ||
		scan.Allowed[0].Reason != "documented example key used by a test" {
		t.Fatalf("allowed = %+v", scan.Allowed)
	}
	if len(scan.Refused) != 1 || scan.Refused[0].File != "other.txt" {
		t.Fatalf("refused = %+v, want only other.txt", scan.Refused)
	}
}

func TestAllowEntryDoesNotCoverAnotherLineOrClass(t *testing.T) {
	for name, entry := range map[string]string{
		"wrong line":   strings.Replace(fixtureAllowEntry, "line = 1", "line = 2", 1),
		"wrong class":  strings.Replace(fixtureAllowEntry, "aws_access_key_id", "slack_token", 1),
		"wrong file":   strings.Replace(fixtureAllowEntry, "notes.txt", "elsewhere.txt", 1),
		"wrong sha256": strings.Replace(fixtureAllowEntry, testMatchDigest(fakeAWSKey()), "0123456789abcdef", 1),
	} {
		t.Run(name, func(t *testing.T) {
			dir := writePod(t, map[string]string{
				"pod.toml":          "[pod]\nname = \"x\"\n",
				"notes.txt":         fakeAWSKey() + "\n",
				CredentialAllowFile: entry,
			})
			scan, err := ScanBundleCredentials(dir)
			if err != nil {
				t.Fatal(err)
			}
			if len(scan.Refused) != 1 || len(scan.Allowed) != 0 {
				t.Fatalf("refused=%+v allowed=%+v", scan.Refused, scan.Allowed)
			}
		})
	}
}

// A malformed allow file is an error, never a silent widening.
func TestMalformedAllowFileIsAnError(t *testing.T) {
	cases := map[string]string{
		"not toml":      "[[allow\n",
		"unknown key":   fixtureAllowEntry + "extra = 1\n",
		"unknown class": strings.Replace(fixtureAllowEntry, "aws_access_key_id", "made_up", 1),
		"no reason":     strings.Replace(fixtureAllowEntry, `reason = "documented example key used by a test"`, `reason = ""`, 1),
		"zero line":     strings.Replace(fixtureAllowEntry, "line = 1", "line = 0", 1),
		"no sha256":     strings.Replace(fixtureAllowEntry, `sha256 = "`+testMatchDigest(fakeAWSKey())+`"`+"\n", "", 1),
		"upper sha256":  strings.Replace(fixtureAllowEntry, testMatchDigest(fakeAWSKey()), strings.ToUpper(testMatchDigest(fakeAWSKey())), 1),
		"short sha256":  strings.Replace(fixtureAllowEntry, testMatchDigest(fakeAWSKey()), testMatchDigest(fakeAWSKey())[:15], 1),
		"traversal":     strings.Replace(fixtureAllowEntry, `"notes.txt"`, `"../notes.txt"`, 1),
		"no file":       strings.Replace(fixtureAllowEntry, "file = \"notes.txt\"\n", "", 1),
		"unknown table": fixtureAllowEntry + "[other]\nx = 1\n",
	}
	for name, content := range cases {
		t.Run(name, func(t *testing.T) {
			dir := writePod(t, map[string]string{
				"pod.toml":          "[pod]\nname = \"x\"\n",
				CredentialAllowFile: content,
			})
			if _, err := ScanBundleCredentials(dir); err == nil {
				t.Fatal("want an error")
			}
		})
	}
}

// An entry may spell the file with a leading "./", as pod.toml does.
func TestAllowEntryAcceptsDotSlashPath(t *testing.T) {
	dir := writePod(t, map[string]string{
		"pod.toml":          "[pod]\nname = \"x\"\n",
		"notes.txt":         fakeAWSKey() + "\n",
		CredentialAllowFile: strings.Replace(fixtureAllowEntry, `"notes.txt"`, `"./notes.txt"`, 1),
	})
	scan, err := ScanBundleCredentials(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(scan.Refused) != 0 || len(scan.Allowed) != 1 {
		t.Fatalf("refused=%+v allowed=%+v", scan.Refused, scan.Allowed)
	}
}

// The example pods and the demo pod in this repository must stay
// publishable: a scan that flags them is a scan authors learn to skip.
func TestRepositoryExamplePodsHaveNoCredentialFindings(t *testing.T) {
	var checked int
	for _, root := range []string{"../../examples", "../../demo"} {
		_ = filepath.WalkDir(root, func(path string, entry os.DirEntry, err error) error {
			if err != nil || entry.IsDir() || entry.Name() != "pod.toml" {
				return nil
			}
			podDir := filepath.Dir(path)
			scan, scanErr := ScanBundleCredentials(podDir)
			if scanErr != nil {
				t.Errorf("%s: %v", podDir, scanErr)
				return nil
			}
			checked++
			if len(scan.Refused) != 0 {
				t.Errorf("%s: %+v", podDir, scan.Refused)
			}
			return nil
		})
	}
	if checked == 0 {
		t.Fatal("found no example pod to scan")
	}
}
