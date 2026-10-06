// Copyright 2026 Jerry David Chan, Konareef.ai
// SPDX-License-Identifier: Apache-2.0

// sealed_grants_fixtures_test.go — runs the shared MCP-C00 sealed-grants
// fixtures (testdata/sealed_grants/v1, vendored byte for byte from
// reef-core test/support/fixtures/sealed_grants/v1) against the konareef
// rules. reef-core's MCP-C02 runs the same publish cases; both sides must
// return the case's publisher_code for every refused case and nothing for
// every accepted one.
package pod

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// sealedFixtureDir is the vendored fixture directory.
const sealedFixtureDir = "testdata/sealed_grants/v1"

// sealedFixtureCases is the slice of cases.json these tests read.
type sealedFixtureCases struct {
	Carrier struct {
		HeadMarkerKey   string `json:"head_marker_key"`
		HeadMarkerValue string `json:"head_marker_value"`
		BodyPath        string `json:"body_path"`
		GrantsFormat    string `json:"grants_format"`
	} `json:"carrier"`
	Canaries           []string `json:"canaries"`
	PublisherCodes     []string `json:"publisher_codes"`
	BrokerRuntimeKinds []string `json:"broker_runtime_kinds"`
	Cases              []struct {
		ID             string  `json:"id"`
		Stage          string  `json:"stage"`
		Description    string  `json:"description"`
		Head           string  `json:"head"`
		Grants         *string `json:"grants"`
		Expect         string  `json:"expect"`
		PublisherCode  string  `json:"publisher_code"`
		PublishRequest struct {
			ZkEnabled bool `json:"zk_enabled"`
		} `json:"publish_request"`
	} `json:"cases"`
}

// loadSealedFixtureCases reads and decodes cases.json.
func loadSealedFixtureCases(t *testing.T) sealedFixtureCases {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(sealedFixtureDir, "cases.json"))
	if err != nil {
		t.Fatalf("read cases.json: %v", err)
	}
	var cases sealedFixtureCases
	if err := json.Unmarshal(raw, &cases); err != nil {
		t.Fatalf("decode cases.json: %v", err)
	}
	return cases
}

// readSealedFixture reads one fixture file by its cases.json-relative path.
func readSealedFixture(t *testing.T, rel string) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(sealedFixtureDir, filepath.FromSlash(rel)))
	if err != nil {
		t.Fatalf("read fixture %s: %v", rel, err)
	}
	return data
}

// TestSealedGrantsFixtures_ManifestMatches checks that the vendored copy
// is byte-identical to what reef-core's MANIFEST.sha256 lists, and that no
// file is missing from or added to the manifest.
func TestSealedGrantsFixtures_ManifestMatches(t *testing.T) {
	manifest, err := os.Open(filepath.Join(sealedFixtureDir, "MANIFEST.sha256"))
	if err != nil {
		t.Fatalf("open MANIFEST.sha256: %v", err)
	}
	defer manifest.Close()
	listed := map[string]bool{}
	scanner := bufio.NewScanner(manifest)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) != 2 {
			t.Fatalf("bad manifest line %q", scanner.Text())
		}
		data := readSealedFixture(t, fields[1])
		sum := sha256.Sum256(data)
		if hex.EncodeToString(sum[:]) != fields[0] {
			t.Errorf("%s: sha256 differs from MANIFEST.sha256; re-vendor from reef-core", fields[1])
		}
		listed[fields[1]] = true
	}
	var onDisk []string
	err = filepath.WalkDir(sealedFixtureDir, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil || entry.IsDir() {
			return walkErr
		}
		rel, _ := filepath.Rel(sealedFixtureDir, path)
		rel = filepath.ToSlash(rel)
		if rel != "MANIFEST.sha256" {
			onDisk = append(onDisk, rel)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk fixtures: %v", err)
	}
	sort.Strings(onDisk)
	for _, rel := range onDisk {
		if !listed[rel] {
			t.Errorf("%s is not in MANIFEST.sha256", rel)
		}
	}
	if len(onDisk) != len(listed) {
		t.Errorf("%d files on disk, %d in MANIFEST.sha256", len(onDisk), len(listed))
	}
}

// TestSealedGrantsFixtures_ConstantsMatch pins the Go constants to the
// carrier block and broker runtime set in cases.json.
func TestSealedGrantsFixtures_ConstantsMatch(t *testing.T) {
	cases := loadSealedFixtureCases(t)
	if cases.Carrier.HeadMarkerKey != "network.sealed_grants" ||
		cases.Carrier.HeadMarkerValue != SealedGrantsFormatV1 ||
		cases.Carrier.GrantsFormat != SealedGrantsFormatV1 ||
		cases.Carrier.BodyPath != SealedGrantsBodyPath {
		t.Fatalf("carrier constants differ from cases.json: %+v", cases.Carrier)
	}
	var kinds []string
	for kind := range mcpBrokerRuntimeKinds {
		kinds = append(kinds, kind)
	}
	sort.Strings(kinds)
	want := append([]string(nil), cases.BrokerRuntimeKinds...)
	sort.Strings(want)
	if strings.Join(kinds, ",") != strings.Join(want, ",") {
		t.Fatalf("broker runtime kinds %v, cases.json has %v", kinds, want)
	}
}

// TestSealedGrantsFixtures_HeadsCarryNoCanary is the head half of the
// canary rule: a canary in a head fixture is a fixture bug.
func TestSealedGrantsFixtures_HeadsCarryNoCanary(t *testing.T) {
	cases := loadSealedFixtureCases(t)
	entries, err := os.ReadDir(filepath.Join(sealedFixtureDir, "heads"))
	if err != nil {
		t.Fatalf("read heads: %v", err)
	}
	for _, entry := range entries {
		data := readSealedFixture(t, "heads/"+entry.Name())
		for _, canary := range cases.Canaries {
			if bytes.Contains(bytes.ToLower(data), []byte(strings.ToLower(canary))) {
				t.Errorf("head %s contains canary %q", entry.Name(), canary)
			}
		}
	}
}

// runSealedFixtureCase validates one publish case the way `pod publish`
// does: the head rules, then G1–G17.
func runSealedFixtureCase(t *testing.T, head []byte, grants []byte, present, zk bool) []Issue {
	t.Helper()
	headIssues, _, err := ValidateWithWarnings(head)
	if err != nil {
		t.Fatalf("validate head: %v", err)
	}
	sealedIssues, err := ValidateSealedGrants(SealedGrantsInput{Head: head, Grants: grants, GrantsPresent: present, ZK: zk})
	if err != nil {
		t.Fatalf("validate sealed grants: %v", err)
	}
	return append(headIssues, sealedIssues...)
}

// quotedValuePattern extracts every double-quoted TOML string value.
var quotedValuePattern = regexp.MustCompile(`"((?:[^"\\]|\\.)*)"`)

// sealedValueAllowlist are grants-file values that are public vocabulary,
// not sealed content, and may appear in a message.
var sealedValueAllowlist = map[string]bool{
	"konareef-sealed-grants/v1": true,
	"konareef-sealed-grants/v2": true,
	"mcp":                       true,
	"http":                      true,
	"bearer":                    true,
}

// TestSealedGrantsFixtures_PublishCases runs every publish case.
func TestSealedGrantsFixtures_PublishCases(t *testing.T) {
	cases := loadSealedFixtureCases(t)
	knownCodes := map[string]bool{}
	for _, code := range cases.PublisherCodes {
		knownCodes[code] = true
	}
	ran := 0
	for _, fixture := range cases.Cases {
		if fixture.Stage != "publish" {
			continue
		}
		ran++
		t.Run(fixture.ID, func(t *testing.T) {
			head := readSealedFixture(t, fixture.Head)
			var grants []byte
			if fixture.Grants != nil {
				grants = readSealedFixture(t, *fixture.Grants)
			}
			issues := runSealedFixtureCase(t, head, grants, fixture.Grants != nil, fixture.PublishRequest.ZkEnabled)
			codes := SortedIssueCodes(issues)
			switch fixture.Expect {
			case "accept":
				if len(issues) != 0 {
					t.Fatalf("%s (%s): want accept, got %v", fixture.ID, fixture.Description, issues)
				}
			case "refuse":
				found := false
				for _, code := range codes {
					if code == fixture.PublisherCode {
						found = true
					}
				}
				if !found {
					t.Fatalf("%s (%s): want %s among %v; issues %v", fixture.ID, fixture.Description, fixture.PublisherCode, codes, issues)
				}
			default:
				t.Fatalf("unknown expect %q", fixture.Expect)
			}
			for _, issue := range issues {
				if issue.Code == "" {
					t.Errorf("%s: uncoded issue %v", fixture.ID, issue)
				} else if !knownCodes[issue.Code] {
					t.Errorf("%s: code %s is not in publisher_codes", fixture.ID, issue.Code)
				}
				lowered := strings.ToLower(issue.String())
				for _, canary := range cases.Canaries {
					if strings.Contains(lowered, strings.ToLower(canary)) {
						t.Errorf("%s: issue quotes canary %q: %s", fixture.ID, canary, issue)
					}
				}
				for _, match := range quotedValuePattern.FindAllSubmatch(grants, -1) {
					value := string(match[1])
					if len(value) < 6 || sealedValueAllowlist[value] {
						continue
					}
					if strings.Contains(issue.String(), value) {
						t.Errorf("%s: issue quotes a sealed value: %s", fixture.ID, issue)
					}
				}
			}
		})
	}
	if ran != 33 {
		t.Fatalf("ran %d publish cases, cases.json promises 33", ran)
	}
}

// TestSealedGrantsFixtures_ReportsEveryViolation checks the reporting
// rule: a file that breaks several rules gets all of their codes, not
// only the first.
func TestSealedGrantsFixtures_ReportsEveryViolation(t *testing.T) {
	head := readSealedFixture(t, "heads/closed-sealed.toml")
	grants := []byte(`format = "konareef-sealed-grants/v1"
salt = "abcd"

[[grant]]
host = "mcp.public-port.example"
secret = "PUBLIC_DEP_TOKEN"
auth = "bearer"
max_calls = 5
protocol = "mcp"
mcp_name = "openbrain"
mcp_tools = ["x"]
`)
	issues := runSealedFixtureCase(t, head, grants, true, true)
	got := strings.Join(SortedIssueCodes(issues), ",")
	wantCodes := []string{
		CodeGatewayMCPHostAlsoEgress,
		CodeGatewayMCPNameReserved,
		CodeSealedGrantSecretPublic,
		CodeSealedGrantsSaltInvalid,
		CodeSealedGrantsZKUnsupported,
	}
	sort.Strings(wantCodes)
	want := strings.Join(wantCodes, ",")
	if got != want {
		t.Fatalf("codes %s, want %s; issues %v", got, want, issues)
	}
}
