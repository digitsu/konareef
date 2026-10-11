// Copyright 2026 Jerry David Chan, Konareef.ai
// SPDX-License-Identifier: Apache-2.0

// v3_publish_test.go — `pod publish --zk` of a pod with a brokered MCP grant
// emits konareef-toml/v3 and commits the broker tool ids (MCP-Z03,
// konareef#15; paygate-zk MCP-Z00 §10, decision D3 option A).
package publish

import (
	"bytes"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/digitsu/konareef/internal/canon"
)

// v3PodTOML builds a valid pod.toml from validMemoryFreePodTOML.
//
// Inputs: contextTools, the [[context.tools]] sources; grantTools, a TOML
// array literal for the one brokered grant's mcp_tools ("" for no grant);
// httpGateway, whether to add an HTTP gateway entry; visibility, the
// [pod].visibility value ("" to leave it out). Output: the pod.toml body.
func v3PodTOML(contextTools []string, grantTools string, httpGateway bool, visibility string) string {
	body := validMemoryFreePodTOML
	if visibility != "" {
		body = strings.Replace(body, "version = \"1.0.0\"\n", "version = \"1.0.0\"\nvisibility = \""+visibility+"\"\n", 1)
	}
	var extra strings.Builder
	var secrets []string
	if grantTools != "" {
		secrets = append(secrets, `"JIRA_TOKEN"`)
	}
	if httpGateway {
		secrets = append(secrets, `"API_TOKEN"`)
	}
	if len(secrets) > 0 {
		extra.WriteString("[dependencies]\nsecrets = [" + strings.Join(secrets, ", ") + "]\n\n")
	}
	for _, source := range contextTools {
		extra.WriteString("[[context.tools]]\nsource = \"" + source + "\"\n\n")
	}
	if grantTools != "" {
		extra.WriteString(`[[network.gateway]]
host = "mcp.example.com"
secret = "JIRA_TOKEN"
auth = "bearer"
max_calls = 5
protocol = "mcp"
mcp_name = "jira"
mcp_tools = ` + grantTools + "\n\n")
	}
	if httpGateway {
		extra.WriteString(`[[network.gateway]]
host = "api.example.com"
secret = "API_TOKEN"
auth = "bearer"
max_calls = 5

`)
	}
	return strings.Replace(body, "[directive]", extra.String()+"[directive]", 1)
}

// committedRoot returns the fields_root the canonical bytes commit.
func committedRoot(t *testing.T, canonical []byte) [32]byte {
	t.Helper()
	root, err := canon.ParseCommitFieldsRoot(canonical)
	if err != nil {
		t.Fatalf("ParseCommitFieldsRoot: %v", err)
	}
	return root
}

// TestPrepareZKWithBrokerGrantEmitsV3 is the dt-open-union vector through
// the real publish pipeline: the manifest is v3 and its fields_root is the
// root over [[context.tools]] ∪ {jira.search, jira.get_issue}. The HTTP
// gateway adds nothing.
func TestPrepareZKWithBrokerGrantEmitsV3(t *testing.T) {
	body := v3PodTOML([]string{"read", "bash"}, `["search", "get_issue"]`, true, "")
	prep, err := Prepare(writePodFixture(t, body), testIdentity(t), PrepareOptions{ZK: true})
	if err != nil {
		t.Fatalf("Prepare: %v", err)
	}
	if !bytes.HasPrefix(prep.CanonicalBytes, []byte("#!konareef-toml/v3\n")) {
		t.Fatalf("a --zk publish with a brokered grant must emit v3; got %q", prep.CanonicalBytes[:20])
	}
	want, err := canon.FieldsRoot([]string{"openai/gpt-4o"},
		[]string{"bash", "jira.get_issue", "jira.search", "read"}, 1000, canon.EmptyMemoryRoot())
	if err != nil {
		t.Fatal(err)
	}
	got := committedRoot(t, prep.CanonicalBytes)
	if got != want {
		t.Fatalf("fields_root = %x, want %x (the dt-open-union set)", got, want)
	}
	// The same root the paygate-zk Rust oracle computed for dt-open-union
	// (internal/canon/testdata/declared_tools_v3_roots.json).
	const rustDtOpenUnion = "187e3bb8768272a4d1b6cece39cacf5d106ede8e4bd3fa114f258fdbd786462c"
	if hex.EncodeToString(got[:]) != rustDtOpenUnion {
		t.Fatalf("fields_root = %x, want the Rust oracle root %s", got, rustDtOpenUnion)
	}
}

// TestPrepareZKWithoutBrokerGrantStaysV2 is dt-http-only: a pod with no
// brokered grant keeps emitting v2, byte for byte, so v2 bytes do not
// change and a reef-core that reads only v1/v2 still accepts the pod.
func TestPrepareZKWithoutBrokerGrantStaysV2(t *testing.T) {
	body := v3PodTOML([]string{"bash"}, "", true, "")
	dir := writePodFixture(t, body)
	prep, err := Prepare(dir, testIdentity(t), PrepareOptions{ZK: true})
	if err != nil {
		t.Fatalf("Prepare: %v", err)
	}
	if !bytes.HasPrefix(prep.CanonicalBytes, []byte("#!konareef-toml/v2\n")) {
		t.Fatalf("a --zk publish with no brokered grant must stay v2; got %q", prep.CanonicalBytes[:20])
	}
	// The same bytes CanonicalizeV2 produced before v3 existed: params with
	// the context tools only.
	spec, meta := parseForTest(t, body)
	params, err := DeriveCommitParams(spec, meta)
	if err != nil {
		t.Fatal(err)
	}
	if len(params.BrokerGrants) != 0 {
		t.Fatalf("an HTTP gateway must not become a broker grant: %+v", params.BrokerGrants)
	}
	want, err := canon.CanonicalizeV2([]byte(body), dir, params)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(prep.CanonicalBytes, want) {
		t.Fatal("v2 output changed")
	}
}

// TestPrepareWithoutZKIgnoresTheGrantCommitment: a plain publish of a pod
// with a grant is still konareef-toml/v1, with no trailer.
func TestPrepareWithoutZKIgnoresTheGrantCommitment(t *testing.T) {
	body := v3PodTOML([]string{"bash"}, `["search"]`, false, "")
	prep, err := Prepare(writePodFixture(t, body), testIdentity(t), PrepareOptions{})
	if err != nil {
		t.Fatalf("Prepare: %v", err)
	}
	if !bytes.HasPrefix(prep.CanonicalBytes, []byte("#!konareef-toml/v1\n")) || bytes.Contains(prep.CanonicalBytes, []byte("[_commit]")) {
		t.Fatal("a publish without --zk must be v1 with no trailer")
	}
}

// TestPrepareZKV3Refusals: every refusal names its code and no manifest is
// produced.
//
//   - dt-collision: a context tool equal to a broker id.
//   - dt-cap-33: 29 context tools plus 4 broker tools.
//   - closed pod with a grant: refused until sealed grants are supported
//     (MCP-Z00 §10.5, D8).
func TestPrepareZKV3Refusals(t *testing.T) {
	var twentyNine []string
	for i := 0; i < 29; i++ {
		twentyNine = append(twentyNine, "t"+string(rune('a'+i/10))+string(rune('0'+i%10)))
	}
	cases := []struct {
		name string
		body string
		code string
	}{
		{"dt-collision", v3PodTOML([]string{"jira.get_issue"}, `["get_issue"]`, false, ""), canon.ErrCommitToolIDCollision},
		{"dt-cap-33", v3PodTOML(twentyNine, `["a", "b", "c", "d"]`, false, ""), canon.ErrCommitOverCap},
		{"closed pod with grant", v3PodTOML([]string{"bash"}, `["search"]`, false, "closed"), canon.ErrCommitSealedGrantZKUnsupported},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			prep, err := Prepare(writePodFixture(t, c.body), testIdentity(t), PrepareOptions{ZK: true})
			if canon.Code(err) != c.code {
				t.Fatalf("Prepare error = %v, want code %s", err, c.code)
			}
			if prep != nil {
				t.Fatal("a refused publish must return no prepared pod")
			}
		})
	}
}

// TestPrepareZKCap32Accepted is dt-cap-32 through publish: 28 context tools
// plus 4 broker tools is exactly the cap and is accepted.
func TestPrepareZKCap32Accepted(t *testing.T) {
	var twentyEight []string
	for i := 0; i < 28; i++ {
		twentyEight = append(twentyEight, "t"+string(rune('a'+i/10))+string(rune('0'+i%10)))
	}
	body := v3PodTOML(twentyEight, `["a", "b", "c", "d"]`, false, "")
	if _, err := Prepare(writePodFixture(t, body), testIdentity(t), PrepareOptions{ZK: true}); err != nil {
		t.Fatalf("32 combined tools must be accepted: %v", err)
	}
}

// TestPrepareZKRefusesARuntimeNameCollision is dt-runtime-name-collision:
// a.b_c and a_b.c commit as two distinct ids, but both render to
// open_brain_a_b_c in the runtime, so pod validation (MCP-K01) refuses the
// manifest before any commitment is made.
func TestPrepareZKRefusesARuntimeNameCollision(t *testing.T) {
	body := strings.Replace(validMemoryFreePodTOML, "[directive]", `[dependencies]
secrets = ["A_TOKEN", "B_TOKEN"]

[[network.gateway]]
host = "a.example.com"
secret = "A_TOKEN"
auth = "bearer"
max_calls = 5
protocol = "mcp"
mcp_name = "a"
mcp_tools = ["b_c"]

[[network.gateway]]
host = "b.example.com"
secret = "B_TOKEN"
auth = "bearer"
max_calls = 5
protocol = "mcp"
mcp_name = "a_b"
mcp_tools = ["c"]

[directive]`, 1)
	_, err := Prepare(writePodFixture(t, body), testIdentity(t), PrepareOptions{ZK: true})
	if err == nil || !strings.Contains(err.Error(), "validation issue") {
		t.Fatalf("err = %v, want the MCP-K01 validation refusal", err)
	}
}
