// Copyright 2026 Jerry David Chan, Konareef.ai
// SPDX-License-Identifier: Apache-2.0

// manifest_params_v3_test.go — install and the witness feeder read a
// konareef-toml/v3 manifest's declared_tools exactly as publish committed
// it (MCP-Z03, konareef#15).
package install

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/digitsu/konareef/internal/canon"
	"github.com/digitsu/konareef/internal/identity"
	"github.com/digitsu/konareef/internal/publish"
)

// brokerGrantBlock is the [dependencies] and brokered grant a v3 fixture
// adds to zkSamplePodTOML. mcpTools is a TOML array literal.
func brokerGrantBlock(mcpTools string) string {
	return `[dependencies]
secrets = ["JIRA_TOKEN"]

[[context.tools]]
source = "read"

[[context.tools]]
source = "bash"

[[network.gateway]]
host = "mcp.example.com"
secret = "JIRA_TOKEN"
auth = "bearer"
max_calls = 5
protocol = "mcp"
mcp_name = "jira"
mcp_tools = ` + mcpTools + `

`
}

// v3PodBody is zkSamplePodTOML with two context tools and one brokered
// grant, the dt-open-union shape.
func v3PodBody() string {
	return strings.Replace(zkSamplePodTOML, "[directive]", brokerGrantBlock(`["search", "get_issue"]`)+"[directive]", 1)
}

// fixtureWithV3Content runs the real --zk publish over body and returns
// the FetchedPod plus the pod directory, like fixtureWithZKContent.
func fixtureWithV3Content(t *testing.T, body string) (*FetchedPod, string) {
	t.Helper()
	podDir := writeZKSamplePod(t)
	if err := os.WriteFile(filepath.Join(podDir, "pod.toml"), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	id, err := identity.Generate("alice")
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	prep, err := publish.Prepare(podDir, id, publish.PrepareOptions{ZK: true})
	if err != nil {
		t.Fatalf("Prepare: %v", err)
	}
	return &FetchedPod{
		Handle:             prep.Handle,
		PodName:            prep.PodName,
		PodVersion:         prep.PodVersion,
		PodHash:            prep.PodHash,
		ManifestCanonical:  prep.CanonicalBytes,
		Signature:          prep.Signature,
		PublisherPubkeyHex: prep.PublicKeyHex,
		ContentTarball:     prep.ContentTarball,
	}, podDir
}

// cacheV3Fixture publishes v3PodBody and caches it.
func cacheV3Fixture(t *testing.T) (home, dir string, f *FetchedPod) {
	t.Helper()
	f, _ = fixtureWithV3Content(t, v3PodBody())
	if !bytes.HasPrefix(f.ManifestCanonical, []byte("#!konareef-toml/v3\n")) {
		t.Fatalf("fixture is not v3: %q", f.ManifestCanonical[:20])
	}
	home = t.TempDir()
	dir, err := Cache(home, f)
	if err != nil {
		t.Fatalf("Cache: %v", err)
	}
	return home, dir, f
}

// TestV3InstallVerifiesAndFeedsTheCommittedTools: a genuine v3 publish
// passes install Verify (signature, pod_hash and the content tarball
// re-canonicalized at v3), and LoadManifestParams hands the witness the
// committed union, whose root is the committed fields_root.
func TestV3InstallVerifiesAndFeedsTheCommittedTools(t *testing.T) {
	home, _, f := cacheV3Fixture(t)
	if err := Verify(f); err != nil {
		t.Fatalf("install rejected a valid v3 pod: %v", err)
	}
	mp, err := LoadManifestParams(home, f.Handle, f.PodName, f.PodVersion)
	if err != nil {
		t.Fatalf("LoadManifestParams: %v", err)
	}
	want := []string{"bash", "jira.get_issue", "jira.search", "read"}
	if !reflect.DeepEqual(mp.Tools, want) {
		t.Fatalf("witness Tools = %q, want %q", mp.Tools, want)
	}
	committed, err := canon.ParseCommitFieldsRoot(f.ManifestCanonical)
	if err != nil {
		t.Fatal(err)
	}
	got, err := canon.FieldsRoot(mp.Models, mp.Tools, mp.CMax, mp.RInit)
	if err != nil {
		t.Fatal(err)
	}
	if got != committed {
		t.Fatalf("witness params root %x != committed %x", got, committed)
	}
}

// TestV3InstallRefusesAGrantToolTamper edits one granted tool in the
// cached manifest body and keeps the trailer (pod_hash rewritten so only
// the commitment check can catch it). Adding, removing or renaming a
// granted tool must each fail the fields_root recomputation.
func TestV3InstallRefusesAGrantToolTamper(t *testing.T) {
	cases := map[string]string{
		"added":   "mcp_tools = [\n\"search\",\n\"get_issue\",\n\"create_issue\"\n]\n",
		"removed": "mcp_tools = [\n\"search\"\n]\n",
		"changed": "mcp_tools = [\n\"search\",\n\"get_issues\"\n]\n",
	}
	for name, replacement := range cases {
		t.Run(name, func(t *testing.T) {
			home, dir, f := cacheV3Fixture(t)
			line := []byte("mcp_tools = [\n\"search\",\n\"get_issue\"\n]\n")
			if !bytes.Contains(f.ManifestCanonical, line) {
				t.Fatalf("canonical manifest has no line %q:\n%s", line, f.ManifestCanonical)
			}
			tampered := bytes.Replace(f.ManifestCanonical, line, []byte(replacement), 1)
			rewriteCachedManifest(t, dir, tampered, true)
			if err := loadFixture(home, f); !errors.Is(err, ErrCommittedFieldsRootMismatch) {
				t.Fatalf("LoadManifestParams = %v, want ErrCommittedFieldsRootMismatch", err)
			}
		})
	}
}

// TestV3InstallRefusesAnHTTPGrantFlip turns the only brokered grant into
// an HTTP gateway entry. The manifest is then a v3 manifest with no grant,
// which is refused before any root is computed
// (COMMIT_V3_REQUIRES_BROKER_GRANT); its tools would also leave the set.
func TestV3InstallRefusesAnHTTPGrantFlip(t *testing.T) {
	home, dir, f := cacheV3Fixture(t)
	tampered := bytes.Replace(f.ManifestCanonical, []byte("protocol = \"mcp\"\n"), []byte("protocol = \"http\"\n"), 1)
	if bytes.Equal(tampered, f.ManifestCanonical) {
		t.Fatal("no protocol line to flip")
	}
	rewriteCachedManifest(t, dir, tampered, true)
	if err := loadFixture(home, f); canon.Code(err) != canon.ErrCommitV3RequiresBrokerGrant {
		t.Fatalf("LoadManifestParams = %v, want COMMIT_V3_REQUIRES_BROKER_GRANT", err)
	}
}

// legacyV2WithGrant builds a v2 manifest for v3PodBody the way a publish
// before konareef-toml/v3 did: [[context.tools]] committed, the grant not.
// It returns the canonical bytes.
func legacyV2WithGrant(t *testing.T) []byte {
	t.Helper()
	_, podDir := fixtureWithV3Content(t, v3PodBody())
	trailerless := canon.CommitParams{
		Models: []string{"openai/gpt-4o"}, Tools: []string{"read", "bash"}, CMax: 1000,
		RInit: canon.EmptyMemoryRoot(), RInitScheme: canon.RInitSchemeV1,
	}
	out, err := canon.CanonicalizeV2([]byte(v3PodBody()), podDir, trailerless)
	if err != nil {
		t.Fatalf("CanonicalizeV2: %v", err)
	}
	return out
}

// TestLegacyV2WithGrantStaysReadable: a v2 manifest that carries a grant
// (published before v3) still loads, and its witness Tools are the v2 set.
// Its brokered calls are refused as undeclared downstream (MCP-Z00 §10.3);
// they are never silently added here.
func TestLegacyV2WithGrantStaysReadable(t *testing.T) {
	home, dir, f := cacheZKFixture(t)
	legacy := legacyV2WithGrant(t)
	rewriteCachedManifest(t, dir, legacy, true)
	mp, err := LoadManifestParams(home, f.Handle, f.PodName, f.PodVersion)
	if err != nil {
		t.Fatalf("LoadManifestParams(legacy v2 with grant): %v", err)
	}
	if !reflect.DeepEqual(mp.Tools, []string{"read", "bash"}) {
		t.Fatalf("witness Tools = %q, want the v2 set [read bash]", mp.Tools)
	}
}

// TestRelabelV2AsV3IsRefused relabels the legacy v2-with-grant manifest as
// v3. Under v3 the grant's ids are part of declared_tools, so the v2
// trailer no longer reproduces: a version flip cannot smuggle a set past
// the commitment.
func TestRelabelV2AsV3IsRefused(t *testing.T) {
	home, dir, f := cacheZKFixture(t)
	relabelled := bytes.Replace(legacyV2WithGrant(t), []byte("#!konareef-toml/v2\n"), []byte("#!konareef-toml/v3\n"), 1)
	rewriteCachedManifest(t, dir, relabelled, true)
	if err := loadFixture(home, f); !errors.Is(err, ErrCommittedFieldsRootMismatch) {
		t.Fatalf("LoadManifestParams = %v, want ErrCommittedFieldsRootMismatch", err)
	}
}

// TestV3ClosedPodWithGrantIsNotAWitnessSource: publish never emits this
// (COMMIT_SEALED_GRANT_ZK_UNSUPPORTED), and a cache entry that holds one
// anyway is refused before any witness is built (MCP-Z00 §10.5, D8).
func TestV3ClosedPodWithGrantIsNotAWitnessSource(t *testing.T) {
	home, dir, f := cacheV3Fixture(t)
	closed := bytes.Replace(f.ManifestCanonical, []byte("[pod]\n"), []byte("[pod]\nvisibility = \"closed\"\n"), 1)
	rewriteCachedManifest(t, dir, closed, true)
	err := loadFixture(home, f)
	if canon.Code(err) != canon.ErrCommitSealedGrantZKUnsupported {
		t.Fatalf("LoadManifestParams = %v, want COMMIT_SEALED_GRANT_ZK_UNSUPPORTED", err)
	}
}
