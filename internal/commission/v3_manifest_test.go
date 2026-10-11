// Copyright 2026 Jerry David Chan, Konareef.ai
// SPDX-License-Identifier: Apache-2.0

// v3_manifest_test.go — commission binding and containment over a
// konareef-toml/v3 manifest (MCP-Z03, konareef#15).
package commission

import (
	"crypto/sha256"
	"errors"
	"reflect"
	"testing"

	"github.com/digitsu/konareef/internal/envelope"
	"github.com/digitsu/konareef/internal/identity"
	"github.com/digitsu/konareef/internal/pod"
)

// v3Manifest builds a minimal canonical-v3 manifest committing frHex. It
// carries one brokered grant (jira.search), since v3 requires one, and
// [budget].max_sats = 1000; those fields reproduce frV3.
func v3Manifest(frHex string) []byte {
	return []byte("#!konareef-toml/v3\n" +
		"[budget]\nmax_sats = 1000\n\n" +
		"[[network.gateway]]\nhost = \"mcp.example.com\"\nmcp_name = \"jira\"\nmcp_tools = [\"search\"]\nprotocol = \"mcp\"\n\n" +
		"[pod]\nname = \"probe\"\n\n" +
		"[_commit]\nfields_root = \"poseidon:" + frHex + "\"\n")
}

// Roots over the fixed fields (no model, c_max 1000, r_init E20):
//   - frV3: declared_tools [jira.search] — what v3Manifest declares.
//   - frV2EvilTool: [evil.x] — v2Manifest's fields plus a tool it never declares.
//   - frV3EvilTool: [evil.x, jira.search] — v3Manifest's plus the same.
const (
	frV3         = "9bed8a28f6160aaaf2cf59bac96617ca62495674340181d65111966b57186027"
	frV2EvilTool = "b297ab2301f4b1278b9bb7c0671372a52539f47090a448fdc0387d1ab9ff6e20"
	frV3EvilTool = "e310e20ffa2aa0256394691f287a84a4882269c333e73803251f80d753209212"
)

// TestValidateAgainstManifest_V3 applies the v2 binding rules to v3: a v3
// manifest commits a fields_root, so it must be pinned, the pin must
// match, and a v3 manifest whose trailer will not parse is an error.
func TestValidateAgainstManifest_V3(t *testing.T) {
	m := v3Manifest(frV3)
	if err := bindingFor(m, hexToArr(t, frV3)).ValidateAgainstManifest(m); err != nil {
		t.Fatalf("a matching pin on a v3 manifest must be accepted, got %v", err)
	}
	if err := bindingFor(m, nil).ValidateAgainstManifest(m); !errors.Is(err, ErrCircuitCommitmentUnpinned) {
		t.Fatalf("an unpinned v3 binding = %v, want ErrCircuitCommitmentUnpinned", err)
	}
	if err := bindingFor(m, hexToArr(t, frB)).ValidateAgainstManifest(m); !errors.Is(err, ErrFieldsRootMismatch) {
		t.Fatalf("a wrong pin on v3 = %v, want ErrFieldsRootMismatch", err)
	}
	broken := []byte("#!konareef-toml/v3\n[pod]\nname = \"probe\"\n")
	if err := bindingFor(broken, nil).ValidateAgainstManifest(broken); !errors.Is(err, ErrManifestCommitmentUnreadable) {
		t.Fatalf("a v3 manifest with no trailer = %v, want ErrManifestCommitmentUnreadable", err)
	}
}

// grantSpec is a spec with two context tools and one brokered grant, the
// dt-open-union shape, plus an HTTP gateway that must add nothing.
func grantSpec() pod.Spec {
	return pod.Spec{
		Model:   &pod.Model{Provider: "openai", Name: "gpt-4o"},
		Budget:  &pod.Budget{MaxSats: 1000},
		Context: &pod.Context{Tools: []pod.ContextTool{{Source: "read"}, {Source: "bash"}}},
		Network: &pod.Network{Gateway: []pod.Gateway{
			{Host: "mcp.example.com", Protocol: "mcp", MCPName: "jira", MCPTools: []string{"search", "get_issue"}},
			{Host: "api.example.com"},
		}},
	}
}

// TestFromManifest_ToolsFollowTheCommittedVersion: the Tools dimension is
// the committed declared_tools set — the union for v3, [[context.tools]]
// only for v2, v1 and author bytes (where it equals FromSpec).
func TestFromManifest_ToolsFollowTheCommittedVersion(t *testing.T) {
	s := grantSpec()
	v3, err := FromManifest(v3Manifest(frA), s)
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"bash", "jira.get_issue", "jira.search", "read"}; !reflect.DeepEqual(v3.Tools, want) {
		t.Fatalf("v3 Tools = %q, want %q", v3.Tools, want)
	}

	fromSpec, err := FromSpec(s)
	if err != nil {
		t.Fatal(err)
	}
	for name, manifest := range map[string][]byte{
		"v2":       v2Manifest(frA),
		"v1":       v1Manifest(),
		"no magic": []byte("[pod]\nname = \"probe\"\n"),
	} {
		got, err := FromManifest(manifest, s)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if !reflect.DeepEqual(got, fromSpec) {
			t.Errorf("%s: FromManifest = %+v, want FromSpec = %+v", name, got, fromSpec)
		}
	}

	if _, err := FromManifest([]byte("#!konareef-toml/v4\n"), s); err == nil {
		t.Fatal("FromManifest must refuse a version this build does not implement")
	}
}

// TestFromManifest_V3ContainmentCoversBrokerTools: a buyer's commission
// that permits the context tools but not a brokered tool does not contain
// a v3 pod, and one that also lists the brokered ids does.
func TestFromManifest_V3ContainmentCoversBrokerTools(t *testing.T) {
	declared, err := FromManifest(v3Manifest(frA), grantSpec())
	if err != nil {
		t.Fatal(err)
	}
	commission := envelope.Envelope{
		Models: []string{"openai/gpt-4o"}, Tools: []string{"bash", "read"}, CMax: 1000,
		ModelsSet: true, ToolsSet: true, CMaxSet: true,
	}
	if res := commission.Contains(declared); res.OK {
		t.Fatal("a commission without the brokered tools must not contain a v3 pod that commits them")
	}
	commission.Tools = envelope.Normalise([]string{"bash", "read", "jira.search", "jira.get_issue"})
	if res := commission.Contains(declared); !res.OK {
		t.Fatalf("a commission listing every committed tool must contain the pod: %+v", res.Failures)
	}
}

// TestFromManifest_V3RefusesACollision: the containment derivation refuses
// the same manifests publish refuses (dt-collision), rather than deriving
// an envelope from a set no publish could have committed.
func TestFromManifest_V3RefusesACollision(t *testing.T) {
	s := grantSpec()
	s.Context.Tools = append(s.Context.Tools, pod.ContextTool{Source: "jira.search"})
	if _, err := FromManifest(v3Manifest(frA), s); err == nil {
		t.Fatal("FromManifest accepted a context tool equal to a broker id")
	}
}

// TestValidateAgainstManifest_RefusesAnExtraToolTrailer is the MCP-Z03
// review M1 case: the publisher signs a manifest whose trailer commits a
// tool (evil.x) the content never declares, and the buyer pins that root.
// The pin equals the trailer, so only recomputing the root from the
// content refuses it. Both v2 and v3 are covered; the controls pass.
func TestValidateAgainstManifest_RefusesAnExtraToolTrailer(t *testing.T) {
	cases := []struct {
		name    string
		build   func(string) []byte
		honest  string
		tainted string
	}{
		{"v2", v2Manifest, frA, frV2EvilTool},
		{"v3", v3Manifest, frV3, frV3EvilTool},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			honest := c.build(c.honest)
			if err := bindingFor(honest, hexToArr(t, c.honest)).ValidateAgainstManifest(honest); err != nil {
				t.Fatalf("control: an honest manifest was refused: %v", err)
			}
			if err := CheckManifestCommitment(honest); err != nil {
				t.Fatalf("control: CheckManifestCommitment refused an honest manifest: %v", err)
			}
			tainted := c.build(c.tainted)
			err := bindingFor(tainted, hexToArr(t, c.tainted)).ValidateAgainstManifest(tainted)
			if !errors.Is(err, ErrManifestCommitmentMismatch) {
				t.Fatalf("an extra-tool trailer = %v, want ErrManifestCommitmentMismatch", err)
			}
		})
	}
}

// TestVerifyAgainstManifest_RefusesAnExtraToolTrailer drives the same case
// through `commission verify`: a signed commission pinning the tainted
// root is refused, and one pinning the honest root verifies.
func TestVerifyAgainstManifest_RefusesAnExtraToolTrailer(t *testing.T) {
	for name, pair := range map[string][2][]byte{
		"v2": {v2Manifest(frA), v2Manifest(frV2EvilTool)},
		"v3": {v3Manifest(frV3), v3Manifest(frV3EvilTool)},
	} {
		t.Run(name, func(t *testing.T) {
			for i, m := range pair {
				root, err := ManifestFieldsRoot(m)
				if err != nil {
					t.Fatal(err)
				}
				spec, err := pod.Parse(m)
				if err != nil {
					t.Fatal(err)
				}
				declared, err := FromManifest(m, spec)
				if err != nil {
					t.Fatal(err)
				}
				c := signedCommissionFor(t, m, root, declared)
				err = c.VerifyAgainstManifest(m, declared)
				if i == 0 && err != nil {
					t.Fatalf("control: commission verify refused the honest manifest: %v", err)
				}
				if i == 1 && !errors.Is(err, ErrManifestCommitmentMismatch) {
					t.Fatalf("commission verify of an extra-tool trailer = %v, want ErrManifestCommitmentMismatch", err)
				}
			}
		})
	}
}

// TestCheckManifestCommitment_MemoryBearingIsUnverifiable: a manifest that
// declares memory and commits a marked populated root cannot be checked
// without the salt, so it is refused rather than trusted.
func TestCheckManifestCommitment_MemoryBearingIsUnverifiable(t *testing.T) {
	m := []byte("#!konareef-toml/v2\n" +
		"[budget]\nmax_sats = 1000\n\n[[context.memory]]\nkind = \"inline\"\ncontent = \"x\"\n\n" +
		"[pod]\nname = \"probe\"\n\n" +
		"[_commit]\nfields_root = \"poseidon:" + frB + "\"\nr_init_scheme = \"konareef-rinit/v1\"\n")
	if err := CheckManifestCommitment(m); !errors.Is(err, ErrManifestCommitmentUnverifiable) {
		t.Fatalf("CheckManifestCommitment = %v, want ErrManifestCommitmentUnverifiable", err)
	}
}

// TestCheckManifestCommitment_V3WithoutGrantRefused (review L4): a v3 manifest with
// no brokered grant would have the v2 root, so it is refused on read.
func TestCheckManifestCommitment_V3WithoutGrantRefused(t *testing.T) {
	m := []byte("#!konareef-toml/v3\n[budget]\nmax_sats = 1000\n\n[pod]\nname = \"probe\"\n\n" +
		"[_commit]\nfields_root = \"poseidon:" + frA + "\"\n")
	if err := CheckManifestCommitment(m); !errors.Is(err, ErrManifestCommitmentMismatch) {
		t.Fatalf("CheckManifestCommitment(v3 without grant) = %v, want ErrManifestCommitmentMismatch", err)
	}
}

// signedCommissionFor signs a proposal whose envelope is declared (labels
// stated empty so it is signable) and whose binding pins manifest and
// root. Input: the manifest, the root it states (nil for none) and the
// derived envelope. Output: the signed commission.
func signedCommissionFor(t *testing.T, manifest []byte, root *[32]byte, declared envelope.Envelope) Commission {
	t.Helper()
	id, err := identity.Generate("test-buyer")
	if err != nil {
		t.Fatal(err)
	}
	declared.Labels, declared.LabelsSet = []string{}, true
	p := Proposal{Envelope: declared, Binding: Binding{
		PodRef: "dave/probe@1.0.0", HManifest: sha256.Sum256(manifest), FieldsRoot: root,
	}}
	c, err := Sign(p, id)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	return c
}
