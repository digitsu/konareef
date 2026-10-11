package install

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"

	"github.com/digitsu/konareef/internal/canon"
)

const testManifestCanon = `pod_spec_version = "0.1"

[pod]
name = "voice-forge"
version = "0.1.3"

[runtime]
kind = "lobster"

[model]
provider = "anthropic"
name = "claude-sonnet-4-5"

[budget]
max_sats = 5000
`

const testManifestCanonWithTools = `pod_spec_version = "0.1"

[pod]
name = "tool-pod"
version = "0.1.0"

[runtime]
kind = "lobster"

[model]
provider = "anthropic"
name = "claude-sonnet-4-5"

[[context.tools]]
source = "bash"

[[context.tools]]
source = "web_search"

[budget]
max_sats = 1000
`

// writeInstallFixture writes a fixture install cache directory
// (<home>/.konareef/installed/<handle>/<pod>/<version>/) with the three
// files LoadManifestParams reads: manifest.canon, signature.bin, meta.json.
func writeInstallFixture(t *testing.T, home, handle, podName, version, manifestCanon string, sigLen int) {
	t.Helper()
	dir := filepath.Join(home, ".konareef", "installed", handle, podName, version)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("mkdir fixture dir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "manifest.canon"), []byte(manifestCanon), 0o644); err != nil {
		t.Fatalf("write manifest.canon: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "signature.bin"), make([]byte, sigLen), 0o644); err != nil {
		t.Fatalf("write signature.bin: %v", err)
	}
	pubkey := make([]byte, 33)
	pubkey[0] = 0x02
	// pod_hash is SHA-256(manifest.canon); LoadManifestParams checks it.
	podHash := sha256.Sum256([]byte(manifestCanon))
	meta := `{"pod_hash":"` + hex.EncodeToString(podHash[:]) + `","publisher_pubkey_hex":"` + hex.EncodeToString(pubkey) + `"}`
	if err := os.WriteFile(filepath.Join(dir, "meta.json"), []byte(meta), 0o644); err != nil {
		t.Fatalf("write meta.json: %v", err)
	}
}

func TestLoadManifestParams(t *testing.T) {
	home := t.TempDir()
	writeInstallFixture(t, home, "acme", "voice-forge", "0.1.3", testManifestCanon, 72)

	mp, err := LoadManifestParams(home, "acme", "voice-forge", "0.1.3")
	if err != nil {
		t.Fatalf("LoadManifestParams: %v", err)
	}

	if string(mp.Manifest) != testManifestCanon {
		t.Fatalf("Manifest not byte-exact:\ngot:  %q\nwant: %q", mp.Manifest, testManifestCanon)
	}
	// "<provider>/<name>", not the bare name: this is the identifier
	// internal/publish.DeriveCommitParams commits into fields_root, and
	// the witness this function feeds is checked against that commitment
	// (spec §4.1, R-V2.5). Both sides derive it through canon.ModelID.
	if len(mp.Models) != 1 || mp.Models[0] != "anthropic/claude-sonnet-4-5" {
		t.Fatalf("Models = %v, want [anthropic/claude-sonnet-4-5]", mp.Models)
	}
	if mp.Tools == nil || len(mp.Tools) != 0 {
		t.Fatalf("Tools = %v, want empty non-nil slice", mp.Tools)
	}
	if mp.CMax != 5000 {
		t.Fatalf("CMax = %d, want 5000", mp.CMax)
	}
	// SigManifest is the 74-byte lane [derLen][DER][zero pad] from the 72-byte
	// raw signature.bin fixture.
	if len(mp.SigManifest) != 74 {
		t.Fatalf("SigManifest len = %d, want 74 (padded lane)", len(mp.SigManifest))
	}
	if mp.SigManifest[0] != 72 {
		t.Fatalf("SigManifest[0] = %d, want 72 (raw DER length prefix)", mp.SigManifest[0])
	}
	if mp.SigManifest[73] != 0 {
		t.Fatalf("SigManifest[73] = %d, want 0 (zero pad)", mp.SigManifest[73])
	}
	if len(mp.PkPub) != 33 {
		t.Fatalf("PkPub len = %d, want 33", len(mp.PkPub))
	}
	if mp.PkPub[0] != 0x02 {
		t.Fatalf("PkPub[0] = %x, want 0x02 (decoded from hex, not re-encoded)", mp.PkPub[0])
	}
}

func TestLoadManifestParamsWithTools(t *testing.T) {
	home := t.TempDir()
	writeInstallFixture(t, home, "acme", "tool-pod", "0.1.0", testManifestCanonWithTools, 71)

	mp, err := LoadManifestParams(home, "acme", "tool-pod", "0.1.0")
	if err != nil {
		t.Fatalf("LoadManifestParams: %v", err)
	}
	want := []string{"bash", "web_search"}
	if len(mp.Tools) != len(want) {
		t.Fatalf("Tools = %v, want %v", mp.Tools, want)
	}
	for i, tool := range want {
		if mp.Tools[i] != tool {
			t.Fatalf("Tools[%d] = %q, want %q", i, mp.Tools[i], tool)
		}
	}
	if mp.CMax != 1000 {
		t.Fatalf("CMax = %d, want 1000", mp.CMax)
	}
}

func TestLoadManifestParamsMissingCache(t *testing.T) {
	home := t.TempDir()
	if _, err := LoadManifestParams(home, "acme", "nope", "0.0.1"); err == nil {
		t.Fatal("expected error for missing install cache, got nil")
	}
}

// TestLoadManifestParamsAgreesWithPublishCommitment is the cross-package
// guard C1 was missing. Every existing test of this function asserted its
// output against a hand-written expectation in the same file, so the three
// Go derivations of the same committed values could — and did — drift
// apart without any test noticing.
//
// This one asserts AGREEMENT instead of a literal: it publishes a
// ZK-eligible pod through the real pipeline (which commits fields_root via
// internal/publish.DeriveCommitParams), caches it exactly as `konareef
// install` does, loads the witness params back, and recomputes fields_root
// from THOSE params. The two roots must be equal — that equality is the
// whole contract between publish and prove, and a proof against a
// published pod fails at prove time when it does not hold.
//
// r_init on the recomputation side is the loaded RInit, which for this
// memory-free pod must be E20: publish commits E20 since MEM-03
// (konareef-rinit/v1 D1-A), replacing the Ruling-8 all-zero placeholder.
//
// The fixture declares a [model], because the models dimension is the one
// that diverged. Before the 2026-09-21 fix this function emitted
// "gpt-4o" while publish committed "openai/gpt-4o", and this test fails
// with mismatched roots against that code.
func TestLoadManifestParamsAgreesWithPublishCommitment(t *testing.T) {
	f, _ := fixtureWithZKContent(t)
	home := t.TempDir()
	if _, err := Cache(home, f); err != nil {
		t.Fatalf("Cache: %v", err)
	}

	mp, err := LoadManifestParams(home, f.Handle, f.PodName, f.PodVersion)
	if err != nil {
		t.Fatalf("LoadManifestParams: %v", err)
	}
	if len(mp.Models) != 1 {
		t.Fatalf("the fixture declares one [model]; got Models = %v", mp.Models)
	}

	committed, err := canon.ParseCommitFieldsRoot(f.ManifestCanonical)
	if err != nil {
		t.Fatalf("ParseCommitFieldsRoot: %v", err)
	}
	if mp.RInit != canon.EmptyMemoryRoot() {
		t.Fatalf("loaded RInit = %x, want E20 for a memory-free pod", mp.RInit)
	}
	if mp.MemoryCells != nil {
		t.Fatal("a memory-free pod must load no memory cells")
	}
	got, err := canon.FieldsRoot(mp.Models, mp.Tools, mp.CMax, mp.RInit)
	if err != nil {
		t.Fatalf("FieldsRoot over the loaded witness params: %v", err)
	}
	if got != committed {
		t.Fatalf("the witness params do not reproduce the committed fields_root:\n"+
			"  got  %x (from Models=%v Tools=%v CMax=%d)\n"+
			"  want %x (committed by publish)\n"+
			"A --zk publish would succeed and the proof would then fail at prove time.",
			got, mp.Models, mp.Tools, mp.CMax, committed)
	}
}

// TestLoadManifestParamsRequiresBothModelParts pins that a [model] naming
// only one of provider and name is refused rather than silently reduced to
// a half identifier the commitment never covered (spec §4.1, R-V2.5).
func TestLoadManifestParamsRequiresBothModelParts(t *testing.T) {
	for name, manifest := range map[string]string{
		"no provider": "pod_spec_version = \"0.1\"\n\n[pod]\nname = \"p\"\nversion = \"1.0.0\"\n\n[runtime]\nkind = \"lobster\"\n\n[model]\nname = \"gpt-4o\"\n\n[budget]\nmax_sats = 10\n",
		"no name":     "pod_spec_version = \"0.1\"\n\n[pod]\nname = \"p\"\nversion = \"1.0.0\"\n\n[runtime]\nkind = \"lobster\"\n\n[model]\nprovider = \"openai\"\n\n[budget]\nmax_sats = 10\n",
		"no model":    "pod_spec_version = \"0.1\"\n\n[pod]\nname = \"p\"\nversion = \"1.0.0\"\n\n[runtime]\nkind = \"lobster\"\n\n[budget]\nmax_sats = 10\n",
	} {
		t.Run(name, func(t *testing.T) {
			home := t.TempDir()
			writeInstallFixture(t, home, "acme", "p", "1.0.0", manifest, 72)
			if _, err := LoadManifestParams(home, "acme", "p", "1.0.0"); err == nil {
				t.Fatal("LoadManifestParams accepted a manifest with an incomplete [model]")
			}
		})
	}
}

// TestLoadManifestParamsRefusesAnAbsentBudget pins spec §4.3 / R-V2.7 on
// the read-back side. This function used to default CMax to 0 when
// [budget] was absent — the exact shape internal/publish.DeriveCommitParams
// refuses at publish time (COMMIT_BUDGET_REQUIRED), because 0 is a
// meaningful committed cap ("this pod cannot spend") while an absent
// section means the server's 200,000-sat ceiling applies. Loading 0 for a
// manifest that committed nothing states a cap the commitment does not
// carry.
//
// The "explicit zero" case is the control: `[budget]` with
// `max_sats = 0` IS a committed cap and must still load, which is why the
// distinction needs pod.ParseWithMeta rather than a nil/zero check.
func TestLoadManifestParamsRefusesAnAbsentBudget(t *testing.T) {
	const head = "pod_spec_version = \"0.1\"\n\n[pod]\nname = \"p\"\nversion = \"1.0.0\"\n\n[runtime]\nkind = \"lobster\"\n\n[model]\nprovider = \"openai\"\nname = \"gpt-4o\"\n"

	t.Run("absent budget is refused", func(t *testing.T) {
		home := t.TempDir()
		writeInstallFixture(t, home, "acme", "p", "1.0.0", head, 72)
		if _, err := LoadManifestParams(home, "acme", "p", "1.0.0"); err == nil {
			t.Fatal("LoadManifestParams silently defaulted c_max for a manifest with no [budget]")
		}
	})

	t.Run("explicit zero still loads", func(t *testing.T) {
		home := t.TempDir()
		writeInstallFixture(t, home, "acme", "p", "1.0.0", head+"\n[budget]\nmax_sats = 0\n", 72)
		mp, err := LoadManifestParams(home, "acme", "p", "1.0.0")
		if err != nil {
			t.Fatalf("LoadManifestParams rejected an explicit max_sats = 0: %v", err)
		}
		if mp.CMax != 0 {
			t.Fatalf("CMax = %d, want 0", mp.CMax)
		}
	})
}
