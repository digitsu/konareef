package install

import (
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"
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
	meta := `{"pod_hash":"` + hex.EncodeToString(make([]byte, 32)) + `","publisher_pubkey_hex":"` + hex.EncodeToString(pubkey) + `"}`
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
	if len(mp.Models) != 1 || mp.Models[0] != "claude-sonnet-4-5" {
		t.Fatalf("Models = %v, want [claude-sonnet-4-5]", mp.Models)
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
