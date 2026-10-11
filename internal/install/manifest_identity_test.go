// Copyright 2026 Jerry David Chan, Konareef.ai
// SPDX-License-Identifier: Apache-2.0

// manifest_identity_test.go — LoadManifestParams refuses an installed
// manifest whose identity or v2 commitment does not hold (IB-03,
// konareef#21). Each refusal test starts from a pod made by the real
// publish pipeline (fixtureWithZKContent) and changes one thing.
package install

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"testing"

	"github.com/digitsu/konareef/internal/commission"
)

// cacheZKFixture installs a real --zk publish into a fresh home and
// returns the home and the cache directory.
func cacheZKFixture(t *testing.T) (home, dir string, f *FetchedPod) {
	t.Helper()
	f, _ = fixtureWithZKContent(t)
	home = t.TempDir()
	dir, err := Cache(home, f)
	if err != nil {
		t.Fatalf("Cache: %v", err)
	}
	return home, dir, f
}

// rewriteCachedManifest replaces manifest.canon and, when rehash is true,
// rewrites meta.json's pod_hash to match the new bytes. Rehashing isolates
// the fields_root check from the pod_hash check.
func rewriteCachedManifest(t *testing.T, dir string, manifest []byte, rehash bool) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, "manifest.canon"), manifest, 0o644); err != nil {
		t.Fatalf("write manifest.canon: %v", err)
	}
	if !rehash {
		return
	}
	metaPath := filepath.Join(dir, "meta.json")
	meta, err := os.ReadFile(metaPath)
	if err != nil {
		t.Fatalf("read meta.json: %v", err)
	}
	sum := sha256.Sum256(manifest)
	re := regexp.MustCompile(`"pod_hash": "[0-9a-f]{64}"`)
	if !re.Match(meta) {
		t.Fatalf("meta.json has no pod_hash to rewrite: %s", meta)
	}
	meta = re.ReplaceAll(meta, []byte(`"pod_hash": "`+hex.EncodeToString(sum[:])+`"`))
	if err := os.WriteFile(metaPath, meta, 0o644); err != nil {
		t.Fatalf("write meta.json: %v", err)
	}
}

// loadFixture calls LoadManifestParams on the cached fixture.
func loadFixture(home string, f *FetchedPod) error {
	_, err := LoadManifestParams(home, f.Handle, f.PodName, f.PodVersion)
	return err
}

// TestLoadManifestParamsAcceptsAGenuineV2Install is the control for every
// refusal below: the unchanged publish output loads.
func TestLoadManifestParamsAcceptsAGenuineV2Install(t *testing.T) {
	home, _, f := cacheZKFixture(t)
	if err := loadFixture(home, f); err != nil {
		t.Fatalf("LoadManifestParams refused a genuine v2 install: %v", err)
	}
}

// TestLoadManifestParamsRefusesAWrongRootOfTheRightLength replaces the
// committed fields_root with another well-formed 32-byte root. The trailer
// still parses, so only a recomputation can refuse it.
func TestLoadManifestParamsRefusesAWrongRootOfTheRightLength(t *testing.T) {
	home, dir, f := cacheZKFixture(t)
	re := regexp.MustCompile(`fields_root = "poseidon:[0-9a-f]{64}"`)
	if !re.Match(f.ManifestCanonical) {
		t.Fatal("fixture manifest has no fields_root line to replace")
	}
	wrong := re.ReplaceAll(f.ManifestCanonical,
		[]byte(`fields_root = "poseidon:`+hex.EncodeToString(bytes.Repeat([]byte{0x01}, 32))+`"`))
	rewriteCachedManifest(t, dir, wrong, true)

	if err := loadFixture(home, f); !errors.Is(err, ErrCommittedFieldsRootMismatch) {
		t.Fatalf("LoadManifestParams = %v, want ErrCommittedFieldsRootMismatch", err)
	}
}

// TestLoadManifestParamsRefusesAProviderOnlyChange changes only the
// declared provider and keeps the trailer. The recomputed root then covers
// a model the publisher never committed.
func TestLoadManifestParamsRefusesAProviderOnlyChange(t *testing.T) {
	home, dir, f := cacheZKFixture(t)
	changed := bytes.Replace(f.ManifestCanonical, []byte(`provider = "openai"`), []byte(`provider = "azure"`), 1)
	if bytes.Equal(changed, f.ManifestCanonical) {
		t.Fatal("fixture manifest does not declare provider = \"openai\"")
	}
	rewriteCachedManifest(t, dir, changed, true)

	if err := loadFixture(home, f); !errors.Is(err, ErrCommittedFieldsRootMismatch) {
		t.Fatalf("LoadManifestParams = %v, want ErrCommittedFieldsRootMismatch", err)
	}
}

// TestLoadManifestParamsRefusesAnAbsentCommitment removes the [_commit]
// trailer from a manifest that still claims konareef-toml/v2.
func TestLoadManifestParamsRefusesAnAbsentCommitment(t *testing.T) {
	home, dir, f := cacheZKFixture(t)
	i := bytes.Index(f.ManifestCanonical, []byte("[_commit]"))
	if i < 0 {
		t.Fatal("fixture manifest has no [_commit] trailer")
	}
	rewriteCachedManifest(t, dir, f.ManifestCanonical[:i], true)

	if err := loadFixture(home, f); !errors.Is(err, commission.ErrManifestCommitmentUnreadable) {
		t.Fatalf("LoadManifestParams = %v, want ErrManifestCommitmentUnreadable", err)
	}
}

// TestLoadManifestParamsRefusesAFutureManifestVersion relabels the
// manifest as a version this build does not implement. v4, not v3: v3 is
// implemented since MCP-Z03 (konareef-toml/v3 spec).
func TestLoadManifestParamsRefusesAFutureManifestVersion(t *testing.T) {
	home, dir, f := cacheZKFixture(t)
	future := bytes.Replace(f.ManifestCanonical, []byte("#!konareef-toml/v2\n"), []byte("#!konareef-toml/v4\n"), 1)
	if bytes.Equal(future, f.ManifestCanonical) {
		t.Fatal("fixture manifest has no v2 magic line")
	}
	rewriteCachedManifest(t, dir, future, true)

	if err := loadFixture(home, f); !errors.Is(err, commission.ErrManifestVersionUnsupported) {
		t.Fatalf("LoadManifestParams = %v, want ErrManifestVersionUnsupported", err)
	}
}

// TestLoadManifestParamsRefusesAManifestThatIsNotThePodHash edits the
// manifest without updating meta.json. The cached bytes are then not the
// bytes install verified.
func TestLoadManifestParamsRefusesAManifestThatIsNotThePodHash(t *testing.T) {
	home, dir, f := cacheZKFixture(t)
	edited := append(bytes.Clone(f.ManifestCanonical), '\n')
	rewriteCachedManifest(t, dir, edited, false)

	if err := loadFixture(home, f); !errors.Is(err, ErrInstalledManifestHashMismatch) {
		t.Fatalf("LoadManifestParams = %v, want ErrInstalledManifestHashMismatch", err)
	}
}
