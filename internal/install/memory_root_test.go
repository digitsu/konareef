// Copyright 2026 Jerry David Chan, Konareef.ai
// SPDX-License-Identifier: Apache-2.0

// memory_root_test.go — install and witness-param behaviour for the
// konareef-rinit/v1 memory root (MEM-03, konareef#26), with
// memory-bearing roots under konareef-rinit/v2 (CL-4-live):
//
//   - a legacy zero-root manifest (published before MEM-03) still verifies
//     and installs byte-for-byte, and is classified: LoadManifestParams
//     refuses it with ErrLegacyZeroMemoryRoot instead of feeding a witness
//     PS-1 would refuse;
//   - a memory-bearing manifest needs the salt holder's evidence; correct
//     evidence loads the checked r_init and cells, and a wrong salt,
//     changed content or missing evidence builds nothing;
//   - the declaration and the root must agree.
package install

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/digitsu/konareef/internal/canon"
	"github.com/digitsu/konareef/internal/identity"
	"github.com/digitsu/konareef/internal/membridge"
	"github.com/digitsu/konareef/internal/publish"
)

// signedV2Fixture canonicalizes podDir's pod.toml with the given commit
// params (bypassing publish's r_init policy, to reproduce manifests that
// publish no longer emits), signs it and packs the content tarball.
func signedV2Fixture(t *testing.T, podDir string, p canon.CommitParams) *FetchedPod {
	t.Helper()
	body, err := os.ReadFile(filepath.Join(podDir, "pod.toml"))
	if err != nil {
		t.Fatal(err)
	}
	canonBytes, err := canon.CanonicalizeV2(body, podDir, p)
	if err != nil {
		t.Fatalf("CanonicalizeV2: %v", err)
	}
	id, err := identity.Generate("alice")
	if err != nil {
		t.Fatal(err)
	}
	sig, err := id.Sign(canonBytes)
	if err != nil {
		t.Fatal(err)
	}
	tarball, err := publish.PackTarball(podDir)
	if err != nil {
		t.Fatal(err)
	}
	return &FetchedPod{
		Handle: id.Handle, PodName: "research-bot", PodVersion: "1.0.0",
		PodHash: sha256.Sum256(canonBytes), ManifestCanonical: canonBytes, Signature: sig,
		PublisherPubkeyHex: id.PublicKeyHex, ContentTarball: tarball,
	}
}

// zkParams returns the models/tools/c_max the ZK sample pod commits, as
// the control fixture's loaded params report them.
func zkParams(t *testing.T) (models, tools []string, cMax uint64) {
	t.Helper()
	home, _, f := cacheZKFixture(t)
	mp, err := LoadManifestParams(home, f.Handle, f.PodName, f.PodVersion)
	if err != nil {
		t.Fatalf("control LoadManifestParams: %v", err)
	}
	return mp.Models, mp.Tools, mp.CMax
}

// TestLegacyZeroManifestInstallsButIsNotProofEligible: a manifest that
// commits r_init = 0 with no marker — what publish emitted from !106 until
// MEM-03 — passes the full install Verify (pod_hash, signature, tarball
// reproduction through CanonicalizeLike), caches, and is then refused as a
// witness source with ErrLegacyZeroMemoryRoot. Its bytes are never
// rewritten. Control: the current publish output loads with RInit = E20.
func TestLegacyZeroManifestInstallsButIsNotProofEligible(t *testing.T) {
	models, tools, cMax := zkParams(t)
	podDir := writeZKSamplePod(t)
	f := signedV2Fixture(t, podDir, canon.CommitParams{Models: models, Tools: tools, CMax: cMax})
	if bytes.Contains(f.ManifestCanonical, []byte("r_init_scheme")) {
		t.Fatal("legacy fixture must carry no marker")
	}
	if err := Verify(f); err != nil {
		t.Fatalf("a legacy zero-root manifest must stay installable: %v", err)
	}
	home := t.TempDir()
	dir, err := Cache(home, f)
	if err != nil {
		t.Fatalf("Cache: %v", err)
	}
	cached, _ := os.ReadFile(filepath.Join(dir, "manifest.canon"))
	if !bytes.Equal(cached, f.ManifestCanonical) {
		t.Fatal("install must cache the legacy manifest byte for byte")
	}
	_, err = LoadManifestParams(home, f.Handle, f.PodName, f.PodVersion)
	if !errors.Is(err, ErrLegacyZeroMemoryRoot) {
		t.Fatalf("LoadManifestParams = %v, want ErrLegacyZeroMemoryRoot", err)
	}

	// Control: the same pod through today's publish commits E20 + marker.
	home2, _, f2 := cacheZKFixture(t)
	mp, err := LoadManifestParams(home2, f2.Handle, f2.PodName, f2.PodVersion)
	if err != nil || mp.RInit != canon.EmptyMemoryRoot() {
		t.Fatalf("control: RInit = %x, err = %v", mp.RInit, err)
	}
	if err := Verify(f2); err != nil {
		t.Fatalf("control: a marked v2 manifest must install: %v", err)
	}
}

// memoryPodTOML is the ZK sample pod plus one inline and one file memory
// source.
const memoryPodTOML = zkSamplePodTOML + `
[[context.memory]]
kind = "file"
path = "./memory/notes.md"

[[context.memory]]
kind = "inline"
content = "Prefer primary sources."
`

// memoryFixture writes a memory-bearing pod, resolves its cells the way
// the publisher does, and signs a v2 manifest with the konareef-rinit/v2
// marker over RInitV2(salt, cells).
// Output: the cached home, the fetched pod, the salt and the cells.
func memoryFixture(t *testing.T) (string, *FetchedPod, [32]byte, []membridge.Cell) {
	t.Helper()
	models, tools, cMax := zkParams(t)
	podDir := writeZKSamplePod(t)
	if err := os.WriteFile(filepath.Join(podDir, "pod.toml"), []byte(memoryPodTOML), 0o644); err != nil {
		t.Fatal(err)
	}
	notes := []byte("The pod remembers this line.\n")
	if err := os.MkdirAll(filepath.Join(podDir, "memory"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(podDir, "memory", "notes.md"), notes, 0o644); err != nil {
		t.Fatal(err)
	}
	cells, err := membridge.ResolveSources([]membridge.MemorySource{
		{Kind: "file", Path: "./memory/notes.md", Loaded: notes},
		{Kind: "inline", Content: "Prefer primary sources."},
	}, map[string][32]byte{"memory/notes.md": sha256.Sum256(notes)})
	if err != nil {
		t.Fatal(err)
	}
	var salt [32]byte
	for i := range salt {
		salt[i] = byte(i)
	}
	rInit, _, err := membridge.RInitV2(salt[:], cells)
	if err != nil {
		t.Fatal(err)
	}
	f := signedV2Fixture(t, podDir, canon.CommitParams{
		Models: models, Tools: tools, CMax: cMax, RInit: rInit, RInitScheme: canon.RInitSchemeV2,
	})
	if err := Verify(f); err != nil {
		t.Fatalf("a memory-bearing v2 manifest must install: %v", err)
	}
	home := t.TempDir()
	if _, err := Cache(home, f); err != nil {
		t.Fatal(err)
	}
	return home, f, salt, cells
}

// TestLoadManifestParamsWithMemoryChecksTheRoot: the salt holder's root
// check. Correct evidence loads r_init and the checked cells (control);
// no evidence, a different salt, changed content, a dropped cell and
// evidence against a memory-free manifest all refuse and return no params.
func TestLoadManifestParamsWithMemoryChecksTheRoot(t *testing.T) {
	home, f, salt, cells := memoryFixture(t)
	load := func(mem *MemoryEvidence) (bool, error) {
		mp, err := LoadManifestParamsWithMemory(home, f.Handle, f.PodName, f.PodVersion, mem)
		return mp.Manifest != nil, err
	}

	mp, err := LoadManifestParamsWithMemory(home, f.Handle, f.PodName, f.PodVersion, &MemoryEvidence{Salt: salt, Cells: cells})
	if err != nil {
		t.Fatalf("control: %v", err)
	}
	want, derived, _ := membridge.RInitV2(salt[:], cells)
	if mp.RInit != want || len(mp.MemoryCells) != len(cells) {
		t.Fatalf("control: RInit %x (want %x), %d cells", mp.RInit, want, len(mp.MemoryCells))
	}
	touched, _ := membridge.TouchedCellID(cells)
	for _, d := range derived {
		if d.CellID == touched && (mp.MemoryTouched == nil || mp.MemoryTouched.Index != d.Index || mp.MemoryTouched.KeyTag != d.KeyTag) {
			t.Fatalf("control: touched row %+v, want the lowest cell_id's row", mp.MemoryTouched)
		}
	}
	committed, _ := canon.ParseCommitFieldsRoot(f.ManifestCanonical)
	if fr, _ := canon.FieldsRoot(mp.Models, mp.Tools, mp.CMax, mp.RInit); fr != committed {
		t.Fatal("control: loaded params must reproduce the committed fields_root")
	}

	otherSalt := salt
	otherSalt[0] ^= 1
	changed := append([]membridge.Cell(nil), cells...)
	changed[0] = membridge.Cell{CellID: cells[0].CellID, ContentHash: bytes.Repeat([]byte{0x42}, 32)}
	for name, c := range map[string]struct {
		mem  *MemoryEvidence
		want error
	}{
		"no evidence":     {nil, ErrMemoryEvidenceRequired},
		"other salt":      {&MemoryEvidence{Salt: otherSalt, Cells: cells}, membridge.ErrRInitMismatch},
		"changed content": {&MemoryEvidence{Salt: salt, Cells: changed}, membridge.ErrRInitMismatch},
		"dropped cell":    {&MemoryEvidence{Salt: salt, Cells: cells[:1]}, membridge.ErrRInitMismatch},
		"duplicate cell":  {&MemoryEvidence{Salt: salt, Cells: append(append([]membridge.Cell(nil), cells...), cells[0])}, membridge.ErrCellDuplicateID},
	} {
		got, err := load(c.mem)
		if !errors.Is(err, c.want) {
			t.Fatalf("%s: err = %v, want %v", name, err, c.want)
		}
		if got {
			t.Fatalf("%s: params returned on refusal", name)
		}
	}

	// Evidence with cells against a memory-free manifest is refused too.
	home2, _, f2 := cacheZKFixture(t)
	_, err = LoadManifestParamsWithMemory(home2, f2.Handle, f2.PodName, f2.PodVersion, &MemoryEvidence{Salt: salt, Cells: cells})
	if !errors.Is(err, ErrCommittedFieldsRootMismatch) {
		t.Fatalf("cells against a memory-free manifest: err = %v", err)
	}
}

// TestMemoryDeclarationMustMatchTheRoot: a manifest that declares memory
// but commits E20 (an empty-tree fallback) is refused, as is one that
// declares no memory but carries the marker with a populated root.
func TestMemoryDeclarationMustMatchTheRoot(t *testing.T) {
	models, tools, cMax := zkParams(t)

	podDir := writeZKSamplePod(t)
	if err := os.WriteFile(filepath.Join(podDir, "pod.toml"), []byte(zkSamplePodTOML+"\n[[context.memory]]\nkind = \"inline\"\ncontent = \"x\"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	f := signedV2Fixture(t, podDir, canon.CommitParams{
		Models: models, Tools: tools, CMax: cMax, RInit: canon.EmptyMemoryRoot(), RInitScheme: canon.RInitSchemeV1,
	})
	home := t.TempDir()
	if _, err := Cache(home, f); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadManifestParams(home, f.Handle, f.PodName, f.PodVersion); !errors.Is(err, ErrCommittedFieldsRootMismatch) {
		t.Fatalf("declared memory over E20: err = %v, want ErrCommittedFieldsRootMismatch", err)
	}

	var populated [32]byte
	populated[0] = 7
	f2 := signedV2Fixture(t, writeZKSamplePod(t), canon.CommitParams{
		Models: models, Tools: tools, CMax: cMax, RInit: populated, RInitScheme: canon.RInitSchemeV1,
	})
	home2 := t.TempDir()
	if _, err := Cache(home2, f2); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadManifestParams(home2, f2.Handle, f2.PodName, f2.PodVersion); !errors.Is(err, ErrCommittedFieldsRootMismatch) {
		t.Fatalf("no memory declared, populated root: err = %v, want ErrCommittedFieldsRootMismatch", err)
	}
}
