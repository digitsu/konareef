// Copyright 2026 Jerry David Chan, Konareef.ai
// SPDX-License-Identifier: Apache-2.0

// memoryroot_test.go — publish-side konareef-rinit/v1 and v2 tests (MEM-03,
// konareef#26): memory-free publishes commit E20 with the r_init_scheme
// marker and round-trip through the verifier-side parser and the install
// re-canonicalizer; memory-bearing publishes stay refused with the gate
// off; with the gate on (test-only), supported shapes produce the
// konareef-rinit/v2 r_init the shared rinit_v2 source vectors pin, and
// every unsupported shape is
// refused with its specific code.
package publish

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/digitsu/konareef/internal/canon"
	"github.com/digitsu/konareef/internal/membridge"
	"github.com/digitsu/konareef/internal/pod"
)

// memoryPodHeader is a v2-eligible manifest head to which tests append
// [[context.memory]] entries.
const memoryPodHeader = validMemoryFreePodTOML

// withMemoryPublishEnabled turns the phase-3 gate on for one test and
// restores it afterwards. Tests using it must not run in parallel.
func withMemoryPublishEnabled(t *testing.T) {
	t.Helper()
	prev := memoryPublishEnabled
	memoryPublishEnabled = true
	t.Cleanup(func() { memoryPublishEnabled = prev })
}

// writeMemoryPod writes a pod with the given extra manifest text and
// extra files (pod-relative slash paths → bytes). Output: the pod dir.
func writeMemoryPod(t *testing.T, extraTOML string, files map[string]string) string {
	t.Helper()
	dir := writePodFixture(t, memoryPodHeader+extraTOML)
	for rel, body := range files {
		p := filepath.Join(dir, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

// saltFrom returns a MemorySalt callback that yields the given salt and
// counts its calls.
func saltFrom(t *testing.T, hexSalt string, calls *int) func(*pod.Spec) ([32]byte, error) {
	t.Helper()
	b, err := hex.DecodeString(hexSalt)
	if err != nil || len(b) != 32 {
		t.Fatalf("bad salt %q", hexSalt)
	}
	var s [32]byte
	copy(s[:], b)
	return func(*pod.Spec) ([32]byte, error) {
		*calls++
		return s, nil
	}
}

// committedRInitCheck recomputes fields_root over the manifest's public
// dimensions and the given r_init, and compares it with the trailer.
func committedRInitCheck(t *testing.T, canonBytes []byte, rInit [32]byte) canon.CommitTrailer {
	t.Helper()
	return committedRInitCheckScheme(t, canonBytes, rInit, canon.RInitSchemeV1)
}

// committedRInitCheckScheme is committedRInitCheck for an explicit
// r_init_scheme: konareef-rinit/v1 for a memory-free publish, v2 for a
// memory-bearing one (rinit/v2 R-M29).
func committedRInitCheckScheme(t *testing.T, canonBytes []byte, rInit [32]byte, scheme string) canon.CommitTrailer {
	t.Helper()
	tr, err := canon.ParseCommitTrailer(canonBytes)
	if err != nil {
		t.Fatalf("ParseCommitTrailer: %v", err)
	}
	if tr.RInitScheme != scheme {
		t.Fatalf("r_init_scheme = %q, want %q", tr.RInitScheme, scheme)
	}
	want, err := canon.FieldsRoot([]string{"openai/gpt-4o"}, nil, 1000, rInit)
	if err != nil {
		t.Fatal(err)
	}
	if tr.FieldsRoot != want {
		t.Fatalf("committed fields_root %x, want %x (over r_init %x)", tr.FieldsRoot, want, rInit)
	}
	return tr
}

// TestPrepareZKMemoryFreeCommitsE20WithMarker is the D1-A/D2-A publish
// test: the signed v2 bytes carry fields_root over E20 and the marker,
// classify as memory_free_rinit_v1, verify through ParseCommitFieldsRoot
// and re-canonicalize byte-for-byte through CanonicalizeLike (the install
// path). A non-ZK publish of the same pod is unchanged v1 (control).
func TestPrepareZKMemoryFreeCommitsE20WithMarker(t *testing.T) {
	dir := writePodFixture(t, validMemoryFreePodTOML)
	prep, err := Prepare(dir, testIdentity(t), PrepareOptions{ZK: true})
	if err != nil {
		t.Fatalf("Prepare: %v", err)
	}
	tr := committedRInitCheck(t, prep.CanonicalBytes, canon.EmptyMemoryRoot())
	if !bytes.HasSuffix(prep.CanonicalBytes, []byte("r_init_scheme = \"konareef-rinit/v1\"\n")) {
		t.Fatalf("marker must be the last trailer line: %q", prep.CanonicalBytes)
	}
	class, err := canon.ClassifyMemoryRoot(tr, []string{"openai/gpt-4o"}, nil, 1000)
	if err != nil || class != canon.MemoryFreeRInitV1 {
		t.Fatalf("class = %s (%v), want %s", class, err, canon.MemoryFreeRInitV1)
	}
	if fr, err := canon.ParseCommitFieldsRoot(prep.CanonicalBytes); err != nil || fr != tr.FieldsRoot {
		t.Fatalf("verifier parser: %x, %v", fr, err)
	}
	author, _ := os.ReadFile(filepath.Join(dir, "pod.toml"))
	again, err := canon.CanonicalizeLike(author, dir, prep.CanonicalBytes)
	if err != nil || !bytes.Equal(again, prep.CanonicalBytes) {
		t.Fatalf("install re-canonicalization must reproduce the signed bytes (err %v)", err)
	}

	v1, err := Prepare(dir, testIdentity(t), PrepareOptions{})
	if err != nil {
		t.Fatalf("Prepare v1: %v", err)
	}
	if bytes.Contains(v1.CanonicalBytes, []byte("[_commit]")) {
		t.Fatal("a non-ZK publish must stay konareef-toml/v1 with no trailer")
	}
}

// TestPrepareZKMemoryBearingRefusedWhileGateOff: with the shipped gate,
// every memory-bearing --zk publish refuses with
// COMMIT_MEMORY_RESOLUTION_UNAVAILABLE, even with a salt source and a
// supported shape, and the salt source is never called.
func TestPrepareZKMemoryBearingRefusedWhileGateOff(t *testing.T) {
	if MemoryPublishEnabled() {
		t.Fatal("memory-bearing publish must be disabled in every build until phase 4")
	}
	dir := writeMemoryPod(t, "\n[[context.memory]]\nkind = \"file\"\npath = \"./memory/notes.md\"\n",
		map[string]string{"memory/notes.md": "The pod remembers this line.\n"})
	calls := 0
	_, err := Prepare(dir, testIdentity(t), PrepareOptions{
		ZK: true, DisclosurePolicy: "D",
		MemorySalt: saltFrom(t, strings.Repeat("aa", 32), &calls),
	})
	if got := canon.Code(err); got != canon.ErrCommitMemoryResolutionUnavailable {
		t.Fatalf("code = %q (%v), want %s", got, err, canon.ErrCommitMemoryResolutionUnavailable)
	}
	if calls != 0 {
		t.Fatalf("salt source called %d times; a refused publish must not provision a salt", calls)
	}
}

// sourceFixture is one source_vectors entry of the konareef-rinit/v2
// shared vectors (membridge/testdata/rinit_v2/vectors.json).
type sourceFixture struct {
	ID      string `json:"id"`
	PodSalt string `json:"pod_salt"`
	Sources []struct {
		Kind      string `json:"kind"`
		Path      string `json:"path"`
		Content   string `json:"content"`
		FileBytes string `json:"file_bytes_utf8"`
	} `json:"sources"`
	RInit string `json:"r_init"`
}

// loadRInitV2SourceFixtures reads the source vectors of the
// konareef-rinit/v2 shared vector file.
func loadRInitV2SourceFixtures(t *testing.T) []sourceFixture {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "membridge", "testdata", "rinit_v2", "vectors.json"))
	if err != nil {
		t.Fatal(err)
	}
	var fx struct {
		Sources []sourceFixture `json:"source_vectors"`
	}
	if err := json.Unmarshal(raw, &fx); err != nil {
		t.Fatal(err)
	}
	return fx.Sources
}

// TestPrepareZKMemoryBearingReproducesSourceFixtures turns the gate on
// and publishes a real pod directory for each konareef-rinit/v2 source
// vector. The committed fields_root must be over exactly the vector
// r_init, with the konareef-rinit/v2 marker (R-M29). A different salt
// gives a different committed root.
func TestPrepareZKMemoryBearingReproducesSourceFixtures(t *testing.T) {
	withMemoryPublishEnabled(t)
	fixtures := loadRInitV2SourceFixtures(t)
	if len(fixtures) < 2 {
		t.Fatalf("want at least 2 source fixtures, got %d", len(fixtures))
	}
	for _, v := range fixtures {
		t.Run(v.ID, func(t *testing.T) {
			var toml strings.Builder
			files := map[string]string{}
			for _, s := range v.Sources {
				toml.WriteString("\n[[context.memory]]\nkind = \"" + s.Kind + "\"\n")
				switch s.Kind {
				case "file":
					toml.WriteString("path = \"" + s.Path + "\"\n")
					files[membridge.FilesKey(s.Path)] = s.FileBytes
				case "inline":
					toml.WriteString("content = \"" + s.Content + "\"\n")
				}
			}
			dir := writeMemoryPod(t, toml.String(), files)
			calls := 0
			prep, err := Prepare(dir, testIdentity(t), PrepareOptions{
				ZK: true, DisclosurePolicy: "D", MemorySalt: saltFrom(t, v.PodSalt, &calls),
			})
			if err != nil {
				t.Fatalf("Prepare: %v", err)
			}
			if calls != 1 {
				t.Fatalf("salt source called %d times, want 1", calls)
			}
			var want [32]byte
			b, _ := hex.DecodeString(v.RInit)
			copy(want[:], b)
			tr := committedRInitCheckScheme(t, prep.CanonicalBytes, want, canon.RInitSchemeV2)
			class, _ := canon.ClassifyMemoryRoot(tr, []string{"openai/gpt-4o"}, nil, 1000)
			if class != canon.NotMemoryFree {
				t.Fatalf("class = %s, want %s", class, canon.NotMemoryFree)
			}

			// Different salt → different commitment.
			other, err := Prepare(dir, testIdentity(t), PrepareOptions{
				ZK: true, DisclosurePolicy: "D", MemorySalt: saltFrom(t, strings.Repeat("ab", 32), &calls),
			})
			if err != nil {
				t.Fatal(err)
			}
			if bytes.Equal(other.CanonicalBytes, prep.CanonicalBytes) {
				t.Fatal("a different salt must change the committed root")
			}
		})
	}
}

// TestPrepareZKMemoryBearingRefusals: with the gate on, each unsupported
// shape refuses with its own code, and no error text carries the salt or
// file content. The file-only control succeeds.
func TestPrepareZKMemoryBearingRefusals(t *testing.T) {
	withMemoryPublishEnabled(t)
	const saltHex = "5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a"
	const secret = "confidential memory line\n"
	fileEntry := "\n[[context.memory]]\nkind = \"file\"\npath = \"./memory/notes.md\"\n"
	notes := map[string]string{"memory/notes.md": secret}

	cases := []struct {
		name   string
		toml   string
		files  map[string]string
		policy string
		salt   bool
		want   string
	}{
		{"control", fileEntry, notes, "D", true, ""},
		{"type C", fileEntry, notes, "C", true, canon.ErrCommitMemoryResolutionUnavailable},
		{"no salt source", fileEntry, notes, "D", false, canon.ErrCommitMemoryResolutionUnavailable},
		{"http", fileEntry + "\n[[context.memory]]\nkind = \"http\"\nurl = \"https://example.com/a.md\"\n", notes, "D", true, "MEMORY_SOURCE_UNSUPPORTED"},
		{"openbrain", "\n[[context.memory]]\nkind = \"openbrain\"\nsnapshot = \"latest\"\n", nil, "D", true, "MEMORY_SOURCE_UNSUPPORTED"},
		{"file not in [_files]", "\n[[context.memory]]\nkind = \"file\"\npath = \"./.hidden.md\"\n", map[string]string{".hidden.md": secret}, "D", true, "MEMORY_FILE_NOT_COMMITTED"},
		{"file missing", fileEntry, nil, "D", true, "MEMORY_FILE_NOT_COMMITTED"},
		{"duplicate file", fileEntry + fileEntry, notes, "D", true, "MEMORY_DUPLICATE_SOURCE"},
		{"duplicate inline", "\n[[context.memory]]\nkind = \"inline\"\ncontent = \"x\"\n\n[[context.memory]]\nkind = \"inline\"\ncontent = \"x\"\n", nil, "D", true, "MEMORY_DUPLICATE_SOURCE"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			dir := writeMemoryPod(t, c.toml, c.files)
			calls := 0
			opts := PrepareOptions{ZK: true, DisclosurePolicy: c.policy}
			if c.salt {
				opts.MemorySalt = saltFrom(t, saltHex, &calls)
			}
			_, err := Prepare(dir, testIdentity(t), opts)
			if c.want == "" {
				if err != nil {
					t.Fatalf("control: %v", err)
				}
				return
			}
			if got := canon.Code(err); got != c.want {
				t.Fatalf("code = %q (%v), want %s", got, err, c.want)
			}
			if strings.Contains(err.Error(), saltHex) || strings.Contains(err.Error(), strings.TrimSpace(secret)) {
				t.Fatalf("error leaks salt or content: %v", err)
			}
		})
	}

	// A salt source that fails stops the publish before any resolution.
	dir := writeMemoryPod(t, fileEntry, notes)
	boom := errors.New("keychain locked")
	_, err := Prepare(dir, testIdentity(t), PrepareOptions{
		ZK: true, DisclosurePolicy: "D",
		MemorySalt: func(*pod.Spec) ([32]byte, error) { return [32]byte{}, boom },
	})
	if !errors.Is(err, boom) {
		t.Fatalf("salt error must propagate: %v", err)
	}
}

// TestCheckMemoryFilesUnchanged: a memory file whose [_files] digest in
// the canonical output differs from the bytes r_init was computed over
// is refused (the file changed between the two reads). Control: the
// matching digest passes.
func TestCheckMemoryFilesUnchanged(t *testing.T) {
	spec, _ := parseForTest(t, memoryPodHeader+"\n[[context.memory]]\nkind = \"file\"\npath = \"./memory/notes.md\"\n")
	sum := func(s string) bodyFile {
		return bodyFile{bytes: []byte(s), sum: sha256.Sum256([]byte(s))}
	}
	used := map[string]bodyFile{"memory/notes.md": sum("a")}
	canonWith := func(content string) []byte {
		return []byte("#!konareef-toml/v2\n[pod]\nname = \"x\"\n[_files]\n\"memory/notes.md\" = \"sha256:" +
			hex.EncodeToString(func() []byte { d := sha256.Sum256([]byte(content)); return d[:] }()) + "\"\n")
	}
	if err := checkMemoryFilesUnchanged(spec, canonWith("a"), used); err != nil {
		t.Fatalf("control: %v", err)
	}
	if err := checkMemoryFilesUnchanged(spec, canonWith("b"), used); !errors.Is(err, errMemoryFilesChanged) {
		t.Fatalf("err = %v, want errMemoryFilesChanged", err)
	}
}
