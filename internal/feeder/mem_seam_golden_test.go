// Copyright 2026 Jerry David Chan, Konareef.ai
// SPDX-License-Identifier: Apache-2.0

// mem_seam_golden_test.go — the shared MEM-SEAM vectors
// (testdata/mem_seam/mem_seam_v1.json), which reef-core copies byte for
// byte to test/support/fixtures/step_disclosure/mem_seam_v1.json.
//
//   - seam_vectors: for each MEM-00 source vector (and a memory-free pod),
//     the exact initial_memory bytes EncodeSeamMemory writes over the
//     cells membridge.ResolveSources resolves from the pod's sources.
//     reef-core must write the same bytes from its own resolver (S-6).
//   - leaf_table_vectors: a leaf table built by the real publish-side
//     path (RInitV1, NewLeafTable, identity.Sign) under a fixed public
//     test key and salt, so reef-core can check that it parses the same
//     canonical bytes and verifies the same signature.
//
// The file is generated. To regenerate after an intended change:
//
//	KONAREEF_UPDATE_GOLDEN=1 go test ./internal/feeder -run TestMemSeamGolden
//
// then copy it to reef-core and update both pinned SHA-256 values.
package feeder

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"

	"github.com/digitsu/konareef/internal/identity"
	"github.com/digitsu/konareef/internal/membridge"
)

// memSeamGoldenPath is the generated shared vector file.
var memSeamGoldenPath = filepath.Join("testdata", "mem_seam", "mem_seam_v1.json")

// memSeamGoldenSHA256 pins the file. reef-core pins the same value, so a
// change on either side without the other fails a test.
const memSeamGoldenSHA256 = "070977a8187356f5f8a621e1b42d618faa63ced377b8fd39a0f35f89b5924cd1"

// goldenSource mirrors one MEM-00 source_vectors entry.
type goldenSource struct {
	Kind          string `json:"kind"`
	Path          string `json:"path,omitempty"`
	FileBytesUTF8 string `json:"file_bytes_utf8,omitempty"`
	Content       string `json:"content,omitempty"`
}

// goldenSeamVector is one seam_vectors entry.
type goldenSeamVector struct {
	ID                string         `json:"id"`
	Sources           []goldenSource `json:"sources"`
	InitialMemoryJSON string         `json:"initial_memory_json"`
}

// goldenLeaf is one expected leaf of a leaf-table vector.
type goldenLeaf struct {
	CellIDHex      string `json:"cell_id_hex"`
	ContentHashHex string `json:"content_hash_hex"`
	Index          uint32 `json:"index"`
	ValueHashHex   string `json:"value_hash_hex"`
}

// goldenLeafTableVector is one leaf_table_vectors entry.
type goldenLeafTableVector struct {
	ID                 string       `json:"id"`
	PodSaltHex         string       `json:"pod_salt_hex"`
	PodHashHex         string       `json:"pod_hash_hex"`
	PublisherPubkeyHex string       `json:"publisher_pubkey_hex"`
	RInitHex           string       `json:"r_init_hex"`
	Leaves             []goldenLeaf `json:"leaves"`
	TableB64           string       `json:"table_b64"`
	SignatureB64       string       `json:"signature_b64"`
}

// goldenFile is the whole shared vector file.
type goldenFile struct {
	Title            string                  `json:"title"`
	Provenance       string                  `json:"provenance"`
	SeamScheme       string                  `json:"seam_scheme"`
	LeafTableScheme  string                  `json:"leaf_table_scheme"`
	SeamVectors      []goldenSeamVector      `json:"seam_vectors"`
	LeafTableVectors []goldenLeafTableVector `json:"leaf_table_vectors"`
}

// memSeamTestIdentity is a fixed, publicly known test key. It signs only
// test vectors; its private scalar is derived from a published string.
func memSeamTestIdentity() *identity.Identity {
	scalar := sha256.Sum256([]byte("konareef MEM-SEAM public test key; never use for real signing"))
	priv := secp256k1.PrivKeyFromBytes(scalar[:])
	return &identity.Identity{
		Handle:        "mem-seam-fixture",
		PublicKeyHex:  hex.EncodeToString(priv.PubKey().SerializeCompressed()),
		PrivateKeyHex: hex.EncodeToString(priv.Serialize()),
	}
}

// resolveGoldenSources resolves one vector's sources the way publish does.
func resolveGoldenSources(t *testing.T, sources []goldenSource) []membridge.Cell {
	t.Helper()
	ms := make([]membridge.MemorySource, 0, len(sources))
	digests := map[string][32]byte{}
	for _, s := range sources {
		src := membridge.MemorySource{Kind: s.Kind, Path: s.Path, Content: s.Content}
		if s.Kind == membridge.SourceKindFile {
			src.Loaded = []byte(s.FileBytesUTF8)
			digests[membridge.FilesKey(s.Path)] = sha256.Sum256(src.Loaded)
		}
		ms = append(ms, src)
	}
	cells, err := membridge.ResolveSources(ms, digests)
	if err != nil {
		t.Fatalf("ResolveSources: %v", err)
	}
	return cells
}

// buildMemSeamGolden computes the whole vector file from the MEM-00
// source vectors.
func buildMemSeamGolden(t *testing.T) goldenFile {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "membridge", "testdata", "rinit_v1", "fixtures.json"))
	if err != nil {
		t.Fatal(err)
	}
	var mem00 struct {
		Sources []struct {
			ID      string         `json:"id"`
			PodSalt string         `json:"pod_salt"`
			Sources []goldenSource `json:"sources"`
		} `json:"source_vectors"`
	}
	if err := json.Unmarshal(raw, &mem00); err != nil {
		t.Fatal(err)
	}
	if len(mem00.Sources) < 2 {
		t.Fatalf("want the MEM-00 source vectors, got %d", len(mem00.Sources))
	}

	g := goldenFile{
		Title: "MEM-SEAM shared vectors: step-disclosure initial_memory and the signed memory leaf table",
		Provenance: "Generated by konareef internal/feeder/mem_seam_golden_test.go from the MEM-00 " +
			"source_vectors (internal/membridge/testdata/rinit_v1/fixtures.json) with " +
			"membridge.ResolveSources, EncodeSeamMemory, RInitV1, NewLeafTable and identity.Sign " +
			"under a fixed public test key. reef-core copies this file byte for byte.",
		SeamScheme:      SeamMemoryScheme,
		LeafTableScheme: LeafTableScheme,
	}
	id := memSeamTestIdentity()
	for _, v := range mem00.Sources {
		cells := resolveGoldenSources(t, v.Sources)
		enc, err := EncodeSeamMemory(cells)
		if err != nil {
			t.Fatal(err)
		}
		g.SeamVectors = append(g.SeamVectors, goldenSeamVector{ID: v.ID, Sources: v.Sources, InitialMemoryJSON: string(enc)})

		salt, _ := hex.DecodeString(v.PodSalt)
		rInit, derived, err := membridge.RInitV1(salt, cells)
		if err != nil {
			t.Fatal(err)
		}
		podHash := sha256.Sum256([]byte("MEM-SEAM leaf table vector " + v.ID))
		table, err := membridge.NewLeafTable(podHash, rInit, cells, derived)
		if err != nil {
			t.Fatal(err)
		}
		tb := table.Bytes()
		sig, err := id.Sign(tb)
		if err != nil {
			t.Fatal(err)
		}
		lv := goldenLeafTableVector{
			ID: v.ID, PodSaltHex: v.PodSalt, PodHashHex: hex.EncodeToString(podHash[:]),
			PublisherPubkeyHex: id.PublicKeyHex, RInitHex: hex.EncodeToString(rInit[:]),
			TableB64: base64.StdEncoding.EncodeToString(tb), SignatureB64: base64.StdEncoding.EncodeToString(sig),
		}
		for _, l := range table.Leaves {
			var idBytes [8]byte
			binary.BigEndian.PutUint64(idBytes[:], l.CellID)
			lv.Leaves = append(lv.Leaves, goldenLeaf{
				CellIDHex: hex.EncodeToString(idBytes[:]), ContentHashHex: hex.EncodeToString(l.ContentHash[:]),
				Index: l.Index, ValueHashHex: hex.EncodeToString(l.ValueHash[:]),
			})
		}
		g.LeafTableVectors = append(g.LeafTableVectors, lv)
	}
	enc, err := EncodeSeamMemory(nil)
	if err != nil {
		t.Fatal(err)
	}
	g.SeamVectors = append(g.SeamVectors, goldenSeamVector{ID: "memory-free", Sources: []goldenSource{}, InitialMemoryJSON: string(enc)})
	return g
}

// TestMemSeamGolden regenerates the vectors from the MEM-00 inputs and
// requires the committed file to equal them byte for byte, and to match
// its pinned SHA-256. With KONAREEF_UPDATE_GOLDEN=1 it writes the file.
func TestMemSeamGolden(t *testing.T) {
	g := buildMemSeamGolden(t)
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	if err := enc.Encode(g); err != nil {
		t.Fatal(err)
	}
	if os.Getenv("KONAREEF_UPDATE_GOLDEN") == "1" {
		if err := os.MkdirAll(filepath.Dir(memSeamGoldenPath), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(memSeamGoldenPath, buf.Bytes(), 0o644); err != nil {
			t.Fatal(err)
		}
		sum := sha256.Sum256(buf.Bytes())
		t.Logf("wrote %s, sha256 %x", memSeamGoldenPath, sum)
	}
	onDisk, err := os.ReadFile(memSeamGoldenPath)
	if err != nil {
		t.Fatalf("read golden: %v", err)
	}
	if !bytes.Equal(onDisk, buf.Bytes()) {
		t.Fatalf("%s is stale: regenerate with KONAREEF_UPDATE_GOLDEN=1", memSeamGoldenPath)
	}
	if sum := sha256.Sum256(onDisk); hex.EncodeToString(sum[:]) != memSeamGoldenSHA256 {
		t.Fatalf("golden sha256 = %x, pinned %s: update the pin here and in reef-core together", sum, memSeamGoldenSHA256)
	}
}

// TestMemSeamGoldenVectorsAreConsistent reads the committed file as a
// consumer would: every seam value parses back to the resolved cells,
// and every leaf table verifies under its key, parses to the listed
// leaves, and authenticates to its r_init.
func TestMemSeamGoldenVectorsAreConsistent(t *testing.T) {
	raw, err := os.ReadFile(memSeamGoldenPath)
	if err != nil {
		t.Fatal(err)
	}
	var g goldenFile
	if err := json.Unmarshal(raw, &g); err != nil {
		t.Fatal(err)
	}
	for _, v := range g.SeamVectors {
		cells, err := ParseSeamMemory(json.RawMessage(v.InitialMemoryJSON))
		if err != nil {
			t.Fatalf("%s: ParseSeamMemory: %v", v.ID, err)
		}
		if !membridge.SameCells(cells, resolveGoldenSources(t, v.Sources)) {
			t.Fatalf("%s: seam cells differ from ResolveSources", v.ID)
		}
	}
	if len(g.LeafTableVectors) == 0 {
		t.Fatal("no leaf table vectors")
	}
	for _, v := range g.LeafTableVectors {
		tb, _ := base64.StdEncoding.DecodeString(v.TableB64)
		sig, _ := base64.StdEncoding.DecodeString(v.SignatureB64)
		if ok, err := identity.Verify(v.PublisherPubkeyHex, tb, sig); err != nil || !ok {
			t.Fatalf("%s: signature does not verify: %v", v.ID, err)
		}
		table, err := membridge.ParseLeafTable(tb)
		if err != nil {
			t.Fatalf("%s: ParseLeafTable: %v", v.ID, err)
		}
		if err := table.CheckRoot(); err != nil {
			t.Fatalf("%s: CheckRoot: %v", v.ID, err)
		}
		if hex.EncodeToString(table.RInit[:]) != v.RInitHex || len(table.Leaves) != len(v.Leaves) {
			t.Fatalf("%s: parsed table differs from the listed values", v.ID)
		}
		if !bytes.Equal(table.Bytes(), tb) {
			t.Fatalf("%s: canonical bytes do not round-trip", v.ID)
		}
	}
}
