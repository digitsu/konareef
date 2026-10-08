// Copyright 2026 Jerry David Chan, Konareef.ai
// SPDX-License-Identifier: Apache-2.0

// leaftable_publish_test.go — the signed memory leaf table of a
// memory-bearing publish (konareef-rinit/v1 spec §6.4, MEM-SEAM A1).
package publish

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/digitsu/konareef/internal/identity"
	"github.com/digitsu/konareef/internal/membridge"
)

// TestPrepareSignsLeafTableForMemoryBearingPublish: with the gate on, a
// memory-bearing publish carries a leaf table bound to its pod_hash,
// signed by the publisher, over the MEM-00 r_init, listing exactly the
// resolved cells, and holding neither the salt nor any content. A
// memory-free publish carries none. Submit sends both fields base64.
func TestPrepareSignsLeafTableForMemoryBearingPublish(t *testing.T) {
	withMemoryPublishEnabled(t)
	raw, err := os.ReadFile(filepath.Join("..", "membridge", "testdata", "rinit_v1", "fixtures.json"))
	if err != nil {
		t.Fatal(err)
	}
	var fx struct {
		Sources []sourceFixture `json:"source_vectors"`
	}
	if err := json.Unmarshal(raw, &fx); err != nil {
		t.Fatal(err)
	}
	v := fx.Sources[len(fx.Sources)-1]
	var toml strings.Builder
	files := map[string]string{}
	var sources []membridge.MemorySource
	digests := map[string][32]byte{}
	for _, s := range v.Sources {
		toml.WriteString("\n[[context.memory]]\nkind = \"" + s.Kind + "\"\n")
		if s.Kind == "file" {
			toml.WriteString("path = \"" + s.Path + "\"\n")
			files[membridge.FilesKey(s.Path)] = s.FileBytes
		} else {
			toml.WriteString("content = \"" + s.Content + "\"\n")
		}
		sources = append(sources, membridge.MemorySource{Kind: s.Kind, Path: s.Path, Content: s.Content, Loaded: []byte(s.FileBytes)})
	}
	for k, b := range files {
		digests[k] = sha256.Sum256([]byte(b))
	}
	wantCells, err := membridge.ResolveSources(sources, digests)
	if err != nil {
		t.Fatal(err)
	}

	dir := writeMemoryPod(t, toml.String(), files)
	id := testIdentity(t)
	calls := 0
	prep, err := Prepare(dir, id, PrepareOptions{ZK: true, DisclosurePolicy: "D", MemorySalt: saltFrom(t, v.PodSalt, &calls)})
	if err != nil {
		t.Fatalf("Prepare: %v", err)
	}
	if len(prep.MemoryLeafTable) == 0 || len(prep.MemoryLeafTableSignature) == 0 {
		t.Fatal("a memory-bearing publish must carry a signed leaf table")
	}
	if ok, err := identity.Verify(id.PublicKeyHex, prep.MemoryLeafTable, prep.MemoryLeafTableSignature); err != nil || !ok {
		t.Fatalf("leaf table signature: ok=%v err=%v", ok, err)
	}
	table, err := membridge.ParseLeafTable(prep.MemoryLeafTable)
	if err != nil {
		t.Fatal(err)
	}
	if table.PodHash != prep.PodHash {
		t.Fatal("the leaf table must be bound to this pod_hash")
	}
	if hex.EncodeToString(table.RInit[:]) != v.Expected.RInit {
		t.Fatalf("table r_init %x, want %s", table.RInit, v.Expected.RInit)
	}
	if err := table.CheckRoot(); err != nil {
		t.Fatalf("CheckRoot: %v", err)
	}
	if !membridge.SameCells(table.Cells(), wantCells) {
		t.Fatal("the table must list exactly the resolved cells")
	}
	salt, _ := hex.DecodeString(v.PodSalt)
	if bytes.Contains(prep.MemoryLeafTable, salt) {
		t.Fatal("the leaf table must not carry the salt")
	}
	for _, b := range files {
		if bytes.Contains(prep.MemoryLeafTable, []byte(b)) {
			t.Fatal("the leaf table must not carry file content")
		}
	}

	// Submit sends both fields, base64, and never the salt.
	var captured map[string]any
	var rawBody []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rawBody, _ = io.ReadAll(r.Body)
		_ = json.Unmarshal(rawBody, &captured)
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"install_url":"x","registered_at":"2026-09-26T00:00:00Z"}`))
	}))
	defer srv.Close()
	if _, err := Submit(srv.URL, prep, SubmitOpts{}); err != nil {
		t.Fatalf("Submit: %v", err)
	}
	if captured["memory_leaf_table"] != base64.StdEncoding.EncodeToString(prep.MemoryLeafTable) ||
		captured["memory_leaf_table_signature"] != base64.StdEncoding.EncodeToString(prep.MemoryLeafTableSignature) {
		t.Fatalf("submit body lacks the leaf table fields: %v", captured)
	}
	if bytes.Contains(rawBody, []byte(v.PodSalt)) || bytes.Contains(rawBody, []byte(base64.StdEncoding.EncodeToString(salt))) {
		t.Fatal("the submit body must not carry the salt")
	}

	// Memory-free control: no table, and no key in the submit body.
	mf, err := Prepare(writePodFixture(t, validMemoryFreePodTOML), id, PrepareOptions{ZK: true})
	if err != nil {
		t.Fatal(err)
	}
	if mf.MemoryLeafTable != nil || mf.MemoryLeafTableSignature != nil {
		t.Fatal("a memory-free publish carries no leaf table")
	}
	captured = nil
	if _, err := Submit(srv.URL, mf, SubmitOpts{}); err != nil {
		t.Fatal(err)
	}
	if _, ok := captured["memory_leaf_table"]; ok {
		t.Fatal("a memory-free submit must not carry memory_leaf_table")
	}
}
