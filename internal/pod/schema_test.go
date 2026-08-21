// Copyright 2026 Jerry David Chan, Konareef.ai
// SPDX-License-Identifier: Apache-2.0

package pod

import (
	"bytes"
	"encoding/json"
	"os"
	"slices"
	"testing"
)

func TestSchemaJSON_IsByteIdenticalToTheEmbeddedFile(t *testing.T) {
	want, err := os.ReadFile("spec_v0_1.schema.json")
	if err != nil {
		t.Fatalf("read spec_v0_1.schema.json: %v", err)
	}
	got := SchemaJSON()
	if !bytes.Equal(got, want) {
		t.Fatalf("SchemaJSON() differs from the file on disk: got %d bytes, want %d", len(got), len(want))
	}

	// The byte comparison above passes as long as both sides resolve to the
	// same file — it would not catch SchemaJSON() returning a filtered,
	// truncated, or reordered document that happened to still be some file
	// on disk. Pin structural facts about the parsed result too: the four
	// top-level required tables, all thirteen table-valued properties, and
	// the declared $id.
	var doc struct {
		ID         string                     `json:"$id"`
		Required   []string                   `json:"required"`
		Properties map[string]json.RawMessage `json:"properties"`
	}
	if err := json.Unmarshal(got, &doc); err != nil {
		t.Fatalf("SchemaJSON() is not valid JSON: %v", err)
	}
	if doc.ID != schemaID {
		t.Fatalf("$id = %q, want %q", doc.ID, schemaID)
	}

	wantRequired := []string{"pod_spec_version", "pod", "runtime", "directive"}
	if !slices.Equal(doc.Required, wantRequired) {
		t.Fatalf("required = %v, want %v", doc.Required, wantRequired)
	}

	// Every property except pod_spec_version (a scalar const) is a table
	// ($ref'd to a $defs entry).
	wantTables := []string{
		"pod", "runtime", "model", "hardware", "dependencies", "context",
		"inputs", "directive", "output", "budget", "wallet", "hooks",
		"marketplace",
	}
	for _, name := range wantTables {
		if _, ok := doc.Properties[name]; !ok {
			t.Fatalf("properties: missing table %q", name)
		}
	}
	if want := len(wantTables) + 1; len(doc.Properties) != want {
		t.Fatalf("properties has %d entries, want %d (thirteen tables plus pod_spec_version)", len(doc.Properties), want)
	}
}

func TestSchemaJSON_ReturnsACopyTheCallerCannotCorrupt(t *testing.T) {
	first := SchemaJSON()
	if len(first) == 0 {
		t.Fatal("SchemaJSON() returned no bytes")
	}
	first[0] = 'X'
	second := SchemaJSON()
	if second[0] == 'X' {
		t.Fatal("SchemaJSON() handed out the embedded bytes; one caller corrupted them for every other caller")
	}
}

func TestSchemaJSON_ParsesAndCarriesTheDeclaredID(t *testing.T) {
	var doc map[string]any
	if err := json.Unmarshal(SchemaJSON(), &doc); err != nil {
		t.Fatalf("embedded schema is not valid JSON: %v", err)
	}
	if doc["$id"] != schemaID {
		t.Fatalf("$id = %v, want %q", doc["$id"], schemaID)
	}
}
