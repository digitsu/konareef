// Copyright 2026 Jerry David Chan, Konareef.ai
// SPDX-License-Identifier: Apache-2.0

// seam_memory_test.go — the seam/2 initial_memory key (seam_memory.go),
// the leaf-table fetch (leaf_table_fetch.go) and the v2/v3 trailer rule
// in checkCommittedRInit (MEM-SEAM security review L6).
package feeder

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/digitsu/konareef/internal/canon"
)

// validSeamMemory is a well-formed two-cell initial_memory value.
const validSeamMemory = `{"cells":[` +
	`{"cell_id":"81ed77926d26caf9","content_hash":"RGENbhTgVwEePZRLC1qWk+GgqKThSa1Bg3B5HVGkcYY="},` +
	`{"cell_id":"b6d362e21dfb6bf9","content_hash":"61LZHLPB+Cv4EwoWqFfPmngd0FlrvXqcJdt/Srgm8hc="}` +
	`],"scheme":"konareef-mem-src/v1"}`

// TestParseSeamMemory: the control parses and re-encodes to the same
// bytes; every malformed shape is refused with ErrSeamMemoryInvalid.
func TestParseSeamMemory(t *testing.T) {
	cells, err := ParseSeamMemory(json.RawMessage(validSeamMemory))
	if err != nil || len(cells) != 2 {
		t.Fatalf("control: %v, %d cells", err, len(cells))
	}
	if enc, _ := EncodeSeamMemory(cells); string(enc) != validSeamMemory {
		t.Fatalf("round trip:\n got %s\nwant %s", enc, validSeamMemory)
	}
	empty, err := ParseSeamMemory(json.RawMessage(`{"cells":[],"scheme":"konareef-mem-src/v1"}`))
	if err != nil || empty == nil || len(empty) != 0 {
		t.Fatalf("empty control: %v, %v", err, empty)
	}

	cell := `{"cell_id":"81ed77926d26caf9","content_hash":"RGENbhTgVwEePZRLC1qWk+GgqKThSa1Bg3B5HVGkcYY="}`
	wrap := func(cells string) string { return `{"cells":[` + cells + `],"scheme":"konareef-mem-src/v1"}` }
	for name, raw := range map[string]string{
		"not an object":         `[]`,
		"null":                  `null`,
		"unknown scheme":        `{"cells":[],"scheme":"konareef-mem-src/v2"}`,
		"missing scheme":        `{"cells":[]}`,
		"missing cells":         `{"scheme":"konareef-mem-src/v1"}`,
		"null cells":            `{"cells":null,"scheme":"konareef-mem-src/v1"}`,
		"extra key":             `{"cells":[],"scheme":"konareef-mem-src/v1","salt":"x"}`,
		"duplicate key":         `{"cells":[],"cells":[],"scheme":"konareef-mem-src/v1"}`,
		"case-variant key":      `{"Cells":[],"scheme":"konareef-mem-src/v1"}`,
		"uppercase hex id":      wrap(strings.Replace(cell, "81ed77926d26caf9", "81ED77926D26CAF9", 1)),
		"short id":              wrap(strings.Replace(cell, "81ed77926d26caf9", "81ed77926d26ca", 1)),
		"id without bit 63":     wrap(strings.Replace(cell, "81ed77926d26caf9", "01ed77926d26caf9", 1)),
		"numeric id":            wrap(strings.Replace(cell, `"81ed77926d26caf9"`, `9362346428837784313`, 1)),
		"short hash":            wrap(strings.Replace(cell, "RGENbhTgVwEePZRLC1qWk+GgqKThSa1Bg3B5HVGkcYY=", "RGENbhTg", 1)),
		"hash not base64":       wrap(strings.Replace(cell, "RGENbhTgVwEePZRLC1qWk+GgqKThSa1Bg3B5HVGkcYY=", "!!", 1)),
		"extra cell key":        wrap(strings.Replace(cell, `}`, `,"kind":"file"}`, 1)),
		"missing cell key":      wrap(`{"cell_id":"81ed77926d26caf9"}`),
		"repeated cell":         wrap(cell + "," + cell),
		"descending order":      `{"cells":[{"cell_id":"b6d362e21dfb6bf9","content_hash":"61LZHLPB+Cv4EwoWqFfPmngd0FlrvXqcJdt/Srgm8hc="},` + cell + `],"scheme":"konareef-mem-src/v1"}`,
		"cell not an object":    wrap(`"81ed77926d26caf9"`),
		"duplicate cell key":    wrap(`{"cell_id":"81ed77926d26caf9","cell_id":"81ed77926d26caf9","content_hash":"RGENbhTgVwEePZRLC1qWk+GgqKThSa1Bg3B5HVGkcYY="}`),
		"trailing garbage cell": wrap(cell + `,{}`),
	} {
		if _, err := ParseSeamMemory(json.RawMessage(raw)); !errors.Is(err, ErrSeamMemoryInvalid) {
			t.Errorf("%s: err = %v, want ErrSeamMemoryInvalid", name, err)
		}
	}
}

// TestReadSeamMemory: an absent key is not present; a present key is
// parsed; a duplicate top-level key is refused.
func TestReadSeamMemory(t *testing.T) {
	write := func(body string) string {
		p := filepath.Join(t.TempDir(), "step-disclosure.json")
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
		return p
	}
	sm, err := ReadSeamMemory(write(`{"index":0,"p":"","r":"","c":0,"model":"m","tool_log":[]}`))
	if err != nil || sm.Present || sm.Cells != nil {
		t.Fatalf("absent: %+v, %v", sm, err)
	}
	sm, err = ReadSeamMemory(write(`{"index":0,"initial_memory":` + validSeamMemory + `}`))
	if err != nil || !sm.Present || len(sm.Cells) != 2 {
		t.Fatalf("present: %+v, %v", sm, err)
	}
	if _, err := ReadSeamMemory(write(`{"initial_memory":` + validSeamMemory + `,"initial_memory":` + validSeamMemory + `}`)); err == nil {
		t.Fatal("a repeated initial_memory key must be refused")
	}
	if _, err := ReadSeamMemory(write(`{"Initial_Memory":` + validSeamMemory + `}`)); err == nil {
		t.Fatal("a case-variant initial_memory key must be refused")
	}
}

// TestFetchLeafTable: the control returns the decoded bytes and sends the
// bearer token; every failure wraps ErrLeafTableFetch and carries no body.
func TestFetchLeafTable(t *testing.T) {
	table, sig := []byte("konareef-mem-leaves/v1 table"), []byte{0x30, 0x44}
	body := func(scheme string) string {
		b, _ := json.Marshal(map[string]string{
			"scheme": scheme, "table": base64.StdEncoding.EncodeToString(table),
			"signature": base64.StdEncoding.EncodeToString(sig),
		})
		return string(b)
	}
	serve := func(status int, resp string) *httptest.Server {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodGet || r.Header.Get("Authorization") != "Bearer tok" {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			w.WriteHeader(status)
			_, _ = w.Write([]byte(resp))
		}))
		t.Cleanup(srv.Close)
		return srv
	}

	srv := serve(http.StatusOK, body(LeafTableScheme))
	gotTable, gotSig, err := FetchLeafTable(context.Background(), srv.URL, "tok")
	if err != nil || string(gotTable) != string(table) || string(gotSig) != string(sig) {
		t.Fatalf("control: %v", err)
	}
	// A v1-labelled response is fetched; the run memory check then refuses
	// the v1 table as MEMORY_LEAF_TABLE_INVALID (konareef-rinit/v2 §3).
	if _, _, err := FetchLeafTable(context.Background(), serve(http.StatusOK, body(LeafTableSchemeV1)).URL, "tok"); err != nil {
		t.Fatalf("v1 label: %v", err)
	}
	if _, _, err := FetchLeafTable(context.Background(), srv.URL, "wrong"); !errors.Is(err, ErrLeafTableFetch) {
		t.Fatalf("wrong token: %v", err)
	}
	for name, s := range map[string]*httptest.Server{
		"404":            serve(http.StatusNotFound, `{"error":"not_found"}`),
		"unknown scheme": serve(http.StatusOK, body("konareef-mem-leaves/v9")),
		"not json":       serve(http.StatusOK, "SECRET-CANARY"),
		"not base64":     serve(http.StatusOK, `{"scheme":"konareef-mem-leaves/v1","table":"!!","signature":"MEQ="}`),
		"empty table":    serve(http.StatusOK, `{"scheme":"konareef-mem-leaves/v1","table":"","signature":"MEQ="}`),
		"oversized":      serve(http.StatusOK, strings.Repeat("a", maxLeafTableResponse+10)),
	} {
		_, _, err := FetchLeafTable(context.Background(), s.URL, "tok")
		if !errors.Is(err, ErrLeafTableFetch) {
			t.Errorf("%s: err = %v, want ErrLeafTableFetch", name, err)
		}
		if err != nil && strings.Contains(err.Error(), "CANARY") {
			t.Errorf("%s: error echoes the body", name)
		}
	}
	if _, _, err := FetchLeafTable(context.Background(), "", "tok"); !errors.Is(err, ErrLeafTableFetch) {
		t.Fatalf("no URL: %v", err)
	}
}

// TestCheckCommittedRInitRefusesUnparseableV2Trailer: before MEM-SEAM, a
// v2 or v3 manifest whose trailer did not parse was read as committing
// nothing (fail open). It is now refused. v1 and magic-less manifests
// still commit nothing, and a parseable trailer still decides.
func TestCheckCommittedRInitRefusesUnparseableV2Trailer(t *testing.T) {
	mp := validManifestParams()
	e20 := canon.EmptyMemoryRoot()
	for _, v := range []string{"v2", "v3"} {
		broken := []byte("#!konareef-toml/" + v + "\n[pod]\nname = \"x\"\n[_commit]\nfields_root = \"garbage\"\n")
		if err := checkCommittedRInit(broken, mp.Models, mp.Tools, mp.CMax, e20); !errors.Is(err, ErrMemoryRootNotCommitted) {
			t.Fatalf("%s broken trailer: err = %v, want ErrMemoryRootNotCommitted", v, err)
		}
		if err := checkCommittedRInit([]byte("#!konareef-toml/"+v+"\n[pod]\n"), mp.Models, mp.Tools, mp.CMax, e20); !errors.Is(err, ErrMemoryRootNotCommitted) {
			t.Fatalf("%s no trailer: err = %v, want ErrMemoryRootNotCommitted", v, err)
		}
	}
	for name, m := range map[string][]byte{"v1": []byte("#!konareef-toml/v1\n[pod]\n"), "no magic": []byte("[pod]\n")} {
		if err := checkCommittedRInit(m, mp.Models, mp.Tools, mp.CMax, e20); err != nil {
			t.Fatalf("%s: err = %v, want nil", name, err)
		}
	}
	if err := checkCommittedRInit(manifestCommitting(t, e20), mp.Models, mp.Tools, mp.CMax, e20); err != nil {
		t.Fatalf("parseable E20 trailer control: %v", err)
	}
}
