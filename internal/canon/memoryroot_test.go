// Copyright 2026 Jerry David Chan, Konareef.ai
// SPDX-License-Identifier: Apache-2.0

// memoryroot_test.go — the r_init_scheme trailer marker (MEM-00 D2-A), the
// E20 memory-free value (D1-A) and the R-M17 classifier, checked against
// the shared MEM-01 fixture testdata/memory_root_v1_vectors.json. That
// file is a byte-exact copy of paygate-zk
// docs/prds/konareef-memory-root-v1-vectors.json (paygate-zk main ecd6232);
// PS-1's preflight and reef-core MEM-02 read the same cases.
package canon

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// memoryRootVectors is the subset of the shared MEM-01 fixture this
// package checks.
type memoryRootVectors struct {
	Encoding []struct {
		Name      string `json:"name"`
		LEHex     string `json:"le_hex"`
		Canonical bool   `json:"canonical"`
	} `json:"encoding"`
	MemoryFree struct {
		RInitV1         string `json:"r_init_v1"`
		RInitLegacyZero string `json:"r_init_legacy_zero"`
	} `json:"memory_free"`
	FieldsRoot []struct {
		Name         string   `json:"name"`
		Models       []string `json:"models"`
		Tools        []string `json:"tools"`
		CMax         uint64   `json:"c_max"`
		FieldsRootV1 string   `json:"fields_root_v1"`
		FieldsRootLZ string   `json:"fields_root_legacy_zero"`
	} `json:"fields_root"`
	CommitClassification struct {
		Cases []struct {
			Name        string   `json:"name"`
			Models      []string `json:"models"`
			Tools       []string `json:"tools"`
			CMax        uint64   `json:"c_max"`
			Committed   string   `json:"committed_fields_root"`
			RInitScheme *string  `json:"r_init_scheme"`
			RInit       string   `json:"r_init"`
			Class       string   `json:"class"`
			PS1         string   `json:"ps1"`
		} `json:"cases"`
	} `json:"commit_classification"`
}

// loadMemoryRootVectors reads the shared fixture. Input: the test. Output:
// the decoded vectors; the test fails on any read or decode error.
func loadMemoryRootVectors(t *testing.T) memoryRootVectors {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", "memory_root_v1_vectors.json"))
	if err != nil {
		t.Fatalf("read shared MEM-01 fixture: %v", err)
	}
	var v memoryRootVectors
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatalf("decode shared MEM-01 fixture: %v", err)
	}
	return v
}

// hex32 decodes a 64-hex string into 32 bytes or fails the test.
func hex32(t *testing.T, s string) [32]byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil || len(b) != 32 {
		t.Fatalf("bad 32-byte hex %q", s)
	}
	var out [32]byte
	copy(out[:], b)
	return out
}

// manifestWithTrailer returns a minimal v2 manifest whose trailer is the
// given raw text (everything after the `[_commit]` header line).
func manifestWithTrailer(trailer string) []byte {
	return []byte("#!konareef-toml/v2\n[pod]\nname = \"x\"\n[_files]\n[_commit]\n" + trailer)
}

// TestEmptyMemoryRootIsSharedE20 pins EmptyMemoryRoot to the fixture's
// r_init_v1 and to its canonical `e20` encoding case.
func TestEmptyMemoryRootIsSharedE20(t *testing.T) {
	v := loadMemoryRootVectors(t)
	e20 := EmptyMemoryRoot()
	if got := hex.EncodeToString(e20[:]); got != v.MemoryFree.RInitV1 {
		t.Fatalf("EmptyMemoryRoot = %s, fixture r_init_v1 = %s", got, v.MemoryFree.RInitV1)
	}
	for _, e := range v.Encoding {
		root := hex32(t, e.LEHex)
		_, err := FieldsRoot(nil, nil, 0, root)
		if e.Canonical && err != nil {
			t.Errorf("encoding %s is canonical but FieldsRoot refused it: %v", e.Name, err)
		}
		if !e.Canonical && !isCode(err, ErrCommitNonCanonicalRInit) {
			t.Errorf("encoding %s is non-canonical; FieldsRoot err = %v, want %s", e.Name, err, ErrCommitNonCanonicalRInit)
		}
	}
}

// TestFieldsRootMemoryFreeConventionsMatchSharedFixture reproduces the
// fixture's fields_root under both memory-free conventions.
func TestFieldsRootMemoryFreeConventionsMatchSharedFixture(t *testing.T) {
	v := loadMemoryRootVectors(t)
	if len(v.FieldsRoot) < 2 {
		t.Fatalf("fixture has %d fields_root cases, want at least 2", len(v.FieldsRoot))
	}
	for _, c := range v.FieldsRoot {
		v1, err := FieldsRoot(c.Models, c.Tools, c.CMax, EmptyMemoryRoot())
		if err != nil {
			t.Fatalf("%s: FieldsRoot(E20): %v", c.Name, err)
		}
		lz, err := FieldsRoot(c.Models, c.Tools, c.CMax, [32]byte{})
		if err != nil {
			t.Fatalf("%s: FieldsRoot(0): %v", c.Name, err)
		}
		if hex.EncodeToString(v1[:]) != c.FieldsRootV1 || hex.EncodeToString(lz[:]) != c.FieldsRootLZ {
			t.Fatalf("%s: v1=%x legacy=%x, fixture v1=%s legacy=%s", c.Name, v1, lz, c.FieldsRootV1, c.FieldsRootLZ)
		}
	}
}

// TestClassifyMemoryRootMatchesSharedFixture runs every
// commit_classification case through the real trailer bytes: the case is
// rendered with CommitTrailerBytes (or, for the unknown scheme, written by
// hand, since the emitter refuses it), parsed back with
// ParseCommitTrailer, and classified. The `refused_scheme_unknown` class
// must surface as the coded COMMIT_RINIT_SCHEME_UNKNOWN parse error.
func TestClassifyMemoryRootMatchesSharedFixture(t *testing.T) {
	v := loadMemoryRootVectors(t)
	cases := v.CommitClassification.Cases
	if len(cases) < 5 {
		t.Fatalf("fixture has %d classification cases, want at least 5", len(cases))
	}
	for _, c := range cases {
		t.Run(c.Name, func(t *testing.T) {
			root := hex32(t, c.Committed)
			trailer := "fields_root = \"poseidon:" + c.Committed + "\"\n"
			if c.RInitScheme != nil {
				trailer += "r_init_scheme = \"" + *c.RInitScheme + "\"\n"
			}
			parsed, err := ParseCommitTrailer(manifestWithTrailer(trailer))
			if c.Class == "refused_scheme_unknown" {
				if !isCode(err, ErrCommitRInitSchemeUnknown) {
					t.Fatalf("err = %v, want %s", err, ErrCommitRInitSchemeUnknown)
				}
				if strings.Contains(err.Error(), *c.RInitScheme) {
					t.Fatal("the refusal must not echo the untrusted scheme value")
				}
				return
			}
			if err != nil {
				t.Fatalf("ParseCommitTrailer: %v", err)
			}
			if parsed.FieldsRoot != root {
				t.Fatalf("parsed root %x, want %x", parsed.FieldsRoot, root)
			}
			if !bytes.Equal(CommitTrailerBytes(parsed), []byte("[_commit]\n"+trailer)) {
				t.Fatalf("trailer does not round-trip:\n got %q\nwant %q", CommitTrailerBytes(parsed), "[_commit]\n"+trailer)
			}
			class, err := ClassifyMemoryRoot(parsed, c.Models, c.Tools, c.CMax)
			if err != nil {
				t.Fatalf("ClassifyMemoryRoot: %v", err)
			}
			if string(class) != c.Class {
				t.Fatalf("class = %s, fixture %s", class, c.Class)
			}
			// The populated case also carries the r_init the root was built
			// from; recomputing it binds the fixture to FieldsRoot.
			if c.RInit != "" {
				fr, err := FieldsRoot(c.Models, c.Tools, c.CMax, hex32(t, c.RInit))
				if err != nil || fr != root {
					t.Fatalf("FieldsRoot over fixture r_init = %x (%v), committed %x", fr, err, root)
				}
			}
		})
	}
}

// TestClassifyMemoryRootWithoutMarkerIsUnrecognized covers the one class
// the shared fixture does not: no marker and neither memory-free root.
// A marker beside the zero root is still legacy zero (control).
func TestClassifyMemoryRootWithoutMarkerIsUnrecognized(t *testing.T) {
	models, tools := []string{"openai/gpt-4o"}, []string{"bash"}
	populated, err := FieldsRoot(models, tools, 1000, hex32(t, "86ec05dda6bd85f65f477160a7cddee1bb0f7e4b1775d09f1b9c88009ee2871f"))
	if err != nil {
		t.Fatal(err)
	}
	if got, _ := ClassifyMemoryRoot(CommitTrailer{FieldsRoot: populated}, models, tools, 1000); got != MemoryRootUnrecognized {
		t.Fatalf("no marker, populated root: class = %s, want %s", got, MemoryRootUnrecognized)
	}
	if got, _ := ClassifyMemoryRoot(CommitTrailer{FieldsRoot: populated, RInitScheme: RInitSchemeV1}, models, tools, 1000); got != NotMemoryFree {
		t.Fatalf("marker, populated root: class = %s, want %s", got, NotMemoryFree)
	}
	zero, _ := FieldsRoot(models, tools, 1000, [32]byte{})
	if got, _ := ClassifyMemoryRoot(CommitTrailer{FieldsRoot: zero, RInitScheme: RInitSchemeV1}, models, tools, 1000); got != MemoryFreeLegacyZero {
		t.Fatalf("marker, zero root: class = %s, want %s", got, MemoryFreeLegacyZero)
	}
	if _, err := ClassifyMemoryRoot(CommitTrailer{}, []string{"a", "a"}, nil, 0); err == nil {
		t.Fatal("a duplicate model must surface FieldsRoot's refusal, not a class")
	}
}

// TestCanonicalizeV2EmitsRInitSchemeMarker is the D2-A emitter test: with
// the v1 scheme the trailer carries the marker line after fields_root, and
// the whole document round-trips through ParseCommitTrailer and
// CanonicalizeLike to identical bytes. With no scheme the legacy trailer
// is unchanged byte for byte (control). An unknown scheme is refused.
func TestCanonicalizeV2EmitsRInitSchemeMarker(t *testing.T) {
	dir := t.TempDir()
	input := []byte("#!konareef-toml/v1\n[pod]\nname = \"x\"\n")
	e20 := EmptyMemoryRoot()

	marked, err := CanonicalizeV2(input, dir, CommitParams{CMax: 7, RInit: e20, RInitScheme: RInitSchemeV1})
	if err != nil {
		t.Fatalf("CanonicalizeV2(v1 scheme): %v", err)
	}
	want, _ := FieldsRoot(nil, nil, 7, e20)
	wantTail := "[_commit]\nfields_root = \"poseidon:" + hex.EncodeToString(want[:]) + "\"\nr_init_scheme = \"konareef-rinit/v1\"\n"
	if !bytes.HasSuffix(marked, []byte(wantTail)) {
		t.Fatalf("marked trailer:\n got %q\nwant suffix %q", marked, wantTail)
	}
	tr, err := ParseCommitTrailer(marked)
	if err != nil || tr.FieldsRoot != want || tr.RInitScheme != RInitSchemeV1 {
		t.Fatalf("ParseCommitTrailer = %+v, %v", tr, err)
	}
	if fr, err := ParseCommitFieldsRoot(marked); err != nil || fr != want {
		t.Fatalf("ParseCommitFieldsRoot must accept the marker: %x, %v", fr, err)
	}
	again, err := CanonicalizeLike(input, dir, marked)
	if err != nil || !bytes.Equal(again, marked) {
		t.Fatalf("CanonicalizeLike must reproduce the marked manifest byte for byte (err %v)", err)
	}

	legacy, err := CanonicalizeV2(input, dir, CommitParams{CMax: 7})
	if err != nil {
		t.Fatal(err)
	}
	lroot, _ := FieldsRoot(nil, nil, 7, [32]byte{})
	if !bytes.HasSuffix(legacy, CommitSectionBytes(lroot)) || bytes.Contains(legacy, []byte("r_init_scheme")) {
		t.Fatalf("legacy trailer changed: %q", legacy)
	}
	if again, err := CanonicalizeLike(input, dir, legacy); err != nil || !bytes.Equal(again, legacy) {
		t.Fatalf("CanonicalizeLike must keep reproducing legacy manifests (err %v)", err)
	}

	if _, err := CanonicalizeV2(input, dir, CommitParams{CMax: 7, RInit: e20, RInitScheme: "konareef-rinit/v9"}); !isCode(err, ErrCommitRInitSchemeUnknown) {
		t.Fatalf("unknown scheme: err = %v, want %s", err, ErrCommitRInitSchemeUnknown)
	}
}

// TestParseCommitTrailerMarkerGrammar covers the marker cases the PS-1
// parser also covers: either key order parses; a duplicate marker, an
// empty or unquoted marker and a third key refuse; an unknown value
// refuses with the coded error. A reordered trailer parses but does not
// reproduce its own bytes through CommitTrailerBytes, which is what makes
// install's pod_hash check fail closed on it.
func TestParseCommitTrailerMarkerGrammar(t *testing.T) {
	root := strings.Repeat("ab", 32)
	fr := "fields_root = \"poseidon:" + root + "\"\n"
	mk := "r_init_scheme = \"konareef-rinit/v1\"\n"

	for name, trailer := range map[string]string{
		"canonical order": fr + mk,
		"marker first":    mk + fr,
		"no marker":       fr,
	} {
		tr, err := ParseCommitTrailer(manifestWithTrailer(trailer))
		if err != nil {
			t.Errorf("%s: %v", name, err)
			continue
		}
		if hex.EncodeToString(tr.FieldsRoot[:]) != root {
			t.Errorf("%s: root %x", name, tr.FieldsRoot)
		}
		roundTrip := bytes.Equal(CommitTrailerBytes(tr), []byte("[_commit]\n"+trailer))
		if (name == "marker first") == roundTrip {
			t.Errorf("%s: round-trip = %v", name, roundTrip)
		}
	}

	for name, trailer := range map[string]string{
		"duplicate marker":   fr + mk + mk,
		"unquoted marker":    fr + "r_init_scheme = konareef-rinit/v1\n",
		"third key":          fr + mk + "salt = \"00\"\n",
		"marker only":        mk,
		"marker not a value": fr + "r_init_scheme\n",
	} {
		if _, err := ParseCommitTrailer(manifestWithTrailer(trailer)); err == nil {
			t.Errorf("%s: parsed; want a refusal", name)
		}
	}

	// PS-1 parity: an empty marker is an unknown scheme, and a malformed
	// fields_root is reported before an unknown scheme.
	if _, err := ParseCommitTrailer(manifestWithTrailer(fr + "r_init_scheme = \"\"\n")); !isCode(err, ErrCommitRInitSchemeUnknown) {
		t.Fatalf("empty marker: err = %v, want %s", err, ErrCommitRInitSchemeUnknown)
	}
	if _, err := ParseCommitTrailer(manifestWithTrailer("fields_root = \"poseidon:XYZ\"\n" + "r_init_scheme = \"konareef-rinit/v9\"\n")); err == nil || isCode(err, ErrCommitRInitSchemeUnknown) {
		t.Fatalf("malformed root + unknown scheme: err = %v, want the malformed-trailer error", err)
	}
	_, err := ParseCommitTrailer(manifestWithTrailer(fr + "r_init_scheme = \"konareef-rinit/v9\"\n"))
	if !isCode(err, ErrCommitRInitSchemeUnknown) {
		t.Fatalf("unknown scheme: err = %v, want %s", err, ErrCommitRInitSchemeUnknown)
	}
	if _, err := ParseCommitFieldsRoot(manifestWithTrailer(fr + "r_init_scheme = \"konareef-rinit/v9\"\n")); !isCode(err, ErrCommitRInitSchemeUnknown) {
		t.Fatalf("ParseCommitFieldsRoot must refuse an unknown scheme too: %v", err)
	}
}

// isCode reports whether err is a canon *Error with the given code.
func isCode(err error, code string) bool {
	var ce *Error
	return errors.As(err, &ce) && ce.Code == code
}

// TestRInitSchemeV2Accepted covers konareef-rinit/v2 R-M29: the emitter
// writes the v2 marker, the parser accepts it and the trailer round-trips,
// and the classifier reads a populated root under the v2 marker as
// NotMemoryFree (a memory-free root stays memory-free under either marker).
func TestRInitSchemeV2Accepted(t *testing.T) {
	dir := t.TempDir()
	input := []byte("#!konareef-toml/v1\n[pod]\nname = \"x\"\n")
	populatedRInit := hex32(t, "86ec05dda6bd85f65f477160a7cddee1bb0f7e4b1775d09f1b9c88009ee2871f")

	marked, err := CanonicalizeV2(input, dir, CommitParams{CMax: 7, RInit: populatedRInit, RInitScheme: RInitSchemeV2})
	if err != nil {
		t.Fatalf("CanonicalizeV2(v2 scheme): %v", err)
	}
	want, _ := FieldsRoot(nil, nil, 7, populatedRInit)
	wantTail := "[_commit]\nfields_root = \"poseidon:" + hex.EncodeToString(want[:]) + "\"\nr_init_scheme = \"konareef-rinit/v2\"\n"
	if !bytes.HasSuffix(marked, []byte(wantTail)) {
		t.Fatalf("v2 trailer:\n got %q\nwant suffix %q", marked, wantTail)
	}
	tr, err := ParseCommitTrailer(marked)
	if err != nil || tr.FieldsRoot != want || tr.RInitScheme != RInitSchemeV2 {
		t.Fatalf("ParseCommitTrailer = %+v, %v", tr, err)
	}
	if again, err := CanonicalizeLike(input, dir, marked); err != nil || !bytes.Equal(again, marked) {
		t.Fatalf("CanonicalizeLike must reproduce the v2-marked manifest byte for byte (err %v)", err)
	}
	if got, _ := ClassifyMemoryRoot(tr, nil, nil, 7); got != NotMemoryFree {
		t.Fatalf("v2 marker, populated root: class = %s, want %s", got, NotMemoryFree)
	}
	free, _ := FieldsRoot(nil, nil, 7, EmptyMemoryRoot())
	if got, _ := ClassifyMemoryRoot(CommitTrailer{FieldsRoot: free, RInitScheme: RInitSchemeV2}, nil, nil, 7); got != MemoryFreeRInitV1 {
		t.Fatalf("v2 marker, E20 root: class = %s, want %s", got, MemoryFreeRInitV1)
	}
}
