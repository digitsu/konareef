package canon

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"
)

type frVectorFile struct {
	Vectors []struct {
		Name       string   `json:"name"`
		Models     []string `json:"models"`
		Tools      []string `json:"tools"`
		CMax       uint64   `json:"c_max"`
		RInit      string   `json:"r_init"`
		FieldsRoot string   `json:"fields_root"`
	} `json:"vectors"`
}

func loadFRVectors(t *testing.T) frVectorFile {
	t.Helper()
	b, err := os.ReadFile("testdata/fields_root_vectors.json")
	if err != nil {
		t.Fatalf("read fields_root vectors: %v", err)
	}
	var f frVectorFile
	if err := json.Unmarshal(b, &f); err != nil {
		t.Fatalf("parse fields_root vectors: %v", err)
	}
	return f
}

func rInit32(t *testing.T, s string) [32]byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil || len(b) != 32 {
		t.Fatalf("bad r_init hex %q", s)
	}
	var out [32]byte
	copy(out[:], b)
	return out
}

// TestFieldsRoot_OracleVectors pins the konareef-toml/v2 fields_root
// construction against golden vectors from the independent Python oracle
// (scripts/poseidon_pallas.py). Covers empty, one-each, mixed, and the
// full MAX_MODELS/MAX_TOOLS caps.
func TestFieldsRoot_OracleVectors(t *testing.T) {
	f := loadFRVectors(t)
	if len(f.Vectors) == 0 {
		t.Fatal("no fields_root vectors")
	}
	for _, v := range f.Vectors {
		got, err := FieldsRoot(v.Models, v.Tools, v.CMax, rInit32(t, v.RInit))
		if err != nil {
			t.Fatalf("%s: FieldsRoot error: %v", v.Name, err)
		}
		if hex.EncodeToString(got[:]) != v.FieldsRoot {
			t.Errorf("%s: FieldsRoot\n got  %x\n want %s", v.Name, got, v.FieldsRoot)
		}
	}
}

// TestFieldsRoot_SortIndependence verifies the fields_root is independent
// of input order (v2 sorts model/tool ids by canonical UTF-8 bytes).
func TestFieldsRoot_SortIndependence(t *testing.T) {
	models := []string{"gpt-4o", "claude-opus-4-8", "llama-3"}
	tools := []string{"write", "search", "read"}
	var r [32]byte
	a, err := FieldsRoot(models, tools, 42, r)
	if err != nil {
		t.Fatalf("FieldsRoot(a): %v", err)
	}
	b, err := FieldsRoot([]string{"llama-3", "gpt-4o", "claude-opus-4-8"}, []string{"read", "write", "search"}, 42, r)
	if err != nil {
		t.Fatalf("FieldsRoot(b): %v", err)
	}
	if a != b {
		t.Errorf("fields_root not order-independent: %x != %x", a, b)
	}
}

// Empty ids must be rejected: an empty id leaf would be indistinguishable
// from the empty-record Z used to pad unused slots (a fixed-max-commitment
// soundness gap). Invalid UTF-8 must be rejected too — the v2 spec commits ids
// as utf8(s) and sorts by canonical UTF-8 bytes, so non-UTF-8 input leaves the
// cross-impl/circuit canonicalization underspecified.
func TestFieldsRoot_RejectsEmptyAndInvalidUTF8Ids(t *testing.T) {
	var r [32]byte
	cases := []struct {
		name          string
		models, tools []string
	}{
		{"empty model id", []string{""}, nil},
		{"empty tool id", nil, []string{""}},
		{"empty among valid models", []string{"gpt-4o", ""}, nil},
		{"invalid utf8 model", []string{"\xff\xfe"}, nil},
		{"invalid utf8 tool", nil, []string{"a\xc3\x28b"}},
	}
	for _, c := range cases {
		if _, err := FieldsRoot(c.models, c.tools, 0, r); err == nil {
			t.Errorf("%s: expected error, got nil", c.name)
		}
	}
}

func TestFieldsRoot_RejectsCapsAndDuplicates(t *testing.T) {
	var r [32]byte
	tooManyModels := make([]string, 17)
	for i := range tooManyModels {
		tooManyModels[i] = string(rune('a' + i))
	}
	if _, err := FieldsRoot(tooManyModels, nil, 0, r); err == nil {
		t.Error("expected error for 17 models (cap 16)")
	}
	tooManyTools := make([]string, 33)
	for i := range tooManyTools {
		tooManyTools[i] = string(rune('a' + i))
	}
	if _, err := FieldsRoot(nil, tooManyTools, 0, r); err == nil {
		t.Error("expected error for 33 tools (cap 32)")
	}
	if _, err := FieldsRoot([]string{"dup", "dup"}, nil, 0, r); err == nil {
		t.Error("expected error for duplicate model")
	}
	if _, err := FieldsRoot(nil, []string{"dup", "dup"}, 0, r); err == nil {
		t.Error("expected error for duplicate tool")
	}
}
