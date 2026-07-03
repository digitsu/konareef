package poseidon

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"
)

// oracleVectors is a broad differential corpus generated from the paygate-zk
// Python oracle (scripts/poseidon_pallas.py, byte-identical to neptune 13.0.0).
// It exercises canonical edge fields (0, 1, 2, p-1) and every value_hash chunk
// boundary (0/1/30/31/32/61/62/63/92/93 bytes) that the artifact's small
// self_test_vectors do not cover. Regenerate via the command in
// testdata/oracle_vectors.json's _generator note if the params ever change.
type oracleVectors struct {
	Internal []struct {
		L string `json:"l"`
		R string `json:"r"`
		H string `json:"h"`
	} `json:"internal"`
	Value []struct {
		Payload string `json:"payload"`
		VH      string `json:"vh"`
		LH      string `json:"lh"`
	} `json:"value"`
	Record []struct {
		RB string `json:"rb"`
		RF string `json:"rf"`
	} `json:"record"`
	TRoot []struct {
		Recs []string `json:"recs"`
		Root string   `json:"root"`
	} `json:"troot"`
}

func loadOracle(t *testing.T) oracleVectors {
	t.Helper()
	b, err := os.ReadFile("testdata/oracle_vectors.json")
	if err != nil {
		t.Fatalf("read oracle vectors: %v", err)
	}
	var ov oracleVectors
	if err := json.Unmarshal(b, &ov); err != nil {
		t.Fatalf("parse oracle vectors: %v", err)
	}
	return ov
}

func TestInternalHash_OracleDifferential(t *testing.T) {
	ov := loadOracle(t)
	p := Default()
	if len(ov.Internal) < 40 {
		t.Fatalf("expected a broad corpus, got only %d internal vectors", len(ov.Internal))
	}
	for i, v := range ov.Internal {
		got, err := p.InternalHash(hexLE32(t, v.L), hexLE32(t, v.R))
		if err != nil {
			t.Fatalf("internal %d: %v", i, err)
		}
		if hex.EncodeToString(got[:]) != v.H {
			t.Errorf("internal %d: InternalHash(%s,%s)\n got  %x\n want %s", i, v.L, v.R, got, v.H)
		}
	}
}

func TestValueHashLeafHash_OracleDifferential(t *testing.T) {
	ov := loadOracle(t)
	p := Default()
	if len(ov.Value) < 30 {
		t.Fatalf("expected a broad corpus, got only %d value vectors", len(ov.Value))
	}
	for i, v := range ov.Value {
		payload, err := hex.DecodeString(v.Payload)
		if err != nil {
			t.Fatalf("value %d: bad payload hex: %v", i, err)
		}
		gotVH, err := p.ValueHash(payload)
		if err != nil {
			t.Fatalf("value %d: ValueHash: %v", i, err)
		}
		if hex.EncodeToString(gotVH[:]) != v.VH {
			t.Errorf("value %d (len=%d): ValueHash\n got  %x\n want %s", i, len(payload), gotVH, v.VH)
		}
		gotLH, err := p.LeafHash(gotVH)
		if err != nil {
			t.Fatalf("value %d: LeafHash: %v", i, err)
		}
		if hex.EncodeToString(gotLH[:]) != v.LH {
			t.Errorf("value %d (len=%d): LeafHash\n got  %x\n want %s", i, len(payload), gotLH, v.LH)
		}
	}
}
