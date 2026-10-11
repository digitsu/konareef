// Copyright 2026 Jerry David Chan, Konareef.ai
// SPDX-License-Identifier: Apache-2.0

package commission

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"

	"github.com/digitsu/konareef/internal/envelope"
)

// commissionVector is one golden vector: fixed inputs and the canonical
// bytes and h_commission they must produce.
type commissionVector struct {
	Name        string   `json:"name"`
	Why         string   `json:"why"`
	Models      []string `json:"models"`
	Tools       []string `json:"tools"`
	Labels      []string `json:"labels"`
	CMax        uint64   `json:"c_max"`
	PodRef      string   `json:"pod_ref"`
	HManifest   string   `json:"h_manifest"`
	Prose       string   `json:"prose"`
	Canonical   string   `json:"canonical"`
	HCommission string   `json:"h_commission"`
}

// commissionVectorFile is testdata/commission_vectors.json.
type commissionVectorFile struct {
	Vectors []commissionVector `json:"vectors"`
}

// loadCommissionVectors reads the golden vector file.
func loadCommissionVectors(t *testing.T) commissionVectorFile {
	t.Helper()
	b, err := os.ReadFile("testdata/commission_vectors.json")
	if err != nil {
		t.Fatalf("read commission vectors: %v", err)
	}
	var f commissionVectorFile
	if err := json.Unmarshal(b, &f); err != nil {
		t.Fatalf("parse commission vectors: %v", err)
	}
	return f
}

// hManifest32 decodes a vector's 64-hex-character h_manifest.
func hManifest32(t *testing.T, s string) [32]byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil || len(b) != 32 {
		t.Fatalf("bad h_manifest hex %q", s)
	}
	var out [32]byte
	copy(out[:], b)
	return out
}

// proposalFromVector rebuilds the proposal a vector describes. Every
// presence flag is set, because the canonical form excludes them by design
// (see canonicalProposal's doc comment) and a vector must not depend on a
// value the encoding does not carry.
func proposalFromVector(t *testing.T, v commissionVector) Proposal {
	t.Helper()
	return Proposal{
		Envelope: envelope.Envelope{
			Models: v.Models, ModelsSet: true,
			Tools: v.Tools, ToolsSet: true,
			Labels: v.Labels, LabelsSet: true,
			CMax: v.CMax, CMaxSet: true,
		},
		Binding: Binding{PodRef: v.PodRef, HManifest: hManifest32(t, v.HManifest)},
		Prose:   v.Prose,
	}
}

// TestCommissionGoldenVectors pins the canonical encoding and h_commission
// against fixed values (spec §10.5).
//
// Every other hash test in this package is self-relative: it compares one
// Canonical() call against another, or one digest against a second digest of
// a mutated input. All of those stay green if the encoding itself changes —
// if a cbor keyasint tag number moves, or a field is added or reordered.
// That change would alter every h_commission the system has ever produced
// and invalidate every signature already issued against one, silently.
//
// These vectors are the tripwire. A failure here is not necessarily a bug;
// it means the wire format moved, and someone has to decide deliberately
// whether that was intended and what happens to commissions signed under the
// old encoding. Do not regenerate the file to make this pass.
func TestCommissionGoldenVectors(t *testing.T) {
	f := loadCommissionVectors(t)
	if len(f.Vectors) == 0 {
		t.Fatal("no commission vectors")
	}
	for _, v := range f.Vectors {
		t.Run(v.Name, func(t *testing.T) {
			p := proposalFromVector(t, v)

			canonical, err := p.Canonical()
			if err != nil {
				t.Fatalf("Canonical: %v", err)
			}
			if got := hex.EncodeToString(canonical); got != v.Canonical {
				t.Errorf("canonical encoding moved\n got  %s\n want %s\n(%s)", got, v.Canonical, v.Why)
			}

			h, err := p.HCommission()
			if err != nil {
				t.Fatalf("HCommission: %v", err)
			}
			if got := hex.EncodeToString(h[:]); got != v.HCommission {
				t.Errorf("h_commission moved\n got  %s\n want %s\n(%s)", got, v.HCommission, v.Why)
			}
		})
	}
}

// TestCommissionGoldenVectors_NormalisationIsPartOfTheContract asserts the
// property the 'typical' and 'unsorted_with_duplicates' vectors encode
// between them: two proposals that permit the same things hash identically
// however they were written. Stating it as its own test means the pair
// cannot be quietly broken by editing one vector's expected digest.
func TestCommissionGoldenVectors_NormalisationIsPartOfTheContract(t *testing.T) {
	f := loadCommissionVectors(t)
	byName := make(map[string]commissionVector, len(f.Vectors))
	for _, v := range f.Vectors {
		byName[v.Name] = v
	}
	sorted, ok := byName["typical"]
	if !ok {
		t.Fatal("vector 'typical' is missing")
	}
	unsorted, ok := byName["unsorted_with_duplicates"]
	if !ok {
		t.Fatal("vector 'unsorted_with_duplicates' is missing")
	}
	if sorted.HCommission != unsorted.HCommission {
		t.Fatalf("the two vectors describe the same permitted sets, so their pinned "+
			"h_commission values must be equal:\n typical  %s\n unsorted %s",
			sorted.HCommission, unsorted.HCommission)
	}
	if sorted.Canonical != unsorted.Canonical {
		t.Fatalf("the two vectors must also pin identical canonical bytes:\n typical  %s\n unsorted %s",
			sorted.Canonical, unsorted.Canonical)
	}
}
