package poseidon

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"testing"
)

// artifactDoc mirrors the subset of the pinned Poseidon parameter artifact that
// the conformance tests read: the self-test golden vectors and the empty-subtree
// roots. The production loader (params.go) parses the instance parameters; the
// tests parse only the vectors so they validate behaviour, not the loader's view.
type artifactDoc struct {
	Modulus         string `json:"modulus"`
	SelfTestVectors struct {
		Node []struct {
			L              string `json:"l"`
			R              string `json:"r"`
			InternalHashLE string `json:"internal_hash_le_hex"`
		} `json:"node"`
		Value []struct {
			PayloadHex  string `json:"payload_hex"`
			LeafHashLE  string `json:"leaf_hash_le_hex"`
			ValueHashLE string `json:"value_hash_le_hex"`
		} `json:"value"`
	} `json:"self_test_vectors"`
	EmptyRootsLE []string `json:"empty_roots_le_hex"`
}

func loadVectors(t *testing.T) artifactDoc {
	t.Helper()
	var doc artifactDoc
	if err := json.Unmarshal(embeddedParamsJSON, &doc); err != nil {
		t.Fatalf("unmarshal embedded artifact: %v", err)
	}
	return doc
}

func hexLE32(t *testing.T, s string) [32]byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("bad hex %q: %v", s, err)
	}
	if len(b) != 32 {
		t.Fatalf("expected 32 bytes, got %d for %q", len(b), s)
	}
	var out [32]byte
	copy(out[:], b)
	return out
}

// The pinned artifact must be byte-identical to the source of truth in
// paygate-zk (docs/prds/konareef-pod-step-v1-poseidon-params-v1.json). This
// mirrors the Rust param_drift_gate.rs discipline: if the embedded params drift,
// every downstream hash silently diverges, so we fail loud at the source.
func TestParamArtifactDriftGate(t *testing.T) {
	sum := sha256.Sum256(embeddedParamsJSON)
	got := hex.EncodeToString(sum[:])
	if got != ParamArtifactSHA256 {
		t.Fatalf("param artifact drift:\n got  %s\n want %s", got, ParamArtifactSHA256)
	}
}

func TestInternalHash_NodeSelfTestVectors(t *testing.T) {
	doc := loadVectors(t)
	p := Default()
	if len(doc.SelfTestVectors.Node) == 0 {
		t.Fatal("no node self-test vectors in artifact")
	}
	for i, v := range doc.SelfTestVectors.Node {
		l := hexLE32(t, v.L)
		r := hexLE32(t, v.R)
		want := hexLE32(t, v.InternalHashLE)
		got, err := p.InternalHash(l, r)
		if err != nil {
			t.Fatalf("vector %d: InternalHash error: %v", i, err)
		}
		if got != want {
			t.Errorf("vector %d: InternalHash(%s, %s)\n got  %x\n want %x", i, v.L, v.R, got, want)
		}
	}
}

func TestValueHashAndLeafHash_SelfTestVectors(t *testing.T) {
	doc := loadVectors(t)
	p := Default()
	if len(doc.SelfTestVectors.Value) == 0 {
		t.Fatal("no value self-test vectors in artifact")
	}
	for i, v := range doc.SelfTestVectors.Value {
		payload, err := hex.DecodeString(v.PayloadHex)
		if err != nil {
			t.Fatalf("vector %d: bad payload hex: %v", i, err)
		}
		wantVH := hexLE32(t, v.ValueHashLE)
		wantLH := hexLE32(t, v.LeafHashLE)

		gotVH, err := p.ValueHash(payload)
		if err != nil {
			t.Fatalf("vector %d: ValueHash error: %v", i, err)
		}
		if gotVH != wantVH {
			t.Errorf("vector %d: ValueHash(%q)\n got  %x\n want %x", i, v.PayloadHex, gotVH, wantVH)
		}

		gotLH, err := p.LeafHash(gotVH)
		if err != nil {
			t.Fatalf("vector %d: LeafHash error: %v", i, err)
		}
		if gotLH != wantLH {
			t.Errorf("vector %d: LeafHash(ValueHash(%q))\n got  %x\n want %x", i, v.PayloadHex, gotLH, wantLH)
		}
	}
}

func TestEmptyRoots_SelfTestVectors(t *testing.T) {
	doc := loadVectors(t)
	p := Default()
	got := p.EmptyRoots()
	if len(got) != len(doc.EmptyRootsLE) {
		t.Fatalf("EmptyRoots len = %d, want %d", len(got), len(doc.EmptyRootsLE))
	}
	for i, want := range doc.EmptyRootsLE {
		if got[i] != hexLE32(t, want) {
			t.Errorf("EmptyRoots[%d]\n got  %x\n want %s", i, got[i], want)
		}
	}
}

// Non-canonical wire inputs (integer >= p) must be rejected, matching the
// Python oracle's parse_field guard.
func TestInternalHash_RejectsNonCanonical(t *testing.T) {
	p := Default()
	var allFF [32]byte
	for i := range allFF {
		allFF[i] = 0xff // 0xff..ff > p, non-canonical
	}
	if _, err := p.InternalHash(allFF, [32]byte{}); err == nil {
		t.Error("expected error for non-canonical left input, got nil")
	}
}
