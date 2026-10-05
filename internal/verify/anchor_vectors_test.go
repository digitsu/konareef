// Copyright 2026 Jerry David Chan, Konareef.ai
// SPDX-License-Identifier: Apache-2.0

// anchor_vectors_test.go — the recorded cross-repo chain-head anchor
// vector (testdata/anchor/chain-head-anchor-vectors-v1.json).
//
// The vector is synthetic: a fixed test identity key, a fixed head hash,
// a three-transaction block mined at the test difficulty. reef-core
// carries a byte copy and checks that its Elixir code parses the same
// BEEF, builds the same statement and anchor map, and verifies the same
// signature. Regenerate with KONAREEF_REGEN_ANCHOR_VECTORS=1; the bytes
// are deterministic (RFC 6979 signatures, first-nonce mining).
package verify

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/fxamacker/cbor/v2"

	"github.com/digitsu/konareef/internal/spv"
	"github.com/digitsu/konareef/internal/spv/spvtest"
)

// anchorVector is the JSON shape of the recorded vector.
type anchorVector struct {
	Comment       string `json:"comment"`
	IdentityKey   string `json:"identity_key_hex"`
	Invoice       string `json:"invoice"`
	DerivedKey    string `json:"derived_key_hex"`
	HeadHash      string `json:"head_hash_hex"`
	HeadTimestamp string `json:"head_timestamp"`
	VkeyHash      string `json:"vkey_hash_hex"`
	LastStep      string `json:"last_step_public_inputs_hex"`
	ProofDigest   string `json:"proof_digest_hex"`
	RawTx         string `json:"raw_tx_hex"`
	Txid          string `json:"txid_hex"`
	Vout          uint64 `json:"vout"`
	Bump          string `json:"bump_hex"`
	BlockHeight   uint64 `json:"block_height"`
	MerkleRoot    string `json:"merkle_root_internal_hex"`
	Header        string `json:"header_hex"`
	AtomicBEEFV1  string `json:"atomic_beef_v1_hex"`
	AtomicBEEFV2  string `json:"atomic_beef_v2_hex"`
	Statement     string `json:"statement_hex"`
	Sig           string `json:"sig_der_hex"`
	AnchorCBOR    string `json:"chain_head_anchor_cbor_hex"`
}

// anchorVectorPath is the recorded vector file.
var anchorVectorPath = filepath.Join("testdata", "anchor", "chain-head-anchor-vectors-v1.json")

// buildAnchorVector computes the vector from its fixed inputs.
func buildAnchorVector(t *testing.T) anchorVector {
	t.Helper()
	key := spvtest.TestIdentityPrivateKey()
	identity := key.PubKey().SerializeCompressed()
	derived, err := spv.DeriveAnyonePublicKey(identity, AnchorInvoice())
	if err != nil {
		t.Fatal(err)
	}
	head := sha256.Sum256([]byte("chain-head-anchor vector head"))
	vkey := sha256.Sum256([]byte("chain-head-anchor vector vkey"))
	lastStep := make([]byte, publicInputsWidth)
	for i := range lastStep {
		lastStep[i] = byte(i)
	}
	digest := sha256.Sum256(lastStep)
	rawTx := spvtest.BuildTx(0x5a, []spvtest.Output{
		{Satoshis: 1000, Script: []byte{0x76, 0xa9}},
		{Satoshis: 0, Script: spv.OpReturnScript(head[:])},
	})
	const headTime = "2026-09-26T12:00:00.000000Z"
	ch := spvtest.BuildChain(rawTx, anchorBlockHeight, 1_790_000_000+600, 0)
	txid := spv.Reverse32(ch.TxID)
	statement := AnchorStatement(txid[:], 1, head[:], vkey[:], lastStep)
	sig := spvtest.SignAnyone(key, AnchorInvoice(), statement)
	beef := spvtest.AtomicBEEFV1(rawTx, ch.BUMP)
	enc, err := cbor.CoreDetEncOptions().EncMode()
	if err != nil {
		t.Fatal(err)
	}
	anchorCBOR, err := enc.Marshal(map[string]any{
		"txid": txid[:], "vout": uint64(1), "beef": beef, "block_height": uint64(anchorBlockHeight),
		"attestation": map[string]any{
			"identity_key": identity, "protocol": AnchorProtocol, "key_id": AnchorKeyID, "sig": sig,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	return anchorVector{
		Comment:       "Synthetic chain-head anchor vector (reef-core#76). The identity key is the test key SHA-256(\"konareef chain-head anchor test identity\"); never use it for anything else.",
		IdentityKey:   hex.EncodeToString(identity),
		Invoice:       AnchorInvoice(),
		DerivedKey:    hex.EncodeToString(derived),
		HeadHash:      hex.EncodeToString(head[:]),
		HeadTimestamp: headTime,
		VkeyHash:      hex.EncodeToString(vkey[:]),
		LastStep:      hex.EncodeToString(lastStep),
		ProofDigest:   hex.EncodeToString(digest[:]),
		RawTx:         hex.EncodeToString(rawTx),
		Txid:          hex.EncodeToString(txid[:]),
		Vout:          1,
		Bump:          hex.EncodeToString(ch.BUMP),
		BlockHeight:   anchorBlockHeight,
		MerkleRoot:    hex.EncodeToString(ch.Root[:]),
		Header:        hex.EncodeToString(ch.Header[:]),
		AtomicBEEFV1:  hex.EncodeToString(beef),
		AtomicBEEFV2:  hex.EncodeToString(spvtest.AtomicBEEFV2(rawTx, ch.BUMP)),
		Statement:     hex.EncodeToString(statement),
		Sig:           hex.EncodeToString(sig),
		AnchorCBOR:    hex.EncodeToString(anchorCBOR),
	}
}

func TestAnchorVector_RecordedBytesMatch(t *testing.T) {
	want := buildAnchorVector(t)
	if os.Getenv("KONAREEF_REGEN_ANCHOR_VECTORS") == "1" {
		out, _ := json.MarshalIndent(want, "", "  ")
		if err := os.MkdirAll(filepath.Dir(anchorVectorPath), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(anchorVectorPath, append(out, '\n'), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	raw, err := os.ReadFile(anchorVectorPath)
	if err != nil {
		t.Fatalf("recorded vector missing (regenerate with KONAREEF_REGEN_ANCHOR_VECTORS=1): %v", err)
	}
	var got anchorVector
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Fatalf("recorded vector differs from the computed one; regenerate and re-vendor into reef-core")
	}

	// The recorded bytes check out with the verifier's own parsers.
	beefBytes, _ := hex.DecodeString(got.AtomicBEEFV1)
	a, err := spv.ParseAtomicBEEF(beefBytes)
	if err != nil {
		t.Fatal(err)
	}
	root, err := a.SubjectBUMP().ComputeRoot(a.Subject)
	if err != nil || hex.EncodeToString(root[:]) != got.MerkleRoot {
		t.Fatalf("root %v", err)
	}
	headerBytes, _ := hex.DecodeString(got.Header)
	h, _ := spv.ParseHeader(headerBytes)
	if h.MerkleRoot != root || h.CheckWork(spvtest.TestMaxTarget) != nil {
		t.Fatal("header")
	}
	identity, _ := hex.DecodeString(got.IdentityKey)
	sig, _ := hex.DecodeString(got.Sig)
	statement, _ := hex.DecodeString(got.Statement)
	if err := verifyAnchorSignature(identity, sig, statement); err != nil {
		t.Fatalf("recorded signature: %v", err)
	}
}
