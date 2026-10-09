// Copyright 2026 Jerry David Chan, Konareef.ai
// SPDX-License-Identifier: Apache-2.0

// internal/saltstore/conformance_test.go — runs the 5 P1.7.1 vectors
// from testdata/vectors/v1.json. Mirrors the per-id dispatch pattern
// used by internal/membridge/conformance_test.go.
package saltstore

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"log"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type vectorFile struct {
	Vectors []rawVector `json:"vectors"`
}

type rawVector struct {
	ID          string          `json:"id"`
	Description string          `json:"description"`
	Inputs      json.RawMessage `json:"inputs"`
	Expected    json.RawMessage `json:"expected"`
	Notes       string          `json:"notes,omitempty"`
}

func TestConformanceVectors(t *testing.T) {
	path := filepath.Join("testdata", "vectors", "v1.json")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read vectors: %v", err)
	}
	var vf vectorFile
	if err := json.Unmarshal(raw, &vf); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(vf.Vectors) != 5 {
		t.Fatalf("expected 5 vectors, got %d", len(vf.Vectors))
	}
	for _, v := range vf.Vectors {
		v := v
		t.Run(v.ID, func(t *testing.T) { runVector(t, v) })
	}
}

func runVector(t *testing.T, v rawVector) {
	switch v.ID {
	case "saltstore-blob-roundtrip-canonical":
		runRoundTripCanonical(t, v)
	case "saltstore-blob-wrong-passphrase-reject":
		runWrongPassphraseReject(t, v)
	case "saltstore-blob-tampered-rejects":
		runTamperedRejects(t, v)
	case "saltstore-resolver-fallthrough-decision":
		runResolverFallthrough(t, v)
	case "saltstore-multi-lineage-roundtrip":
		runMultiLineageRoundTrip(t, v)
	default:
		t.Fatalf("unknown vector id: %s", v.ID)
	}
}

// paddedSaltHex left-pads s with leading zeros to exactly 64 hex
// characters so vector authors can write a friendlier (shorter) salt
// while the runner still derives a deterministic 32-byte value.
func paddedSaltHex(s string) string {
	if len(s) >= 64 {
		return s[:64]
	}
	return strings.Repeat("0", 64-len(s)) + s
}

func runRoundTripCanonical(t *testing.T, v rawVector) {
	var in struct {
		Passphrase  string `json:"passphrase"`
		LineageID   string `json:"lineage_id"`
		Salt        string `json:"salt"`
		KDFSalt     string `json:"kdf_salt"`
		Nonce       string `json:"nonce"`
		Iterations  uint32 `json:"iterations"`
		MemoryKiB   uint32 `json:"memory_kib"`
		Parallelism uint32 `json:"parallelism"`
		CreatedAt   uint64 `json:"created_at"`
	}
	var exp struct {
		Magic            string `json:"magic"`
		Version          string `json:"version"`
		KDFParams        string `json:"kdf_params"`
		KDFSalt          string `json:"kdf_salt"`
		Nonce            string `json:"nonce"`
		DerivedKey       string `json:"derived_key"`
		AAD              string `json:"aad"`
		PlaintextCBOR    string `json:"plaintext_cbor"`
		CiphertextAndTag string `json:"ciphertext_and_tag"`
		FinalBlob        string `json:"final_blob"`
	}
	mustJSON(t, v.Inputs, &in)
	mustJSON(t, v.Expected, &exp)

	saltBytes := mustHexBytes(t, paddedSaltHex(in.Salt))
	var salt [32]byte
	copy(salt[:], saltBytes)
	var lid [16]byte
	copy(lid[:], mustHexBytes(t, in.LineageID))

	blob, err := SealBlobDeterministic(
		[]Entry{{LineageID: lid, Salt: salt}},
		[]byte(in.Passphrase),
		KDFParams{Iterations: in.Iterations, MemoryKiB: in.MemoryKiB, Parallelism: in.Parallelism},
		in.CreatedAt,
		mustHexBytes(t, in.KDFSalt),
		mustHexBytes(t, in.Nonce),
	)
	if err != nil {
		t.Fatalf("SealBlobDeterministic: %v", err)
	}
	got := hex.EncodeToString(blob)
	if got != exp.FinalBlob {
		t.Fatalf("final_blob mismatch\n got: %s\nwant: %s", got, exp.FinalBlob)
	}
	// Decrypt and assert byte-equality of inputs.
	entries, err := ImportBlob(blob, []byte(in.Passphrase))
	if err != nil {
		t.Fatalf("ImportBlob: %v", err)
	}
	if len(entries) != 1 || entries[0].LineageID != lid || entries[0].Salt != salt {
		t.Errorf("decrypt round-trip mismatch")
	}
}

func runWrongPassphraseReject(t *testing.T, v rawVector) {
	var in struct {
		FinalBlob  string `json:"final_blob"`
		Passphrase string `json:"passphrase"`
	}
	var exp struct {
		ErrorCode string `json:"error_code"`
	}
	mustJSON(t, v.Inputs, &in)
	mustJSON(t, v.Expected, &exp)
	_, err := ImportBlob(mustHexBytes(t, in.FinalBlob), []byte(in.Passphrase))
	if !errors.Is(err, ErrSaltBlobDecrypt) || Code(err) != exp.ErrorCode {
		t.Fatalf("err = %v (code=%s), want code=%s", err, Code(err), exp.ErrorCode)
	}
}

func runTamperedRejects(t *testing.T, v rawVector) {
	canonicalHex := "4b5253414c5430310102000000004000000100000000112233445566778899aabbccddeeff0123456789abcdef012345678024f36010ea1bca1f5b292a47a9924f51f7504df4cae75da00111ed2d36bd288b1d2c01edb4767eb91be1c88ed5234995fee5c5721c010d5f19c99bcb973a3781739bfafea783f53ddb8ff2a599980f2726280180ea4f0187fe53f64691d1b4af38e852abad619ffab3d06c31c2"
	blob := mustHexBytes(t, canonicalHex)
	var in struct {
		Offset     int    `json:"final_blob_tampered_offset"`
		Passphrase string `json:"passphrase"`
	}
	var exp struct {
		ErrorCode string `json:"error_code"`
	}
	mustJSON(t, v.Inputs, &in)
	mustJSON(t, v.Expected, &exp)
	blob[in.Offset] ^= 0xFF
	_, err := ImportBlob(blob, []byte(in.Passphrase))
	if !errors.Is(err, ErrSaltBlobDecrypt) || Code(err) != exp.ErrorCode {
		t.Fatalf("err = %v (code=%s), want code=%s", err, Code(err), exp.ErrorCode)
	}
}

func runResolverFallthrough(t *testing.T, v rawVector) {
	var in struct {
		KErr *string `json:"k_available_err"`
		EErr *string `json:"e_available_err"`
		PErr *string `json:"p_available_err"`
	}
	var exp struct {
		PickedName    string   `json:"picked_name"`
		LogSubstrings []string `json:"log_substrings"`
	}
	mustJSON(t, v.Inputs, &in)
	mustJSON(t, v.Expected, &exp)

	mk := func(name string, errStr *string) Backend {
		m := NewMockBackend()
		if errStr != nil {
			m.AvailableErr = errors.New(*errStr)
		}
		return namedMock{m: m, name: name}
	}
	var buf bytes.Buffer
	orig := log.Writer()
	log.SetOutput(&buf)
	defer log.SetOutput(orig)
	b, err := resolveFrom([]Backend{
		mk("keychain", in.KErr),
		mk("encrypted-file", in.EErr),
		mk("plain-file", in.PErr),
	})
	if err != nil {
		t.Fatalf("resolveFrom: %v", err)
	}
	if b.Name() != exp.PickedName {
		t.Errorf("picked = %q, want %q", b.Name(), exp.PickedName)
	}
	for _, want := range exp.LogSubstrings {
		if !strings.Contains(buf.String(), want) {
			t.Errorf("log missing %q\nlog:\n%s", want, buf.String())
		}
	}
}

func runMultiLineageRoundTrip(t *testing.T, v rawVector) {
	var in struct {
		Passphrase string `json:"passphrase"`
		Entries    []struct {
			LineageID string `json:"lineage_id"`
			Salt      string `json:"salt"` // single-byte hex; replicated to 32 B
		} `json:"entries"`
	}
	var exp struct {
		EntryCount     int  `json:"entry_count"`
		OrderPreserved bool `json:"order_preserved"`
	}
	mustJSON(t, v.Inputs, &in)
	mustJSON(t, v.Expected, &exp)

	entries := make([]Entry, 0, len(in.Entries))
	for _, e := range in.Entries {
		var lid [16]byte
		copy(lid[:], mustHexBytes(t, e.LineageID))
		var s [32]byte
		b, err := hex.DecodeString(e.Salt)
		if err != nil || len(b) != 1 {
			t.Fatalf("salt hex must be 1 byte for replication, got %q", e.Salt)
		}
		for i := range s {
			s[i] = b[0]
		}
		entries = append(entries, Entry{LineageID: lid, Salt: s})
	}
	// Use the test KDF params for speed (the multi-lineage vector
	// asserts logical equality, not byte-exact output).
	blob, err := ExportBlobWithParams(entries, []byte(in.Passphrase), TestKDFParams, 1717977600)
	if err != nil {
		t.Fatalf("ExportBlobWithParams: %v", err)
	}
	got, err := ImportBlob(blob, []byte(in.Passphrase))
	if err != nil {
		t.Fatalf("ImportBlob: %v", err)
	}
	if len(got) != exp.EntryCount {
		t.Errorf("len = %d, want %d", len(got), exp.EntryCount)
	}
	for i := range entries {
		if got[i] != entries[i] {
			t.Errorf("entry[%d] order/content mismatch", i)
		}
	}
}

func mustJSON(t *testing.T, raw json.RawMessage, into any) {
	t.Helper()
	if err := json.Unmarshal(raw, into); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
}

func mustHexBytes(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("hex %q: %v", s, err)
	}
	return b
}
