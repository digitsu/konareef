// Copyright 2026 Jerry David Chan, Konareef.ai
// SPDX-License-Identifier: Apache-2.0

// sealed_grants_golden_test.go — golden public head + ciphertext pairs for
// the MCP-C00 accept cases A01–A03, produced by the real packer (Prepare),
// for MCP-C02 and MCP-C03 to replay on the reef-core side.
//
// Each testdata/sealed_grants_golden/<case>/ holds:
//
//	manifest_canonical   the signed head bytes (pod_hash preimage)
//	pod_hash.hex         SHA-256 of manifest_canonical
//	signature.hex        the publisher signature over manifest_canonical
//	publisher_pubkey.hex the throwaway publisher's public key
//	body_enc.bin         AES-256-GCM ciphertext + tag, AAD = raw pod_hash
//	body_enc_nonce.hex   the 12-byte nonce
//	body_key.hex         K_body for THIS fixture only
//
// body_key.hex is a test key that seals public fixture plaintext; it is
// published so the server side can open the body. No publisher private key
// is stored: the identity is generated in memory and dropped.
//
// Regenerate with:
//
//	go test ./internal/publish -run TestSealedGrantsGolden -update-sealed-golden
//
// Without the flag the test checks the stored pairs: the head re-derives
// byte for byte from the fixture inputs, the signature verifies, the body
// opens only under its own pod_hash and carries exactly the fixture grants
// file, and the negative swap/tamper/old-version cases fail.
package publish

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"flag"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/digitsu/konareef/internal/canon"
	"github.com/digitsu/konareef/internal/identity"
	"github.com/digitsu/konareef/internal/pod"
)

var updateSealedGolden = flag.Bool("update-sealed-golden", false, "rewrite testdata/sealed_grants_golden from the real packer")

// sealedGoldenCases maps each golden case to its fixture head and grants.
var sealedGoldenCases = []struct {
	id, head, grants string
}{
	{"A01", "heads/closed-sealed.toml", "grants/valid-one.toml"},
	{"A02", "heads/closed-sealed.toml", "grants/valid-zero.toml"},
	{"A03", "heads/closed-sealed.toml", "grants/valid-two-port-distinct.toml"},
}

// sealedGoldenFixtureDir is the vendored MCP-C00 fixture directory.
const sealedGoldenFixtureDir = "../pod/testdata/sealed_grants/v1"

// sealedGoldenCanaries are the fixture canaries (cases.json).
var sealedGoldenCanaries = []string{"cnry-c00k7q", "cnryc00k7q", "cnry_c00k7q", "cnry_a"}

// buildSealedGoldenPod writes the pod directory a golden case is packed
// from: the fixture head, prompts/task.md, and the fixture grants file.
func buildSealedGoldenPod(t *testing.T, headRel, grantsRel string) (string, []byte) {
	t.Helper()
	dir := t.TempDir()
	head, err := os.ReadFile(filepath.Join(sealedGoldenFixtureDir, headRel))
	if err != nil {
		t.Fatal(err)
	}
	grants, err := os.ReadFile(filepath.Join(sealedGoldenFixtureDir, grantsRel))
	if err != nil {
		t.Fatal(err)
	}
	mustWrite := func(rel string, data []byte) {
		path := filepath.Join(dir, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, data, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	mustWrite("pod.toml", head)
	mustWrite("prompts/task.md", []byte("Do the task.\n"))
	mustWrite(pod.SealedGrantsBodyPath, grants)
	return dir, grants
}

// readGoldenHex reads and hex-decodes one golden file.
func readGoldenHex(t *testing.T, dir, name string) []byte {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(dir, name))
	if err != nil {
		t.Fatalf("read %s: %v (regenerate with -update-sealed-golden)", name, err)
	}
	decoded, err := hex.DecodeString(strings.TrimSpace(string(raw)))
	if err != nil {
		t.Fatalf("%s: %v", name, err)
	}
	return decoded
}

// untarGolden returns the regular files of a gzip tar; directory
// entries are skipped.
func untarGolden(t *testing.T, data []byte) map[string][]byte {
	t.Helper()
	gz, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}
	reader := tar.NewReader(gz)
	files := map[string][]byte{}
	for {
		header, err := reader.Next()
		if err == io.EOF {
			return files
		}
		if err != nil {
			t.Fatal(err)
		}
		if header.Typeflag != tar.TypeReg {
			continue
		}
		content, _ := io.ReadAll(reader)
		files[header.Name] = content
	}
}

// TestSealedGrantsGolden writes (with the flag) or checks the golden pairs.
func TestSealedGrantsGolden(t *testing.T) {
	bodies := map[string]*SealedBody{}
	hashes := map[string][32]byte{}
	for _, tc := range sealedGoldenCases {
		goldenDir := filepath.Join("testdata", "sealed_grants_golden", tc.id)
		podDir, grants := buildSealedGoldenPod(t, tc.head, tc.grants)

		if *updateSealedGolden {
			publisher, err := identity.Generate("sealedfixture")
			if err != nil {
				t.Fatal(err)
			}
			prepared, err := Prepare(podDir, publisher, PrepareOptions{})
			if err != nil {
				t.Fatalf("%s: prepare: %v", tc.id, err)
			}
			if err := os.MkdirAll(goldenDir, 0o755); err != nil {
				t.Fatal(err)
			}
			files := map[string][]byte{
				"manifest_canonical":   prepared.CanonicalBytes,
				"pod_hash.hex":         []byte(hex.EncodeToString(prepared.PodHash[:]) + "\n"),
				"signature.hex":        []byte(hex.EncodeToString(prepared.Signature) + "\n"),
				"publisher_pubkey.hex": []byte(prepared.PublicKeyHex + "\n"),
				"body_enc.bin":         prepared.Sealed.Ciphertext,
				"body_enc_nonce.hex":   []byte(hex.EncodeToString(prepared.Sealed.Nonce) + "\n"),
				"body_key.hex":         []byte(hex.EncodeToString(prepared.Sealed.Key) + "\n"),
			}
			for name, data := range files {
				if err := os.WriteFile(filepath.Join(goldenDir, name), data, 0o644); err != nil {
					t.Fatal(err)
				}
			}
		}

		manifest, err := os.ReadFile(filepath.Join(goldenDir, "manifest_canonical"))
		if err != nil {
			t.Fatalf("%s: %v (regenerate with -update-sealed-golden)", tc.id, err)
		}
		// The head re-derives byte for byte from the fixture inputs.
		rederived, err := canon.Canonicalize(mustReadFile(t, filepath.Join(podDir, "pod.toml")), podDir)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(rederived, manifest) {
			t.Fatalf("%s: golden head no longer matches the canonicalizer output", tc.id)
		}
		podHash := sha256.Sum256(manifest)
		if !bytes.Equal(readGoldenHex(t, goldenDir, "pod_hash.hex"), podHash[:]) {
			t.Fatalf("%s: pod_hash.hex is not sha256(manifest_canonical)", tc.id)
		}
		pubkey := strings.TrimSpace(string(mustReadFile(t, filepath.Join(goldenDir, "publisher_pubkey.hex"))))
		if ok, err := identity.Verify(pubkey, manifest, readGoldenHex(t, goldenDir, "signature.hex")); err != nil || !ok {
			t.Fatalf("%s: signature does not verify: %v", tc.id, err)
		}
		lowered := strings.ToLower(string(manifest))
		for _, canary := range sealedGoldenCanaries {
			if strings.Contains(lowered, canary) {
				t.Fatalf("%s: public head contains canary %q", tc.id, canary)
			}
		}
		if !strings.Contains(string(manifest), `sealed_grants = "konareef-sealed-grants/v1"`) {
			t.Fatalf("%s: head lacks the marker", tc.id)
		}

		sealed := &SealedBody{
			Ciphertext: mustReadFile(t, filepath.Join(goldenDir, "body_enc.bin")),
			Nonce:      readGoldenHex(t, goldenDir, "body_enc_nonce.hex"),
			Key:        readGoldenHex(t, goldenDir, "body_key.hex"),
			Scheme:     BodyEncScheme,
		}
		plain, err := OpenBodyForTest(sealed, podHash[:])
		if err != nil {
			t.Fatalf("%s: body does not open: %v", tc.id, err)
		}
		files := untarGolden(t, plain)
		if len(files) != 2 || !bytes.Equal(files[pod.SealedGrantsBodyPath], grants) {
			t.Fatalf("%s: body file set %v does not carry exactly the fixture grants file", tc.id, keysOf(files))
		}
		bodies[tc.id] = sealed
		hashes[tc.id] = podHash
	}

	// Swap: A01's body does not open under A02's head.
	if _, err := OpenBodyForTest(bodies["A01"], func() []byte { h := hashes["A02"]; return h[:] }()); err == nil {
		t.Fatalf("A01 body opened under A02 pod_hash")
	}
	// Tamper: one flipped ciphertext bit fails authentication.
	tampered := *bodies["A01"]
	tampered.Ciphertext = append([]byte(nil), tampered.Ciphertext...)
	tampered.Ciphertext[len(tampered.Ciphertext)/2] ^= 0x01
	a01Hash := hashes["A01"]
	if _, err := OpenBodyForTest(&tampered, a01Hash[:]); err == nil {
		t.Fatalf("tampered A01 body opened")
	}
	// Old version / downgrade: the same head without the marker is a
	// different pod_hash, so the signature and the AAD both fail.
	manifest := mustReadFile(t, filepath.Join("testdata", "sealed_grants_golden", "A01", "manifest_canonical"))
	stripped := bytes.Replace(manifest, []byte("sealed_grants = \"konareef-sealed-grants/v1\"\n"), nil, 1)
	if bytes.Equal(stripped, manifest) {
		t.Fatalf("marker line not found in A01 head")
	}
	strippedHash := sha256.Sum256(stripped)
	if _, err := OpenBodyForTest(bodies["A01"], strippedHash[:]); err == nil {
		t.Fatalf("A01 body opened under the marker-stripped head")
	}
	pubkey := strings.TrimSpace(string(mustReadFile(t, filepath.Join("testdata", "sealed_grants_golden", "A01", "publisher_pubkey.hex"))))
	signature := readGoldenHex(t, filepath.Join("testdata", "sealed_grants_golden", "A01"), "signature.hex")
	if ok, _ := identity.Verify(pubkey, stripped, signature); ok {
		t.Fatalf("signature verified over the marker-stripped head")
	}
}

// mustReadFile reads a file or fails the test.
func mustReadFile(t *testing.T, path string) []byte {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

// keysOf returns the keys of a file map, for failure messages.
func keysOf(files map[string][]byte) []string {
	var keys []string
	for key := range files {
		keys = append(keys, key)
	}
	return keys
}
