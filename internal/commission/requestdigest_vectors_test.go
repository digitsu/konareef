// Copyright 2026 Jerry David Chan, Konareef.ai
// SPDX-License-Identifier: Apache-2.0

// requestdigest_vectors_test.go — the request_digest vector file,
// testdata/request_digest_v1/vectors.json, meant to be vendored byte for
// byte by reef-core as it vendors admission_v1 (review m3). Each case is a
// string-valued inputs map, its JCS (RFC 8785) serialization and
// SHA-256 of that serialization. The file is generated here and pinned:
// a change to CanonicalInputsJSON that alters any byte fails the test.

package commission

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// requestDigestVectorsPath is the committed vector file.
const requestDigestVectorsPath = "testdata/request_digest_v1/vectors.json"

// requestDigestCase is one vector. Inputs is nil for the omitted-inputs
// case, which the server reads as {}.
type requestDigestCase struct {
	ID            string            `json:"id"`
	Why           string            `json:"why"`
	Inputs        map[string]string `json:"inputs"`
	CanonicalJSON string            `json:"canonical_json"`
	DigestHex     string            `json:"request_digest_hex"`
}

// requestDigestFixture is the whole vector file.
type requestDigestFixture struct {
	Purpose string              `json:"_purpose"`
	Rule    string              `json:"_rule"`
	Cases   []requestDigestCase `json:"cases"`
}

// buildRequestDigestVectors computes every vector with the production
// functions.
func buildRequestDigestVectors(t *testing.T) requestDigestFixture {
	t.Helper()
	inputs := []struct {
		id, why string
		in      map[string]string
	}{
		{"J01", "omitted inputs are read as {}", nil},
		{"J02", "one ASCII pair", map[string]string{"topic": "risky MRs"}},
		{"J03", "keys sort by UTF-16 code units: U+1F600 (surrogates D83D DE00) sorts before U+FB33", map[string]string{"דּ": "1", "\U0001F600": "2", "a": "3", "10": "4", "1": "5"}},
		{"J04", "only quote, backslash and C0 controls are escaped; U+2028, non-ASCII and <>& are written raw", map[string]string{"k": "a\"b\\c\n\u0001 é\b\t\f\r\u001f<>&"}},
		{"J05", "empty key and empty value", map[string]string{"": ""}},
		{"J06", "keys that differ only after a shared prefix", map[string]string{"ab": "x", "a": "y", "abc": "z"}},
	}
	fx := requestDigestFixture{
		Purpose: "request_digest vectors for konareef-commission-admission/v1 (IB-06); vendor byte for byte",
		Rule:    "request_digest = SHA-256(RFC 8785 JCS of inputs); omitted inputs = {}; inputs are a JSON object of strings",
	}
	for _, c := range inputs {
		canonical, err := CanonicalInputsJSON(c.in)
		if err != nil {
			t.Fatalf("%s: %v", c.id, err)
		}
		digest, err := RequestDigest(c.in)
		if err != nil {
			t.Fatalf("%s: %v", c.id, err)
		}
		fx.Cases = append(fx.Cases, requestDigestCase{ID: c.id, Why: c.why, Inputs: c.in,
			CanonicalJSON: string(canonical), DigestHex: hex.EncodeToString(digest[:])})
	}
	return fx
}

// TestRequestDigestVectorsAreCurrent regenerates the vector file and
// requires it to equal the committed copy. Set
// KONAREEF_UPDATE_REQUEST_DIGEST_VECTORS=1 to rewrite it after a reviewed
// change.
func TestRequestDigestVectorsAreCurrent(t *testing.T) {
	fx := buildRequestDigestVectors(t)
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", " ")
	if err := enc.Encode(fx); err != nil {
		t.Fatal(err)
	}
	if os.Getenv("KONAREEF_UPDATE_REQUEST_DIGEST_VECTORS") == "1" {
		if err := os.MkdirAll(filepath.Dir(requestDigestVectorsPath), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(requestDigestVectorsPath, buf.Bytes(), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(requestDigestVectorsPath)
	if err != nil {
		t.Fatalf("read vectors: %v", err)
	}
	if !bytes.Equal(buf.Bytes(), want) {
		t.Fatalf("%s is stale: regenerate with KONAREEF_UPDATE_REQUEST_DIGEST_VECTORS=1 and review the diff", requestDigestVectorsPath)
	}
}

// TestRequestDigestVectorsMatchServerValues pins the cases whose expected
// JCS output reef-core's request_body_test.exs asserts literally, so the
// file cannot drift from the server even before reef-core vendors it.
func TestRequestDigestVectorsMatchServerValues(t *testing.T) {
	raw, err := os.ReadFile(requestDigestVectorsPath)
	if err != nil {
		t.Fatal(err)
	}
	var fx requestDigestFixture
	if err := json.Unmarshal(raw, &fx); err != nil {
		t.Fatal(err)
	}
	server := map[string]string{
		"J01": "{}",
		"J03": `{"1":"5","10":"4","a":"3","` + "\U0001F600" + `":"2","` + "דּ" + `":"1"}`,
	}
	for _, c := range fx.Cases {
		sum := sha256.Sum256([]byte(c.CanonicalJSON))
		if hex.EncodeToString(sum[:]) != c.DigestHex {
			t.Errorf("%s: digest is not SHA-256 of canonical_json", c.ID)
		}
		if want, ok := server[c.ID]; ok && c.CanonicalJSON != want {
			t.Errorf("%s: canonical %s, reef-core expects %s", c.ID, c.CanonicalJSON, want)
		}
	}
}
