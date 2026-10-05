// Copyright 2026 Jerry David Chan, Konareef.ai
// SPDX-License-Identifier: Apache-2.0

// der_gate_test.go — exercise ParseStrict over the 4 shared P1.4
// conformance vectors plus an empty-input smoke check.
//
// The fixture files at testdata/der_gate/ are byte-identical copies
// of reef-core's `test/support/fixtures/der_gate/`; a CI hook
// (`scripts/check_vectors_byte_identical.sh`) asserts the two trees
// never drift.
package identity

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"testing"
)

// vectorManifest mirrors test/support/fixtures/der_gate/vectors.json
// on the reef-core side. Adding a field here without mirroring it
// on the Elixir side will cause the CI byte-identical check to fail.
type vectorManifest struct {
	PubkeyCompressedHex string `json:"pubkey_compressed_hex"`
	DigestHex           string `json:"digest_hex"`
	DigestPreimageUTF8  string `json:"digest_preimage_utf8"`
	Vectors             []struct {
		ID     string `json:"id"`
		SigHex string `json:"sig_hex"`
		Expect string `json:"expect"`
	} `json:"vectors"`
}

func loadVectors(t *testing.T) vectorManifest {
	t.Helper()
	p := filepath.Join("testdata", "der_gate", "vectors.json")
	raw, err := os.ReadFile(p)
	if err != nil {
		t.Fatalf("read vectors.json: %v", err)
	}
	var m vectorManifest
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatalf("parse vectors.json: %v", err)
	}
	return m
}

// TestParseStrict_RejectsEmpty is the smoke check; ParseStrict must
// reject zero-length input rather than panic or return nil-nil-nil.
func TestParseStrict_RejectsEmpty(t *testing.T) {
	_, _, err := ParseStrict(nil)
	if !errors.Is(err, ErrDerGateReject) {
		t.Fatalf("want ErrDerGateReject, got %v", err)
	}
}

// TestParseStrict_ConformanceVectors iterates the 4 shared P1.4
// conformance vectors and asserts the documented outcome for each.
func TestParseStrict_ConformanceVectors(t *testing.T) {
	m := loadVectors(t)
	if len(m.Vectors) == 0 {
		t.Fatal("vectors.json contains zero vectors")
	}
	for _, v := range m.Vectors {
		v := v
		t.Run(v.ID, func(t *testing.T) {
			sig, err := hex.DecodeString(v.SigHex)
			if err != nil {
				t.Fatalf("decode sig_hex: %v", err)
			}
			r, s, err := ParseStrict(sig)
			switch v.Expect {
			case "accept":
				if err != nil {
					t.Fatalf("want accept, got err %v", err)
				}
				if r == nil || s == nil {
					t.Fatalf("want non-nil r,s on accept")
				}
			case "der_gate_reject":
				if !errors.Is(err, ErrDerGateReject) {
					t.Fatalf("want ErrDerGateReject, got %v", err)
				}
			default:
				t.Fatalf("unknown expect %q", v.Expect)
			}
		})
	}
}

// derEncodeRS builds a minimal strict-DER SEQUENCE over positive r,s for the
// range-gate tests. Each INTEGER uses minimal big-endian encoding with a
// leading 0x00 when the high bit is set (to keep the signed INTEGER positive),
// so a structurally-valid signature isolates the r,s ∈ [1,n-1] range gate as
// the sole reason for rejection.
func derEncodeRS(t *testing.T, r, s *big.Int) []byte {
	t.Helper()
	enc := func(v *big.Int) []byte {
		b := v.Bytes()
		if len(b) == 0 {
			b = []byte{0x00}
		}
		if b[0]&0x80 != 0 {
			b = append([]byte{0x00}, b...)
		}
		return append([]byte{0x02, byte(len(b))}, b...)
	}
	body := append(enc(r), enc(s)...)
	return append([]byte{0x30, byte(len(body))}, body...)
}

// TestParseStrict_RejectsOutOfRangeScalars guards the r,s ∈ [1,n-1] gate
// (Check 4 blocker, Hermes !33). A strict-DER, otherwise-canonical signature
// with r >= n (or s >= n) MUST be rejected by ParseStrict — not merely
// classified on the error path — and ClassifyStrictError must report
// rs_out_of_range. Before the fix ParseStrict accepted r == n.
func TestParseStrict_RejectsOutOfRangeScalars(t *testing.T) {
	one := big.NewInt(1)
	nPlus1 := new(big.Int).Add(curveN, one)
	cases := []struct {
		name string
		r, s *big.Int
	}{
		{"r==n", new(big.Int).Set(curveN), one},
		{"r>n", nPlus1, one},
		{"s==n", one, new(big.Int).Set(curveN)},
		{"s>n", one, nPlus1},
	}
	for _, c := range cases {
		c := c
		t.Run(c.name, func(t *testing.T) {
			der := derEncodeRS(t, c.r, c.s)
			if _, _, err := ParseStrict(der); !errors.Is(err, ErrDerGateReject) {
				t.Fatalf("ParseStrict accepted out-of-range %s; want ErrDerGateReject", c.name)
			}
			if got := ClassifyStrictError(der); got != "rs_out_of_range" {
				t.Errorf("ClassifyStrictError(%s)=%q, want rs_out_of_range", c.name, got)
			}
		})
	}
}
