// Copyright 2026 Jerry David Chan, Konareef.ai
// SPDX-License-Identifier: Apache-2.0

// wire_test.go — byte parity of the production wire encoder (EncodeWireV1)
// with the admission_v1 vectors that reef-core also vendors, the §5.6
// sign-time limits, and the request_digest (JCS) rules.

package commission

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/digitsu/konareef/internal/envelope"
	"github.com/digitsu/konareef/internal/identity"
)

// loadAdmissionFixture reads the committed admission_v1 vectors.
func loadAdmissionFixture(t *testing.T) admissionFixture {
	t.Helper()
	raw, err := os.ReadFile(admissionFixturePath)
	if err != nil {
		t.Fatal(err)
	}
	var fx admissionFixture
	if err := json.Unmarshal(raw, &fx); err != nil {
		t.Fatal(err)
	}
	return fx
}

// TestEncodeWireV1MatchesAdmissionVectors requires the production encoder
// to reproduce every vector's wire bytes that it can produce at all, and to
// refuse the rest only where the server refuses them before authorization
// (a bad signature, Q4, or bad semantics, Q5). Every admit case must be
// reproduced byte for byte.
func TestEncodeWireV1MatchesAdmissionVectors(t *testing.T) {
	fx := loadAdmissionFixture(t)
	encoded, refused := 0, 0
	admits := map[string]bool{}
	for _, c := range fx.Cases {
		wire, err := hex.DecodeString(c.WireHex)
		if err != nil {
			t.Fatalf("%s: wire hex: %v", c.ID, err)
		}
		w, code := decodeWireV1(wire)
		if code != "" {
			continue // not a v1 wire envelope; nothing to reproduce
		}
		p, code := decodeCanonicalV1(w.canonical)
		if code != "" {
			continue // not canonical; the encoder cannot produce it
		}
		got, err := EncodeWireV1(Reconstruct(p, hex.EncodeToString(w.pubKey), w.sig))
		if err != nil {
			refused++
			if c.Expect.Verdict != "refuse" || (c.Expect.Code != "commission_signature_invalid" && c.Expect.Code != "commission_invalid") {
				t.Errorf("%s: encoder refused (%v), but the server expects %s %s", c.ID, err, c.Expect.Verdict, c.Expect.Code)
			}
			continue
		}
		encoded++
		if !bytes.Equal(got, wire) {
			t.Errorf("%s: encoder output differs from the vector\n got  %x\n want %s", c.ID, got, c.WireHex)
		}
		switch c.Expect.Code {
		case "commission_too_large", "commission_malformed", "commission_version_unsupported",
			"commission_noncanonical", "commission_signature_invalid", "commission_invalid":
			t.Errorf("%s: encoder produced wire bytes the server refuses at decode (%s)", c.ID, c.Expect.Code)
		}
		if c.Expect.Verdict == "admit" {
			admits[c.ID] = true
			hc, err := Reconstruct(p, hex.EncodeToString(w.pubKey), w.sig).HCommissionHex()
			if err != nil || hc != c.Expect.HCommission {
				t.Errorf("%s: HCommissionHex = %s, %v; want %s", c.ID, hc, err, c.Expect.HCommission)
			}
		}
	}
	for _, c := range fx.Cases {
		if c.Expect.Verdict == "admit" && !admits[c.ID] {
			t.Errorf("%s: admit case was not reproduced by the encoder", c.ID)
		}
	}
	if encoded < 30 || refused == 0 {
		t.Fatalf("encoded %d cases and refused %d; the fixture should exercise both", encoded, refused)
	}
	t.Logf("encoded %d vectors byte for byte; refused %d (Q4/Q5 refusals)", encoded, refused)
}

// TestEncodeWireV1ResignsAdmitVectors signs each admit case's proposal with
// the fixture key again, through commission.Sign, and requires the same
// wire bytes: RFC 6979 signing is deterministic, so the CLI path from a
// signed artifact to wire bytes is reproducible.
func TestEncodeWireV1ResignsAdmitVectors(t *testing.T) {
	fx := loadAdmissionFixture(t)
	keys := map[string]fixtureKey{}
	for _, k := range fx.Keys {
		keys[k.PublicKeyHex] = k
	}
	n := 0
	for _, c := range fx.Cases {
		if c.Expect.Verdict != "admit" {
			continue
		}
		wire, _ := hex.DecodeString(c.WireHex)
		w, _ := decodeWireV1(wire)
		p, _ := decodeCanonicalV1(w.canonical)
		k := keys[hex.EncodeToString(w.pubKey)]
		signed, err := Sign(p, &identity.Identity{PrivateKeyHex: k.PrivateKeyHex, PublicKeyHex: k.PublicKeyHex})
		if err != nil {
			t.Fatalf("%s: sign: %v", c.ID, err)
		}
		got, err := EncodeWireV1(signed)
		if err != nil {
			t.Fatalf("%s: encode: %v", c.ID, err)
		}
		if !bytes.Equal(got, wire) {
			t.Errorf("%s: re-signed wire differs from the vector", c.ID)
		}
		n++
	}
	if n == 0 {
		t.Fatal("no admit cases")
	}
}

// controlCommission returns a signed commission that EncodeWireV1 accepts,
// and the key that signed it.
func controlCommission(t *testing.T) (Commission, *identity.Identity) {
	t.Helper()
	_, id := testKey("wire-test", "account-1", "active")
	p := Proposal{
		Envelope: envelope.Envelope{Models: []string{"anthropic/claude-sonnet-4-5"}, Tools: []string{"bash"},
			CMax: 100, ModelsSet: true, ToolsSet: true, LabelsSet: true, CMaxSet: true},
		Binding: Binding{PodRef: "dave/pod@1.0.0", HManifest: sha256.Sum256([]byte("manifest"))},
		Prose:   "control",
	}
	c, err := Sign(p, id)
	if err != nil {
		t.Fatal(err)
	}
	return c, id
}

// TestEncodeWireV1Refusals checks the successful control and each refusal:
// an unsigned or tampered artifact, a presence-flag tamper, a bad key and a
// high-S signature never reach the wire.
func TestEncodeWireV1Refusals(t *testing.T) {
	c, _ := controlCommission(t)
	if _, err := EncodeWireV1(c); err != nil {
		t.Fatalf("control: %v", err)
	}

	p := c.Proposal()
	cases := map[string]Commission{
		"unsigned":          Reconstruct(p, c.PubKeyHex, nil),
		"tampered prose":    Reconstruct(Proposal{Envelope: p.Envelope, Binding: p.Binding, Prose: "other"}, c.PubKeyHex, c.Sig),
		"presence tampered": Reconstruct(Proposal{Envelope: envelope.Envelope{Models: p.Envelope.Models, Tools: p.Envelope.Tools, CMax: p.Envelope.CMax, ModelsSet: true, ToolsSet: true, CMaxSet: true}, Binding: p.Binding, Prose: p.Prose}, c.PubKeyHex, c.Sig),
		"uncompressed key":  Reconstruct(p, "04"+strings.Repeat("00", 64), c.Sig),
		"high-S signature":  Reconstruct(p, c.PubKeyHex, highS(t, c.Sig)),
	}
	for name, bad := range cases {
		if _, err := EncodeWireV1(bad); !errors.Is(err, ErrWireEncode) {
			t.Errorf("%s: err = %v, want ErrWireEncode", name, err)
		}
	}
}

// TestSignAppliesAdmissionLimits checks each §5.6 limit at sign time, next
// to a proposal exactly at the limit that signs.
func TestSignAppliesAdmissionLimits(t *testing.T) {
	c, id := controlCommission(t)
	base := c.Proposal()
	elems := func(n, size int) []string {
		out := make([]string, n)
		for i := range out {
			out[i] = strings.Repeat("x", size-4) + string(rune('a'+i/676%26)) + string(rune('a'+i/26%26)) + string(rune('a'+i%26)) + "z"
		}
		return out
	}
	with := func(f func(*Proposal)) Proposal {
		p := base
		f(&p)
		return p
	}
	accepted := map[string]Proposal{
		"prose at the limit":    with(func(p *Proposal) { p.Prose = strings.Repeat("x", MaxProseBytes) }),
		"64 models":             with(func(p *Proposal) { p.Envelope.Models = elems(MaxModelElements, 8) }),
		"element of 256 bytes":  with(func(p *Proposal) { p.Envelope.Tools = []string{strings.Repeat("t", MaxElementBytes)} }),
		"pod_ref of 256 bytes":  with(func(p *Proposal) { p.Binding.PodRef = "d/" + strings.Repeat("p", MaxPodRefBytes-8) + "@1.0.0" }),
		"stated-empty labels":   with(func(p *Proposal) { p.Envelope.Labels = []string{} }),
		"duplicates normalised": with(func(p *Proposal) { p.Envelope.Tools = []string{"bash", "bash"} }),
	}
	for name, p := range accepted {
		if _, err := Sign(p, id); err != nil {
			t.Errorf("%s: sign refused: %v", name, err)
		}
	}
	refused := map[string]struct {
		p    Proposal
		want error
	}{
		"prose over the limit":   {with(func(p *Proposal) { p.Prose = strings.Repeat("x", MaxProseBytes+1) }), ErrOverAdmissionLimit},
		"65 models":              {with(func(p *Proposal) { p.Envelope.Models = elems(MaxModelElements+1, 8) }), ErrOverAdmissionLimit},
		"257 tools":              {with(func(p *Proposal) { p.Envelope.Tools = elems(MaxToolElements+1, 8) }), ErrOverAdmissionLimit},
		"257 labels":             {with(func(p *Proposal) { p.Envelope.Labels = elems(MaxLabelElements+1, 8) }), ErrOverAdmissionLimit},
		"element of 257 bytes":   {with(func(p *Proposal) { p.Envelope.Tools = []string{strings.Repeat("t", MaxElementBytes+1)} }), ErrOverAdmissionLimit},
		"pod_ref of 257 bytes":   {with(func(p *Proposal) { p.Binding.PodRef = "d/" + strings.Repeat("p", MaxPodRefBytes-7) + "@1.0.0" }), ErrOverAdmissionLimit},
		"empty element":          {with(func(p *Proposal) { p.Envelope.Tools = []string{"bash", ""} }), ErrEmptySetElement},
		"invalid UTF-8 prose":    {with(func(p *Proposal) { p.Prose = "R\xffview" }), ErrNotUTF8},
		"wire over 32768 bytes":  {with(func(p *Proposal) { p.Envelope.Tools = elems(200, 200) }), ErrOverAdmissionLimit},
		"invalid UTF-8 in a set": {with(func(p *Proposal) { p.Envelope.Labels = []string{"\xff"} }), ErrNotUTF8},
	}
	for name, tc := range refused {
		if _, err := Sign(tc.p, id); !errors.Is(err, tc.want) {
			t.Errorf("%s: sign err = %v, want %v", name, err, tc.want)
		}
		if err := ValidateSignable(tc.p); !errors.Is(err, tc.want) {
			t.Errorf("%s: ValidateSignable err = %v, want %v", name, err, tc.want)
		}
	}
}

// TestRequestDigestMatchesServerJCS pins the JCS rules against the values
// reef-core's RequestBody tests assert, and the omitted-inputs rule.
func TestRequestDigestMatchesServerJCS(t *testing.T) {
	empty := sha256.Sum256([]byte("{}"))
	for _, inputs := range []map[string]string{nil, {}} {
		got, err := RequestDigest(inputs)
		if err != nil || got != empty {
			t.Errorf("RequestDigest(%v) = %x, %v; want SHA-256(\"{}\")", inputs, got, err)
		}
	}

	cases := []struct {
		inputs map[string]string
		want   string
	}{
		// UTF-16 order: U+1F600 (surrogates D83D DE00) sorts before U+FB33.
		{map[string]string{"דּ": "1", "\U0001F600": "2", "a": "3", "10": "4", "1": "5"},
			`{"1":"5","10":"4","a":"3","` + "\U0001F600" + `":"2","` + "דּ" + `":"1"}`},
		// Only quote, backslash and control characters are escaped.
		{map[string]string{"k": "a\"b\\c\n\u0001 é\b\t\f\r\u001f<>&"},
			`{"k":"a\"b\\c\n\u0001` + " é" + `\b\t\f\r\u001f<>&"}`},
	}
	for _, tc := range cases {
		got, err := CanonicalInputsJSON(tc.inputs)
		if err != nil || string(got) != tc.want {
			t.Errorf("CanonicalInputsJSON = %s, %v; want %s", got, err, tc.want)
		}
		digest, _ := RequestDigest(tc.inputs)
		if digest != sha256.Sum256([]byte(tc.want)) {
			t.Errorf("RequestDigest is not SHA-256 of the canonical JSON")
		}
	}

	if _, err := RequestDigest(map[string]string{"k": "\xff"}); !errors.Is(err, ErrInputsNotUTF8) {
		t.Errorf("invalid UTF-8 value: err = %v, want ErrInputsNotUTF8", err)
	}
}

// TestAdmissionLimitsReportShapeBeforeSize: a proposal that is both
// malformed and oversize is reported as malformed, so an
// ErrOverAdmissionLimit always means "valid, only too large" (review m4).
func TestAdmissionLimitsReportShapeBeforeSize(t *testing.T) {
	c, _ := controlCommission(t)
	p := c.Proposal()
	p.Prose = strings.Repeat("x", MaxProseBytes+1)
	p.Envelope.Tools = []string{"bash", ""}
	if err := ValidateAdmissionLimits(p); !errors.Is(err, ErrEmptySetElement) || errors.Is(err, ErrOverAdmissionLimit) {
		t.Fatalf("err = %v, want ErrEmptySetElement only", err)
	}
}
