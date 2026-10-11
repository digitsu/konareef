// Copyright 2026 Jerry David Chan, Konareef.ai
// SPDX-License-Identifier: Apache-2.0

package listing

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"testing"
)

// goldenFixture is the shared cross-repo parity fixture. reef-core's
// canonical_test.exs pins the same field values.
var goldenFixture = Fields{
	Revision:       Revision(1),
	Handle:         "alice",
	PodName:        "research-bot",
	AuthorFeeSats:  500,
	ExecutionClass: "cloud",
	Category:       "research",
	Description:    "Summarizes a research question.",
}

// mustCanonical renders f and fails the test if it is rejected. Used by
// the layout tests, whose fixtures are all valid by construction.
func mustCanonical(t *testing.T, f Fields, op Operation) []byte {
	t.Helper()
	got, err := Canonical(f, op)
	if err != nil {
		t.Fatalf("Canonical(%+v, %q): unexpected error: %v", f, op, err)
	}
	return got
}

// Digest-level parity anchor. reef-core's canonical_test.exs pins the
// same three values in its "matches the cross-repo golden digest" test,
// so a silent divergence between the two encoders fails loudly on both
// sides instead of surviving until someone eyeballs the two files side
// by side. Changing any of these means the two implementations no
// longer agree on what publishers sign.
//
// Field ORDER is the most likely way the two drift: `category` comes
// BEFORE `display_description`, which is neither alphabetical nor the
// order the design prose lists them in. Reordering two fields leaves
// the length unchanged, so the length check alone would not catch it —
// that is what the digest is for.
func TestCanonicalGoldenDigest(t *testing.T) {
	// Both operations are pinned. Pinning only upsert would leave the
	// delist domain free to drift between the two repos unnoticed.
	cases := map[Operation]struct {
		wantLen    int
		wantSHA256 string
	}{
		OpUpsert: {167, "41e30d21b9d0d11bf97bf198e7bdc5f8287f5096a0f2faf6f39bd49a98270556"},
		OpDelist: {167, "f304454828a2e910207c09dd29fa3a346305ce9a41f1193f6c2fac00fca538a7"},
	}
	for op, want := range cases {
		t.Run(string(op), func(t *testing.T) {
			got := mustCanonical(t, goldenFixture, op)

			if len(got) != want.wantLen {
				t.Errorf("len(Canonical) = %d, want %d", len(got), want.wantLen)
			}
			if sum := hex.EncodeToString(sha256digest(got)); sum != want.wantSHA256 {
				t.Errorf("sha256(Canonical) = %s, want %s", sum, want.wantSHA256)
			}
			// 0x2e is '.', the final byte of the description — proof
			// there is no trailing newline at the digest level too.
			if last := got[len(got)-1]; last != 0x2e {
				t.Errorf("last byte = 0x%02x, want 0x2e ('.')", last)
			}
		})
	}
}

func sha256digest(b []byte) []byte {
	sum := sha256.Sum256(b)
	return sum[:]
}

// Byte-parity anchor with reef-core lib/pod/listings/canonical.ex — the
// exact same expected string appears in that repo's canonical_test.exs.
func TestCanonicalByteLayout(t *testing.T) {
	want := "op\tupsert\n" +
		"revision\t1\n" +
		"handle\talice\n" +
		"pod_name\tresearch-bot\n" +
		"author_fee_sats\t500\n" +
		"execution_class\tcloud\n" +
		"category\tresearch\n" +
		"display_description\tSummarizes a research question."

	if got := string(mustCanonical(t, goldenFixture, OpUpsert)); got != want {
		t.Errorf("Canonical mismatch:\n got: %q\nwant: %q", got, want)
	}
}

// The preimage must never carry a trailing newline: reef-core re-derives
// these bytes and hashes them, so a stray "\n" on either side silently
// breaks every listing signature.
func TestCanonicalHasNoTrailingNewline(t *testing.T) {
	got := string(mustCanonical(t, Fields{Revision: Revision(1), Handle: "alice", PodName: "research-bot"}, OpUpsert))
	if got[len(got)-1] == '\n' {
		t.Errorf("Canonical ends with a newline: %q", got)
	}
}

// Empty optional fields still emit their line — the field set is fixed,
// so the server can re-derive the preimage from the stored row without
// knowing which fields the publisher happened to fill in.
func TestCanonicalEmitsEveryFieldEvenWhenEmpty(t *testing.T) {
	want := "op\tupsert\n" +
		"revision\t0\n" +
		"handle\t\n" +
		"pod_name\t\n" +
		"author_fee_sats\t0\n" +
		"execution_class\t\n" +
		"category\t\n" +
		"display_description\t"

	if got := string(mustCanonical(t, Fields{Revision: Revision(0)}, OpUpsert)); got != want {
		t.Errorf("Canonical mismatch:\n got: %q\nwant: %q", got, want)
	}
}

// THE property that fixes the replay vulnerability.
//
// upsert and delist previously signed a byte-identical preimage, so a
// captured PUT body replayed to DELETE verified perfectly and took the
// listing down — no key compromise required, an access log or a proxy
// was enough, and the publisher's corrective PUT returned 200 while the
// row stayed delisted. The preimages must differ for identical field
// values, and they must differ in the DIGEST (not merely in length), so
// assert it directly rather than inferring it from the golden numbers.
func TestCanonicalOperationsAreDomainSeparated(t *testing.T) {
	upsert := mustCanonical(t, goldenFixture, OpUpsert)
	delist := mustCanonical(t, goldenFixture, OpDelist)

	if bytes.Equal(upsert, delist) {
		t.Fatalf("upsert and delist signed identical bytes — a PUT can be replayed as a DELETE: %q", upsert)
	}
	if hex.EncodeToString(sha256digest(upsert)) == hex.EncodeToString(sha256digest(delist)) {
		t.Error("upsert and delist digests are equal")
	}
	// The difference must be the op line specifically, not some
	// incidental divergence elsewhere in the encoding.
	if !bytes.HasPrefix(upsert, []byte("op\tupsert\n")) {
		t.Errorf("upsert preimage does not begin with the op line: %q", upsert[:20])
	}
	if !bytes.HasPrefix(delist, []byte("op\tdelist\n")) {
		t.Errorf("delist preimage does not begin with the op line: %q", delist[:20])
	}
	if !bytes.Equal(upsert[len("op\tupsert\n"):], delist[len("op\tdelist\n"):]) {
		t.Error("the two preimages differ somewhere other than the op line")
	}
}

// The operation is a closed set. Go allows Operation("anything"), so an
// unrecognised value must be refused rather than silently signed into a
// preimage no verifier will ever accept.
func TestCanonicalRejectsUnknownOperation(t *testing.T) {
	for _, op := range []Operation{"", "UPSERT", "Upsert", "delete", "suspend", "upsert "} {
		t.Run(string(op), func(t *testing.T) {
			if _, err := Canonical(goldenFixture, op); err == nil {
				t.Errorf("Canonical accepted operation %q", op)
			}
		})
	}
}

// The property that makes an old body unusable: the same operation over
// the same field values at a DIFFERENT revision is different bytes.
//
// Domain separation alone stops a PUT being replayed as a DELETE, but
// leaves same-operation replay open — every body a publisher ever sent
// would stay a standing authorisation to re-apply those exact values,
// reverting a later price edit or re-listing a pod deliberately
// delisted. Binding the revision is what makes a signature single-use.
func TestCanonicalRevisionsAreDomainSeparated(t *testing.T) {
	for _, op := range []Operation{OpUpsert, OpDelist} {
		t.Run(string(op), func(t *testing.T) {
			first := goldenFixture
			first.Revision = Revision(1)
			second := goldenFixture
			second.Revision = Revision(2)

			a := mustCanonical(t, first, op)
			b := mustCanonical(t, second, op)
			if bytes.Equal(a, b) {
				t.Fatalf("revisions 1 and 2 signed identical bytes: %q", a)
			}
			if !bytes.HasPrefix(a, []byte("op\t"+string(op)+"\nrevision\t1\n")) {
				t.Errorf("revision is not the second line: %q", a[:32])
			}
		})
	}
}

// The revision bound mirrors reef-core's Canonical.max_revision/0. A
// value outside it, or an unset one, must not produce signable bytes.
func TestCanonicalRejectsOutOfRangeRevision(t *testing.T) {
	cases := map[string]*int64{
		"unset":         nil,
		"negative":      Revision(-1),
		"far negative":  Revision(-9007199254740991),
		"above max":     Revision(MaxRevision + 1),
		"far above max": Revision(1 << 62),
		"int64 max":     Revision(9223372036854775807),
	}
	for name, rev := range cases {
		t.Run(name, func(t *testing.T) {
			f := goldenFixture
			f.Revision = rev
			if _, err := Canonical(f, OpUpsert); err == nil {
				t.Error("Canonical accepted an out-of-range revision")
			}
		})
	}
}

// The bounds are inclusive at both ends: 0 and MaxRevision are valid
// revisions, so the guard must not be off by one.
func TestCanonicalAcceptsRevisionBounds(t *testing.T) {
	for name, rev := range map[string]int64{"zero": 0, "max": MaxRevision} {
		t.Run(name, func(t *testing.T) {
			f := goldenFixture
			f.Revision = Revision(rev)
			if _, err := Canonical(f, OpUpsert); err != nil {
				t.Errorf("Canonical rejected revision %d: %v", rev, err)
			}
		})
	}
}
