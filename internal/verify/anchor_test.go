// Copyright 2026 Jerry David Chan, Konareef.ai
// SPDX-License-Identifier: Apache-2.0

// anchor_test.go — tests for the chain-head anchor check (anchor.go,
// reef-core#76).
//
// Every test builds a synthetic block around a synthetic anchor
// transaction (spvtest), signs the statement with the fixed test
// identity key, and serves headers from memory. Nothing touches a
// network, a wallet or a chain.
package verify

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/fxamacker/cbor/v2"

	"github.com/digitsu/konareef/internal/spv"
	"github.com/digitsu/konareef/internal/spv/spvtest"
)

// anchorParts holds a bundle and every piece of its anchor, so a test can
// change one piece and re-encode.
type anchorParts struct {
	bundle   *BundleV2
	rawTx    []byte
	vout     uint64
	chain    *spvtest.Chain
	beef     []byte
	txid     []byte // display order
	identity []byte
	sig      []byte
	wire     map[string]any
	att      map[string]any
	opts     AnchorOptions
}

// anchorBlockHeight is the synthetic anchor block height.
const anchorBlockHeight = 930_000

// newAnchorParts builds an honest bundle of the given disclosure ("C" or
// "D") with a valid, attested anchor two blocks deep (three
// confirmations) and options that trust the test key.
func newAnchorParts(t *testing.T, disclosure string) *anchorParts {
	t.Helper()
	var b *BundleV2
	var err error
	switch disclosure {
	case "C":
		fr := v2FieldsRoot(t)
		b, err = decodeBundleV2(buildV2Z0FieldsRootBundle(t, fr, fr[:], fr[:], nil))
	case "D":
		b, err = decodeBundleV2(loadParityEnvelopeStripped(t, "parity-v2-typed.cbor"))
	}
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	return anchorPartsFor(t, b)
}

// anchorPartsFor builds a valid, attested anchor two blocks deep (three
// confirmations) for the decoded bundle b, with options that trust the
// test key. Input: b. Output: the parts.
func anchorPartsFor(t *testing.T, b *BundleV2) *anchorParts {
	t.Helper()
	head := b.Chain[len(b.Chain)-1]
	headTime, err := time.Parse(time.RFC3339Nano, head.Timestamp)
	if err != nil {
		t.Fatalf("head timestamp %q: %v", head.Timestamp, err)
	}
	p := &anchorParts{bundle: b, vout: 1}
	p.rawTx = spvtest.BuildTx(7, []spvtest.Output{
		{Satoshis: 1234, Script: []byte{0x76, 0xa9}},
		{Satoshis: 0, Script: spv.OpReturnScript(head.Hash)},
	})
	p.chain = spvtest.BuildChain(p.rawTx, anchorBlockHeight, uint32(headTime.Unix()+600), 2)
	p.beef = spvtest.AtomicBEEFV1(p.rawTx, p.chain.BUMP)
	disp := spv.Reverse32(p.chain.TxID)
	p.txid = disp[:]
	key := spvtest.TestIdentityPrivateKey()
	p.identity = key.PubKey().SerializeCompressed()
	statement := AnchorStatement(p.txid, p.vout, head.Hash,
		b.SpartanCompressResult.VkeyHash, b.SpartanCompressResult.LastStepPublicInputs)
	p.sig = spvtest.SignAnyone(key, AnchorInvoice(), statement)
	p.att = map[string]any{
		"identity_key": p.identity, "protocol": AnchorProtocol, "key_id": AnchorKeyID, "sig": p.sig,
	}
	p.wire = map[string]any{
		"txid": p.txid, "vout": p.vout, "beef": p.beef,
		"block_height": uint64(anchorBlockHeight), "attestation": p.att,
	}
	p.opts = AnchorOptions{
		Headers:         p.chain.Headers,
		TrustedNodeKeys: [][]byte{p.identity},
		MaxTarget:       spvtest.TestMaxTarget,
	}
	return p
}

// resign recomputes the attestation over the bundle's current state.
func (p *anchorParts) resign(t *testing.T) {
	t.Helper()
	head := p.bundle.Chain[len(p.bundle.Chain)-1]
	txid, _ := p.wire["txid"].([]byte)
	vout, _ := p.wire["vout"].(uint64)
	statement := AnchorStatement(txid, vout, head.Hash,
		p.bundle.SpartanCompressResult.VkeyHash, p.bundle.SpartanCompressResult.LastStepPublicInputs)
	p.att["sig"] = spvtest.SignAnyone(spvtest.TestIdentityPrivateKey(), AnchorInvoice(), statement)
}

// encode writes the anchor into the bundle and re-encodes it.
func (p *anchorParts) encode(t *testing.T) []byte {
	t.Helper()
	enc, err := cbor.CoreDetEncOptions().EncMode()
	if err != nil {
		t.Fatal(err)
	}
	if p.wire != nil {
		raw, err := enc.Marshal(p.wire)
		if err != nil {
			t.Fatal(err)
		}
		p.bundle.ChainHeadAnchor = raw
	} else {
		p.bundle.ChainHeadAnchor = nil
	}
	out, err := enc.Marshal(p.bundle)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// verify encodes and verifies with the accepting SNARK stub.
func (p *anchorParts) verify(t *testing.T) *ResultV2 {
	t.Helper()
	opts := WithAcceptingVerifierForTests()
	opts.Anchor = p.opts
	return VerifyV2(p.encode(t), opts)
}

// anchorStatus returns the anchor status of r.
func anchorStatus(r *ResultV2) AnchorStatus {
	if r.V2Verdict == nil || r.V2Verdict.ChainHeadAnchor == nil {
		return ""
	}
	return r.V2Verdict.ChainHeadAnchor.Status
}

// requireAnchorError asserts one anchor divergence wrapping want, status
// invalid, anchored false and OK false.
func requireAnchorError(t *testing.T, r *ResultV2, want error) {
	t.Helper()
	if r.OK {
		t.Fatalf("bundle with a bad anchor verified OK")
	}
	if r.V2Verdict.ChainHeadAnchored || anchorStatus(r) != AnchorInvalid {
		t.Fatalf("anchored=%v status=%s, want false/invalid", r.V2Verdict.ChainHeadAnchored, anchorStatus(r))
	}
	found := false
	for _, d := range r.Divergences {
		if errors.Is(d.Err, want) {
			found = true
		}
	}
	if !found {
		t.Fatalf("no %v divergence: %v", want, divergenceStrings(r))
	}
}

// requireAnchorStatus asserts a non-error anchor status: the bundle still
// verifies (Type C) and is not anchored.
func requireAnchorStatus(t *testing.T, r *ResultV2, want AnchorStatus) {
	t.Helper()
	if !r.OK {
		t.Fatalf("status %s must not fail the bundle: %v", want, divergenceStrings(r))
	}
	if got := anchorStatus(r); got != want {
		t.Fatalf("status = %s, want %s", got, want)
	}
	if r.V2Verdict.ChainHeadAnchored {
		t.Fatalf("anchored=true with status %s", want)
	}
}

func TestAnchor_GenuineTypeCVerifies(t *testing.T) {
	p := newAnchorParts(t, "C")
	r := p.verify(t)
	if !r.OK {
		t.Fatalf("genuine anchored bundle rejected: %v", divergenceStrings(r))
	}
	av := r.V2Verdict.ChainHeadAnchor
	if !r.V2Verdict.ChainHeadAnchored || av.Status != AnchorVerified {
		t.Fatalf("anchored=%v status=%s", r.V2Verdict.ChainHeadAnchored, av.Status)
	}
	if av.Confirmations != 3 || av.BlockHeight != anchorBlockHeight || av.AnchorLagSecs < 599 || av.AnchorLagSecs > 601 {
		t.Fatalf("verdict detail %+v", *av)
	}
	if av.AttributedTo != hex.EncodeToString(p.identity) || av.Txid != hex.EncodeToString(p.txid) {
		t.Fatalf("attribution or txid %+v", *av)
	}
}

func TestAnchor_GenuineTypeDVerifies(t *testing.T) {
	p := newAnchorParts(t, "D")
	r := p.verify(t)
	// The Type-D parity fixture's publisher signature is synthetic, so
	// the whole bundle does not pass; the anchor itself must. A failed
	// bundle never reports its head as anchored.
	if anchorStatus(r) != AnchorVerified {
		t.Fatalf("Type-D anchor status %s: %v", anchorStatus(r), divergenceStrings(r))
	}
	if r.OK || r.V2Verdict.ChainHeadAnchored {
		t.Fatalf("OK=%v anchored=%v: a failed bundle must not read as anchored", r.OK, r.V2Verdict.ChainHeadAnchored)
	}
	for _, d := range r.Divergences {
		if strings.Contains(d.Msg, "chain_head_anchor") {
			t.Fatalf("anchor divergence on a genuine Type-D anchor: %v", d.Msg)
		}
	}
}

func TestAnchor_BEEFV2Verifies(t *testing.T) {
	p := newAnchorParts(t, "C")
	p.wire["beef"] = spvtest.AtomicBEEFV2(p.rawTx, p.chain.BUMP)
	if r := p.verify(t); !r.OK || !r.V2Verdict.ChainHeadAnchored {
		t.Fatalf("V2 BEEF: %v", divergenceStrings(r))
	}
}

// TestAnchor_AbsentKeepsResidual replaces TestR2b_RehashedChainIsAnAcceptedResidual:
// with no anchor, a rewritten and re-hashed chain still verifies, and the
// verdict says the head is not anchored.
func TestAnchor_AbsentKeepsResidual(t *testing.T) {
	p := newAnchorParts(t, "C")
	p.wire = nil
	tail := &p.bundle.Chain[len(p.bundle.Chain)-1]
	tail.Data = []byte(strings.Replace(string(tail.Data), "ITERATIONS:", "ITERATIONS: 9\nX:", 1))
	h := ComputeChainHash(hex.EncodeToString(tail.PrevHash), string(tail.Data), tail.Timestamp)
	tail.Hash = h[:]
	r := p.verify(t)
	requireAnchorStatus(t, r, AnchorAbsent)
}

// TestAnchor_RehashedChainWithOriginalAnchorRefused: the original anchor
// holds the original head hash, so a rewritten head fails step 4.
func TestAnchor_RehashedChainWithOriginalAnchorRefused(t *testing.T) {
	p := newAnchorParts(t, "C")
	tail := &p.bundle.Chain[len(p.bundle.Chain)-1]
	tail.Data = []byte(strings.Replace(string(tail.Data), "TOTAL_SATS: 0", "TOTAL_SATS: 9", 1))
	h := ComputeChainHash(hex.EncodeToString(tail.PrevHash), string(tail.Data), tail.Timestamp)
	tail.Hash = h[:]
	requireAnchorError(t, p.verify(t), ErrAnchorMismatch)
}

// TestAnchor_RehashedChainWithForgedAnchorNotAnchored is the test the
// design added: a forger anchors the NEW head hash in a new, valid SPV
// transaction. Without a trusted attestation it must not read as
// anchored; with the old signature copied over it is refused.
func TestAnchor_RehashedChainWithForgedAnchorNotAnchored(t *testing.T) {
	p := newAnchorParts(t, "C")
	tail := &p.bundle.Chain[len(p.bundle.Chain)-1]
	tail.Data = []byte(strings.Replace(string(tail.Data), "TOTAL_SATS: 0", "TOTAL_SATS: 9", 1))
	h := ComputeChainHash(hex.EncodeToString(tail.PrevHash), string(tail.Data), tail.Timestamp)
	tail.Hash = h[:]
	headTime, _ := time.Parse(time.RFC3339Nano, tail.Timestamp)
	forged := spvtest.BuildTx(9, []spvtest.Output{{Satoshis: 0, Script: spv.OpReturnScript(tail.Hash)}})
	ch := spvtest.BuildChain(forged, anchorBlockHeight, uint32(headTime.Unix()+600), 2)
	disp := spv.Reverse32(ch.TxID)
	p.wire["txid"] = disp[:]
	p.wire["vout"] = uint64(0)
	p.wire["beef"] = spvtest.AtomicBEEFV1(forged, ch.BUMP)
	p.opts.Headers = ch.Headers

	// (a) The old signature copied over: refused.
	requireAnchorError(t, p.verify(t), ErrAnchorUnattributed)

	// (b) No attestation: valid SPV, but unattributed.
	delete(p.wire, "attestation")
	requireAnchorStatus(t, p.verify(t), AnchorUnattributed)

	// (c) The forger signs with its own key: unattributed (untrusted key).
	seed := sha256.Sum256([]byte("forger identity"))
	forger := secp256k1.PrivKeyFromBytes(seed[:])
	statement := AnchorStatement(disp[:], 0, tail.Hash,
		p.bundle.SpartanCompressResult.VkeyHash, p.bundle.SpartanCompressResult.LastStepPublicInputs)
	p.wire["attestation"] = map[string]any{
		"identity_key": forger.PubKey().SerializeCompressed(), "protocol": AnchorProtocol,
		"key_id": AnchorKeyID, "sig": spvtest.SignAnyone(forger, AnchorInvoice(), statement),
	}
	requireAnchorStatus(t, p.verify(t), AnchorUnattributed)
}

// TestAnchor_SpliceOntoAnotherProofRefused: a genuine chain and anchor
// attached to a proof with different public inputs fail the attestation
// (the proof digest differs).
func TestAnchor_SpliceOntoAnotherProofRefused(t *testing.T) {
	p := newAnchorParts(t, "D")
	scr := &p.bundle.SpartanCompressResult
	scr.LastStepPublicInputs = append([]byte(nil), scr.LastStepPublicInputs...)
	scr.LastStepPublicInputs[0] ^= 0x01
	scr.FirstStepPublicInputs = append([]byte(nil), scr.LastStepPublicInputs...)
	r := p.verify(t)
	if anchorStatus(r) != AnchorInvalid || r.V2Verdict.ChainHeadAnchored {
		t.Fatalf("status %s", anchorStatus(r))
	}
	found := false
	for _, d := range r.Divergences {
		found = found || errors.Is(d.Err, ErrAnchorUnattributed)
	}
	if !found {
		t.Fatalf("no ErrAnchorUnattributed: %v", divergenceStrings(r))
	}
}

func TestAnchor_Refusals(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(t *testing.T, p *anchorParts)
		want   error
	}{
		{"unknown key", func(t *testing.T, p *anchorParts) { p.wire["extra"] = uint64(1) }, ErrAnchorMalformed},
		{"missing beef", func(t *testing.T, p *anchorParts) { delete(p.wire, "beef") }, ErrAnchorMalformed},
		{"txid wrong type", func(t *testing.T, p *anchorParts) { p.wire["txid"] = hex.EncodeToString(p.txid) }, ErrAnchorMalformed},
		{"short txid", func(t *testing.T, p *anchorParts) { p.wire["txid"] = p.txid[:31] }, ErrAnchorMalformed},
		{"wrong protocol", func(t *testing.T, p *anchorParts) { p.att["protocol"] = "other protocol" }, ErrAnchorMalformed},
		{"garbage beef", func(t *testing.T, p *anchorParts) { p.wire["beef"] = []byte{1, 2, 3} }, ErrAnchorMalformed},
		{"beef subject is another txid", func(t *testing.T, p *anchorParts) {
			other := append([]byte(nil), p.txid...)
			other[0] ^= 1
			p.wire["txid"] = other
		}, ErrAnchorMalformed},
		{"wrong vout", func(t *testing.T, p *anchorParts) { p.wire["vout"] = uint64(0); p.resign(t) }, ErrAnchorMismatch},
		{"vout out of range", func(t *testing.T, p *anchorParts) { p.wire["vout"] = uint64(5); p.resign(t) }, ErrAnchorMismatch},
		{"link txid differs", func(t *testing.T, p *anchorParts) {
			p.bundle.Chain[len(p.bundle.Chain)-1].Txid = strings.Repeat("ab", 32)
		}, ErrChainBroken},
		{"bsv_txids differs", func(t *testing.T, p *anchorParts) {
			head := p.bundle.Chain[len(p.bundle.Chain)-1]
			p.bundle.BsvTxids = map[string]string{hex.EncodeToString(head.Hash): strings.Repeat("cd", 32)}
		}, ErrChainBroken},
		{"no bump", func(t *testing.T, p *anchorParts) {
			// A V1 BEEF with no BUMPs and hasBump=0.
			txid := spv.DoubleSHA256(p.rawTx)
			out := append([]byte{1, 1, 1, 1}, txid[:]...)
			out = append(out, 0x01, 0x00, 0xbe, 0xef, 0x00, 0x01)
			out = append(out, p.rawTx...)
			p.wire["beef"] = append(out, 0x00)
		}, ErrAnchorProofInvalid},
		{"block height differs", func(t *testing.T, p *anchorParts) {
			p.wire["block_height"] = uint64(anchorBlockHeight + 1)
		}, ErrAnchorProofInvalid},
		{"bad merkle path", func(t *testing.T, p *anchorParts) {
			// A path for another block whose root no header holds.
			bump, _ := spvtest.BuildBUMP(anchorBlockHeight, [][32]byte{spv.DoubleSHA256(p.rawTx), spv.DoubleSHA256([]byte("x"))}, 0)
			p.wire["beef"] = spvtest.AtomicBEEFV1(p.rawTx, bump)
		}, ErrAnchorHeaderMismatch},
		{"header below the floor", func(t *testing.T, p *anchorParts) { p.opts.MaxTarget = nil }, ErrAnchorHeaderUntrusted},
		{"header sources disagree", func(t *testing.T, p *anchorParts) {
			other := spvtest.MineHeader([32]byte{9}, p.chain.Root, 1)
			p.opts.Headers = &spv.Agreeing{Sources: []spv.HeaderSource{p.chain.Headers,
				&spv.Memory{Headers: map[uint64][spv.HeaderSize]byte{anchorBlockHeight: other}, Tip: anchorBlockHeight + 2}}}
		}, ErrAnchorHeaderUntrusted},
		{"anchor predates the head", func(t *testing.T, p *anchorParts) {
			ch := spvtest.BuildChain(p.rawTx, anchorBlockHeight, 1_000_000, 2)
			p.opts.Headers = ch.Headers
		}, ErrAnchorMismatch},
		{"bad signature", func(t *testing.T, p *anchorParts) {
			sig := append([]byte(nil), p.sig...)
			sig[len(sig)-1] ^= 0x01
			p.att["sig"] = sig
		}, ErrAnchorUnattributed},
		{"high-S signature", func(t *testing.T, p *anchorParts) { p.att["sig"] = highSDER(t, p.sig) }, ErrAnchorUnattributed},
		{"vkey hash changed", func(t *testing.T, p *anchorParts) {
			p.bundle.SpartanCompressResult.VkeyHash = make([]byte, 32)
		}, ErrAnchorUnattributed},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			p := newAnchorParts(t, "C")
			c.mutate(t, p)
			r := p.verify(t)
			if r.OK {
				t.Fatalf("verified OK")
			}
			if r.V2Verdict.ChainHeadAnchored {
				t.Fatal("anchored=true")
			}
			found := false
			for _, d := range r.Divergences {
				found = found || errors.Is(d.Err, c.want)
			}
			if !found {
				t.Fatalf("no %v divergence: %v", c.want, divergenceStrings(r))
			}
		})
	}
}

func TestAnchor_StatusesThatDoNotFail(t *testing.T) {
	t.Run("no header source", func(t *testing.T) {
		p := newAnchorParts(t, "C")
		p.opts.Headers = nil
		requireAnchorStatus(t, p.verify(t), AnchorHeadersUnavailable)
	})
	t.Run("header missing", func(t *testing.T) {
		p := newAnchorParts(t, "C")
		p.opts.Headers = &spv.Memory{Headers: map[uint64][spv.HeaderSize]byte{1: {}}, Tip: 1}
		requireAnchorStatus(t, p.verify(t), AnchorHeadersUnavailable)
	})
	t.Run("insufficient depth", func(t *testing.T) {
		p := newAnchorParts(t, "C")
		p.opts.MinConfirmations = 6
		r := p.verify(t)
		requireAnchorStatus(t, r, AnchorInsufficientDepth)
		if r.V2Verdict.ChainHeadAnchor.Confirmations != 3 {
			t.Fatalf("confirmations %d", r.V2Verdict.ChainHeadAnchor.Confirmations)
		}
	})
	t.Run("untrusted key", func(t *testing.T) {
		p := newAnchorParts(t, "C")
		p.opts.TrustedNodeKeys = nil
		r := p.verify(t)
		requireAnchorStatus(t, r, AnchorUnattributed)
		if r.V2Verdict.ChainHeadAnchor.AttributedTo != "" {
			t.Fatal("attributed_to set for an untrusted key")
		}
	})
	t.Run("no attestation", func(t *testing.T) {
		p := newAnchorParts(t, "C")
		delete(p.wire, "attestation")
		requireAnchorStatus(t, p.verify(t), AnchorUnattributed)
	})
	t.Run("zero-value options never verify", func(t *testing.T) {
		p := newAnchorParts(t, "C")
		p.opts = AnchorOptions{}
		requireAnchorStatus(t, p.verify(t), AnchorHeadersUnavailable)
	})
}

// TestAnchor_LaneDisagreementBlocksVerified: when first_step and
// last_step disagree (F1), the anchor cannot read as verified even with
// a valid signature over last_step.
func TestAnchor_LaneDisagreementBlocksVerified(t *testing.T) {
	p := newAnchorParts(t, "C")
	scr := &p.bundle.SpartanCompressResult
	scr.FirstStepPublicInputs = append([]byte(nil), scr.FirstStepPublicInputs...)
	scr.FirstStepPublicInputs[200] ^= 0x01 // chain_head_hash lane
	r := p.verify(t)
	if r.V2Verdict.ChainHeadAnchored || anchorStatus(r) != AnchorUnattributed {
		t.Fatalf("anchored=%v status=%s", r.V2Verdict.ChainHeadAnchored, anchorStatus(r))
	}
}

// TestAnchor_StatementEncoding pins the statement bytes: deterministic
// CBOR with the keys in RFC 8949 § 4.2.1 order. reef-core must produce
// the same bytes (its test pins the same vector).
func TestAnchor_StatementEncoding(t *testing.T) {
	txid := make([]byte, 32)
	head := make([]byte, 32)
	vkey := make([]byte, 32)
	for i := range txid {
		txid[i], head[i], vkey[i] = 0x11, 0x22, 0x33
	}
	digest := sha256.Sum256([]byte("last-step"))
	got := hex.EncodeToString(AnchorStatement(txid, 1, head, vkey, []byte("last-step")))
	want := "a6" +
		"6176" + "781d" + hex.EncodeToString([]byte(AnchorStatementVersion)) +
		"6474786964" + "5820" + strings.Repeat("11", 32) +
		"64766f7574" + "01" +
		"69686561645f68617368" + "5820" + strings.Repeat("22", 32) +
		"69766b65795f68617368" + "5820" + strings.Repeat("33", 32) +
		"6c70726f6f665f646967657374" + "5820" + hex.EncodeToString(digest[:])
	if got != want {
		t.Fatalf("statement:\n got %s\nwant %s", got, want)
	}
	if got != anchorStatementVector {
		t.Fatalf("statement differs from the pinned cross-repo vector:\n got %s", got)
	}
}

// anchorStatementVector is the statement for txid=0x11*32, vout=1,
// head=0x22*32, vkey=0x33*32, last_step="last-step". reef-core's
// ChainHeadAnchor test pins the same hex.
const anchorStatementVector = "a66176781d726565662d636f72652f636861696e2d686561642d616e63686f722f3164747869645820111111111111111111111111111111111111111111111111111111111111111164766f75740169686561645f686173685820222222222222222222222222222222222222222222222222222222222222222269766b65795f68617368582033333333333333333333333333333333333333333333333333333333333333336c70726f6f665f64696765737458200ecaa7d5db7441e98c573f06ed62c5de6e1994e57479c5651a5cde48fe10924a"

func TestAnchorConfig_Options(t *testing.T) {
	id := hex.EncodeToString(spvtest.TestIdentityPrivateKey().PubKey().SerializeCompressed())
	opts, err := AnchorConfig{TrustedNodeKeys: []string{id}, MinConfirmations: 4}.Options()
	if err != nil || len(opts.TrustedNodeKeys) != 1+len(PinnedTrustedNodeKeys) || opts.MinConfirmations != 4 {
		t.Fatalf("options %+v %v", opts, err)
	}
	if opts.Headers != nil {
		t.Fatal("a header source was configured without a file or URL")
	}
	bad := AnchorConfig{TrustedNodeKeys: []string{"zz"}}
	if _, err := bad.Options(); err == nil {
		t.Fatal("malformed key accepted")
	}
	if _, err := (AnchorConfig{HeadersFile: "/nonexistent/headers.bin"}).Options(); err == nil {
		t.Fatal("missing headers file accepted")
	}
	if _, err := (AnchorConfig{HeaderURLs: []string{"https://one.example"}}).Options(); err == nil {
		t.Fatal("a single remote header service was accepted (A4(a) needs two that agree)")
	}
	if _, err := (AnchorConfig{HeaderURLs: []string{"http://one.example", "https://two.example"}}).Options(); err == nil {
		t.Fatal("plain http to a non-loopback header service was accepted")
	}
	opts, err = AnchorConfig{HeaderURLs: []string{"http://127.0.0.1:1", "http://localhost:1"}}.Options()
	if err != nil || opts.Headers == nil {
		t.Fatalf("remote config: %v", err)
	}
	if _, err := opts.Headers.HeaderAt(context.Background(), 1); !errors.Is(err, spv.ErrHeaderUnavailable) {
		t.Fatalf("unreachable remote: %v", err)
	}
	floor, err := AnchorConfig{MaxTargetBits: "207fffff"}.Options()
	if err != nil || floor.MaxTarget == nil || floor.MaxTarget.Cmp(spvtest.TestMaxTarget) != 0 {
		t.Fatalf("max target bits: %v", err)
	}
	if _, err := (AnchorConfig{MaxTargetBits: "01800000"}).Options(); err == nil {
		t.Fatal("negative compact target accepted")
	}
	merged := AnchorConfig{HeaderURLs: []string{"a"}, MinConfirmations: 2}.Merge(AnchorConfig{HeaderURLs: []string{"b"}})
	if len(merged.HeaderURLs) != 2 || merged.MinConfirmations != 2 {
		t.Fatalf("merge %+v", merged)
	}
}

// TestAnchor_BadSignatureFailsWithoutHeaders: the attestation is checked
// before the header lookup, so a forged signature fails the bundle even
// with no header source (security review L1).
func TestAnchor_BadSignatureFailsWithoutHeaders(t *testing.T) {
	p := newAnchorParts(t, "C")
	p.opts.Headers = nil
	sig := append([]byte(nil), p.sig...)
	sig[len(sig)-1] ^= 0x01
	p.att["sig"] = sig
	requireAnchorError(t, p.verify(t), ErrAnchorUnattributed)
}

// TestAnchor_FloorOverrideIsReported: a lowered difficulty floor shows in
// the verdict.
func TestAnchor_FloorOverrideIsReported(t *testing.T) {
	p := newAnchorParts(t, "C")
	r := p.verify(t)
	if !r.V2Verdict.ChainHeadAnchor.FloorOverridden {
		t.Fatal("test floor not reported as an override")
	}
	p.opts.MaxTarget = spv.DefaultMaxTarget
	r = p.verify(t)
	if r.V2Verdict.ChainHeadAnchor.FloorOverridden {
		t.Fatal("default floor reported as an override")
	}
}

// TestAnchor_TipComesFromTheSupplyingSource: a second source with a
// higher tip cannot raise the confirmation count (security review L3).
func TestAnchor_TipComesFromTheSupplyingSource(t *testing.T) {
	p := newAnchorParts(t, "C")
	inflated := &spv.Memory{Headers: map[uint64][spv.HeaderSize]byte{1: {}}, Tip: anchorBlockHeight + 1000}
	p.opts.Headers = &spv.First{Sources: []spv.HeaderSource{p.chain.Headers, inflated}}
	r := p.verify(t)
	if got := r.V2Verdict.ChainHeadAnchor.Confirmations; got != 3 {
		t.Fatalf("confirmations %d, want 3 from the supplying source", got)
	}
}
