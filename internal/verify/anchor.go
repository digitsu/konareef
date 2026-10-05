// Copyright 2026 Jerry David Chan, Konareef.ai
// SPDX-License-Identifier: Apache-2.0

// anchor.go — the chain-head anchor check (reef-core#76, PRD 3 § 8.5).
//
// A konareef-bundle/v2 bundle may carry `chain_head_anchor`: the BSV
// transaction that holds the BRC-18 OP_RETURN of the chain head hash
// (chain[last].hash), as a BRC-95 Atomic BEEF with a BRC-74 merkle path,
// plus a node attestation. The attestation is a BRC-100 signature, made
// by the node's wallet identity for counterparty "anyone", over the
// statement
//
//	{ "v": "reef-core/chain-head-anchor/1", "txid", "vout", "head_hash",
//	  "vkey_hash", "proof_digest" = SHA-256(last_step_public_inputs) }
//
// (deterministic CBOR). An OP_RETURN alone has no author: anyone can
// anchor any hash. The attestation names the node, and the proof digest
// ties the chain to this proof, so a genuine chain cannot be moved onto
// another proof.
//
// Check order (each step runs only when the previous ones passed):
//
//  1. absent key: status "absent", no error;
//  2. map shape, key set and types; the BEEF parses; its subject is the
//     txid — else ERR_ANCHOR_MALFORMED;
//  3. the subject transaction hashes to the txid — ERR_ANCHOR_MISMATCH;
//  4. output vout is exactly 00 6a 20 ‖ head hash — ERR_ANCHOR_MISMATCH;
//     a link txid or bsv_txids entry for the head that differs —
//     ERR_CHAIN_BROKEN;
//  5. the subject has a BUMP at block_height that holds the txid —
//     ERR_ANCHOR_PROOF_INVALID;
//  6. the attestation signature verifies under the key derived from its
//     identity key — else ERR_ANCHOR_UNATTRIBUTED. It needs no headers,
//     so it runs before them. A missing attestation, an untrusted
//     identity key, or public-input lanes that disagree (F1) only make
//     the final status "unattributed";
//  7. the header source has the header — else status
//     "headers_unavailable", no error;
//  8. the header meets its target and the difficulty floor —
//     ERR_ANCHOR_HEADER_UNTRUSTED (also for sources that disagree);
//  9. the header merkle root equals the computed root —
//     ERR_ANCHOR_HEADER_MISMATCH;
//  10. header time is not earlier than the head timestamp minus 2 h —
//     ERR_ANCHOR_MISMATCH;
//  11. confirmations, counted from the tip of the source that supplied
//     the header, reach the minimum — else status "insufficient_depth"
//     (or "headers_unavailable" when the tip is unknown), no error.
//
// (The design lists attribution as step 10; it runs earlier here so a
// bad signature is never masked by missing headers. The outcome for
// every input is otherwise the same.)
//
// A step-2..10 error fails the bundle (owner decision A3(a)). The status
// is "verified" only when every step passes; Verdict.ChainHeadAnchored is
// true only when, in addition, the whole bundle passed (verifySnarkPhase).
package verify

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"time"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/decred/dcrd/dcrec/secp256k1/v4/ecdsa"
	"github.com/fxamacker/cbor/v2"

	"github.com/digitsu/konareef/internal/identity"
	"github.com/digitsu/konareef/internal/spv"
)

// Anchor attestation constants. reef-core signs with exactly these.
const (
	// AnchorStatementVersion is the "v" value of the signed statement.
	AnchorStatementVersion = "reef-core/chain-head-anchor/1"
	// AnchorProtocol is the BRC-43 protocol name of the signature.
	AnchorProtocol = "reef chain anchor"
	// AnchorKeyID is the BRC-43 key id of the signature.
	AnchorKeyID = "1"
	// AnchorSecurityLevel is the BRC-43 security level of the signature.
	AnchorSecurityLevel = 2
	// anchorTimeTolerance is how far a block time may precede the head
	// link's timestamp (block timestamps may lag real time by up to about
	// two hours).
	anchorTimeTolerance = 2 * time.Hour
	// maxAnchorBEEF bounds the BEEF a bundle may carry.
	maxAnchorBEEF = 1 << 20
	// defaultAnchorTimeout bounds all header lookups for one bundle.
	defaultAnchorTimeout = 30 * time.Second
)

// AnchorStatus is the outcome of the chain-head anchor check.
type AnchorStatus string

// Anchor statuses (Verdict.ChainHeadAnchor.Status).
const (
	AnchorAbsent             AnchorStatus = "absent"
	AnchorVerified           AnchorStatus = "verified"
	AnchorHeadersUnavailable AnchorStatus = "headers_unavailable"
	AnchorInsufficientDepth  AnchorStatus = "insufficient_depth"
	AnchorUnattributed       AnchorStatus = "unattributed"
	AnchorInvalid            AnchorStatus = "invalid"
)

// ChainHeadAnchorVerdict is the informative anchor object of the verdict.
type ChainHeadAnchorVerdict struct {
	// Status is the check outcome.
	Status AnchorStatus `json:"status"`
	// Txid is the anchor transaction id, display hex; empty when absent
	// or unreadable.
	Txid string `json:"txid,omitempty"`
	// BlockHeight is the block the merkle path proves.
	BlockHeight uint64 `json:"block_height,omitempty"`
	// Confirmations is tip - block_height + 1, when the tip is known.
	Confirmations uint64 `json:"confirmations,omitempty"`
	// AnchorLagSecs is the block time minus the head link time.
	AnchorLagSecs int64 `json:"anchor_lag_secs,omitempty"`
	// AttributedTo is the trusted node identity key (hex) that signed
	// the attestation; empty unless the attestation verified under a
	// trusted key.
	AttributedTo string `json:"attributed_to,omitempty"`
	// FloorOverridden is true when the caller replaced the mainnet
	// difficulty floor (--max-target-bits, for testnet or regtest). A
	// display must say so next to any "anchored" claim.
	FloorOverridden bool `json:"difficulty_floor_overridden,omitempty"`
}

// AnchorOptions configures the anchor check.
type AnchorOptions struct {
	// Headers is the header source. Nil means no headers: an anchor can
	// then reach at most "headers_unavailable".
	Headers spv.HeaderSource
	// MinConfirmations is the confirmation minimum; 0 means 1.
	MinConfirmations uint64
	// TrustedNodeKeys are the node identity keys (33-byte compressed)
	// whose attestations count.
	TrustedNodeKeys [][]byte
	// MaxTarget is the difficulty floor as a target; nil means
	// spv.DefaultMaxTarget.
	MaxTarget *big.Int
	// Timeout bounds the header lookups; 0 means 30 s.
	Timeout time.Duration
}

// anchorWire is the decoded chain_head_anchor map.
type anchorWire struct {
	Txid        []byte
	Vout        uint64
	BEEF        []byte
	BlockHeight uint64
	Attestation *anchorAttestationWire
}

// anchorAttestationWire is the decoded attestation map.
type anchorAttestationWire struct {
	IdentityKey []byte
	Sig         []byte
}

// CBOR major types used by the strict anchor decoder.
const (
	cborMajorUint  = 0
	cborMajorBytes = 2
	cborMajorText  = 3
	cborMajorMap   = 5
)

// decodeStrictMap decodes raw as a map with text keys, checks the major
// type of every value against want, and refuses unknown keys and missing
// required keys.
func decodeStrictMap(raw cbor.RawMessage, want map[string]byte, required []string) (map[string]cbor.RawMessage, error) {
	if len(raw) == 0 || raw[0]>>5 != cborMajorMap {
		return nil, errors.New("not a CBOR map")
	}
	var m map[string]cbor.RawMessage
	if err := detDecMode.Unmarshal(raw, &m); err != nil {
		return nil, err
	}
	for k, v := range m {
		major, ok := want[k]
		if !ok {
			return nil, fmt.Errorf("unknown key %q", k)
		}
		if len(v) == 0 || v[0]>>5 != major {
			return nil, fmt.Errorf("key %q has the wrong CBOR type", k)
		}
	}
	for _, k := range required {
		if _, ok := m[k]; !ok {
			return nil, fmt.Errorf("missing key %q", k)
		}
	}
	return m, nil
}

// decodeAnchorWire decodes and shape-checks chain_head_anchor.
func decodeAnchorWire(raw cbor.RawMessage) (*anchorWire, error) {
	m, err := decodeStrictMap(raw, map[string]byte{
		"txid": cborMajorBytes, "vout": cborMajorUint, "beef": cborMajorBytes,
		"block_height": cborMajorUint, "attestation": cborMajorMap,
	}, []string{"txid", "vout", "beef", "block_height"})
	if err != nil {
		return nil, err
	}
	w := &anchorWire{}
	if err := detDecMode.Unmarshal(m["txid"], &w.Txid); err != nil || len(w.Txid) != 32 {
		return nil, errors.New("txid must be a 32-byte bstr")
	}
	if err := detDecMode.Unmarshal(m["vout"], &w.Vout); err != nil {
		return nil, errors.New("vout must be a uint")
	}
	if err := detDecMode.Unmarshal(m["beef"], &w.BEEF); err != nil || len(w.BEEF) == 0 || len(w.BEEF) > maxAnchorBEEF {
		return nil, fmt.Errorf("beef must be a bstr of 1..%d bytes", maxAnchorBEEF)
	}
	if err := detDecMode.Unmarshal(m["block_height"], &w.BlockHeight); err != nil {
		return nil, errors.New("block_height must be a uint")
	}
	if att, ok := m["attestation"]; ok {
		a, err := decodeAttestationWire(att)
		if err != nil {
			return nil, fmt.Errorf("attestation: %w", err)
		}
		w.Attestation = a
	}
	return w, nil
}

// decodeAttestationWire decodes and shape-checks the attestation map.
// protocol and key_id must be the fixed reef-core values.
func decodeAttestationWire(raw cbor.RawMessage) (*anchorAttestationWire, error) {
	m, err := decodeStrictMap(raw, map[string]byte{
		"identity_key": cborMajorBytes, "protocol": cborMajorText,
		"key_id": cborMajorText, "sig": cborMajorBytes,
	}, []string{"identity_key", "protocol", "key_id", "sig"})
	if err != nil {
		return nil, err
	}
	a := &anchorAttestationWire{}
	var protocol, keyID string
	if err := detDecMode.Unmarshal(m["identity_key"], &a.IdentityKey); err != nil || len(a.IdentityKey) != 33 {
		return nil, errors.New("identity_key must be a 33-byte bstr")
	}
	if err := detDecMode.Unmarshal(m["protocol"], &protocol); err != nil || protocol != AnchorProtocol {
		return nil, fmt.Errorf("protocol must be %q", AnchorProtocol)
	}
	if err := detDecMode.Unmarshal(m["key_id"], &keyID); err != nil || keyID != AnchorKeyID {
		return nil, fmt.Errorf("key_id must be %q", AnchorKeyID)
	}
	if err := detDecMode.Unmarshal(m["sig"], &a.Sig); err != nil || len(a.Sig) == 0 || len(a.Sig) > 80 {
		return nil, errors.New("sig must be a DER bstr")
	}
	return a, nil
}

// anchorStatementEncMode is the deterministic CBOR encoder for the
// statement (RFC 8949 § 4.2.1 key order, the rule reef-core's encoder
// also follows).
var anchorStatementEncMode = func() cbor.EncMode {
	em, err := cbor.CoreDetEncOptions().EncMode()
	if err != nil {
		panic(err)
	}
	return em
}()

// AnchorStatement encodes the signed statement.
// Inputs: txid (display order, 32 bytes); vout; head hash; vkey hash;
// the last_step_public_inputs buffer.
// Output: the deterministic CBOR bytes the node signs (SHA-256 of them is
// the ECDSA digest).
func AnchorStatement(txid []byte, vout uint64, headHash, vkeyHash, lastStep []byte) []byte {
	digest := sha256.Sum256(lastStep)
	out, err := anchorStatementEncMode.Marshal(map[string]any{
		"v":            AnchorStatementVersion,
		"txid":         txid,
		"vout":         vout,
		"head_hash":    headHash,
		"vkey_hash":    vkeyHash,
		"proof_digest": digest[:],
	})
	if err != nil {
		panic(err)
	}
	return out
}

// AnchorInvoice returns the BRC-43 invoice number of the attestation key.
func AnchorInvoice() string {
	return spv.InvoiceNumber(AnchorSecurityLevel, AnchorProtocol, AnchorKeyID)
}

// verifyAnchorSignature checks sig (strict DER, low S) over
// SHA-256(statement) under the key derived from identityKey.
func verifyAnchorSignature(identityKey, sig, statement []byte) error {
	if _, _, err := identity.ParseStrict(sig); err != nil {
		return fmt.Errorf("signature is not strict DER with low S: %w", err)
	}
	child, err := spv.DeriveAnyonePublicKey(identityKey, AnchorInvoice())
	if err != nil {
		return err
	}
	pub, err := secp256k1.ParsePubKey(child)
	if err != nil {
		return err
	}
	parsed, err := ecdsa.ParseDERSignature(sig)
	if err != nil {
		return err
	}
	digest := sha256.Sum256(statement)
	if !parsed.Verify(digest[:], pub) {
		return errors.New("signature does not verify over the recomputed statement")
	}
	return nil
}

// trusted reports whether key is one of the trusted node keys.
func trusted(key []byte, keys [][]byte) bool {
	for _, k := range keys {
		if bytes.Equal(k, key) {
			return true
		}
	}
	return false
}

// checkChainHeadAnchor runs the anchor check (see the file comment) and
// fills v.ChainHeadAnchor and v.ChainHeadAnchored.
//
// Inputs: b, the decoded bundle; opts; lanesAgree, the result of
// checkStepLaneAgreement (F1); v; r.
// Output: none. A step-2..10 fault adds a divergence (so r.OK is false),
// sets the status to "invalid", and, for a cross-reference fault, sets
// v.ChainPolicyValid to false.
func checkChainHeadAnchor(b *BundleV2, opts AnchorOptions, lanesAgree bool, v *Verdict, r *ResultV2) {
	av := &ChainHeadAnchorVerdict{Status: AnchorAbsent, FloorOverridden: opts.MaxTarget != nil && opts.MaxTarget.Cmp(spv.DefaultMaxTarget) != 0}
	v.ChainHeadAnchor = av
	v.ChainHeadAnchored = false
	if len(b.ChainHeadAnchor) == 0 {
		return
	}
	fail := func(err error, format string, args ...any) {
		av.Status = AnchorInvalid
		r.diverge(err, "chain_head_anchor: "+fmt.Sprintf(format, args...))
	}
	if len(b.Chain) == 0 || len(b.Chain[len(b.Chain)-1].Hash) != 32 {
		fail(ErrAnchorMismatch, "the bundle has no 32-byte chain head hash")
		return
	}
	head := b.Chain[len(b.Chain)-1]

	// Step 2: shape and BEEF.
	w, err := decodeAnchorWire(b.ChainHeadAnchor)
	if err != nil {
		fail(ErrAnchorMalformed, "%v", err)
		return
	}
	av.Txid = hex.EncodeToString(w.Txid)
	av.BlockHeight = w.BlockHeight
	beef, err := spv.ParseAtomicBEEF(w.BEEF)
	if err != nil {
		fail(ErrAnchorMalformed, "beef: %v", err)
		return
	}
	var txidDisplay [32]byte
	copy(txidDisplay[:], w.Txid)
	txidInternal := spv.Reverse32(txidDisplay)
	if beef.Subject != txidInternal {
		fail(ErrAnchorMalformed, "the beef subject is not txid")
		return
	}

	// Step 3: the subject transaction is the txid.
	subject := beef.SubjectTx()
	if subject.Tx == nil || subject.Tx.TxID() != txidInternal {
		fail(ErrAnchorMismatch, "the subject transaction does not hash to txid")
		return
	}

	// Step 4: the OP_RETURN and the in-bundle cross-references.
	if w.Vout >= uint64(len(subject.Tx.Outputs)) {
		fail(ErrAnchorMismatch, "vout %d is out of range (%d outputs)", w.Vout, len(subject.Tx.Outputs))
		return
	}
	if !bytes.Equal(subject.Tx.Outputs[w.Vout].LockingScript, spv.OpReturnScript(head.Hash)) {
		fail(ErrAnchorMismatch, "output %d is not OP_FALSE OP_RETURN of the chain head hash", w.Vout)
		return
	}
	crossRefOK := true
	if head.Txid != "" && head.Txid != av.Txid {
		fail(ErrChainBroken, "chain head txid %q != anchor txid %s", head.Txid, av.Txid)
		crossRefOK = false
	}
	if t, ok := b.BsvTxids[hex.EncodeToString(head.Hash)]; ok && t != av.Txid {
		fail(ErrChainBroken, "bsv_txids entry %q != anchor txid %s", t, av.Txid)
		crossRefOK = false
	}
	if !crossRefOK {
		v.ChainPolicyValid = false
		return
	}

	// Step 5: the merkle path.
	bump := beef.SubjectBUMP()
	if bump == nil {
		fail(ErrAnchorProofInvalid, "the subject transaction has no merkle path")
		return
	}
	if bump.BlockHeight != w.BlockHeight {
		fail(ErrAnchorProofInvalid, "merkle path height %d != block_height %d", bump.BlockHeight, w.BlockHeight)
		return
	}
	root, err := bump.ComputeRoot(txidInternal)
	if err != nil {
		fail(ErrAnchorProofInvalid, "%v", err)
		return
	}

	// Step 6 (design step 10): attribution. It needs no headers, so a bad
	// signature fails the bundle even when no header source is set.
	attributed := false
	if w.Attestation != nil {
		statement := AnchorStatement(w.Txid, w.Vout, head.Hash,
			b.SpartanCompressResult.VkeyHash, b.SpartanCompressResult.LastStepPublicInputs)
		if err := verifyAnchorSignature(w.Attestation.IdentityKey, w.Attestation.Sig, statement); err != nil {
			fail(ErrAnchorUnattributed, "attestation: %v", err)
			return
		}
		attributed = lanesAgree && trusted(w.Attestation.IdentityKey, opts.TrustedNodeKeys)
		if attributed {
			av.AttributedTo = hex.EncodeToString(w.Attestation.IdentityKey)
		}
	}

	// Step 7 (design 6): the header.
	if opts.Headers == nil {
		av.Status = AnchorHeadersUnavailable
		return
	}
	timeout := opts.Timeout
	if timeout <= 0 {
		timeout = defaultAnchorTimeout
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	rawHeader, err := opts.Headers.HeaderAt(ctx, w.BlockHeight)
	if err != nil {
		if errors.Is(err, spv.ErrHeaderDisagreement) {
			fail(ErrAnchorHeaderUntrusted, "%v", err)
			return
		}
		av.Status = AnchorHeadersUnavailable
		return
	}
	header, _ := spv.ParseHeader(rawHeader[:])

	// Step 8 (design 7): proof of work and the difficulty floor.
	if err := header.CheckWork(opts.MaxTarget); err != nil {
		fail(ErrAnchorHeaderUntrusted, "header at %d: %v", w.BlockHeight, err)
		return
	}
	// Step 9 (design 8): the merkle root.
	if header.MerkleRoot != root {
		fail(ErrAnchorHeaderMismatch, "header merkle root at %d differs from the path root", w.BlockHeight)
		return
	}

	// Step 10 (design 9): the anchor cannot predate the data it anchors.
	headTime, err := time.Parse(time.RFC3339Nano, head.Timestamp)
	if err != nil {
		fail(ErrAnchorMismatch, "chain head timestamp %q is unreadable", head.Timestamp)
		return
	}
	blockTime := header.Timestamp()
	av.AnchorLagSecs = int64(blockTime.Sub(headTime) / time.Second)
	if blockTime.Before(headTime.Add(-anchorTimeTolerance)) {
		fail(ErrAnchorMismatch, "block time %s predates the chain head timestamp %s",
			blockTime.Format(time.RFC3339), head.Timestamp)
		return
	}

	// Step 11: depth.
	minConf := opts.MinConfirmations
	if minConf == 0 {
		minConf = 1
	}
	var tip uint64
	var tipErr error
	if tf, ok := opts.Headers.(interface {
		TipFor(context.Context, uint64) (uint64, error)
	}); ok {
		tip, tipErr = tf.TipFor(ctx, w.BlockHeight)
	} else {
		tip, tipErr = opts.Headers.TipHeight(ctx)
	}
	switch {
	case tipErr == nil && tip >= w.BlockHeight:
		av.Confirmations = tip - w.BlockHeight + 1
	case tipErr == nil:
		// A tip below the block means the sources are inconsistent.
		fail(ErrAnchorHeaderUntrusted, "tip %d is below the anchor block %d", tip, w.BlockHeight)
		return
	}

	switch {
	case !attributed:
		av.Status = AnchorUnattributed
	case tipErr != nil:
		av.Status = AnchorHeadersUnavailable
	case av.Confirmations < minConf:
		av.Status = AnchorInsufficientDepth
	default:
		av.Status = AnchorVerified
		v.ChainHeadAnchored = true
	}
}
