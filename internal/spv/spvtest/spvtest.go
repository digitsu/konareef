// Copyright 2026 Jerry David Chan, Konareef.ai
// SPDX-License-Identifier: Apache-2.0

// Package spvtest builds synthetic SPV data for tests: raw
// transactions, BUMPs, mined block headers at a trivial test difficulty,
// Atomic BEEF envelopes, and BRC-42 "anyone" signatures from a fixed
// test key. Nothing here touches a network or a real chain.
package spvtest

import (
	"crypto/sha256"
	"encoding/binary"
	"math/big"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/decred/dcrd/dcrec/secp256k1/v4/ecdsa"

	"github.com/digitsu/konareef/internal/spv"
)

// TestBits is a regtest-style compact target (0x207fffff): about half of
// all nonces meet it, so mining a test header takes a few tries.
const TestBits uint32 = 0x207fffff

// TestMaxTarget is the target floor to use with TestBits headers.
var TestMaxTarget = spv.CompactToTarget(TestBits)

// Output is one output to put in a built transaction.
type Output struct {
	// Satoshis is the value.
	Satoshis uint64
	// Script is the locking script.
	Script []byte
}

// BuildTx serializes a version-1 transaction with one input that spends
// a fixed synthetic outpoint (seeded by salt) and the given outputs.
// Inputs: salt, to make distinct transactions; outputs.
// Output: the raw transaction bytes.
func BuildTx(salt byte, outputs []Output) []byte {
	out := binary.LittleEndian.AppendUint32(nil, 1)
	out = spv.AppendVarInt(out, 1)
	prev := sha256.Sum256([]byte{salt})
	out = append(out, prev[:]...)
	out = binary.LittleEndian.AppendUint32(out, 0)
	script := []byte{0x51} // OP_TRUE: a placeholder unlocking script
	out = spv.AppendVarInt(out, uint64(len(script)))
	out = append(out, script...)
	out = binary.LittleEndian.AppendUint32(out, 0xffffffff)
	out = spv.AppendVarInt(out, uint64(len(outputs)))
	for _, o := range outputs {
		out = binary.LittleEndian.AppendUint64(out, o.Satoshis)
		out = spv.AppendVarInt(out, uint64(len(o.Script)))
		out = append(out, o.Script...)
	}
	return binary.LittleEndian.AppendUint32(out, 0)
}

// Tree builds the full merkle tree over txids (internal order) and
// returns every level, leaves first, with the Bitcoin rule that an odd
// last node is paired with itself.
func Tree(txids [][32]byte) [][][32]byte {
	levels := [][][32]byte{txids}
	for cur := txids; len(cur) > 1; {
		var next [][32]byte
		for i := 0; i < len(cur); i += 2 {
			right := cur[i]
			if i+1 < len(cur) {
				right = cur[i+1]
			}
			var buf [64]byte
			copy(buf[:32], cur[i][:])
			copy(buf[32:], right[:])
			next = append(next, spv.DoubleSHA256(buf[:]))
		}
		levels = append(levels, next)
		cur = next
	}
	return levels
}

// BuildBUMP serializes the BRC-74 path for txids[index] in a block of
// txids at height. The subject leaf is flagged as a txid; an odd last
// sibling is written as a duplicate.
// Inputs: height; txids (internal order, at least two); index.
// Output: the BUMP bytes and the merkle root (internal order).
func BuildBUMP(height uint64, txids [][32]byte, index int) ([]byte, [32]byte) {
	levels := Tree(txids)
	root := levels[len(levels)-1][0]
	treeHeight := len(levels) - 1
	out := spv.AppendVarInt(nil, height)
	out = append(out, byte(treeHeight))
	pos := index
	for level := 0; level < treeHeight; level++ {
		nodes := levels[level]
		sib := pos ^ 1
		type leaf struct {
			off   int
			flags byte
			hash  [32]byte
		}
		var leaves []leaf
		if level == 0 {
			leaves = append(leaves, leaf{pos, spv.LeafTxID, nodes[pos]})
		}
		if sib < len(nodes) {
			leaves = append(leaves, leaf{sib, spv.LeafData, nodes[sib]})
		} else {
			leaves = append(leaves, leaf{sib, spv.LeafDuplicate, [32]byte{}})
		}
		out = spv.AppendVarInt(out, uint64(len(leaves)))
		for _, l := range leaves {
			out = spv.AppendVarInt(out, uint64(l.off))
			out = append(out, l.flags)
			if l.flags != spv.LeafDuplicate {
				out = append(out, l.hash[:]...)
			}
		}
		pos >>= 1
	}
	return out, root
}

// MineHeader builds a header over root at TestBits and searches the
// nonce until the header meets its own target.
// Inputs: prev (internal order); root (internal order); unix time.
// Output: the 80 header bytes.
func MineHeader(prev, root [32]byte, unixTime uint32) [spv.HeaderSize]byte {
	var h [spv.HeaderSize]byte
	binary.LittleEndian.PutUint32(h[0:4], 0x20000000)
	copy(h[4:36], prev[:])
	copy(h[36:68], root[:])
	binary.LittleEndian.PutUint32(h[68:72], unixTime)
	binary.LittleEndian.PutUint32(h[72:76], TestBits)
	for nonce := uint32(0); ; nonce++ {
		binary.LittleEndian.PutUint32(h[76:80], nonce)
		parsed, _ := spv.ParseHeader(h[:])
		if parsed.CheckWork(TestMaxTarget) == nil {
			return h
		}
	}
}

// AtomicBEEFV1 wraps one transaction and its BUMP as a BRC-95 Atomic
// BEEF with a V1 body.
// Inputs: raw transaction; bump bytes. Output: the envelope bytes.
func AtomicBEEFV1(rawTx, bump []byte) []byte {
	txid := spv.DoubleSHA256(rawTx)
	out := binary.LittleEndian.AppendUint32(nil, 0x01010101)
	out = append(out, txid[:]...)
	out = binary.LittleEndian.AppendUint32(out, spv.BEEFV1)
	out = spv.AppendVarInt(out, 1)
	out = append(out, bump...)
	out = spv.AppendVarInt(out, 1)
	out = append(out, rawTx...)
	out = append(out, 1)
	return spv.AppendVarInt(out, 0)
}

// AtomicBEEFV2 is AtomicBEEFV1 with a V2 body (format byte 1).
func AtomicBEEFV2(rawTx, bump []byte) []byte {
	txid := spv.DoubleSHA256(rawTx)
	out := binary.LittleEndian.AppendUint32(nil, 0x01010101)
	out = append(out, txid[:]...)
	out = binary.LittleEndian.AppendUint32(out, spv.BEEFV2)
	out = spv.AppendVarInt(out, 1)
	out = append(out, bump...)
	out = spv.AppendVarInt(out, 1)
	out = append(out, 1)
	out = spv.AppendVarInt(out, 0)
	return append(out, rawTx...)
}

// TestIdentityPrivateKey is the fixed test identity key:
// SHA-256("konareef chain-head anchor test identity"). Never use it for
// anything but tests.
func TestIdentityPrivateKey() *secp256k1.PrivateKey {
	seed := sha256.Sum256([]byte("konareef chain-head anchor test identity"))
	return secp256k1.PrivKeyFromBytes(seed[:])
}

// SignAnyone signs SHA-256(message) the way a BRC-100 wallet does for
// counterparty "anyone": with identity_priv + HMAC tweak (mod n). The
// signature is DER, low-S (RFC 6979).
// Inputs: identity private key; invoice; message. Output: DER bytes.
func SignAnyone(identity *secp256k1.PrivateKey, invoice string, message []byte) []byte {
	pub := identity.PubKey().SerializeCompressed()
	tweak, err := spv.AnyoneTweak(pub, invoice)
	if err != nil {
		panic(err)
	}
	var t, child secp256k1.ModNScalar
	t.SetBytes(&tweak)
	child.Set(&identity.Key).Add(&t)
	childKey := secp256k1.NewPrivateKey(&child)
	digest := sha256.Sum256(message)
	return ecdsa.Sign(childKey, digest[:]).Serialize()
}

// Chain is a synthetic block and chain around one anchor transaction.
type Chain struct {
	// RawTx is the anchor transaction.
	RawTx []byte
	// TxID is its id, internal order.
	TxID [32]byte
	// BUMP is its merkle path.
	BUMP []byte
	// Root is the block merkle root.
	Root [32]byte
	// Height is the block height.
	Height uint64
	// Header is the mined block header.
	Header [spv.HeaderSize]byte
	// Headers is a header source holding the block and Extra blocks on top.
	Headers *spv.Memory
}

// BuildChain builds a block at height with three transactions: a filler,
// the anchor transaction rawTx at index 1, and another filler. It mines
// the block at unixTime and extra further blocks on top of it, and
// returns them in an in-memory header source whose tip is the last one.
// Inputs: rawTx; height; unixTime; extra. Output: the chain.
func BuildChain(rawTx []byte, height uint64, unixTime uint32, extra int) *Chain {
	txid := spv.DoubleSHA256(rawTx)
	txids := [][32]byte{sha256.Sum256([]byte("filler-a")), txid, sha256.Sum256([]byte("filler-b"))}
	bump, root := BuildBUMP(height, txids, 1)
	prev := sha256.Sum256([]byte("genesis-parent"))
	header := MineHeader(prev, root, unixTime)
	mem := &spv.Memory{Headers: map[uint64][spv.HeaderSize]byte{height: header}, Tip: height}
	last := header
	for i := 1; i <= extra; i++ {
		parsed, _ := spv.ParseHeader(last[:])
		next := MineHeader(parsed.Hash(), sha256.Sum256([]byte{byte(i)}), unixTime+uint32(600*i))
		mem.Headers[height+uint64(i)] = next
		mem.Tip = height + uint64(i)
		last = next
	}
	return &Chain{RawTx: rawTx, TxID: txid, BUMP: bump, Root: root, Height: height, Header: header, Headers: mem}
}

// BigTarget is a helper returning the target for bits as a *big.Int.
func BigTarget(bits uint32) *big.Int { return spv.CompactToTarget(bits) }
