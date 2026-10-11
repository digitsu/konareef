// Copyright 2026 Jerry David Chan, Konareef.ai
// SPDX-License-Identifier: Apache-2.0

// primitives.go — the three hash/tree primitives the verifier
// re-runs locally, byte-for-byte equivalent to reef-core's Elixir
// implementations.
//
//   - ComputeChainHash   ↔  ReefCore.Proofs.Hash.compute/3
//   - BuildMerkleRoot    ↔  ReefCore.Proofs.MerkleTree.build/1
//   - ComputeAccessLogHash ↔ ReefCore.Proofs.compute_access_log_hash/1
//
// A bug in any of these breaks every Verify() in the field, so the
// implementations are deliberately minimal and the unit tests treat
// them as the wire-format spec.

package verify

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"sort"
)

// ComputeChainHash returns SHA-256(prev_hash_bytes || data || timestamp),
// mirroring ReefCore.Proofs.Hash.compute/3. prevHashHex is an empty
// string for the genesis commitment (prev_hash omitted from the
// hash input) or a 64-char hex string of the 32-byte previous hash.
// Mixed-case hex is accepted (case-insensitive decode).
//
// data and timestamp are appended as their raw UTF-8 bytes — no
// length prefix, no separator, no encoding transformation. This is
// the byte-exact wire contract; do not "improve" it.
func ComputeChainHash(prevHashHex, data, timestamp string) [32]byte {
	h := sha256.New()
	if prevHashHex != "" {
		if b, err := hex.DecodeString(prevHashHex); err == nil && len(b) == 32 {
			h.Write(b)
		}
	}
	h.Write([]byte(data))
	h.Write([]byte(timestamp))
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

// BuildMerkleRoot rebuilds the deterministic binary Merkle root from
// a list of 32-byte leaves, exactly as ReefCore.Proofs.MerkleTree.build/1
// does:
//
//   - Empty input → all-zero root.
//   - Single leaf → root = leaf.
//   - Otherwise: dedupe, sort bytewise, then SHA-256(left || right)
//     pair-up reductions. Odd-count levels duplicate the trailing
//     node (Bitcoin-style).
//
// The caller passes raw byte slices, not hex strings; the bundle's
// snapshot_leaves[].content_hash field is hex and must be decoded
// before being fed here.
func BuildMerkleRoot(leaves [][]byte) [32]byte {
	sorted := sortAndDedup(leaves)
	switch len(sorted) {
	case 0:
		return [32]byte{}
	case 1:
		var out [32]byte
		copy(out[:], sorted[0])
		return out
	default:
		return reduceRoot(sorted)
	}
}

// reduceRoot pair-reduces until one node remains. The trailing node
// at an odd-length level is paired with itself (Bitcoin-style).
func reduceRoot(level [][]byte) [32]byte {
	for len(level) > 1 {
		next := make([][]byte, 0, (len(level)+1)/2)
		for i := 0; i < len(level); i += 2 {
			a := level[i]
			var b []byte
			if i+1 < len(level) {
				b = level[i+1]
			} else {
				b = a
			}
			h := sha256.Sum256(append(append([]byte{}, a...), b...))
			next = append(next, h[:])
		}
		level = next
	}
	var out [32]byte
	copy(out[:], level[0])
	return out
}

// ComputeAccessLogHash returns SHA-256(sorted_unique_concatenation),
// matching ReefCore.Proofs.compute_access_log_hash/1:
//
//  1. Take the access content-hash bytes (raw, not hex).
//  2. Sort ascending by raw byte order.
//  3. Dedupe.
//  4. Concatenate (no separator).
//  5. SHA-256.
//
// An empty input yields SHA-256(""), the well-known
// e3b0c442 98fc1c14 9afbf4c8 996fb924 27ae41e4 649b934c a495991b 7852b855.
func ComputeAccessLogHash(hashes [][]byte) [32]byte {
	sorted := sortAndDedup(hashes)
	return sha256.Sum256(bytes.Join(sorted, nil))
}

// ── internal ──────────────────────────────────────────────────────

// sortAndDedup returns a fresh slice with the input sorted bytewise
// ascending and duplicates removed (set semantics, as the Elixir
// `Enum.uniq` + `Enum.sort` pair does). The input is not mutated.
func sortAndDedup(in [][]byte) [][]byte {
	if len(in) == 0 {
		return nil
	}
	cp := make([][]byte, len(in))
	for i, b := range in {
		cp[i] = b
	}
	sort.Slice(cp, func(i, j int) bool { return bytes.Compare(cp[i], cp[j]) < 0 })
	out := cp[:0]
	for i, b := range cp {
		if i == 0 || !bytes.Equal(b, cp[i-1]) {
			out = append(out, b)
		}
	}
	return out
}
