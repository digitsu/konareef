// Copyright 2026 Jerry David Chan, Konareef.ai
// SPDX-License-Identifier: Apache-2.0

// Package spv is a small, dependency-free SPV toolkit for the
// konareef-bundle/v2 chain-head anchor (reef-core#76, PRD 3 § 8.5).
//
// It parses exactly the BSV structures the anchor carries and nothing
// more:
//
//   - raw transactions (ParseTx, TxID) — enough to read outputs and
//     compute the transaction id;
//   - BRC-74 BUMP merkle paths (ParseBUMP, BUMP.ComputeRoot);
//   - BRC-62 / BRC-96 BEEF inside a BRC-95 Atomic BEEF envelope
//     (ParseAtomicBEEF);
//   - 80-byte block headers with a proof-of-work check against a
//     difficulty floor (ParseHeader, Header.CheckWork);
//   - block-header sources (HeaderSource and its pinned-file, remote
//     and combined implementations);
//   - BRC-42 key derivation for the counterparty "anyone"
//     (DeriveAnyonePublicKey), used to check a node's anchor
//     attestation.
//
// Byte orders. A txid or block hash is computed as double SHA-256 and
// kept in "internal" order (the hash output as is). The "display" order
// shown by explorers is the reverse. BUMP leaf hashes and the header
// merkle root are in internal order on the wire. Functions name the
// order they take or return.
//
// Every parser is strict: it consumes the whole input and refuses
// trailing bytes, truncation and non-minimal variable-length integers.
package spv
