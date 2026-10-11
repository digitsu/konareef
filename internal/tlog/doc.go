// Copyright 2026 Jerry David Chan, Konareef.ai
// SPDX-License-Identifier: Apache-2.0

// Package tlog implements PRD 1 § 5.4: deterministic reconstruction of
// `t_root`, the Merkle commitment over a pod invocation's tool-call log
// `T_log`, from an ordered sequence of `proof_tool_calls`-equivalent
// rows.
//
// `t_root` is one of 13 public inputs to the konareef-pod-step-v1 Nova
// IVC step circuit (PRD 1 § 5.1). It is byte-interoperable across the
// Go CLI verifier (this package), reef-core's Elixir
// ReefCore.Proofs.TLog (the writer side), the TypeScript SDK verifier,
// and the (v1.5) BSV Script verifier. Any drift between
// implementations breaks every proof in flight, so the leaf/inner/
// length-bind encoding here is treated as wire-format spec — not
// "implementation detail".
//
// Public surface:
//
//   - Row           — a single tool-call record (matches the writer-side
//     `proof_tool_calls` row schema)
//   - LeafHash      — SHA-256(0x00 || record_bytes_i)
//   - TRootFromRows — full t_root from an unsorted []Row
//   - Z             — the all-empty-T_log padding sentinel
//     SHA-256(0x00 || 0x00)
//   - LeafTag, InternalTag, LengthBindTag — PRD 1 § 5.4 tag set
//
// All constants in this package are normative per PRD 1 § 5.4. Do not
// modify without a counter-amendment to the upstream PRD and the
// `tlog-from-db-rows` conformance vector.
package tlog
