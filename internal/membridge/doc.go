// Copyright 2026 Jerry David Chan, Konareef.ai
// SPDX-License-Identifier: Apache-2.0

// Package membridge implements PRD 4 Part B byte-exactly: the bridge
// from the Phase-0 set-semantic MemorySnapshot model to the PRD 1 § 5.5
// depth-20 sparse address-indexed ZK memory tree.
//
// Since MEM-03 (konareef#26, konareef-rinit/v1 spec D6) the value, leaf
// and node hashes are Poseidon-over-Pallas (PRD 1 §5.5 after the
// 2026-06-10 PRD 4 hash swap); only the cell index stays SHA-256. The
// tree root is therefore a canonical field element and is the r_init a
// konareef-toml/v2 manifest commits.
//
// Public surface (B.1 derivation, B.5 import, B.6 lineage, rinit/v1):
//
//   - LogicalKey, CellIndex, CanonicalCellPayload, ValueHash, LeafHash
//   - SparseRoot, BuildAuthPath, VerifyAuthPath
//   - GenesisAssign, AssignCapture, EnforceHardCap
//   - ImportSnapshot, AuditTrailEntry, CheckRInitV1
//   - RInitV1, Cell, DerivedCell (konareef-rinit/v1 §5)
//   - ResolveSources, MemorySource, SourceCellID, FilesKey (§4)
//   - Clone, Fork, Migrate, NewLineage
//   - DisclosurePolicy, PublicBundleView
//
// Every rejection is fatal and returns a *MembridgeError whose Code is a
// stable PRD 4 § 6 identifier (e.g. ERR_CELL_SALT_LEN). Callers branch on
// the code via errors.Is(err, ErrCellSaltLen).
package membridge
