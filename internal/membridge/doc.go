// Package membridge implements PRD 4 Part B byte-exactly: the bridge
// from the Phase-0 set-semantic MemorySnapshot model to the PRD 1 § 5.5
// depth-20 sparse address-indexed ZK memory tree.
//
// Public surface (B.1 derivation, B.5 import, B.6 lineage):
//
//   - LogicalKey, CellIndex, CanonicalCellPayload, ValueHash, LeafHash
//   - SparseRoot, BuildAuthPath, VerifyAuthPath
//   - GenesisAssign, AssignCapture, EnforceHardCap
//   - ImportSnapshot, AuditTrailEntry
//   - Clone, Fork, Migrate, NewLineage
//   - DisclosurePolicy, PublicBundleView
//
// Every rejection is fatal and returns a *MembridgeError whose Code is a
// stable PRD 4 § 6 identifier (e.g. ERR_CELL_SALT_LEN). Callers branch on
// the code via errors.Is(err, ErrCellSaltLen).
package membridge
