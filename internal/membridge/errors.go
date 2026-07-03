// internal/membridge/errors.go — stable sentinels matching PRD 4 §6.
//
// Every named code in PRD 4 §6 has a sentinel here. The Code() helper
// extracts the string for golden-vector comparison; errors.Is matches
// even when the sentinel is wrapped with fmt.Errorf("...: %w", e).
package membridge

import "errors"

// MembridgeError is the concrete sentinel type. Each exported Err*
// variable is a *MembridgeError, so wrapped errors compare equal to the
// sentinel via errors.Is (the default *T pointer-equality unwrap path).
type MembridgeError struct {
	CodeStr string
}

func (e *MembridgeError) Error() string { return e.CodeStr }

// Code returns the stable PRD 4 §6 identifier string for the sentinel.
// Equivalent to e.CodeStr; provided so callers can read .Code on
// *MembridgeError values surfaced through errors.As without naming the
// field directly.
func (e *MembridgeError) Code() string { return e.CodeStr }

// Sentinel values. The string field equals the stable PRD 4 §6 code.
var (
	ErrCellSaltLen            = &MembridgeError{CodeStr: "ERR_CELL_SALT_LEN"}
	ErrLeb128NonMinimal       = &MembridgeError{CodeStr: "ERR_LEB128_NONMINIMAL"}
	ErrCellCapExceeded        = &MembridgeError{CodeStr: "ERR_CELL_CAP_EXCEEDED"}
	ErrGenesisReseedCollision = &MembridgeError{CodeStr: "ERR_GENESIS_RESEED_COLLISION"}
	ErrCellIndexCollision     = &MembridgeError{CodeStr: "ERR_CELL_INDEX_COLLISION"}
	ErrRInitMismatch          = &MembridgeError{CodeStr: "ERR_RINIT_MISMATCH"}
	ErrSnapshotImportFailed   = &MembridgeError{CodeStr: "ERR_SNAPSHOT_IMPORT_FAILED"}
	ErrProvisionalIDMismatch  = &MembridgeError{CodeStr: "ERR_PROVISIONAL_ID_MISMATCH"}
	ErrTypeDConfidentialLeak  = &MembridgeError{CodeStr: "ERR_TYPE_D_CONFIDENTIAL_LEAK"}
	// ErrSparseIndexOutOfRange is raised when a caller passes a tree
	// index >= 2^D into the sparse Merkle API. Masking belongs only at
	// the normative CellIndex derivation boundary; the tree itself is
	// fail-closed on out-of-range caller input (Hermes review on MR !7).
	ErrSparseIndexOutOfRange = &MembridgeError{CodeStr: "ERR_SPARSE_INDEX_OUT_OF_RANGE"}
)

// Code extracts the stable error string. Returns "" if err is nil or
// not (a wrap of) a *MembridgeError.
func Code(err error) string {
	var me *MembridgeError
	if errors.As(err, &me) {
		return me.CodeStr
	}
	return ""
}
