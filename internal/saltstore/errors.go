// internal/saltstore/errors.go — sentinels per PRD P1.7.1 error catalog.
//
// All sentinels are *SaltStoreError; wrapped errors compare equal via
// errors.Is. Code(err) extracts the stable identifier string for
// golden-vector comparison and logging.
package saltstore

import "errors"

// SaltStoreError is the concrete sentinel type. Every exported Err*
// variable is a *SaltStoreError so a wrap via fmt.Errorf("%w", e)
// compares equal under errors.Is via the default pointer-equality
// unwrap path.
type SaltStoreError struct {
	CodeStr string
}

// Error returns the stable error code string.
func (e *SaltStoreError) Error() string { return e.CodeStr }

// Code returns the stable error code string.
func (e *SaltStoreError) Code() string { return e.CodeStr }

// Sentinel errors for the saltstore package. See PRD §"Error catalog".
var (
	ErrSaltStorageUnavailable       = &SaltStoreError{CodeStr: "ERR_SALT_STORAGE_UNAVAILABLE"}
	ErrSaltNotFound                 = &SaltStoreError{CodeStr: "ERR_SALT_NOT_FOUND"}
	ErrSaltAlreadyExists            = &SaltStoreError{CodeStr: "ERR_SALT_ALREADY_EXISTS"}
	ErrSaltBlobDecrypt              = &SaltStoreError{CodeStr: "ERR_SALT_BLOB_DECRYPT"}
	ErrSaltBlobMalformed            = &SaltStoreError{CodeStr: "ERR_SALT_BLOB_MALFORMED"}
	ErrSaltBlobUnsupportedVersion   = &SaltStoreError{CodeStr: "ERR_SALT_BLOB_UNSUPPORTED_VERSION"}
	ErrSaltBlobKDFParamsInvalid     = &SaltStoreError{CodeStr: "ERR_SALT_BLOB_KDF_PARAMS_INVALID"}
	ErrSaltBackendIO                = &SaltStoreError{CodeStr: "ERR_SALT_BACKEND_IO"}
	ErrSaltLineageIDInvalid         = &SaltStoreError{CodeStr: "ERR_SALT_LINEAGE_ID_INVALID"}
	ErrSaltManifestMissingLineageID = &SaltStoreError{CodeStr: "ERR_SALT_MANIFEST_MISSING_LINEAGE_ID"}
)

// Code extracts the stable error string. Returns "" if err is nil or
// not (a wrap of) a *SaltStoreError.
func Code(err error) string {
	var se *SaltStoreError
	if errors.As(err, &se) {
		return se.CodeStr
	}
	return ""
}
