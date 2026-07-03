// errors.go — fatal canonicalization failures.
//
// Every canonicalizer rejection is fatal: no partial output is ever
// produced. An Error carries a stable, machine-readable Code (the
// strings frozen in konareef-toml/v1 spec §7) plus a human-readable
// Message that callers may surface but MUST NOT pattern-match on —
// only Code is contractually stable.
package canon

import "errors"

// Error is a fatal canonicalization failure.
//
// Code is one of the constants below — a stable identifier safe for
// machine dispatch and golden-vector expected.error files. Message is
// a human-readable elaboration and may change between releases.
type Error struct {
	Code    string
	Message string
}

// Error renders the failure as "CODE: message", or just "CODE" when no
// message is attached.
func (e *Error) Error() string {
	if e.Message == "" {
		return e.Code
	}
	return e.Code + ": " + e.Message
}

// Error codes — stable strings, konareef-toml/v1 spec §7. These MUST
// NOT change once the spec is locked; a verifier in any language keys
// off these exact bytes.
const (
	ErrEncodingNotUTF8         = "ENCODING_NOT_UTF8"
	ErrEncodingBOMPresent      = "ENCODING_BOM_PRESENT"
	ErrWrongVersion            = "WRONG_VERSION"
	ErrTOMLParseError          = "TOML_PARSE_ERROR"
	ErrFloatNaNForbidden       = "FLOAT_NAN_FORBIDDEN"
	ErrFloatInfForbidden       = "FLOAT_INF_FORBIDDEN"
	ErrFloatOutOfRange         = "FLOAT_OUT_OF_RANGE"
	ErrFloatSubnormalForbidden = "FLOAT_SUBNORMAL_FORBIDDEN"
	ErrReservedKeyFiles        = "RESERVED_KEY_FILES"
	ErrReservedKeyUnderscore   = "RESERVED_KEY_UNDERSCORE_PREFIX"
	ErrDatetimeNotUTC          = "DATETIME_NOT_UTC"
	ErrDatetimeDateOnly        = "DATETIME_DATE_ONLY"
	ErrTimeOnly                = "TIME_ONLY"
	ErrKeyInvalidChar          = "KEY_INVALID_CHAR"
	ErrFileNotReadable         = "FILE_NOT_READABLE"
	ErrSymlinkForbidden        = "SYMLINK_FORBIDDEN"
	ErrPathInvalid             = "PATH_INVALID"
	ErrPodSizeExceeded         = "POD_SIZE_EXCEEDED"
	ErrNonRegularFile          = "NON_REGULAR_FILE_FORBIDDEN"

	// ErrArrayOfInlineTables rejects an array whose elements are inline
	// tables (`key = [{a=1}, {b=2}]`). Spec §11 implementation found
	// this TOML construct has no defined canonical form — R11 expands
	// inline tables into `[table]` headers, but an array *element*
	// cannot become a table header. Rather than invent an ambiguous
	// form, v1 rejects it. konareef pod schemas never produce it; all
	// repeating structures use array-of-tables (`[[...]]`).
	ErrArrayOfInlineTables = "ARRAY_OF_INLINE_TABLES_FORBIDDEN"
)

// newErr constructs a fatal canon.Error.
func newErr(code, message string) *Error {
	return &Error{Code: code, Message: message}
}

// Code extracts the stable error code from err. It returns "" when err
// is nil or is not a *canon.Error — letting callers branch on the
// canonicalizer's documented failure modes without string matching.
func Code(err error) string {
	var e *Error
	if errors.As(err, &e) {
		return e.Code
	}
	return ""
}

// Warning is a non-fatal advisory raised during canonicalization.
// Unlike an Error it never aborts the process: canonical output is
// still produced and the pod_hash is unaffected. Warnings surface only
// through CanonicalizeWithWarnings; the spec-mandated Canonicalize
// discards them.
type Warning struct {
	Code    string
	Message string
}

// WarnPodSizeLarge is raised when the total pod size exceeds the R15
// advisory threshold (100 KiB) while staying within the 1 MiB hard
// cap. It flags a pod that is unusually heavy — a likely sign of
// accidentally vendored content — without rejecting it.
const WarnPodSizeLarge = "pod-size-large"
