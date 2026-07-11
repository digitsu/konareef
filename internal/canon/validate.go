// Copyright 2026 Jerry David Chan, Konareef.ai
// SPDX-License-Identifier: Apache-2.0

// validate.go — the domain-rejection gates of konareef-toml/v1.
//
// These run after TOML parsing and AST construction, before any
// serialization (spec §4 step 3). Each gate corresponds to a row in
// the spec §7 failure table. The first violation found aborts the
// whole canonicalization — there is no partial output and no issue
// list, unlike pod.Validate.
//
// Integer range is not gated here: BurntSushi/toml decodes integers
// into int64 and rejects an out-of-i64-range literal at parse time, so
// an over-range integer surfaces as TOML_PARSE_ERROR before this file
// runs. The spec §7 documents that behavior; there is no separate
// INT_OVERFLOW code.
package canon

import (
	"fmt"
	"math"
	"strings"
)

// floatRangeMax is the inclusive upper bound of the R8 allowed float
// range [0.0, 1.0e6].
const floatRangeMax = 1.0e6

// validateTree walks the AST and returns the first domain violation,
// or nil when every value is admissible.
func validateTree(root *table) error {
	return validateTable(root, nil)
}

// validateTable checks every field of t. path is the dotted key path
// to t, used both for error messages and to identify a top-level
// `[_files]` table.
func validateTable(t *table, path []string) error {
	for _, f := range t.fields {
		full := childPath(path, f.key)
		if err := validateKey(f.key, full); err != nil {
			return err
		}
		if err := validateValue(f.val, full); err != nil {
			return err
		}
	}
	return nil
}

// validateKey enforces the reserved-namespace and character-set rules
// (R2/charset and R15). A `_files` key is reported as RESERVED_KEY_FILES
// regardless of depth — it is the manifest name the canonicalizer
// itself synthesizes; any other `_`-prefixed key is the general
// reserved-namespace violation.
//
// The character set deliberately excludes `.`: a literal dot in a key
// (a TOML quoted key such as `"a.b"`) is indistinguishable from a
// dotted key path once emitted unquoted, which would make the
// canonical form non-idempotent. An empty key — the TOML quoted key
// `""` — is likewise rejected: it has no bare-key spelling.
func validateKey(key string, path []string) error {
	dotted := strings.Join(path, ".")
	if strings.HasPrefix(key, "_") {
		if key == "_files" {
			return newErr(ErrReservedKeyFiles,
				fmt.Sprintf("key %q: [_files] is synthesized by the canonicalizer and must not be hand-authored", dotted))
		}
		return newErr(ErrReservedKeyUnderscore,
			fmt.Sprintf("key %q: the `_` prefix is a reserved namespace", dotted))
	}
	if key == "" {
		return newErr(ErrKeyInvalidChar, "empty keys are not permitted")
	}
	for _, r := range key {
		if !isKeyChar(r) {
			return newErr(ErrKeyInvalidChar,
				fmt.Sprintf("key %q: character %q is outside the allowed set [A-Za-z0-9_-]", dotted, r))
		}
	}
	return nil
}

// isKeyChar reports whether r is in the canonical key character set
// [A-Za-z0-9_-]. `.` is excluded — see validateKey.
func isKeyChar(r rune) bool {
	switch {
	case r >= 'A' && r <= 'Z':
		return true
	case r >= 'a' && r <= 'z':
		return true
	case r >= '0' && r <= '9':
		return true
	case r == '_' || r == '-':
		return true
	default:
		return false
	}
}

// validateValue recursively checks one AST value.
func validateValue(v *value, path []string) error {
	switch v.kind {
	case kindFloat:
		return validateFloat(v.f, path)
	case kindDatetime:
		return validateDatetime(v, path)
	case kindArray:
		for _, e := range v.arr {
			if err := validateValue(e, path); err != nil {
				return err
			}
		}
	case kindTable:
		return validateTable(v.tbl, path)
	case kindArrayTable:
		for _, entry := range v.aot {
			if err := validateTable(entry, path); err != nil {
				return err
			}
		}
	}
	return nil
}

// validateFloat enforces R8: no NaN, no ±Inf, no subnormals, and a
// value within [0.0, 1.0e6].
func validateFloat(f float64, path []string) error {
	dotted := strings.Join(path, ".")
	switch {
	case math.IsNaN(f):
		return newErr(ErrFloatNaNForbidden, fmt.Sprintf("key %q: NaN is forbidden", dotted))
	case math.IsInf(f, 0):
		return newErr(ErrFloatInfForbidden, fmt.Sprintf("key %q: ±Inf is forbidden", dotted))
	case isSubnormal(f):
		return newErr(ErrFloatSubnormalForbidden, fmt.Sprintf("key %q: subnormal floats are forbidden", dotted))
	case f < 0.0 || f > floatRangeMax:
		return newErr(ErrFloatOutOfRange,
			fmt.Sprintf("key %q: float %g is outside the allowed range [0.0, 1.0e6]", dotted, f))
	}
	return nil
}

// isSubnormal reports whether f is a denormalized (subnormal) double:
// a biased exponent of zero with a non-zero mantissa. Plain zero
// (exponent and mantissa both zero) is normal, not subnormal.
func isSubnormal(f float64) bool {
	bits := math.Float64bits(f)
	exponent := (bits >> 52) & 0x7FF
	mantissa := bits & 0x000FFFFFFFFFFFFF
	return exponent == 0 && mantissa != 0
}

// validateDatetime enforces R10: only a UTC (`Z`) datetime is
// admissible. BurntSushi tags the TOML datetime sub-kinds via the
// parsed time.Location:
//
//   - "UTC"            — offset datetime with a literal `Z`  → accepted
//   - "date-local"     — local date (date-only)              → DATETIME_DATE_ONLY
//   - "time-local"     — local time (time-only)              → TIME_ONLY
//   - "datetime-local" — local datetime (no offset)          → DATETIME_NOT_UTC
//   - anything else    — an explicit numeric offset, e.g.
//     `+00:00` or `+05:00` (location name is "")             → DATETIME_NOT_UTC
//
// Note `+00:00` is rejected even though it denotes the same instant as
// `Z`: R10 admits exactly one spelling so the canonical form is
// unambiguous.
func validateDatetime(v *value, path []string) error {
	dotted := strings.Join(path, ".")
	switch v.dt.Location().String() {
	case "UTC":
		return nil
	case "date-local":
		return newErr(ErrDatetimeDateOnly,
			fmt.Sprintf("key %q: date-only values are forbidden; use a full RFC 3339 UTC datetime", dotted))
	case "time-local":
		return newErr(ErrTimeOnly,
			fmt.Sprintf("key %q: time-only values are forbidden; use a full RFC 3339 UTC datetime", dotted))
	case "datetime-local":
		return newErr(ErrDatetimeNotUTC,
			fmt.Sprintf("key %q: local datetime has no UTC offset; append `Z`", dotted))
	default:
		return newErr(ErrDatetimeNotUTC,
			fmt.Sprintf("key %q: datetime carries a non-`Z` offset; only UTC `Z` is permitted", dotted))
	}
}
