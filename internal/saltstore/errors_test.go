// internal/saltstore/errors_test.go — assert every sentinel wraps
// correctly via errors.Is and Code() extracts the stable identifier.
package saltstore

import (
	"errors"
	"fmt"
	"testing"
)

func TestSentinelsWrap(t *testing.T) {
	all := []*SaltStoreError{
		ErrSaltStorageUnavailable,
		ErrSaltNotFound,
		ErrSaltAlreadyExists,
		ErrSaltBlobDecrypt,
		ErrSaltBlobMalformed,
		ErrSaltBlobUnsupportedVersion,
		ErrSaltBackendIO,
		ErrSaltLineageIDInvalid,
		ErrSaltManifestMissingLineageID,
	}
	for _, s := range all {
		wrapped := fmt.Errorf("wrap: %w", s)
		if !errors.Is(wrapped, s) {
			t.Errorf("errors.Is wrap of %s: got false", s.CodeStr)
		}
		if Code(wrapped) != s.CodeStr {
			t.Errorf("Code(wrap of %s) = %q", s.CodeStr, Code(wrapped))
		}
	}
}
