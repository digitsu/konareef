// internal/paygate/export_test.go — test-only re-exports.
package paygate

import (
	"errors"
	"net/http"
)

// ClassifyHTTPErrorForTest exposes (*Client).classifyHTTPError so
// codederr_test.go can build a wrapped codedErr without standing up
// an HTTP client. The receiver is a zero-value Client because
// classifyHTTPError does not consult any Client state.
//
// The header parameter mirrors the production signature so callers can
// assert the round-3 B1 fix (Retry-After header takes precedence over
// the JSON body's retry_after_seconds field). Pass nil when the test
// only cares about the body-level credit_token / sentinel mapping.
func ClassifyHTTPErrorForTest(status int, header http.Header, body []byte) error {
	var c Client
	return c.classifyHTTPError(status, header, body)
}

// RetryAfterSecondsFromErrorForTest extracts codedErr.RetryAfterSeconds
// from a wrapped error (typically the return of
// ClassifyHTTPErrorForTest or a SubmitFold failure). Returns 0 when the
// error is not a *codedErr.
func RetryAfterSecondsFromErrorForTest(err error) int {
	var ce *codedErr
	if errors.As(err, &ce) {
		return ce.RetryAfterSeconds
	}
	return 0
}
