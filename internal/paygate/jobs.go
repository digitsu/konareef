// internal/paygate/jobs.go — async job lifecycle (submit / poll / fetch).
package paygate

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"
)

// FoldStepInput is the runtime-side input to one fold submission.
type FoldStepInput struct {
	StepIndex    uint64
	PublicInputs map[string]interface{}
	Witness      map[string]interface{}
	HP           [32]byte // SHA-256 of canonical public-input vector
	BSVUSDRate   float64  // for BEEF sizing
}

// SubmitResp mirrors PRD 2 § 3.1 202 Accepted body.
type SubmitResp struct {
	JobID       string    `json:"job_id"`
	SubmittedAt time.Time `json:"submitted_at"`
}

// StatusResp mirrors PRD 2 § 3.2.
type StatusResp struct {
	JobID      string    `json:"job_id"`
	Status     string    `json:"status"`
	ProofType  string    `json:"proof_type"`
	CircuitID  string    `json:"circuit_id"`
	CreatedAt  time.Time `json:"created_at"`
	UpdatedAt  time.Time `json:"updated_at"`
	Error      *PRDError `json:"error"`
	RetryAfter int       `json:"-"` // populated from header
}

// PRDError mirrors PRD 2 § 6.3 envelope.
//
// CreditTokenIssuedAt / CreditTokenExpiresAt carry the server-declared
// validity window for `credit_token` (round-2 B3). When the server
// omits either, the client treats the token as un-trustworthy and does
// NOT persist a synthesised "now + 1h" placeholder — that placeholder
// would let the runtime keep a credit_token alive past server-side
// expiry or reject a still-valid one early. The fields are zero-valued
// for non-payment failures.
type PRDError struct {
	Code                 string                 `json:"code"`
	Category             Category               `json:"category"`
	Message              string                 `json:"message"`
	Details              map[string]interface{} `json:"details"`
	Retryable            bool                   `json:"retryable"`
	CreditToken          string                 `json:"credit_token"`
	CreditTokenIssuedAt  *time.Time             `json:"credit_token_issued_at,omitempty"`
	CreditTokenExpiresAt *time.Time             `json:"credit_token_expires_at,omitempty"`
	RetryAfterSeconds    int                    `json:"retry_after_seconds"`
}

// ResultBody mirrors PRD 2 § 3.3 for nova-fold.
//
// JobID is a konareef-local extension (PRD 2 § 3.3 erratum recommendation
// — the published spec returns it only in the 202 Accepted submit response,
// but tracking it on the result envelope makes M-3 / M-4 / M-6b assertions
// substantially simpler. The stub server echoes it; live PayGate servers
// MAY omit it and callers should fall back to the Idempotency-Key cache.
type ResultBody struct {
	AccumulatorOut     []byte                 `json:"accumulator_out"`
	StepProof          []byte                 `json:"step_proof"`
	PublicInputsEchoed map[string]interface{} `json:"public_inputs_echoed"`
	CostMeta           map[string]interface{} `json:"cost_meta"`
	JobID              string                 `json:"job_id"`
}

// submitNovaFold issues POST /v1/prove/nova-fold against c.BaseURL.
func (c *Client) submitNovaFold(ctx context.Context, sess *Session, in FoldStepInput, idemKey string, beef *BEEF, creditToken string) (*SubmitResp, error) {
	body, _ := json.Marshal(map[string]interface{}{
		"circuit_id":    sess.CircuitID,
		"public_inputs": in.PublicInputs,
		"witness":       in.Witness,
	})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.BaseURL+"/v1/prove/nova-fold", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", sess.BRC31Session.AuthorizationHeader([]byte("POST /v1/prove/nova-fold")))
	req.Header.Set("Idempotency-Key", idemKey)
	if creditToken != "" {
		req.Header.Set("X-Payment", "credit_token "+creditToken)
	} else {
		// PRD P1.8 / BRC-29 wire contract: payment payload is hex-encoded
		// so the binary BEEF transaction graph round-trips as ASCII safe
		// for an HTTP header. Sending raw bytes would corrupt the header
		// (control bytes / non-UTF-8 octets) and surface as opaque
		// "invalid header value" rejections at the proxy or stub.
		req.Header.Set("X-Payment", "Brc29 "+hex.EncodeToString(beef.WireBytes))
	}
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return nil, fmt.Errorf("paygate: submit: %w", err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusAccepted {
		return nil, c.classifyHTTPError(resp.StatusCode, resp.Header, raw)
	}
	var sr SubmitResp
	if err := json.Unmarshal(raw, &sr); err != nil {
		return nil, fmt.Errorf("paygate: parse submit response: %w", err)
	}
	return &sr, nil
}

// PollStatus issues GET /v1/jobs/{job_id}.
func (c *Client) PollStatus(ctx context.Context, sess *Session, jobID string) (*StatusResp, error) {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, c.BaseURL+"/v1/jobs/"+jobID, nil)
	req.Header.Set("Authorization", sess.BRC31Session.AuthorizationHeader([]byte("GET /v1/jobs/"+jobID)))
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return nil, fmt.Errorf("paygate: poll: %w", err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return nil, c.classifyHTTPError(resp.StatusCode, resp.Header, raw)
	}
	var s StatusResp
	if err := json.Unmarshal(raw, &s); err != nil {
		return nil, err
	}
	if v := resp.Header.Get("Retry-After"); v != "" {
		s.RetryAfter = int(ParseRetryAfter(resp.Header, time.Now().UTC()).Seconds())
	}
	return &s, nil
}

// FetchResult issues GET /v1/jobs/{job_id}/result. A 410 Gone surfaces
// ErrResultExpired per PRD 2 § 4.4.
func (c *Client) FetchResult(ctx context.Context, sess *Session, jobID string) (*ResultBody, error) {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, c.BaseURL+"/v1/jobs/"+jobID+"/result", nil)
	req.Header.Set("Authorization", sess.BRC31Session.AuthorizationHeader([]byte("GET /v1/jobs/"+jobID+"/result")))
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return nil, fmt.Errorf("paygate: fetch: %w", err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	if resp.StatusCode == http.StatusGone {
		return nil, ErrResultExpired
	}
	if resp.StatusCode != http.StatusOK {
		return nil, c.classifyHTTPError(resp.StatusCode, resp.Header, raw)
	}
	var rb ResultBody
	if err := json.Unmarshal(raw, &rb); err != nil {
		return nil, err
	}
	// Carry the job_id forward when the server omits it from the
	// result envelope (some live deployments only echo it on submit).
	if rb.JobID == "" {
		rb.JobID = jobID
	}
	return &rb, nil
}

// classifyHTTPError maps a non-success response (status + header + body)
// into a *codedErr that callers can pattern-match via errors.Is. The
// Retry-After signal is sourced from the HTTP header FIRST (RFC 7231 §7.1.3 /
// RFC 9110 §10.2.3, parsed via ParseRetryAfter so delta-seconds AND HTTP-date
// both work), and only falls back to the JSON body's
// `retry_after_seconds` field when the header is absent.
func (c *Client) classifyHTTPError(status int, header http.Header, body []byte) error {
	var env struct {
		Error PRDError `json:"error"`
	}
	if err := json.Unmarshal(body, &env); err != nil {
		return fmt.Errorf("paygate: http %d (unparseable body)", status)
	}
	pe := mapCodeToErr(env.Error.Code)
	if pe != nil {
		retryAfterSeconds := env.Error.RetryAfterSeconds
		if header != nil {
			if d := ParseRetryAfter(header, time.Now().UTC()); d > 0 {
				retryAfterSeconds = int(d.Seconds())
			}
		}
		return &codedErr{
			PaygateError:         pe,
			CreditToken:          env.Error.CreditToken,
			CreditTokenIssuedAt:  env.Error.CreditTokenIssuedAt,
			CreditTokenExpiresAt: env.Error.CreditTokenExpiresAt,
			Details:              env.Error.Details,
			HTTPStatus:           status,
			RetryAfterSeconds:    retryAfterSeconds,
		}
	}
	return fmt.Errorf("paygate: http %d code=%s", status, env.Error.Code)
}

// codedErr wraps a sentinel *PaygateError with extra wire-level context
// (HTTP status, credit_token, Retry-After) AND implements errors.Is /
// Unwrap so callers can use the standard library to match sentinels.
//
// CreditTokenIssuedAt / CreditTokenExpiresAt mirror the server failure
// envelope's validity window. Both nil means the server did not declare
// validity, in which case SubmitFold MUST NOT persist the token (round-2
// B3 fail-closed contract).
type codedErr struct {
	*PaygateError
	CreditToken          string
	CreditTokenIssuedAt  *time.Time
	CreditTokenExpiresAt *time.Time
	Details              map[string]interface{}
	HTTPStatus           int
	RetryAfterSeconds    int
}

// Unwrap exposes the inner *PaygateError so errors.Is/As traverse the
// wrap chain.
func (e *codedErr) Unwrap() error { return e.PaygateError }

// Is is a defensive fallback so direct pointer equality with the
// sentinel succeeds even if a future PaygateError type implements its
// own Is method that intercepts the chain.
func (e *codedErr) Is(target error) bool {
	if target == nil || e == nil {
		return false
	}
	if pe, ok := target.(*PaygateError); ok {
		return e.PaygateError == pe
	}
	return false
}

func mapCodeToErr(code string) *PaygateError {
	switch code {
	case "PAYMENT_AMOUNT_INSUFFICIENT":
		return ErrPaymentAmountInsufficient
	case "PAYMENT_CREDIT_TOKEN_INVALID":
		return ErrCreditTokenInvalid
	case "PAYMENT_CREDIT_TOKEN_EXPIRED":
		return ErrCreditTokenExpired
	case "COMPUTE_WORKER_CRASH":
		return ErrComputeWorkerCrash
	case "COMPUTE_TIMEOUT":
		return ErrComputeTimeout
	case "VALIDATION_WITNESS_SHAPE":
		return ErrValidationWitnessShape
	case "SERVICE_UNAVAILABLE":
		return ErrServiceUnavailable
	case "RESULT_EXPIRED":
		return ErrResultExpired
	case "PROOF_SELF_VERIFY_FAILED":
		return ErrProofSelfVerifyFailed
	}
	return nil
}

// CreditTokenFrom walks the error chain and returns the credit_token
// from the innermost *codedErr it finds. Returns "" if none.
func CreditTokenFrom(err error) string {
	var ce *codedErr
	if errors.As(err, &ce) {
		return ce.CreditToken
	}
	return ""
}

// CreditTokenValidityFrom walks the error chain and returns the
// server-declared (issued_at, expires_at, ok) for the credit_token,
// where ok is true only when BOTH timestamps are present on the
// failure envelope. Callers MUST treat ok == false as "no validity
// declared" and refuse to persist the token (round-2 B3 fail-closed).
func CreditTokenValidityFrom(err error) (issuedAt, expiresAt time.Time, ok bool) {
	var ce *codedErr
	if errors.As(err, &ce) {
		if ce.CreditTokenIssuedAt != nil && ce.CreditTokenExpiresAt != nil {
			return ce.CreditTokenIssuedAt.UTC(), ce.CreditTokenExpiresAt.UTC(), true
		}
	}
	return time.Time{}, time.Time{}, false
}
