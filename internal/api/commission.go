// Copyright 2026 Jerry David Chan, Konareef.ai
// SPDX-License-Identifier: Apache-2.0

// commission.go — the reef-core routes of the signed commission admission
// contract (docs/design/commission-admission-contract.md):
//
//   - POST /api/commissioned-runs: submit a signed commission and start
//     one run (§5.3, §14.1);
//   - GET /api/commissioned-runs/:receipt_id: read a receipt (§14.1);
//   - POST /api/commissions/revoke: revoke a commission (§7.5);
//   - GET /api/commission-keys/challenge, POST /api/commission-keys,
//     GET /api/commission-keys, DELETE /api/commission-keys/:id: the buyer
//     key registry (§6.1).
//
// The submit call never falls back. It posts to one route, sends
// `Content-Type: application/json` (the only type the server accepts),
// does not follow redirects, and classifies every failure into exactly one
// of three kinds a caller can tell apart with errors.As / errors.Is:
//
//   - *ServerError: the server answered with a coded refusal
//     ({"error": {"kind": ...}}); Kind is the server's code, unchanged;
//   - ErrCommissionRouteMissing: the server has no such route (404 or 405
//     with no refusal code), so it predates the contract;
//   - *HTTPRefusal: another 4xx with no refusal code (an authentication
//     plug or a proxy refused the request);
//   - *TransportError: no usable HTTP answer (connection, timeout, a
//     redirect, an uncoded 5xx, or a body that does not decode).
//
// None of these is ever turned into a spawn on another route.

package api

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
)

// Commission routes.
const (
	pathCommissionedRuns   = "/api/commissioned-runs"
	pathCommissionRevoke   = "/api/commissions/revoke"
	pathCommissionKeys     = "/api/commission-keys"
	pathCommissionKeyChall = "/api/commission-keys/challenge"
)

// maxCommissionResponseBytes bounds a commission route response body. A
// receipt is a few KiB.
const maxCommissionResponseBytes = 1 << 20

// ErrCommissionRouteMissing means the server has no commission route: it
// answered 404 or 405 without a refusal code. Such a server predates the
// admission contract. The run was not started, and the caller must not
// retry the run on another route (§15).
var ErrCommissionRouteMissing = errors.New("server does not implement the commission admission contract (no such route)")

// HTTPRefusal is a 4xx answer without a refusal code, for example reef-core's
// 401 {"error": "invalid_session"} from its authentication plug, or a 403
// or 413 from a proxy. It is a final answer from the server side, not a
// transport failure: the request arrived and was refused, so it is never
// retried.
type HTTPRefusal struct {
	// Status is the HTTP status.
	Status int
	// Err is the decoded body, already escaped for a terminal.
	Err error
}

// Error renders the refusal.
func (e *HTTPRefusal) Error() string { return fmt.Sprintf("refused without a code: %v", e.Err) }

// TransportError means the request got no usable HTTP answer: the
// connection failed or timed out, the server redirected, answered an
// uncoded 5xx, or sent a body that does not decode. For a submit, the
// request may or may not have reached the server.
type TransportError struct {
	// Status is the HTTP status when there was a response, else 0.
	Status int
	// Err is the underlying error.
	Err error
}

// Error renders the transport failure.
func (e *TransportError) Error() string {
	if e.Status != 0 {
		return fmt.Sprintf("transport: http %d: %v", e.Status, e.Err)
	}
	return fmt.Sprintf("transport: %v", e.Err)
}

// Unwrap returns the underlying error, so errors.Is sees context errors.
func (e *TransportError) Unwrap() error { return e.Err }

// CommissionedRunRequest is the body of POST /api/commissioned-runs
// (§5.3). It has exactly these four keys; the pod is named only by the
// signed binding inside Commission, so there is no pod, model or budget
// field to set.
type CommissionedRunRequest struct {
	// Contract is commission.AdmissionContractV1.
	Contract string `json:"contract"`
	// AssuranceMode is commission.AssuranceModeLimitedV1.
	AssuranceMode string `json:"assurance_mode"`
	// Commission is the standard base64 (with padding) of the wire bytes.
	Commission string `json:"commission"`
	// Inputs are the run's per-run inputs. They are not signed (§7.4).
	// Omitted when empty; the server reads an omitted value as {}.
	Inputs map[string]string `json:"inputs,omitempty"`
}

// CommissionRevokeRequest is the body of POST /api/commissions/revoke
// (§7.5).
type CommissionRevokeRequest struct {
	Contract   string `json:"contract"`
	Commission string `json:"commission"`
}

// CommissionRevokeResponse is the answer to a revocation: state is
// "revoked" (201) or "already_revoked" (200).
type CommissionRevokeResponse struct {
	HCommission string `json:"h_commission"`
	State       string `json:"state"`
}

// CommissionReceipt is the unsigned admission receipt (§14.1). Its
// authenticity is only the API session that delivered it
// (Authenticity = "api_session_only").
type CommissionReceipt struct {
	ReceiptID     string            `json:"receipt_id"`
	Contract      string            `json:"contract"`
	AssuranceMode string            `json:"assurance_mode"`
	HCommission   string            `json:"h_commission"`
	SignerPubkey  string            `json:"signer_pubkey"`
	SignerKeyID   string            `json:"signer_key_id"`
	PodHash       string            `json:"pod_hash"`
	PodRef        string            `json:"pod_ref"`
	FieldsRoot    string            `json:"fields_root"`
	MemoryClass   string            `json:"memory_class"`
	Derived       ReceiptDerived    `json:"derived"`
	Fees          ReceiptFees       `json:"fees"`
	RunState      string            `json:"run_state"`
	Effective     ReceiptEffective  `json:"effective"`
	Dimensions    map[string]string `json:"dimensions"`
	Inputs        string            `json:"inputs"`
	VerifierImpl  string            `json:"verifier_impl"`
	AdmittedAt    string            `json:"admitted_at"`
	Authenticity  string            `json:"authenticity"`
}

// ReceiptDerived is the envelope the server derived from the stored
// manifest (§9).
type ReceiptDerived struct {
	Models   []string `json:"models"`
	Tools    []string `json:"tools"`
	CMaxSats uint64   `json:"c_max_sats"`
}

// ReceiptFees lists the fees the run's hold reserves beside the compute
// cap, and whether the commission cap bounds them (D17).
type ReceiptFees struct {
	AuthorFeeSats       uint64 `json:"author_fee_sats"`
	ZKFeeSats           uint64 `json:"zk_fee_sats"`
	BoundedByCommission bool   `json:"bounded_by_commission"`
}

// ReceiptEffective is the model and budget the run was configured with
// (§11).
type ReceiptEffective struct {
	ModelID    string `json:"model_id"`
	BudgetSats uint64 `json:"budget_sats"`
}

// CommissionedRunResponse is the 201 (started) or 200 (replayed) body of
// POST /api/commissioned-runs: the spawn fields plus the receipt.
type CommissionedRunResponse struct {
	SpawnResponse
	Receipt *CommissionReceipt `json:"receipt"`
}

// CommissionKeyChallenge is a single-use registration challenge (§6.1).
type CommissionKeyChallenge struct {
	Challenge string `json:"challenge"`
	ExpiresAt string `json:"expires_at"`
	// UserID is the session's account id exactly as the registration
	// message signs it (reef-core Keys.message_user_id/1). It is nil when
	// the server does not send it: reef-core before !149, or a JSON null.
	// The value is server text: validate it before use and escape it
	// before printing.
	UserID *string `json:"user_id"`
}

// CommissionKeyRegistration is the body of POST /api/commission-keys.
type CommissionKeyRegistration struct {
	// Pubkey is the 33-byte compressed key, 66 lowercase hex characters.
	Pubkey string `json:"pubkey"`
	// Challenge is the challenge from GetCommissionKeyChallenge.
	Challenge string `json:"challenge"`
	// Signature is hex DER over SHA-256 of the registration message.
	Signature string `json:"signature"`
}

// CommissionKey is one registered buyer key.
type CommissionKey struct {
	KeyID        string  `json:"key_id"`
	Pubkey       string  `json:"pubkey"`
	RegisteredAt string  `json:"registered_at"`
	RetiredAt    *string `json:"retired_at"`
}

// SubmitCommissionedRun posts one commissioned-run request.
//
// Inputs: a context (cancel it to abort) and the request. Output:
//   - the response and replayed=false on 201 (the run started);
//   - the response and replayed=true on 200 (this account already started
//     a run with this commission and these inputs; the body is that run);
//   - a *ServerError, ErrCommissionRouteMissing, *HTTPRefusal or
//     *TransportError.
//
// A 2xx without a receipt is a *TransportError: a success that carries no
// evidence of admission is not treated as one.
//
// Requires a session token.
func (c *Client) SubmitCommissionedRun(ctx context.Context, req CommissionedRunRequest) (*CommissionedRunResponse, bool, error) {
	if c.SessionToken == "" {
		return nil, false, fmt.Errorf("submit commissioned run: session token required")
	}
	var out CommissionedRunResponse
	status, err := c.doCommissionJSON(ctx, http.MethodPost, pathCommissionedRuns, req, &out)
	if err != nil {
		return nil, false, err
	}
	if status != http.StatusCreated && status != http.StatusOK {
		return nil, false, &TransportError{Status: status, Err: fmt.Errorf("unexpected success status")}
	}
	if out.Receipt == nil || out.AgentID == "" {
		return nil, false, &TransportError{Status: status, Err: fmt.Errorf("success response has no receipt or agent_id")}
	}
	return &out, status == http.StatusOK, nil
}

// GetCommissionReceipt reads one of the caller's receipts.
//
// Inputs: a context and the receipt id. Output: the receipt, or an error
// as SubmitCommissionedRun classifies it (another account's receipt and an
// unknown id are a *ServerError with Kind "not_found").
//
// Requires a session token.
func (c *Client) GetCommissionReceipt(ctx context.Context, receiptID string) (*CommissionReceipt, error) {
	if c.SessionToken == "" {
		return nil, fmt.Errorf("get commission receipt: session token required")
	}
	var out struct {
		Receipt *CommissionReceipt `json:"receipt"`
	}
	if _, err := c.doCommissionJSON(ctx, http.MethodGet, pathCommissionedRuns+"/"+url.PathEscape(receiptID), nil, &out); err != nil {
		return nil, err
	}
	if out.Receipt == nil {
		return nil, &TransportError{Err: fmt.Errorf("response has no receipt")}
	}
	return out.Receipt, nil
}

// RevokeCommission revokes a commission the caller holds.
//
// Inputs: a context and the request (the signed wire bytes). Output: the
// server's answer, or a classified error.
//
// Requires a session token.
func (c *Client) RevokeCommission(ctx context.Context, req CommissionRevokeRequest) (*CommissionRevokeResponse, error) {
	if c.SessionToken == "" {
		return nil, fmt.Errorf("revoke commission: session token required")
	}
	var out CommissionRevokeResponse
	if _, err := c.doCommissionJSON(ctx, http.MethodPost, pathCommissionRevoke, req, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// GetCommissionKeyChallenge fetches a registration challenge bound to this
// session. A new challenge replaces the session's earlier one.
//
// Requires a session token.
func (c *Client) GetCommissionKeyChallenge(ctx context.Context) (*CommissionKeyChallenge, error) {
	if c.SessionToken == "" {
		return nil, fmt.Errorf("get commission key challenge: session token required")
	}
	var out CommissionKeyChallenge
	if _, err := c.doCommissionJSON(ctx, http.MethodGet, pathCommissionKeyChall, nil, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// RegisterCommissionKey registers a buyer key with proof of possession.
//
// Inputs: a context and the registration. Output: the registered key, or a
// classified error (for example Kind "commission_key_already_registered").
//
// Requires a session token.
func (c *Client) RegisterCommissionKey(ctx context.Context, reg CommissionKeyRegistration) (*CommissionKey, error) {
	if c.SessionToken == "" {
		return nil, fmt.Errorf("register commission key: session token required")
	}
	var out CommissionKey
	if _, err := c.doCommissionJSON(ctx, http.MethodPost, pathCommissionKeys, reg, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// ListCommissionKeys lists the caller's registered keys.
//
// Requires a session token.
func (c *Client) ListCommissionKeys(ctx context.Context) ([]CommissionKey, error) {
	if c.SessionToken == "" {
		return nil, fmt.Errorf("list commission keys: session token required")
	}
	var out struct {
		Keys []CommissionKey `json:"keys"`
	}
	if _, err := c.doCommissionJSON(ctx, http.MethodGet, pathCommissionKeys, nil, &out); err != nil {
		return nil, err
	}
	return out.Keys, nil
}

// RetireCommissionKey retires one of the caller's keys. Retirement is
// permanent and refuses every commission of the key not yet admitted.
//
// Requires a session token.
func (c *Client) RetireCommissionKey(ctx context.Context, keyID string) (*CommissionKey, error) {
	if c.SessionToken == "" {
		return nil, fmt.Errorf("retire commission key: session token required")
	}
	var out CommissionKey
	if _, err := c.doCommissionJSON(ctx, http.MethodDelete, pathCommissionKeys+"/"+url.PathEscape(keyID), nil, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// doCommissionJSON sends one request to a commission route and classifies
// the result (see this file's header).
//
// Inputs: a context, the method, the path, an optional JSON body, and the
// value to decode a 2xx body into. Output: the 2xx status, or a
// *ServerError, ErrCommissionRouteMissing, *HTTPRefusal or *TransportError.
func (c *Client) doCommissionJSON(ctx context.Context, method, path string, body, out any) (int, error) {
	var reader io.Reader
	if body != nil {
		buf, err := json.Marshal(body)
		if err != nil {
			return 0, fmt.Errorf("marshal: %w", err)
		}
		reader = bytes.NewReader(buf)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.BaseURL+path, reader)
	if err != nil {
		return 0, fmt.Errorf("new request: %w", err)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("Accept", "application/json")
	if c.SessionToken != "" {
		req.Header.Set("Authorization", "Bearer "+c.SessionToken)
	}

	resp, err := c.noRedirectHTTPClient().Do(req)
	if err != nil {
		return 0, &TransportError{Err: err}
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxCommissionResponseBytes))
	if err != nil {
		return 0, &TransportError{Status: resp.StatusCode, Err: fmt.Errorf("read body: %w", err)}
	}

	switch {
	case resp.StatusCode >= 300 && resp.StatusCode < 400:
		// A redirect could point the signed request at another route. It
		// is not followed; the caller sees a transport failure.
		return 0, &TransportError{Status: resp.StatusCode, Err: fmt.Errorf("redirect to %q not followed", resp.Header.Get("Location"))}
	case resp.StatusCode >= 400:
		decoded := decodeErrorBody(resp.StatusCode, raw)
		var serverErr *ServerError
		if errors.As(decoded, &serverErr) {
			return 0, serverErr
		}
		if resp.StatusCode == http.StatusNotFound || resp.StatusCode == http.StatusMethodNotAllowed {
			return 0, fmt.Errorf("%w: http %d", ErrCommissionRouteMissing, resp.StatusCode)
		}
		if resp.StatusCode < 500 {
			return 0, &HTTPRefusal{Status: resp.StatusCode, Err: decoded}
		}
		return 0, &TransportError{Status: resp.StatusCode, Err: decoded}
	}

	if out != nil {
		if err := json.Unmarshal(raw, out); err != nil {
			return 0, &TransportError{Status: resp.StatusCode, Err: fmt.Errorf("decode: %w", err)}
		}
	}
	return resp.StatusCode, nil
}

// noRedirectHTTPClient returns the client's HTTP client with redirects
// disabled: a copy, so the client's other routes keep their behaviour.
func (c *Client) noRedirectHTTPClient() *http.Client {
	base := c.HTTPClient
	if base == nil {
		base = http.DefaultClient
	}
	cp := *base
	cp.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return &cp
}
