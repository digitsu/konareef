// Copyright 2026 Jerry David Chan, Konareef.ai
// SPDX-License-Identifier: Apache-2.0

// internal/paygate/client.go — top-level Client + canonical 11-step
// submit lifecycle from PRD P1.8 "Submit lifecycle".
package paygate

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"math"
	"net/http"
	"time"

	"github.com/digitsu/konareef/internal/saltstore"
	"github.com/digitsu/konareef/internal/vkeystore"
)

// Client is the konareef runtime's PayGate ZK API consumer.
type Client struct {
	BaseURL       string
	HTTP          *http.Client
	IdentityPath  string
	StateDBPath   string
	ManifestCache *ManifestCache
	Resolver      *vkeystore.Resolver
	SaltBackend   saltstore.Backend
	PinChecker    PinCheck // interface; defaults to *PinChecker in production wiring
	IdempCache    *IdempCache
	TokenLedger   *TokenLedger

	// SubmitMaxRetries bounds the SubmitFold Retry-After loop.
	// Zero means default (2). One initial attempt PLUS up to N retries.
	SubmitMaxRetries int
}

// PinCheck is the minimal interface SubmitFold's Open path consumes.
// Default production wiring is *PinChecker (vkeystore-backed). Tests
// can supply a noopPinChecker via newSmokeClient or Options.PinChecker.
type PinCheck interface {
	Check(ctx context.Context, circuitID, manifestPin string) (PinState, error)
}

// DisclosurePolicy selects whether the runtime needs to look up a
// Type-D session salt from saltstore (Type-D) or skip salt lookup
// entirely because the bundle discloses the salt itself (Type-C).
// Required field — Open returns an error if it is the zero value.
type DisclosurePolicy string

const (
	// DisclosureTypeC indicates the bundle discloses salt; no saltstore lookup.
	DisclosureTypeC DisclosurePolicy = "C"
	// DisclosureTypeD indicates the runtime MUST load salt from saltstore; missing is fatal.
	DisclosureTypeD DisclosurePolicy = "D"
)

// OpenSessionInput drives Open().
//
// DisclosurePolicy is REQUIRED. For Type-D, LineageID MUST be set and
// saltstore.ErrSaltNotFound is FATAL — Open returns the wrapped error
// and does NOT open the session. For Type-C, LineageID is ignored and
// saltstore is not consulted (the bundle carries the salt).
type OpenSessionInput struct {
	CircuitID        string
	LineageID        [16]byte         // Type-D only; from pod manifest; used for saltstore lookup
	DisclosurePolicy DisclosurePolicy // REQUIRED: "C" or "D"
}

// Open performs the pre-session ritual: refresh manifest, pin-check
// (State A/B/C), create BRC-31 session (v1-simplified — within-process
// only; see Non-goals), load Type-D salt if applicable, prepare the
// pipelining gate. Returns the ready Session.
func (c *Client) Open(ctx context.Context, in OpenSessionInput) (*Session, error) {
	switch in.DisclosurePolicy {
	case DisclosureTypeC, DisclosureTypeD:
		// ok
	default:
		return nil, fmt.Errorf("paygate: open: DisclosurePolicy is required (must be %q or %q, got %q)",
			DisclosureTypeC, DisclosureTypeD, in.DisclosurePolicy)
	}
	manifest, err := c.ManifestCache.Get(ctx)
	if err != nil {
		return nil, fmt.Errorf("paygate: open: manifest: %w", err)
	}
	circ, ok := manifest.Circuits[in.CircuitID]
	if !ok {
		return nil, fmt.Errorf("paygate: open: circuit %q not in manifest", in.CircuitID)
	}
	state, err := c.PinChecker.Check(ctx, in.CircuitID, circ.VkeySha256)
	if err != nil {
		return nil, fmt.Errorf("paygate: open: pin check (state %v): %w", state, err)
	}
	identity, err := LoadOrCreateBRC31Identity(c.IdentityPath)
	if err != nil {
		return nil, err
	}
	// V1-simplified BRC-31: session ID is the lowercase-hex SHA-256 of
	// the identity pubkey (locally derived, NOT server-issued).
	sid := sha256.Sum256([]byte(identity.PubKeyHex()))
	brc31 := &BRC31Session{ID: fmt.Sprintf("%x", sid), Identity: identity}

	// Type-D vs Type-C salt handling:
	//   - Type-D: salt MUST be present; ErrSaltNotFound is FATAL.
	//   - Type-C: salt is disclosed by the bundle at verify time; the
	//     runtime does not consult saltstore here.
	var typeDSalt [32]byte
	if in.DisclosurePolicy == DisclosureTypeD {
		if c.SaltBackend == nil {
			return nil, fmt.Errorf("paygate: open: Type-D requires a SaltBackend but none was configured")
		}
		s, err := c.SaltBackend.Get(in.LineageID)
		if err != nil {
			// ErrSaltNotFound is FATAL for Type-D — no zero-value fallback.
			return nil, fmt.Errorf("paygate: open: Type-D salt lookup (lineage_id=%x): %w", in.LineageID, err)
		}
		typeDSalt = s
	}
	// Type-C: typeDSalt stays zero-valued.
	return &Session{
		BRC31Session:      brc31,
		DiscoveryManifest: manifest,
		ManifestFetchedAt: time.Now().UTC(),
		CircuitID:         in.CircuitID,
		PinnedVkeyHash:    circ.VkeySha256,
		CreditTokens:      c.TokenLedger,
		IdempotencyCache:  c.IdempCache,
		Gate:              &PipeliningGate{},
		LineageID:         in.LineageID,
		TypeDSalt:         typeDSalt,
	}, nil
}

// ErrCircuitNotInRefreshedManifest is returned by
// refreshManifestAndRevalidatePin when the freshly-fetched manifest no
// longer advertises the session's circuit. Surfacing this instead of
// silently allowing submission ensures a manifest that drops a circuit
// mid-session is treated as a hard failure for both the primary and
// credit-token retry paths.
var ErrCircuitNotInRefreshedManifest = errors.New("paygate: refreshed manifest no longer advertises session circuit")

// refreshManifestAndRevalidatePin re-fetches the manifest and, if the
// advertised vkey_sha256 for sess.CircuitID has rotated relative to
// sess.PinnedVkeyHash, re-runs the State A/B/C pin check and adopts the
// new pin for the remainder of the session. Returns the freshly-fetched
// manifest so callers can build BEEF from current pricing without a
// second round-trip.
//
// Shared by SubmitFold (primary submission) and SubmitFoldWithCredit
// (credit-token retry): the credit-token path MUST NOT slip across a
// mid-session vkey rotation that the primary path would fail closed on
// (Hermes round-3 B2).
func (c *Client) refreshManifestAndRevalidatePin(ctx context.Context, sess *Session) (*Manifest, error) {
	fresh, err := c.ManifestCache.Get(ctx)
	if err != nil {
		return nil, err
	}
	freshCirc, ok := fresh.Circuits[sess.CircuitID]
	if !ok {
		return nil, fmt.Errorf("%w: circuit=%q", ErrCircuitNotInRefreshedManifest, sess.CircuitID)
	}
	if freshCirc.VkeySha256 != sess.PinnedVkeyHash {
		if c.PinChecker == nil {
			return nil, fmt.Errorf("paygate: refreshManifestAndRevalidatePin: manifest pin rotated mid-session but no PinChecker is wired")
		}
		state, err := c.PinChecker.Check(ctx, sess.CircuitID, freshCirc.VkeySha256)
		if err != nil {
			return nil, fmt.Errorf("paygate: refreshManifestAndRevalidatePin: refreshed pin check (state %v): %w", state, err)
		}
		// Adopt the refreshed pin for the remainder of the session
		// so subsequent submissions compare against the new pin
		// (without this, every call would re-trigger the check).
		sess.PinnedVkeyHash = freshCirc.VkeySha256
	}
	return fresh, nil
}

// SubmitFold executes the canonical 11-step lifecycle from PRD P1.8
// "Submit lifecycle":
//
//  1. ensureFreshManifest
//  2. assertNotSpeculative
//  3. (witness/public-inputs supplied by caller)
//  4. idempKey
//  5. constructBEEF (or take credit_token)
//  6. submit
//  7. handle 202 / 4xx / 5xx
//  8. on 5xx with credit_token: ledger.Persist
//  9. poll status loop
//  10. fetch result
//  11. durableBind
func (c *Client) SubmitFold(ctx context.Context, sess *Session, in FoldStepInput) (*ResultBody, error) {
	// 1. fresh manifest (round-2 B1 / round-3 B2): the returned manifest
	// is the source of pricing / vkey-pin truth for THIS submission. The
	// captured sess.DiscoveryManifest from Open() can be stale by the
	// time SubmitFold is called, so we use the freshly-fetched value for
	// BEEF construction below. If the refreshed manifest advertises a
	// new vkey_sha256 for sess.CircuitID, refreshManifestAndRevalidatePin
	// re-runs the pin check before submitting (mid-session vkey rotation
	// must not slip past the State A/B/C machine). The same helper is
	// shared with SubmitFoldWithCredit so the credit-token retry path is
	// not weaker than the primary path.
	freshManifest, err := c.refreshManifestAndRevalidatePin(ctx, sess)
	if err != nil {
		return nil, err
	}
	// 2. anti-speculation
	if err := sess.Gate.AssertNotSpeculative(in.StepIndex); err != nil {
		return nil, err
	}
	// 4. idempotency (round-2 B5): only ErrIdempCacheMiss may fall
	// through to a fresh BEEF submission. Any other lookup error (SQLite
	// I/O fault, schema drift, etc.) MUST surface unwrapped — silently
	// treating a transient lookup error as a cache miss would let the
	// runtime construct + submit a fresh BEEF for an already-paid
	// (brc31_session_id, idempotency_key) pair and double-debit.
	idemKey := IdempotencyKey(sess.CircuitID, in.StepIndex, in.HP)
	cached, err := sess.IdempotencyCache.Lookup(sess.BRC31Session.ID, idemKey)
	switch {
	case err == nil:
		// PRD P1.8 M-3: replay returns same job_id with no second BEEF.
		return c.pollAndFetch(ctx, sess, cached)
	case errors.Is(err, ErrIdempCacheMiss):
		// fall through — fresh submission permitted
	default:
		return nil, fmt.Errorf("paygate: SubmitFold: idempotency cache lookup: %w", err)
	}
	// 5. BEEF (round-2 B6): use the caller-supplied BSV/USD rate so the
	// payment amount reflects the live market rate the runtime is
	// observing, not a hard-coded fixture. The rate MUST be finite +
	// strictly positive — a non-positive rate would mint a zero or
	// negative payment that the server would reject anyway.
	if !(in.BSVUSDRate > 0) || math.IsInf(in.BSVUSDRate, 0) || math.IsNaN(in.BSVUSDRate) {
		return nil, fmt.Errorf("paygate: SubmitFold: BSVUSDRate must be finite and >0; got %v", in.BSVUSDRate)
	}
	beef, err := BuildBEEF(freshManifest, sess.CircuitID, "nova-fold", in.BSVUSDRate)
	if err != nil {
		return nil, err
	}
	// 6+7. submit, with bounded Retry-After loop.
	maxRetries := c.SubmitMaxRetries
	if maxRetries == 0 {
		maxRetries = 2
	}
	var resp *SubmitResp
	for attempt := 0; attempt <= maxRetries; attempt++ {
		resp, err = c.submitNovaFold(ctx, sess, in, idemKey, beef, "")
		if err == nil {
			break
		}
		// Only retry on 503 + Retry-After. Everything else is terminal.
		ce, ok := err.(*codedErr)
		if !ok || ce.HTTPStatus != http.StatusServiceUnavailable || ce.RetryAfterSeconds <= 0 {
			break
		}
		if attempt == maxRetries {
			break // budget exhausted; surface the last error
		}
		wait := time.Duration(ce.RetryAfterSeconds) * time.Second
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(wait):
		}
	}
	if err != nil {
		// 8. credit_token capture on retryable failure (round-2 B3):
		// validity window comes from the server failure envelope. If
		// the server omitted credit_token_issued_at OR
		// credit_token_expires_at the token is treated as untrusted
		// (no synthesised "now + 1h" fallback) and NOT persisted.
		if tok := CreditTokenFrom(err); tok != "" {
			if issuedAt, expiresAt, ok := CreditTokenValidityFrom(err); ok {
				_ = sess.CreditTokens.Persist(tok, issuedAt, expiresAt)
			}
		}
		return nil, err
	}
	if err := sess.IdempotencyCache.Insert(sess.BRC31Session.ID, idemKey, resp.JobID, resp.SubmittedAt); err != nil {
		return nil, err
	}
	// 9+10+11
	return c.pollAndFetch(ctx, sess, resp.JobID)
}

// SubmitFoldWithCredit retries a previously-failed step using the
// supplied credit_token. M-4 / M-8 exercise this path.
//
// Round-3 B1 + B2 contract: the credit-token retry path MUST be no
// weaker than the primary path. That means:
//
//   - the manifest is re-fetched AND the State A/B/C pin check re-runs
//     on a rotated vkey_sha256 (shared refreshManifestAndRevalidatePin
//     helper) — a credit-retry MUST fail closed across a mid-session
//     vkey rotation, exactly like SubmitFold;
//   - the post-submission IdempotencyCache.Insert error is fatal —
//     swallowing it would leave the runtime reporting success while
//     no durable (brc31_session_id, idempotency_key) → job_id binding
//     exists, which the pipelining gate would then permit a later
//     replay to slip past as a fresh BEEF for the same logical fold
//     (duplicate-payment risk that round-2 B5 was meant to close).
func (c *Client) SubmitFoldWithCredit(ctx context.Context, sess *Session, in FoldStepInput, creditToken string) (*ResultBody, error) {
	if _, err := sess.CreditTokens.Take(creditToken); err != nil {
		return nil, err
	}
	if _, err := c.refreshManifestAndRevalidatePin(ctx, sess); err != nil {
		return nil, err
	}
	if err := sess.Gate.AssertNotSpeculative(in.StepIndex); err != nil {
		return nil, err
	}
	idemKey := IdempotencyKey(sess.CircuitID, in.StepIndex, in.HP)
	resp, err := c.submitNovaFold(ctx, sess, in, idemKey, nil, creditToken)
	if err != nil {
		return nil, err
	}
	if err := sess.IdempotencyCache.Insert(sess.BRC31Session.ID, idemKey, resp.JobID, resp.SubmittedAt); err != nil {
		return nil, fmt.Errorf("paygate: credit-token idempotency persist: %w", err)
	}
	return c.pollAndFetch(ctx, sess, resp.JobID)
}

func (c *Client) pollAndFetch(ctx context.Context, sess *Session, jobID string) (*ResultBody, error) {
	for attempt := 0; attempt < 60; attempt++ {
		st, err := c.PollStatus(ctx, sess, jobID)
		if err != nil {
			return nil, err
		}
		if st.Status == "completed" {
			rb, err := c.FetchResult(ctx, sess, jobID)
			if err != nil {
				return nil, err
			}
			if rb.JobID == "" {
				rb.JobID = jobID
			}
			sess.Gate.DurablyBind(parseStepFromEcho(rb), jobID, rb.AccumulatorOut)
			return rb, nil
		}
		if st.Status == "failed" {
			if mapped := mapCodeToErr(st.Error.Code); mapped != nil {
				return nil, mapped
			}
			return nil, fmt.Errorf("paygate: poll: job failed code=%s", st.Error.Code)
		}
		// Respect server Retry-After if present.
		wait := time.Duration(st.RetryAfter) * time.Second
		if wait == 0 {
			wait = BackoffStep(attempt)
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(wait):
		}
	}
	return nil, fmt.Errorf("paygate: pollAndFetch: gave up after 60 attempts")
}

func parseStepFromEcho(rb *ResultBody) uint64 {
	if rb == nil || rb.PublicInputsEchoed == nil {
		return 0
	}
	if v, ok := rb.PublicInputsEchoed["step_index"].(float64); ok {
		return uint64(v)
	}
	return 0
}
