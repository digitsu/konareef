// Package stubserver is the in-process conformance-stub PayGate ZK
// endpoint built from PRD 2's behavioural matrix. Each M-1..M-8 test
// instantiates one with the specific Options it needs.
package stubserver

import (
	"net/http"
	"net/http/httptest"
	"sync"
	"time"
)

// Options tunes the stub server behaviour per acceptance check.
type Options struct {
	ManifestProfile      string        // "active" | "stale"
	StaleScheduleEnforce bool          // M-1: reject BEEFs after schedule transition
	IdempotencyReplay    bool          // M-3: return same job_id on dupe Idempotency-Key
	CreditTokenInjection string        // M-4: inject this token in next failure response
	RetryAfterDuration   time.Duration // (legacy single-shot) include Retry-After on next 503
	RetentionState       string        // M-6: "fresh" | "expired"
	FirstFetchWindow     time.Duration // M-6b: when set, first GET /result starts a window
	NextFailureCode      string        // generic failure injection
	PinMismatchManifest  string        // alternative vkey_sha256 for M-5

	// M-7 deterministic retry knobs.
	//
	// AttemptScript is consumed left-to-right on each POST to
	// /v1/prove/nova-fold. Each AttemptResponse fully determines
	// the response for that attempt. If the script is non-empty,
	// it takes precedence over NextFailureCode + RetryAfterDuration
	// for /v1/prove/nova-fold. If the script is exhausted, the
	// stub returns 500 (so test bugs surface loudly).
	//
	// OnAttempt fires inside the handler's critical section BEFORE
	// the response is written, allowing tests to record per-attempt
	// timestamps from the server side (eliminating client roundtrip
	// jitter from M-7's elapsed-time assertion).
	AttemptScript []AttemptResponse
	OnAttempt     func()
}

// AttemptResponse fully determines a single response from the stub's
// /v1/prove/nova-fold endpoint when AttemptScript is in use.
//
//   - Status == 503: write 503 + (optional) Retry-After header.
//   - Status == 200 or 202: write 202 Accepted with the given JobID
//     (the field is named for clarity; the wire status remains 202
//     per PRD 2 § 3 for async job acceptance).
//   - Any other Status: write that status with a stub error body.
type AttemptResponse struct {
	Status        int           // 503 | 200 (== 202 wire) | other
	RetryAfter    time.Duration // only emitted when > 0
	JobID         string        // only used on Status == 200/202
	AcceptedAtUTC bool          // when true, set submitted_at = time.Now().UTC()
}

// Server wraps an httptest.Server + stub state.
type Server struct {
	srv  *httptest.Server
	opts Options

	mu            sync.Mutex
	nextJobID     int
	jobs          map[string]*jobState
	idempKeyToJob map[string]string
	firstFetchAt  map[string]time.Time
	beefSubmits   int
}

type jobState struct {
	JobID       string
	Status      string
	ProofType   string
	CircuitID   string
	CreatedAt   time.Time
	StepIndex   uint64
	Accumulator []byte
	FailureCode string
	CompletedAt time.Time
}

// New returns a started stub server.
func New(opts Options) *Server {
	s := &Server{
		opts:          opts,
		jobs:          map[string]*jobState{},
		idempKeyToJob: map[string]string{},
		firstFetchAt:  map[string]time.Time{},
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/.well-known/x402-info", s.handleManifest)
	mux.HandleFunc("/v1/prove/nova-fold", s.handleSubmit)
	mux.HandleFunc("/v1/jobs/", s.handleJob)
	s.srv = httptest.NewServer(mux)
	return s
}

// URL returns the base URL of the stub server.
func (s *Server) URL() string { return s.srv.URL }

// Client returns the test HTTP client (handles internal TLS quirks).
func (s *Server) Client() *http.Client { return s.srv.Client() }

// Close shuts down the stub server.
func (s *Server) Close() { s.srv.Close() }

// BEEFSubmits returns the number of BRC-29 BEEF submissions received.
// M-3 / M-4 / M-8 use this to assert "no second debit".
func (s *Server) BEEFSubmits() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.beefSubmits
}
