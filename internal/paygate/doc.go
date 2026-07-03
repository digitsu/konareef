// Package paygate is the konareef runtime client for the PayGate ZK
// API (PRD 2). It implements the six PRD 4 § 2.1 / PRD P1.8 obligations
// and counter-signs the eight named acceptance checks M-1..M-8 plus the
// konareef-added M-6b first-fetch-window extension.
//
// Public surface:
//
//   - Client + Session
//   - Open, SubmitFold, PollStatus, FetchResult
//   - IdempotencyKey (PRD 2 § 6.5 errata-locked preimage)
//   - Typed error model (Category + Code + IsRetryable)
//
// All rejection paths return wrapped sentinel errors. Branch with
// errors.Is(err, paygate.ErrCircuitPinMismatch) for the canonical
// PRD P1.8 § 2 (Obligation 6) State C halt code; see errors.go for
// the closed enumeration of categories and codes inherited from
// PRD 2 § 6.4.
package paygate
