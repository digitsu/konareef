// Copyright 2026 Jerry David Chan, Konareef.ai
// SPDX-License-Identifier: Apache-2.0

// internal/paygate/idempotency_cache.go — PRD P1.8 WI-4 normative cache.
//
// Schema:
//
//	CREATE TABLE idempotency_cache (
//	  brc31_session_id TEXT NOT NULL,
//	  idempotency_key  TEXT NOT NULL,
//	  job_id           TEXT NOT NULL,
//	  submitted_at     TIMESTAMP NOT NULL,
//	  expires_at       TIMESTAMP NOT NULL,
//	  PRIMARY KEY (brc31_session_id, idempotency_key)
//	);
//
// Lookup is filter-on-now < expires_at; older rows count as cache miss
// for dedupe purposes (a resubmission past expiry is a billable fresh
// submission). Single-argument lookup is NOT a supported API per PRD
// P1.8 § "Idempotency cache schema (WI-4 normative)".
package paygate

import (
	"database/sql"
	"errors"
	"time"

	_ "modernc.org/sqlite"
)

// ErrIdempCacheMiss signals "no live cache row" — distinct from a
// PaygateError because it is internal to the client's bookkeeping.
var ErrIdempCacheMiss = errors.New("paygate: idempotency cache miss")

// IdempotencyTTL is the default server-mirrored cache window (1h per
// PRD 2 § 6.5).
const IdempotencyTTL = time.Hour

// IdempCache is the SQLite-backed `(brc31_session_id, idempotency_key)`
// → job_id store.
type IdempCache struct {
	db *sql.DB
}

// OpenIdempCache opens or creates the SQLite database at dbPath and
// migrates the schema.
func OpenIdempCache(dbPath string) (*IdempCache, error) {
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		return nil, err
	}
	if _, err := db.Exec(`
		CREATE TABLE IF NOT EXISTS idempotency_cache (
			brc31_session_id TEXT NOT NULL,
			idempotency_key  TEXT NOT NULL,
			job_id           TEXT NOT NULL,
			submitted_at     TIMESTAMP NOT NULL,
			expires_at       TIMESTAMP NOT NULL,
			PRIMARY KEY (brc31_session_id, idempotency_key)
		);
	`); err != nil {
		_ = db.Close()
		return nil, err
	}
	return &IdempCache{db: db}, nil
}

// Close releases the underlying database handle.
func (c *IdempCache) Close() error { return c.db.Close() }

// Insert records (sessionID, idemKey) → jobID with submitted_at and a
// derived expires_at = submitted_at + IdempotencyTTL.
func (c *IdempCache) Insert(sessionID, idemKey, jobID string, submittedAt time.Time) error {
	expiresAt := submittedAt.Add(IdempotencyTTL)
	_, err := c.db.Exec(
		`INSERT OR REPLACE INTO idempotency_cache
		 (brc31_session_id, idempotency_key, job_id, submitted_at, expires_at)
		 VALUES (?, ?, ?, ?, ?)`,
		sessionID, idemKey, jobID, submittedAt.UTC(), expiresAt.UTC(),
	)
	return err
}

// Lookup returns the cached job_id for (sessionID, idemKey) if a row
// exists AND now < expires_at. Otherwise ErrIdempCacheMiss.
//
// Single-argument lookup is intentionally NOT supported per PRD P1.8
// WI-4: the server-side cache key is two-tuple, so the client mirror
// MUST be two-tuple. A future caller cannot accidentally collapse two
// distinct sessions presenting identical idempotency keys.
func (c *IdempCache) Lookup(sessionID, idemKey string) (string, error) {
	var jobID string
	var expiresAt time.Time
	err := c.db.QueryRow(
		`SELECT job_id, expires_at FROM idempotency_cache
		 WHERE brc31_session_id = ? AND idempotency_key = ?`,
		sessionID, idemKey,
	).Scan(&jobID, &expiresAt)
	if errors.Is(err, sql.ErrNoRows) {
		return "", ErrIdempCacheMiss
	}
	if err != nil {
		return "", err
	}
	if time.Now().UTC().After(expiresAt) {
		return "", ErrIdempCacheMiss
	}
	return jobID, nil
}
