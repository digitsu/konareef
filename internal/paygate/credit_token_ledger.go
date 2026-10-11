// Copyright 2026 Jerry David Chan, Konareef.ai
// SPDX-License-Identifier: Apache-2.0

// internal/paygate/credit_token_ledger.go — single-use credit_token store.
//
// Schema:
//
//	CREATE TABLE credit_tokens (
//	  token       TEXT PRIMARY KEY,
//	  issued_at   TIMESTAMP NOT NULL,
//	  expires_at  TIMESTAMP NOT NULL,
//	  used_at     TIMESTAMP
//	);
//
// Take performs the single-use enforcement atomically:
//  1. Load token, check expiry  → ErrCreditTokenExpired
//  2. Check used_at IS NULL     → ErrCreditTokenInvalid (already used)
//  3. UPDATE used_at = now()    → only one caller wins
package paygate

import (
	"database/sql"
	"errors"
	"time"
)

// TokenLedger persists credit_tokens issued in failed-job response bodies.
type TokenLedger struct {
	db *sql.DB
}

// LedgerEntry is one durable credit_token record.
type LedgerEntry struct {
	Token     string
	IssuedAt  time.Time
	ExpiresAt time.Time
	UsedAt    *time.Time
}

// OpenTokenLedger opens or creates the SQLite database at dbPath and
// migrates the schema.
func OpenTokenLedger(dbPath string) (*TokenLedger, error) {
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		return nil, err
	}
	if _, err := db.Exec(`
		CREATE TABLE IF NOT EXISTS credit_tokens (
			token       TEXT PRIMARY KEY,
			issued_at   TIMESTAMP NOT NULL,
			expires_at  TIMESTAMP NOT NULL,
			used_at     TIMESTAMP
		);
	`); err != nil {
		_ = db.Close()
		return nil, err
	}
	return &TokenLedger{db: db}, nil
}

// Close releases the underlying database handle.
func (l *TokenLedger) Close() error { return l.db.Close() }

// Persist records a freshly-issued credit_token. issuedAt + expiresAt
// are read from the server's failure-body envelope.
func (l *TokenLedger) Persist(token string, issuedAt, expiresAt time.Time) error {
	_, err := l.db.Exec(
		`INSERT OR REPLACE INTO credit_tokens (token, issued_at, expires_at, used_at) VALUES (?, ?, ?, NULL)`,
		token, issuedAt.UTC(), expiresAt.UTC(),
	)
	return err
}

// Take consumes a credit_token atomically. Returns ErrCreditTokenInvalid
// for unknown OR already-used tokens; ErrCreditTokenExpired for expired
// tokens. The single-use enforcement is the UPDATE … WHERE used_at IS NULL
// row count.
func (l *TokenLedger) Take(token string) (*LedgerEntry, error) {
	var e LedgerEntry
	var usedAt sql.NullTime
	err := l.db.QueryRow(
		`SELECT token, issued_at, expires_at, used_at FROM credit_tokens WHERE token = ?`,
		token,
	).Scan(&e.Token, &e.IssuedAt, &e.ExpiresAt, &usedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrCreditTokenInvalid
	}
	if err != nil {
		return nil, err
	}
	if usedAt.Valid {
		return nil, ErrCreditTokenInvalid
	}
	if time.Now().UTC().After(e.ExpiresAt) {
		return nil, ErrCreditTokenExpired
	}
	// Single-use enforcement: zero rows updated means another caller won.
	now := time.Now().UTC()
	res, err := l.db.Exec(
		`UPDATE credit_tokens SET used_at = ? WHERE token = ? AND used_at IS NULL`,
		now, token,
	)
	if err != nil {
		return nil, err
	}
	n, _ := res.RowsAffected()
	if n != 1 {
		return nil, ErrCreditTokenInvalid
	}
	e.UsedAt = &now
	return &e, nil
}
