// Copyright 2026 Jerry David Chan, Konareef.ai
// SPDX-License-Identifier: Apache-2.0

// internal/paygate/session.go — per-publish-session state.
package paygate

import "time"

// FoldStep records the durable binding from a /result fetch.
type FoldStep struct {
	StepIndex   uint64
	JobID       string
	Accumulator []byte
	BoundAt     time.Time
}

// Session is the per-publish-session bag of mutable state.
type Session struct {
	BRC31Session      *BRC31Session
	DiscoveryManifest *Manifest
	ManifestFetchedAt time.Time
	CircuitID         string
	PinnedVkeyHash    string // hex, mirrors manifest's vkey_sha256
	CreditTokens      *TokenLedger
	IdempotencyCache  *IdempCache
	LastDurableStep   *FoldStep
	Gate              *PipeliningGate
	LineageID         [16]byte
	TypeDSalt         [32]byte
}
