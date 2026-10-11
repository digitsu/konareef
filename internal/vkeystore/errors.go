// Copyright 2026 Jerry David Chan, Konareef.ai
// SPDX-License-Identifier: Apache-2.0

package vkeystore

import "errors"

// ErrVkeyUnavailable means no byte source could supply a vkey: Tier 1
// failed (or absent), no fresh cache hit. Tier 2 (the anchor) is HASH-ONLY
// and cannot satisfy this case — it does not provide vkey bytes. The
// verifier MUST NOT proceed. Surface code: ERR_VKEY_UNAVAILABLE.
//
// Retryable in a future invocation (restore network, supply cached vkey,
// or add a real byte-source backend). Not retryable within the current call.
var ErrVkeyUnavailable = errors.New("ERR_VKEY_UNAVAILABLE")

// ErrCircuitPinMismatch means a vkey was obtained but SHA-256(vkey) does not
// match the committed vkey_sha256. The verifier MUST NOT use the vkey.
// Surface code: ERR_CIRCUIT_PIN_MISMATCH. Non-retryable; requires diagnosis.
var ErrCircuitPinMismatch = errors.New("ERR_CIRCUIT_PIN_MISMATCH")

// ErrVkeyCorrupt means a locally cached file failed structural integrity
// checks (e.g. meta.json malformed, vkey.bin missing, zero-length blob).
// Treated as a cache miss; the resolver falls through to Tier 1.
// Surface code: ERR_VKEY_CORRUPT.
var ErrVkeyCorrupt = errors.New("ERR_VKEY_CORRUPT")

// ErrCircuitIDInvalid means the supplied circuit_id failed the safe-token
// allow-list (`^[A-Za-z0-9._-]+$`, no `.` / `..` segments, no path
// separators). Inputs that fail this check MUST NOT be used to build cache
// paths. Surface code: ERR_CIRCUIT_ID_INVALID.
var ErrCircuitIDInvalid = errors.New("ERR_CIRCUIT_ID_INVALID")

// ErrVkeySha256Invalid means the supplied vkey_sha256 pin is not exactly
// 64 lowercase hex characters. Surface code: ERR_VKEY_SHA256_INVALID.
var ErrVkeySha256Invalid = errors.New("ERR_VKEY_SHA256_INVALID")

// ErrDomainAlreadyPrefixed means the supplied PublisherDomain already
// begins with `paygate-zk.` — caller likely passed the full service host
// instead of the publisher base domain. The Tier-1 backend would otherwise
// build a doubled host (`paygate-zk.paygate-zk.example.com`). Surface
// code: ERR_DOMAIN_ALREADY_PREFIXED.
var ErrDomainAlreadyPrefixed = errors.New("ERR_DOMAIN_ALREADY_PREFIXED")

// ErrPublisherDomainInvalid means the supplied PublisherDomain failed
// strict DNS-hostname validation. Rejected inputs include: schemes
// (`https://`, etc.), userinfo (`@`), path/query/fragment delimiters
// (`/`, `?`, `#`), backslashes, whitespace, control characters, ports,
// labels with leading/trailing hyphens, labels >63 chars, fewer than 2
// labels, and all-digit TLDs (IPv4-looking). Surface code:
// ERR_PUBLISHER_DOMAIN_INVALID. SECURITY-CRITICAL: the validated value
// is interpolated into the Tier-1 fetch URL host.
var ErrPublisherDomainInvalid = errors.New("ERR_PUBLISHER_DOMAIN_INVALID")
