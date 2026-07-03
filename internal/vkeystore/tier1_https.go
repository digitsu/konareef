package vkeystore

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"
)

// maxVkeyBody caps a single Tier-1 fetch. Vkeys are ~10 KB for the v1 circuit
// per PRD 3 § 6 ("self_contained" profile is ~10 KB inline); a 4 MB ceiling
// is generous and stops a malicious origin from streaming forever.
const maxVkeyBody = 4 * 1024 * 1024

// Tier1HTTPSBackend fetches a vkey from the well-known URL. The Fetch and
// BuildURL methods take the publisher **base** domain (e.g. `example.com`)
// — NOT the full `paygate-zk.<domain>` service host. The `paygate-zk.`
// prefix is added by this backend. Passing an already-prefixed input is
// rejected with ErrDomainAlreadyPrefixed to prevent the doubled host
// `paygate-zk.paygate-zk.example.com`.
//
// In production BuildURL emits
//
//	https://paygate-zk.{domain}/.well-known/circuits/{circuit_id}/vkey
//
// In tests, set BaseURLOverride to an httptest.Server URL to bypass the
// "paygate-zk." prefix and TLS — every other path component stays identical.
type Tier1HTTPSBackend struct {
	Client          *http.Client
	BaseURLOverride string // test seam; empty in production
}

// NewTier1HTTPSBackend returns a backend with a 30s default HTTP timeout when
// client is nil.
func NewTier1HTTPSBackend(client *http.Client) *Tier1HTTPSBackend {
	if client == nil {
		client = &http.Client{Timeout: 30 * time.Second}
	}
	return &Tier1HTTPSBackend{Client: client}
}

// BuildURL constructs the well-known URL. publisherDomain MUST be the
// publisher base domain (e.g. `example.com`); the `paygate-zk.` host
// prefix is added here. Inputs already starting with `paygate-zk.` are
// rejected with ErrDomainAlreadyPrefixed; inputs that fail strict
// DNS-hostname validation are rejected with ErrPublisherDomainInvalid.
// circuitID is validated against the safe-token allow-list before it is
// interpolated into the URL path; url.PathEscape further hardens the
// path segment.
//
// SECURITY-CRITICAL: the URL is constructed via net/url after both
// circuitID and publisherDomain are validated, so a malformed input
// cannot inject authority/path components even if a future validation
// rule is loosened.
//
// When BaseURLOverride is non-empty, the override host replaces
// "https://paygate-zk.{publisherDomain}" — used in tests — but circuitID
// is still validated.
func (b *Tier1HTTPSBackend) BuildURL(circuitID, publisherDomain string) (string, error) {
	if err := ValidateCircuitID(circuitID); err != nil {
		return "", err
	}
	path := "/.well-known/circuits/" + url.PathEscape(circuitID) + "/vkey"
	if b.BaseURLOverride != "" {
		return b.BaseURLOverride + path, nil
	}
	if err := ValidatePublisherDomain(publisherDomain); err != nil {
		return "", err
	}
	u := &url.URL{
		Scheme: "https",
		Host:   "paygate-zk." + publisherDomain,
		Path:   path,
	}
	return u.String(), nil
}

// Fetch returns the raw vkey body for circuitID. All transport / status /
// oversize / context-cancellation errors are folded into ErrVkeyUnavailable
// so the resolver can fall through to Tier 2 / cache cleanly. Input
// validation errors (ErrCircuitIDInvalid, ErrDomainAlreadyPrefixed) are
// surfaced as-is and NOT folded into ErrVkeyUnavailable — they indicate a
// programming bug, not transient unavailability.
func (b *Tier1HTTPSBackend) Fetch(ctx context.Context, circuitID, publisherDomain string) ([]byte, error) {
	url, err := b.BuildURL(circuitID, publisherDomain)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("%w: build request: %v", ErrVkeyUnavailable, err)
	}
	req.Header.Set("Accept", "application/octet-stream")
	resp, err := b.Client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("%w: http: %v", ErrVkeyUnavailable, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%w: http status %d", ErrVkeyUnavailable, resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxVkeyBody+1))
	if err != nil {
		return nil, fmt.Errorf("%w: read body: %v", ErrVkeyUnavailable, err)
	}
	if len(body) > maxVkeyBody {
		return nil, fmt.Errorf("%w: body exceeds %d bytes", ErrVkeyUnavailable, maxVkeyBody)
	}
	return body, nil
}
