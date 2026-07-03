// discovery.go — thin helper that fetches the reef-core discovery
// manifest used by PreflightPinCheck. The full manifest schema is
// owned by PRD 2 § 5.3; here we decode only the slice this package
// consumes.
//
// Domain contract bridge (MR !21 round-2 B2 / note 680):
// reef-core's `/api/discovery` returns `paygate_zk_domain` as the
// **service host** where the publisher's PayGate ZK runs
// (e.g. `paygate-zk.example.com`). The downstream
// vkeystore.ResolveRequest.PublisherDomain contract is the publisher
// **base** domain (e.g. `example.com`) — the Tier-1 backend prepends
// `paygate-zk.` itself and rejects already-prefixed inputs with
// ErrDomainAlreadyPrefixed. PublisherBaseDomain bridges the two:
// strip the `paygate-zk.` prefix in the caller, then hand the base
// domain to the resolver.

package publish

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
)

// paygateZKHostPrefix is the fixed sub-host prefix the Tier-1 backend
// prepends to the publisher base domain to produce the well-known
// vkey URL (`https://paygate-zk.<base>/.well-known/circuits/...`).
const paygateZKHostPrefix = "paygate-zk."

// ErrPaygateZKDomainMissingPrefix is returned by PublisherBaseDomain
// when the discovery manifest's `paygate_zk_domain` is not the
// expected service host (must start with `paygate-zk.`). The contract
// is documented at PRD 2 § 5.3 and internal/publish/discovery.go: the
// value MUST be the bare service host (e.g.
// `paygate-zk.example.com`), not a publisher base domain.
var ErrPaygateZKDomainMissingPrefix = errors.New("ERR_PAYGATE_ZK_DOMAIN_MISSING_PREFIX")

// PublisherBaseDomain converts a discovery `paygate_zk_domain` service
// host into the publisher base domain expected by
// vkeystore.ResolveRequest.PublisherDomain. The conversion is a pure
// case-insensitive `paygate-zk.` prefix strip; the remainder MUST be a
// non-empty base domain (the caller passes it to
// vkeystore.ValidatePublisherDomain, which applies the strict
// DNS-hostname grammar).
//
// Returns ErrPaygateZKDomainMissingPrefix when zkServiceHost is empty
// or does not start with `paygate-zk.` (case-insensitive). The
// prefix-stripped remainder is also checked for non-emptiness so a
// pathological input like `paygate-zk.` alone is rejected.
//
// MR !21 round-2 B2 (note 680): fixes the live ZK publish + standalone
// pin flows when reef-core returns `paygate_zk_domain=
// "paygate-zk.example.com"`. Before this helper the value was passed
// raw to the resolver, which rejected it with
// ErrDomainAlreadyPrefixed.
func PublisherBaseDomain(zkServiceHost string) (string, error) {
	host := strings.TrimSpace(zkServiceHost)
	if host == "" {
		return "", fmt.Errorf("%w: paygate_zk_domain is empty", ErrPaygateZKDomainMissingPrefix)
	}
	lower := strings.ToLower(host)
	if !strings.HasPrefix(lower, paygateZKHostPrefix) {
		return "", fmt.Errorf("%w: %q must begin with %q",
			ErrPaygateZKDomainMissingPrefix, host, paygateZKHostPrefix)
	}
	base := host[len(paygateZKHostPrefix):]
	if base == "" {
		return "", fmt.Errorf("%w: %q has empty base domain after %q",
			ErrPaygateZKDomainMissingPrefix, host, paygateZKHostPrefix)
	}
	return base, nil
}

// fetchedManifest is the on-wire shape of the slice we consume.
type fetchedManifest struct {
	PaygateZKDomain string `json:"paygate_zk_domain"`
	Circuits        []struct {
		CircuitID  string `json:"circuit_id"`
		VkeySha256 string `json:"vkey_sha256"`
	} `json:"circuits"`
}

// PaygateZKDomainHost returns the bare host the publisher's PayGate ZK
// service runs at.
func (m fetchedManifest) PaygateZKDomainHost() string { return m.PaygateZKDomain }

// VkeySha256For returns the manifest's pinned vkey_sha256 for
// circuitID, or ("", false) if the circuit is not advertised.
func (m fetchedManifest) VkeySha256For(circuitID string) (string, bool) {
	for _, c := range m.Circuits {
		if c.CircuitID == circuitID {
			return c.VkeySha256, true
		}
	}
	return "", false
}

// FetchDiscoveryManifest GETs <serverURL>/api/discovery and decodes
// the slice consumed by PreflightPinCheck.
func FetchDiscoveryManifest(ctx context.Context, serverURL string) (DiscoveryManifest, error) {
	url := strings.TrimRight(serverURL, "/") + "/api/discovery"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("discovery: build request: %w", err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("discovery: GET %s: %w", url, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("discovery: GET %s: status %d", url, resp.StatusCode)
	}
	var m fetchedManifest
	if err := json.NewDecoder(resp.Body).Decode(&m); err != nil {
		return nil, fmt.Errorf("discovery: decode: %w", err)
	}
	return m, nil
}
