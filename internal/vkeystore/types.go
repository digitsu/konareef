package vkeystore

import (
	"errors"
	"fmt"
	"strings"
	"time"
)

// Source records how a Vkey was obtained. Persisted in meta.json.
type Source string

const (
	SourceCache         Source = "cache"
	SourceWellKnown     Source = "well-known-url"
	SourceAnchor        Source = "on-chain-anchor"
	SourceBundleInline  Source = "bundle-self-contained"
	SourcePublisherFile Source = "publisher-file"
)

// Vkey is a resolved verification key plus provenance metadata.
type Vkey struct {
	CircuitID  string    // exact circuit_id string from bundle header
	VkeySha256 string    // lowercase-hex SHA-256 of Bytes
	Bytes      []byte    // raw vkey bytes
	Source     Source    // how this vkey was obtained
	ResolvedAt time.Time // wallclock at resolution time
	Stale      bool      // true if served from cache past TTL with no Tier-1 backend
}

// ResolveRequest names the circuit to resolve plus the pin the resolved vkey
// MUST match. PublisherDomain is the publisher **base** domain (e.g.
// "example.com"); the Tier-1 backend prepends "paygate-zk." internally to
// produce the well-known URL
// `https://paygate-zk.example.com/.well-known/circuits/{circuit_id}/vkey`.
// Passing a value already prefixed with `paygate-zk.` is rejected with
// ErrDomainAlreadyPrefixed at Validate() time, since the backend would
// otherwise build the doubled host `paygate-zk.paygate-zk.example.com`.
type ResolveRequest struct {
	CircuitID       string
	VkeySha256      string // lowercase-hex 32-byte pin from discovery manifest
	PublisherDomain string // publisher base domain, no scheme, no `paygate-zk.` prefix
}

// Validate enforces the minimum field set required for resolution AND
// hardens every field that is later interpolated into a filesystem path or
// URL host. CircuitID must be a safe token (`^[A-Za-z0-9._-]+$`, no `.` or
// `..` segments, no path separators). VkeySha256 must be exactly 64
// lowercase-hex characters. PublisherDomain must be non-empty and MUST NOT
// already start with `paygate-zk.`.
func (r ResolveRequest) Validate() error {
	if err := ValidateCircuitID(r.CircuitID); err != nil {
		return err
	}
	if err := ValidateVkeySha256(r.VkeySha256); err != nil {
		return err
	}
	if err := ValidatePublisherDomain(r.PublisherDomain); err != nil {
		return err
	}
	return nil
}

// ValidateCircuitID enforces a safe-token allow-list. circuit_id strings
// are interpolated directly into filesystem cache paths and URL path
// segments, so any path-separator, control character, or `.` / `..` segment
// is rejected with ErrCircuitIDInvalid.
//
// Allowed: ASCII letters, digits, `.`, `_`, `-` (one or more).
// Rejected: empty, whitespace, `/`, `\`, `\0`, any other byte, and the
// special segments `.` and `..`.
func ValidateCircuitID(id string) error {
	if id == "" {
		return fmt.Errorf("%w: empty", ErrCircuitIDInvalid)
	}
	if id == "." || id == ".." {
		return fmt.Errorf("%w: reserved segment %q", ErrCircuitIDInvalid, id)
	}
	for i := 0; i < len(id); i++ {
		c := id[i]
		ok := (c >= 'A' && c <= 'Z') ||
			(c >= 'a' && c <= 'z') ||
			(c >= '0' && c <= '9') ||
			c == '.' || c == '_' || c == '-'
		if !ok {
			return fmt.Errorf("%w: disallowed byte 0x%02x at offset %d", ErrCircuitIDInvalid, c, i)
		}
	}
	return nil
}

// ValidateVkeySha256 requires exactly 64 lowercase hex characters.
// Mixed-case, short, long, or non-hex inputs are rejected with
// ErrVkeySha256Invalid.
func ValidateVkeySha256(pin string) error {
	if len(pin) != 64 {
		return fmt.Errorf("%w: length %d, want 64", ErrVkeySha256Invalid, len(pin))
	}
	for i := 0; i < len(pin); i++ {
		c := pin[i]
		ok := (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')
		if !ok {
			return fmt.Errorf("%w: byte 0x%02x at offset %d is not lowercase hex", ErrVkeySha256Invalid, c, i)
		}
	}
	return nil
}

// ValidatePublisherDomain enforces a strict DNS-hostname grammar on the
// publisher base domain BEFORE it is interpolated into the Tier-1 fetch
// URL host. SECURITY-CRITICAL: an unvalidated domain string could carry
// URL-authority or path-injection bytes (`/`, `@`, `?`, `#`, whitespace,
// control bytes, scheme prefix, port, userinfo) that would alter the URL
// the Tier-1 backend retrieves.
//
// Rules:
//   - Trim ASCII whitespace, then reject empty.
//   - Reject inputs already starting with `paygate-zk.` (caller passed the
//     full service host; the backend would build a doubled host).
//   - Allowed bytes: ASCII letters, digits, `.`, `-`. Anything else
//     (including `/`, `\`, `@`, `?`, `#`, `:`, whitespace, control bytes,
//     and any non-ASCII byte) is rejected.
//   - Must contain at least 2 labels separated by `.`.
//   - Each label: 1-63 bytes, no leading or trailing `-`.
//   - Reject all-digit TLD (IPv4-looking, e.g. `1.2.3.4`).
//
// Returns ErrDomainAlreadyPrefixed for the prefix case and
// ErrPublisherDomainInvalid for every other rejection.
func ValidatePublisherDomain(domain string) error {
	if domain == "" {
		return errors.New("vkeystore: ResolveRequest.PublisherDomain is required")
	}
	if domain != strings.TrimSpace(domain) {
		return fmt.Errorf("%w: leading/trailing whitespace not allowed", ErrPublisherDomainInvalid)
	}
	d := domain
	if strings.HasPrefix(strings.ToLower(d), "paygate-zk.") {
		return fmt.Errorf("%w: %q already has paygate-zk. prefix; pass the publisher base domain instead", ErrDomainAlreadyPrefixed, d)
	}
	// Whole-string character allow-list. Iterate by byte (not rune): any
	// non-ASCII byte is outside the allow-list and is rejected here, which
	// also rejects UTF-8 multibyte sequences without needing rune decoding.
	for i := 0; i < len(d); i++ {
		c := d[i]
		ok := (c >= 'A' && c <= 'Z') ||
			(c >= 'a' && c <= 'z') ||
			(c >= '0' && c <= '9') ||
			c == '.' || c == '-'
		if !ok {
			return fmt.Errorf("%w: disallowed byte 0x%02x at offset %d", ErrPublisherDomainInvalid, c, i)
		}
	}
	labels := strings.Split(d, ".")
	if len(labels) < 2 {
		return fmt.Errorf("%w: must contain at least 2 dot-separated labels", ErrPublisherDomainInvalid)
	}
	for idx, label := range labels {
		if len(label) == 0 {
			return fmt.Errorf("%w: empty label at position %d", ErrPublisherDomainInvalid, idx)
		}
		if len(label) > 63 {
			return fmt.Errorf("%w: label %q length %d exceeds 63", ErrPublisherDomainInvalid, label, len(label))
		}
		if label[0] == '-' || label[len(label)-1] == '-' {
			return fmt.Errorf("%w: label %q has leading or trailing hyphen", ErrPublisherDomainInvalid, label)
		}
	}
	tld := labels[len(labels)-1]
	if isAllDigits(tld) {
		return fmt.Errorf("%w: numeric TLD %q (IPv4-looking)", ErrPublisherDomainInvalid, tld)
	}
	return nil
}

// isAllDigits returns true when s is non-empty and every byte is an ASCII
// digit. Used to reject IPv4-looking publisher domains.
func isAllDigits(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}
