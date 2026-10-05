// Copyright 2026 Jerry David Chan, Konareef.ai
// SPDX-License-Identifier: Apache-2.0

// anchor_options.go — how the live verify path configures the chain-head
// anchor check: the pinned trusted node keys, and the header source,
// confirmation minimum and extra keys from flags or environment.
//
// Default header sources (US-007, design decision A4(a)): with no headers
// file and no header URL from flags or environment, the check asks the
// two public header services in DefaultHeaderServices, and both must
// agree. No pinned headers file ships with konareef yet. The check asks
// the network only when a bundle carries a chain-head anchor. With no
// reachable source, an anchored bundle reports "headers_unavailable" and
// chain_head_anchored stays false.
//
// Offline mode (--offline or KONAREEF_OFFLINE): the check never opens a
// network connection for headers. A pinned headers file is then the only
// source. With no file, an anchored bundle reports "headers_unavailable",
// as when no source is reachable. Offline mode with header URLs is an
// error (ErrOfflineWithHeaderURLs).
package verify

import (
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"strconv"
	"strings"

	"github.com/digitsu/konareef/internal/spv"
)

// PinnedTrustedNodeKeys lists, as compressed-key hex, the wallet identity
// keys of the reef-core nodes whose chain-head anchor attestations this
// build trusts (reef-core#76 decision A1(b)).
//
// A node's identity key is added here only after its operator publishes
// it through a channel the owner trusts. A key is removed only by a new
// release. For a node that is not on the list, a verifier adds its key
// with --trusted-node-key or KONAREEF_TRUSTED_NODE_KEYS. An attestation
// from any other key gives the status "unattributed", never "verified".
// The README section "Trusted node keys" is the publication record of
// each key on this list.
var PinnedTrustedNodeKeys = []string{
	// reefcore-beta, the hosted private-beta node (beta-api.konareef.ai).
	// Observed 2026-10-04 (ZK-005); published in the README section
	// "Trusted node keys" on merge. First attested bundle: custody proof
	// e3055cb5a8de895ba113fd11af05c3b707b6070c12900c34f6b5726795725a71
	// (anchor txid
	// e2564ebe999f433b941367bd70f28c3c29dad5382dc807577cb2e6b6b0277ebf,
	// block 969525).
	"02154cc6943aeede702a2d5c8ff51e15cc567eb4522396ebb12e1d5656343f5820",
}

// Public header services of the default chain (design decision A4(a)).
// They are two independent operators with a WhatsOnChain-style JSON API.
// The reef-core node is never one of them: it is the party being checked.
//
// To rotate a service: replace its constant with the base URL of another
// public BSV mainnet service that serves GET {base}/block/height/{h}
// with the block header fields, and a tip endpoint that returns JSON
// with a "blocks" field. Set its tip path in DefaultHeaderServices if
// the path is not "chain/info". Keep two operators that do not share a
// backend, because the agreement check is worth nothing if one party
// runs both.
const (
	// WhatsOnChainHeadersURL is the WhatsOnChain BSV mainnet API root.
	WhatsOnChainHeadersURL = "https://api.whatsonchain.com/v1/bsv/main"
	// BitailsHeadersURL is the Bitails BSV mainnet API root.
	BitailsHeadersURL = "https://api.bitails.io"
	// BitailsTipPath is the Bitails tip endpoint. Bitails has no
	// /chain/info; /network/info returns the same "blocks" field.
	BitailsTipPath = "network/info"
)

// DefaultHeaderService is one remote header service of the default
// header chain.
type DefaultHeaderService struct {
	// BaseURL is the API root (see spv.Remote).
	BaseURL string
	// TipPath is the tip endpoint path; empty means spv.DefaultTipPath.
	TipPath string
}

// DefaultHeaderServices are the remote header services the anchor check
// uses when no headers file and no header URL are configured. All of
// them must agree on each header. Fewer than two gives no default
// source, so an anchored bundle reports "headers_unavailable". Tests set
// this to local servers or to nil, so that they never reach the network.
//
// A malformed response from a default service (a bad hash, merkle root,
// previous hash or bits field, or a header that does not hash to the
// returned hash) counts as a disagreement: the anchor fails with
// ERR_ANCHOR_HEADER_UNTRUSTED and the bundle is refused. It does not give
// "headers_unavailable". Thus, if either public service changes its
// response schema, every anchored bundle is refused until these defaults
// are updated. This fails closed on purpose.
var DefaultHeaderServices = []DefaultHeaderService{
	{BaseURL: WhatsOnChainHeadersURL},
	{BaseURL: BitailsHeadersURL, TipPath: BitailsTipPath},
}

// Environment variables of the live anchor check.
const (
	// HeadersFileEnv names a pinned headers file (spv.EncodePinnedFile).
	HeadersFileEnv = "KONAREEF_HEADERS_FILE"
	// HeadersURLsEnv is a comma-separated list of header service base
	// URLs (WhatsOnChain-style API). All of them must agree.
	HeadersURLsEnv = "KONAREEF_HEADERS_URLS"
	// MinConfirmationsEnv is the confirmation minimum (default 1).
	MinConfirmationsEnv = "KONAREEF_MIN_CONFIRMATIONS"
	// TrustedNodeKeysEnv is a comma-separated list of extra trusted node
	// identity keys, compressed hex.
	TrustedNodeKeysEnv = "KONAREEF_TRUSTED_NODE_KEYS"
	// OfflineEnv set to "1" or "true" turns on offline mode: no network
	// header source is used (see AnchorConfig.Offline).
	OfflineEnv = "KONAREEF_OFFLINE"
)

// ErrOfflineWithHeaderURLs is the error for offline mode together with
// header URLs from a flag or from the environment. The two contradict, so
// konareef refuses them instead of dropping the URLs without a message.
var ErrOfflineWithHeaderURLs = errors.New("--offline cannot be combined with --headers-url (or " + HeadersURLsEnv + ")")

// AnchorConfig is the user-facing anchor configuration, before it is
// turned into AnchorOptions.
type AnchorConfig struct {
	// HeadersFile is a pinned headers file path; empty for none.
	HeadersFile string
	// HeaderURLs are header service base URLs; they must all agree.
	HeaderURLs []string
	// MinConfirmations is the confirmation minimum; 0 means 1.
	MinConfirmations uint64
	// TrustedNodeKeys are extra trusted identity keys, compressed hex.
	TrustedNodeKeys []string
	// MaxTargetBits, when non-empty, replaces the mainnet difficulty floor
	// with this compact target (hex). For testnet or regtest only. It is
	// set by the --max-target-bits flag, never from the environment, and
	// the verdict reports it (difficulty_floor_overridden).
	MaxTargetBits string
	// Offline, when true, keeps the anchor check off the network: the
	// default header services are not used, and header URLs are an error.
	// A pinned headers file is the only permitted source.
	Offline bool
}

// CheckOffline reports a contradiction in offline mode.
// Output: ErrOfflineWithHeaderURLs when Offline is set and there are
// header URLs, otherwise nil.
func (c AnchorConfig) CheckOffline() error {
	if c.Offline && len(c.HeaderURLs) > 0 {
		return ErrOfflineWithHeaderURLs
	}
	return nil
}

// checkHeaderURL requires https, except for a loopback host (local
// header services and tests).
func checkHeaderURL(raw string) error {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return fmt.Errorf("header URL %q is not an absolute URL", raw)
	}
	if u.Scheme == "https" {
		return nil
	}
	host := u.Hostname()
	if u.Scheme == "http" && (host == "localhost" || net.ParseIP(host) != nil && net.ParseIP(host).IsLoopback()) {
		return nil
	}
	return fmt.Errorf("header URL %q must use https", raw)
}

// splitList splits a comma-separated list and drops empty items.
func splitList(s string) []string {
	var out []string
	for _, item := range strings.Split(s, ",") {
		if item = strings.TrimSpace(item); item != "" {
			out = append(out, item)
		}
	}
	return out
}

// AnchorConfigFromEnv reads the anchor configuration from the environment.
// Output: the config, or an error for a malformed confirmation count.
func AnchorConfigFromEnv() (AnchorConfig, error) {
	c := AnchorConfig{
		HeadersFile:     os.Getenv(HeadersFileEnv),
		HeaderURLs:      splitList(os.Getenv(HeadersURLsEnv)),
		TrustedNodeKeys: splitList(os.Getenv(TrustedNodeKeysEnv)),
	}
	offlineRaw := os.Getenv(OfflineEnv)
	switch strings.ToLower(strings.TrimSpace(offlineRaw)) {
	case "", "0", "false":
	case "1", "true":
		c.Offline = true
	default:
		return c, fmt.Errorf("%s=%q: use 1 or true", OfflineEnv, offlineRaw)
	}
	if s := os.Getenv(MinConfirmationsEnv); s != "" {
		n, err := strconv.ParseUint(s, 10, 32)
		if err != nil {
			return c, fmt.Errorf("%s=%q: %w", MinConfirmationsEnv, s, err)
		}
		c.MinConfirmations = n
	}
	return c, nil
}

// Merge returns c with the non-empty fields of override applied: lists
// are appended, the file and the minimum are replaced. Offline mode is on
// when either side turns it on.
func (c AnchorConfig) Merge(override AnchorConfig) AnchorConfig {
	out := c
	if override.HeadersFile != "" {
		out.HeadersFile = override.HeadersFile
	}
	out.HeaderURLs = append(append([]string{}, c.HeaderURLs...), override.HeaderURLs...)
	out.TrustedNodeKeys = append(append([]string{}, c.TrustedNodeKeys...), override.TrustedNodeKeys...)
	if override.MinConfirmations != 0 {
		out.MinConfirmations = override.MinConfirmations
	}
	if override.MaxTargetBits != "" {
		out.MaxTargetBits = override.MaxTargetBits
	}
	out.Offline = c.Offline || override.Offline
	return out
}

// defaultHeaderSource builds the default remote header source from
// DefaultHeaderServices.
// Output: an spv.Agreeing over the services, nil when fewer than two
// services are set, or an error for a service URL that is not https.
func defaultHeaderSource() (spv.HeaderSource, error) {
	if len(DefaultHeaderServices) < 2 {
		return nil, nil
	}
	var remotes []spv.HeaderSource
	for _, service := range DefaultHeaderServices {
		if err := checkHeaderURL(service.BaseURL); err != nil {
			return nil, err
		}
		remotes = append(remotes, &spv.Remote{BaseURL: service.BaseURL, TipPath: service.TipPath})
	}
	return &spv.Agreeing{Sources: remotes}, nil
}

// Options builds AnchorOptions: the pinned file first, then the remote
// services (which must all agree); the pinned trusted keys plus the
// configured ones. With no headers file and no header URL, the header
// source is the default one (DefaultHeaderServices). An explicit file or
// URL replaces the defaults; it is never combined with them. In offline
// mode the defaults are not used, so the pinned file is the only source.
// Output: the options, or an error for an unreadable headers file, a
// malformed key, or offline mode with header URLs.
func (c AnchorConfig) Options() (AnchorOptions, error) {
	opts := AnchorOptions{MinConfirmations: c.MinConfirmations}
	if err := c.CheckOffline(); err != nil {
		return opts, err
	}
	if c.MaxTargetBits != "" {
		bits, err := strconv.ParseUint(strings.TrimPrefix(c.MaxTargetBits, "0x"), 16, 32)
		target := spv.CompactToTarget(uint32(bits))
		if err != nil || target == nil {
			return opts, fmt.Errorf("max target bits %q is not a compact target", c.MaxTargetBits)
		}
		opts.MaxTarget = target
	}
	var sources []spv.HeaderSource
	if c.HeadersFile != "" {
		m, err := spv.LoadPinnedFile(c.HeadersFile)
		if err != nil {
			return opts, err
		}
		sources = append(sources, m)
	}
	if len(c.HeaderURLs) == 1 {
		// Owner decision A4(a): remote services must agree, so one is not
		// enough (a pinned file alone is fine).
		return opts, fmt.Errorf("give at least two --headers-url services (they must agree), or a --headers-file")
	}
	if len(c.HeaderURLs) > 0 {
		var remotes []spv.HeaderSource
		for _, u := range c.HeaderURLs {
			if err := checkHeaderURL(u); err != nil {
				return opts, err
			}
			remotes = append(remotes, &spv.Remote{BaseURL: u})
		}
		sources = append(sources, &spv.Agreeing{Sources: remotes})
	}
	if len(sources) == 0 && !c.Offline {
		defaults, err := defaultHeaderSource()
		if err != nil {
			return opts, err
		}
		if defaults != nil {
			sources = append(sources, defaults)
		}
	}
	if len(sources) > 0 {
		opts.Headers = &spv.First{Sources: sources}
	}
	for _, k := range append(append([]string{}, PinnedTrustedNodeKeys...), c.TrustedNodeKeys...) {
		b, err := hex.DecodeString(k)
		if err != nil || len(b) != 33 || (b[0] != 0x02 && b[0] != 0x03) {
			return opts, fmt.Errorf("trusted node key %q is not a compressed secp256k1 key in hex", k)
		}
		opts.TrustedNodeKeys = append(opts.TrustedNodeKeys, b)
	}
	return opts, nil
}
