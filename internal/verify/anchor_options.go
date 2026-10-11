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
//
// Trusted node keys (US-007): the check trusts the keys in
// PinnedTrustedNodeKeys, the keys from --trusted-node-key and
// KONAREEF_TRUSTED_NODE_KEYS, and the keys in the node key file
// (KONAREEF_NODE_KEY_FILE, default ~/.proof_server_node_key). A node key
// file that does not exist adds no keys. A node key file that cannot be
// read or has a bad line is an error: konareef does not skip it.
package verify

import (
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"net"
	"net/url"
	"os"
	"path/filepath"
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
// with --trusted-node-key, KONAREEF_TRUSTED_NODE_KEYS or the node key
// file (NodeKeyFileEnv, default ~/.proof_server_node_key). An attestation
// from any other key gives the status "unattributed", never "verified".
// The README section "Trusted node keys" is the publication record of
// each key on this list.
var PinnedTrustedNodeKeys = []string{
	// reefcore-beta, the hosted private-beta node (beta-api.konareef.ai):
	// the wallet identity key of the reef-core beta node. Observed
	// 2026-10-04 (ZK-005). The owner published it on 2026-10-06 in
	// ~/.proof_server_node_key, and it is recorded in the README section
	// "Trusted node keys". It attested the first beta v2 bundle on
	// 2026-10-04: custody proof
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
	// NodeKeyFileEnv names the node key file: a file of extra trusted
	// node identity keys (see LoadNodeKeyFile). When it is not set,
	// konareef reads DefaultNodeKeyFile. Set it to an empty string to
	// read no node key file.
	NodeKeyFileEnv = "KONAREEF_NODE_KEY_FILE"
)

// NodeKeyFileName is the name of the node key file in the home
// directory of the user. The node operator publishes the identity key of
// the node in this file.
const NodeKeyFileName = ".proof_server_node_key"

// DefaultNodeKeyFile is the node key file that konareef reads when
// NodeKeyFileEnv is not set: $HOME/.proof_server_node_key. It is empty
// when the home directory is not known; then no file is read. Tests set
// it to an empty string, so that the file of a developer cannot change
// a test result.
var DefaultNodeKeyFile = defaultNodeKeyFilePath()

// defaultNodeKeyFilePath finds the default node key file.
// Output: $HOME/NodeKeyFileName, or "" when the home directory is not
// known.
func defaultNodeKeyFilePath() string {
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		return ""
	}
	return filepath.Join(home, NodeKeyFileName)
}

// NodeKeyFilePath gives the node key file to read.
// Output: the value of NodeKeyFileEnv when that variable is set (also
// when it is empty, which turns the file off), else DefaultNodeKeyFile.
// An empty result means "read no file".
func NodeKeyFilePath() string {
	if path, isSet := os.LookupEnv(NodeKeyFileEnv); isSet {
		return strings.TrimSpace(path)
	}
	return DefaultNodeKeyFile
}

// parseTrustedNodeKey decodes one trusted node identity key. All key
// sources (the pinned list, flags, environment and node key file) use
// this check.
// Input: hexKey, a compressed secp256k1 public key in hex.
// Output: the 33 key bytes, or an error when hexKey is not 66 hex
// characters with the prefix 02 or 03.
func parseTrustedNodeKey(hexKey string) ([]byte, error) {
	keyBytes, err := hex.DecodeString(hexKey)
	if err != nil || len(keyBytes) != 33 || (keyBytes[0] != 0x02 && keyBytes[0] != 0x03) {
		return nil, fmt.Errorf("trusted node key %q is not a compressed secp256k1 key in hex", hexKey)
	}
	return keyBytes, nil
}

// LoadNodeKeyFile reads the trusted node identity keys in a node key
// file. The file has one compressed key in hex on each line. Blank lines
// and lines that start with "#" are ignored. Spaces around a key are
// removed.
//
// Input: path, the file path; empty means "no file".
// Output: the keys in file order. A file that does not exist gives no
// keys and no error. A file that konareef cannot read, or a line that is
// not a valid compressed key, gives an error that names the file (and
// the line number). The error does not show the text of a bad line,
// because the line can be a secret that was put there by mistake.
func LoadNodeKeyFile(path string) ([]string, error) {
	if path == "" {
		return nil, nil
	}
	content, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("node key file %s: cannot read: %w", path, err)
	}
	var keys []string
	for index, rawLine := range strings.Split(string(content), "\n") {
		line := strings.TrimSpace(rawLine)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if _, err := parseTrustedNodeKey(line); err != nil {
			return nil, fmt.Errorf("node key file %s line %d: not a compressed secp256k1 public key in hex (66 hex characters, prefix 02 or 03)",
				path, index+1)
		}
		keys = append(keys, line)
	}
	return keys, nil
}

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

// AnchorConfigFromEnv reads the anchor configuration from the environment
// and from the node key file (NodeKeyFilePath). The keys in the node key
// file are trusted in addition to the keys in TrustedNodeKeysEnv.
// Output: the config, or an error for a malformed confirmation count or
// offline value, or for a node key file that cannot be read or has a bad
// line.
func AnchorConfigFromEnv() (AnchorConfig, error) {
	c := AnchorConfig{
		HeadersFile:     os.Getenv(HeadersFileEnv),
		HeaderURLs:      splitList(os.Getenv(HeadersURLsEnv)),
		TrustedNodeKeys: splitList(os.Getenv(TrustedNodeKeysEnv)),
	}
	fileKeys, err := LoadNodeKeyFile(NodeKeyFilePath())
	if err != nil {
		return c, err
	}
	c.TrustedNodeKeys = append(c.TrustedNodeKeys, fileKeys...)
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
	for _, hexKey := range append(append([]string{}, PinnedTrustedNodeKeys...), c.TrustedNodeKeys...) {
		keyBytes, err := parseTrustedNodeKey(hexKey)
		if err != nil {
			return opts, err
		}
		opts.TrustedNodeKeys = append(opts.TrustedNodeKeys, keyBytes)
	}
	return opts, nil
}
