// Package install implements the buyer-side half of the publisher-
// signing workflow (P0.6 6e): fetch a published pod from reef-core,
// re-verify that the manifest hashes to the claimed pod_hash and that
// the publisher signature is valid, and cache the canonical manifest
// + signature locally so the harness can re-verify at spawn time
// without a network round-trip.
//
// Three discrete steps, exposed as separate functions so the CLI can
// surface each as its own confirmation line:
//
//   - Fetch  — GET <server>/api/pods/<handle>/<pod>/[latest|<version>]
//   - Verify — SHA-256 manifest must equal pod_hash; ECDSA must check out
//   - Cache  — write to <home>/.konareef/installed/<handle>/<pod>/<version>/
//
// Deliberately *not* in this slice: known_publishers.json TOFU, key
// rotation, already-installed handling, withdrawn-pod handling,
// download resumability. They are independent follow-ups (see
// install-path-design v0); the core verification path lands first.
package install

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/digitsu/konareef/internal/identity"
)

// ErrManifestNotFound is returned by Fetch when reef-core responds
// with HTTP 404 for the requested handle/pod/version. CLI callers
// MUST use errors.Is(err, ErrManifestNotFound) to detect this case
// and map it to exit code 4 (upstream missing); the wrapped error
// retains the requested URL for log triage.
var ErrManifestNotFound = errors.New("MANIFEST_NOT_FOUND: no published pod at this URL")

// ErrInstallHashMismatch is the sentinel CLI callers wrap when
// CheckInstalled returns StatusConflict — that is, when a local
// meta.json's pod_hash differs from the fetched manifest's pod_hash
// for the same handle/pod/version. Maps to exit code 5 (local
// refused); never use --force to bypass.
var ErrInstallHashMismatch = errors.New("INSTALL_HASH_MISMATCH: version already installed with a different hash")

// ErrLocalLocked is returned by AcquireLock when another process
// holds the per-pod advisory lock and the configured timeout
// elapses. Maps to exit code 5 (local refused).
var ErrLocalLocked = errors.New("LOCAL_LOCKED: another install of this handle/pod is in progress")

// FetchedPod is the parsed wire response from reef-core, decoded
// into the byte / [32]byte / hex shapes the verifier and the cache
// consume directly.
type FetchedPod struct {
	Handle             string
	PodName            string
	PodVersion         string
	PodHash            [32]byte
	ManifestCanonical  []byte
	Signature          []byte
	PublisherPubkeyHex string
}

// fetchWire is the JSON shape reef-core returns. byte fields ride as
// base64 and pod_hash rides as hex — symmetric with the publish
// submitRequest, so reef-core can implement both endpoints with the
// same encoder.
type fetchWire struct {
	Handle            string `json:"handle"`
	PodName           string `json:"pod_name"`
	PodVersion        string `json:"pod_version"`
	PodHash           string `json:"pod_hash"`
	ManifestCanonical string `json:"manifest_canonical"`
	Signature         string `json:"signature"`
	PublisherPubkey   string `json:"publisher_pubkey"`
}

// Fetch GETs `<serverURL>/api/pods/<handle>/<podName>/<version>` and
// returns the decoded FetchedPod. An empty version resolves to
// `/latest`, the design's "give me whatever ships today" shortcut.
//
// Any non-2xx status, network failure, JSON parse error, or
// malformed-byte field is a fatal error. The caller MUST run Verify
// on the returned FetchedPod before trusting any of its contents —
// Fetch validates wire-format only, not the cryptographic claims.
func Fetch(serverURL, handle, podName, version string) (*FetchedPod, error) {
	v := version
	if v == "" {
		v = "latest"
	}
	url := strings.TrimRight(serverURL, "/") + "/api/pods/" + handle + "/" + podName + "/" + v
	resp, err := http.Get(url)
	if err != nil {
		return nil, fmt.Errorf("GET %s: %w", url, err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode == http.StatusNotFound {
		return nil, fmt.Errorf("GET %s: %w", url, ErrManifestNotFound)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("GET %s: status %d: %s",
			url, resp.StatusCode, strings.TrimSpace(string(body)))
	}

	var w fetchWire
	if err := json.Unmarshal(body, &w); err != nil {
		return nil, fmt.Errorf("parse response body: %w", err)
	}
	return decodeFetch(w)
}

// decodeFetch turns the wire JSON into the typed FetchedPod. Any
// malformed encoding (bad hex, bad base64, wrong-length pod_hash) is
// a fatal Fetch error — Verify assumes its inputs are at least
// well-formed.
func decodeFetch(w fetchWire) (*FetchedPod, error) {
	hashBytes, err := hex.DecodeString(w.PodHash)
	if err != nil {
		return nil, fmt.Errorf("decode pod_hash hex: %w", err)
	}
	if len(hashBytes) != 32 {
		return nil, fmt.Errorf("pod_hash is %d bytes; SHA-256 is exactly 32", len(hashBytes))
	}
	var ph [32]byte
	copy(ph[:], hashBytes)

	manifest, err := base64.StdEncoding.DecodeString(w.ManifestCanonical)
	if err != nil {
		return nil, fmt.Errorf("decode manifest_canonical base64: %w", err)
	}
	sig, err := base64.StdEncoding.DecodeString(w.Signature)
	if err != nil {
		return nil, fmt.Errorf("decode signature base64: %w", err)
	}
	pubBytes, err := base64.StdEncoding.DecodeString(w.PublisherPubkey)
	if err != nil {
		return nil, fmt.Errorf("decode publisher_pubkey base64: %w", err)
	}

	return &FetchedPod{
		Handle:             w.Handle,
		PodName:            w.PodName,
		PodVersion:         w.PodVersion,
		PodHash:            ph,
		ManifestCanonical:  manifest,
		Signature:          sig,
		PublisherPubkeyHex: hex.EncodeToString(pubBytes),
	}, nil
}

// Verify enforces the two cryptographic invariants `konareef install`
// MUST satisfy before any pod is cached locally:
//
//  1. SHA-256(ManifestCanonical) == PodHash — the bytes you received
//     are the bytes that produced the claimed hash.
//  2. The publisher signature is valid over ManifestCanonical under
//     PublisherPubkeyHex — that hash was attested by the publisher
//     who controls PublisherPubkeyHex.
//
// A failure here is **never recoverable** at the CLI — refuse to
// install and surface the divergence; do not prompt the user past it.
func Verify(f *FetchedPod) error {
	got := sha256.Sum256(f.ManifestCanonical)
	if got != f.PodHash {
		return fmt.Errorf(
			"pod_hash mismatch: SHA-256(manifest) = %x, server claimed %x",
			got, f.PodHash,
		)
	}
	ok, err := identity.Verify(f.PublisherPubkeyHex, f.ManifestCanonical, f.Signature)
	if err != nil {
		return fmt.Errorf("verify publisher signature: %w", err)
	}
	if !ok {
		return fmt.Errorf("publisher signature is invalid for pubkey %s", f.PublisherPubkeyHex)
	}
	return nil
}

// Cache writes the verified pod to
// `<home>/.konareef/installed/<handle>/<podName>/<version>/`,
// returning the cache-directory path. Three files land:
//
//   - manifest.canon — the exact canonical bytes (pre-image of pod_hash)
//   - signature.bin  — the DER-encoded ECDSA signature
//   - meta.json      — handle, pod name, version, pod_hash hex,
//     publisher pubkey hex (the bits a tool wants without parsing TOML)
//
// Callers SHOULD only call Cache after Verify returns nil; Cache
// trusts its input and writes verbatim.
func Cache(home string, f *FetchedPod) (string, error) {
	dir := filepath.Join(home, ".konareef", "installed", f.Handle, f.PodName, f.PodVersion)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", fmt.Errorf("create cache dir: %w", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "manifest.canon"), f.ManifestCanonical, 0o644); err != nil {
		return "", fmt.Errorf("write manifest.canon: %w", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "signature.bin"), f.Signature, 0o644); err != nil {
		return "", fmt.Errorf("write signature.bin: %w", err)
	}
	meta, err := json.MarshalIndent(map[string]string{
		"handle":               f.Handle,
		"pod_name":             f.PodName,
		"pod_version":          f.PodVersion,
		"pod_hash":             hex.EncodeToString(f.PodHash[:]),
		"publisher_pubkey_hex": f.PublisherPubkeyHex,
	}, "", "  ")
	if err != nil {
		return "", fmt.Errorf("marshal meta.json: %w", err)
	}
	meta = append(meta, '\n')
	if err := os.WriteFile(filepath.Join(dir, "meta.json"), meta, 0o644); err != nil {
		return "", fmt.Errorf("write meta.json: %w", err)
	}
	return dir, nil
}
