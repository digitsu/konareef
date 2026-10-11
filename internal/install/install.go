// Copyright 2026 Jerry David Chan, Konareef.ai
// SPDX-License-Identifier: Apache-2.0

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

	"github.com/digitsu/konareef/internal/canon"
	"github.com/digitsu/konareef/internal/identity"
	"github.com/digitsu/konareef/internal/publish"
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

// ErrContentHashMismatch is returned by Verify when a fetched
// ContentTarball, extracted and re-run through
// canon.CanonicalizeLike (at ManifestCanonical's own version), does
// not reproduce PodHash. Like
// ErrInstallHashMismatch, this is never recoverable at the CLI —
// the tarball bytes disagree with the signed manifest hash, so
// nothing is cached. Maps to exit code 5 (local refused).
var ErrContentHashMismatch = errors.New("CONTENT_HASH_MISMATCH: extracted content does not reproduce pod_hash")

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

	// ContentTarball is the gzip tar of the pod directory produced by
	// publish.PackTarball (Task B2), carried through so Verify can
	// reproduce PodHash from the actual content rather than trusting
	// the tarball bytes on a weaker check. nil when the server response
	// omits content_tarball — a legacy (pre-B2) reef-core, a pod
	// published before content tarballs existed, or a CLOSED pod, whose
	// body is never served in the clear.
	ContentTarball []byte

	// Visibility is the fetched pod's publication mode: VisibilityClosed
	// ("closed") for a pod whose body stays on konareef's infrastructure,
	// or empty for an open pod (the absent-means-open default; an
	// explicit "open" from the server is normalized away by decodeFetch).
	// A closed pod installs HEAD-only — manifest, signature and metadata,
	// no content/ dir — because there is no body to cache.
	//
	// This field is NOT part of the signed manifest bytes as a separate
	// claim: `visibility` is an ordinary [pod] key inside
	// ManifestCanonical, so the publisher signature already covers it.
	// The wire copy here is a decoding convenience, not a new trust root.
	Visibility string
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

	// ContentTarball is optional end-to-end (Task B2/B3): a legacy
	// server omits it entirely, and decodeFetch treats that the same
	// as an explicit empty string — both decode to a nil
	// FetchedPod.ContentTarball. A closed pod always omits it.
	ContentTarball string `json:"content_tarball"`

	// Visibility is "closed" for a closed pod. Open pods either omit
	// the key (legacy server) or send "open"; both decode to an empty
	// FetchedPod.Visibility.
	Visibility string `json:"visibility"`
}

// visibilityOpen and visibilityClosed are the only two publication
// modes this CLI understands. They mirror the pod-spec enum, with
// publish.VisibilityClosed as the single source of truth for the
// closed value so the publish and install halves can never drift.
const (
	visibilityOpen   = "open"
	visibilityClosed = publish.VisibilityClosed
)

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

	var tarball []byte
	if w.ContentTarball != "" {
		tarball, err = base64.StdEncoding.DecodeString(w.ContentTarball)
		if err != nil {
			return nil, fmt.Errorf("decode content_tarball base64: %w", err)
		}
	}

	// Unknown visibility modes are fatal, never silently downgraded to
	// open: a future private mode misread as public is precisely the
	// disclosure closed pods exist to prevent. An explicit "open" is
	// normalized to the empty string so open pods decode — and cache —
	// exactly as they did before this field existed.
	visibility := w.Visibility
	switch visibility {
	case "", visibilityOpen:
		visibility = ""
	case visibilityClosed:
	default:
		return nil, fmt.Errorf(
			"unrecognized visibility %q: this konareef build understands only %q and %q; upgrade the CLI",
			w.Visibility, visibilityOpen, visibilityClosed)
	}

	return &FetchedPod{
		Handle:             w.Handle,
		PodName:            w.PodName,
		PodVersion:         w.PodVersion,
		PodHash:            ph,
		ManifestCanonical:  manifest,
		Signature:          sig,
		PublisherPubkeyHex: hex.EncodeToString(pubBytes),
		ContentTarball:     tarball,
		Visibility:         visibility,
	}, nil
}

// IsClosed reports whether the fetched pod is a closed pod — body
// encrypted at publish, never served in the clear, installed HEAD-only.
func (f *FetchedPod) IsClosed() bool { return f.Visibility == visibilityClosed }

// Verify enforces the cryptographic invariants `konareef install`
// MUST satisfy before any pod is cached locally:
//
//  1. SHA-256(ManifestCanonical) == PodHash — the bytes you received
//     are the bytes that produced the claimed hash.
//  2. The publisher signature is valid over ManifestCanonical under
//     PublisherPubkeyHex — that hash was attested by the publisher
//     who controls PublisherPubkeyHex.
//  3. When ContentTarball is present: extracting it and re-running
//     canon.CanonicalizeLike over the result, AT THE SAME VERSION AS
//     ManifestCanonical, reproduces PodHash too (Task B3) — the actual
//     pod content agrees with what was signed, not just the manifest
//     bytes. This dispatches on ManifestCanonical's own version
//     (v1 or v2, konareef-toml/v2) rather than assuming v1, because by
//     this point checks 1 and 2 above have already authenticated
//     ManifestCanonical — see verifyContentTarball's doc comment for
//     why that ordering is what makes reusing its trailer sound.
//  4. ManifestCanonical's first line is not a near miss of a
//     konareef-toml magic line (canon.CheckMagicLine, KR-MAGIC): a
//     signed `#!KONAREEF-TOML/V3` or ` #!konareef-toml/v3` manifest is
//     refused with MAGIC_NEAR_MISS rather than cached as a legacy
//     manifest. It runs after checks 1 and 2, before check 3, and for a
//     closed pod too.
//
// Checks 1 and 2 are NOT relaxed for a closed pod. Only check 3 drops
// out, and it does so on its own: the branch is guarded on
// `ContentTarball != nil` and a closed pod never carries one, so no
// visibility test is needed here. Deliberately no explicit closed-pod
// branch — a second condition would be a second thing to get wrong.
// Pinned by TestVerifyAcceptsClosedPodWithoutContent (closed pods
// verify clean) and TestInstall_ClosedPodStillVerifiesHead /
// TestInstall_ClosedPodStillVerifiesPodHash (tampered closed HEADs are
// still refused).
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
	if err := canon.CheckMagicLine(f.ManifestCanonical); err != nil {
		return fmt.Errorf("manifest_canonical: %w", err)
	}
	if f.ContentTarball != nil {
		if err := verifyContentTarball(f); err != nil {
			return err
		}
	}
	return nil
}

// verifyContentTarball extracts f.ContentTarball to a scratch
// directory and confirms canon.CanonicalizeLike over the extracted
// pod.toml reproduces f.PodHash, cleaning up the scratch directory
// unconditionally. Called only once ContentTarball is known non-nil.
//
// The extracted pod.toml is AUTHOR input, not already-canonical bytes
// — it is exactly what the publisher wrote into the tarball, never
// re-derived from stored canonical output. So it must be canonicalized,
// not merely re-derived: this calls CanonicalizeLike, passing
// f.ManifestCanonical as the reference whose version and (for v2)
// `[_commit]` trailer the extracted content is canonicalized against.
// (An earlier design routed this through canon.Recanonicalize, which
// demanded byte-identical canonical input and would have rejected every
// install; Ruling 7 removed that, and the function itself was deleted
// on 2026-09-21 once no site was left that could call it.)
//
// This line is the §6.2 install-side reproduction site, and
// TestV2PodSurvivesPublishInstallRoundTrip (roundtrip_v2_test.go) is the
// R-V2.16 guard over it: reverting the call below to canon.Canonicalize
// fails that test with CONTENT_HASH_MISMATCH.
//
// Reusing f.ManifestCanonical's trailer this way is sound only because
// it is ALREADY authenticated by the time this function runs: Verify
// checks SHA-256(ManifestCanonical) == PodHash and the publisher
// signature over ManifestCanonical (install.go, both above
// verifyContentTarball's call site) BEFORE the tarball check ever
// executes. So ManifestCanonical's committed fields_root is exactly as
// trustworthy as the rest of the manifest the publisher signed — this
// function's job is only to confirm the tarball's actual content
// (the author tree) reproduces that same commitment, not to
// re-establish trust in the trailer itself. A tampered tarball changes
// the author tree while the trailer stays reference's untouched
// bytes, so the resulting canonical bytes diverge from PodHash and the
// sha256 comparison below still catches it.
func verifyContentTarball(f *FetchedPod) error {
	tmpDir, err := os.MkdirTemp("", "konareef-install-verify-*")
	if err != nil {
		return fmt.Errorf("create scratch directory for content verification: %w", err)
	}
	defer os.RemoveAll(tmpDir)

	if err := publish.ExtractTarball(f.ContentTarball, tmpDir); err != nil {
		return fmt.Errorf("extract content_tarball: %w", err)
	}
	body, err := os.ReadFile(filepath.Join(tmpDir, "pod.toml"))
	if err != nil {
		return fmt.Errorf("read extracted pod.toml: %w", err)
	}
	canonBytes, err := canon.CanonicalizeLike(body, tmpDir, f.ManifestCanonical)
	if err != nil {
		return fmt.Errorf("canonicalize extracted content: %w", err)
	}
	if sha256.Sum256(canonBytes) != f.PodHash {
		return fmt.Errorf("%w: extracted content hashes to a different pod_hash", ErrContentHashMismatch)
	}
	return nil
}

// Cache writes the verified pod to
// `<home>/.konareef/installed/<handle>/<podName>/<version>/`,
// returning the cache-directory path. Three files always land:
//
//   - manifest.canon — the exact canonical bytes (pre-image of pod_hash)
//   - signature.bin  — the DER-encoded ECDSA signature
//   - meta.json      — handle, pod name, version, pod_hash hex,
//     publisher pubkey hex (the bits a tool wants without parsing TOML)
//
// When f.ContentTarball is present, a fourth artifact lands: the
// extracted pod directory under `content/` (Task B3), which `pod run`
// (Task C2) executes directly rather than re-extracting at spawn
// time. A legacy fetch with no tarball leaves no `content/` dir at
// all — manifest-only caching, exactly as before this field existed.
//
// A CLOSED pod is cached HEAD-only by construction: meta.json gains a
// `visibility` key and no `content/` dir is written, even in the
// should-never-happen case of a server that sends a closed pod WITH a
// tarball. `pod run` reads meta.json's `visibility` and `pod_hash` to
// commission such a pod by reference instead of from local content.
// An open pod's meta.json is unchanged — no `visibility` key at all —
// so open installs keep byte-identical cache metadata.
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
	metaFields := map[string]string{
		"handle":               f.Handle,
		"pod_name":             f.PodName,
		"pod_version":          f.PodVersion,
		"pod_hash":             hex.EncodeToString(f.PodHash[:]),
		"publisher_pubkey_hex": f.PublisherPubkeyHex,
	}
	// Written only for a closed pod. An open pod's meta.json keeps the
	// exact key set it had before closed pods existed, so an old cache
	// entry and a new one are indistinguishable — absent means open,
	// on the wire and on disk alike.
	if f.IsClosed() {
		metaFields["visibility"] = f.Visibility
	}
	meta, err := json.MarshalIndent(metaFields, "", "  ")
	if err != nil {
		return "", fmt.Errorf("marshal meta.json: %w", err)
	}
	meta = append(meta, '\n')
	if err := os.WriteFile(filepath.Join(dir, "meta.json"), meta, 0o644); err != nil {
		return "", fmt.Errorf("write meta.json: %w", err)
	}
	// A closed pod has no body to materialize, and must not grow one:
	// the check is on visibility rather than on the tarball alone, so a
	// misbehaving server cannot smuggle content into a private pod's
	// cache directory.
	if f.ContentTarball != nil && !f.IsClosed() {
		if err := extractContentClean(dir, f.ContentTarball); err != nil {
			return "", err
		}
	}
	return dir, nil
}

// extractContentClean extracts contentTarball into `<versionDir>/content/`
// such that the result exactly reflects the tarball's contents — no
// residue from a previous extraction survives. A re-Cache of the same
// version with a shrunk tarball (fewer files than before) MUST NOT
// leave the removed files behind in content/, because that directory
// is executed directly by `pod run` (Task C2): stale files there are
// stale *executable* content, not just stale cache bookkeeping.
//
// Achieved by extracting into a fresh sibling temp directory first,
// then swapping it in for any existing content/ (removed beforehand)
// — so a failed extraction (including a rejected hidden-entry
// tarball, ErrTarballHiddenEntry) never touches the real content/ dir
// at all, and a successful one fully replaces it.
func extractContentClean(versionDir string, contentTarball []byte) error {
	tmpDir, err := os.MkdirTemp(versionDir, "content-tmp-*")
	if err != nil {
		return fmt.Errorf("create scratch dir for content extraction: %w", err)
	}
	defer os.RemoveAll(tmpDir)

	if err := publish.ExtractTarball(contentTarball, tmpDir); err != nil {
		return fmt.Errorf("extract content_tarball: %w", err)
	}

	contentDir := filepath.Join(versionDir, "content")
	if err := os.RemoveAll(contentDir); err != nil {
		return fmt.Errorf("remove stale content dir: %w", err)
	}
	if err := os.Rename(tmpDir, contentDir); err != nil {
		return fmt.Errorf("move extracted content into place: %w", err)
	}
	return nil
}
