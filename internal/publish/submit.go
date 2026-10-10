// Copyright 2026 Jerry David Chan, Konareef.ai
// SPDX-License-Identifier: Apache-2.0

// submit.go — the network half of `konareef pod publish`.
//
// Submit takes a PreparedPod and POSTs it to a reef-core instance
// at `POST <server>/api/pods` per publisher-signing-design v0
// §"API Surface". The signature is its own authentication — there
// is no session token / OAuth handshake here; reef-core verifies
// the signature against the supplied pubkey and accepts or rejects
// the request on that alone.

package publish

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/digitsu/konareef/internal/serverurl"
)

// submitClient is the HTTP client used to POST a signed pod.
//
// It deliberately does NOT follow redirects. The publisher's signature
// IS the credential on this endpoint, so re-sending the body to whatever
// host a redirect names would hand a valid signature + pubkey to that
// host — and Go's default client would then parse the redirect target's
// response and report success. Returning ErrUseLastResponse makes the
// 3xx visible to Submit, which surfaces it as a failure like any other
// non-2xx.
//
// The timeout bounds the whole exchange (dial through body read); the
// default client has none, so a hung server would block the CLI forever.
var submitClient = &http.Client{
	CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	},
	Timeout: 60 * time.Second,
}

// SubmitResponse is the 201 body from `POST /api/pods`.
type SubmitResponse struct {
	InstallURL   string    `json:"install_url"`
	RegisteredAt time.Time `json:"registered_at"`
}

// submitRequest is the wire JSON. byte fields ride as base64 (the
// design doc's choice for compactness without binary-in-JSON
// fragility); pod_hash is hex (the conventional digest encoding and
// what the CLI already prints to humans).
//
// WI-P0-012: `public_bundle` is the publisher's opt-in for the full
// unsanitized verifiable bundle to be served at
// `GET /api/public/proofs/:hash/bundle`. `omitempty` keeps the
// default-off case out of the wire shape — reef-core defaults to
// false on absence, so the opted-out wire body is byte-identical to
// the pre-WI-P0-012 format.
//
// P1.3 additions (PRD 4 § 4.3): `circuit_id`, `zk_enabled`,
// `disclosure_policy`, `lineage_id` are all `omitempty`. A legacy
// publish wire body is byte-identical to the pre-P1.3 format. The
// 32-byte salt is NEVER serialised here (PRD 4 § B.2 — Witness.Salt
// is consumed locally by the v2 bundle packer for index / value_hash
// derivation, then discarded; it never leaves the publisher's
// machine).
type submitRequest struct {
	Handle            string `json:"handle"`
	PodName           string `json:"pod_name"`
	PodVersion        string `json:"pod_version"`
	PodHash           string `json:"pod_hash"`           // hex (64 chars)
	ManifestCanonical string `json:"manifest_canonical"` // base64
	Signature         string `json:"signature"`          // base64
	PublisherPubkey   string `json:"publisher_pubkey"`   // base64 (33 bytes compressed)
	PublicBundle      bool   `json:"public_bundle,omitempty"`

	// P1.3 additions (PRD 4 § 4.3).
	CircuitID        string `json:"circuit_id,omitempty"`
	ZkEnabled        bool   `json:"zk_enabled,omitempty"`
	DisclosurePolicy string `json:"disclosure_policy,omitempty"`

	// P1.3 round-4 B1 addition (PRD 4 § B.1, § B.2). The Type-D
	// lineage commitment travels with the publish so reef-core can
	// re-derive Type-D cells across sessions. LineageID is emitted
	// as 32-char lowercase hex. The 32-byte salt is NEVER serialised
	// here.
	LineageID string `json:"lineage_id,omitempty"`

	// Task B2 addition. ContentTarball is the base64 gzip tar of the
	// pod directory (PreparedPod.ContentTarball), `omitempty` so a
	// publish that somehow carries no tarball keeps the pre-B2 wire
	// shape byte-identical — the field is optional end-to-end, and an
	// older CLI talking to a newer server (or vice versa) must not
	// break. A closed pod never sets this: its body rides encrypted in
	// BodyEnc instead, and the two are mutually exclusive.
	ContentTarball string `json:"content_tarball,omitempty"`

	// Closed-pod body seal. Every field is `omitempty`, so an open-pod
	// publish emits a wire body byte-identical to the pre-closed-pod
	// format — the same backward-compat contract the manifest itself
	// keeps. None of these are signed: the publisher's signature covers
	// `manifest_canonical` only, and the body commitment is already the
	// `[_files]` table inside those canonical bytes.
	//
	// SECURITY — BodyKey is K_body, the AES-256 key for BodyEnc. It is
	// a secret in transit: this endpoint MUST be HTTPS in any real
	// deployment, and this field must NEVER be logged, dumped, echoed
	// into an error message, or written to disk. Nothing in this
	// package logs request bodies (deliberately — see Submit, which
	// surfaces only the response status and body on failure); if
	// request logging is ever added here, redact this field first. The
	// build-tagged main_submit_dump_testhook.go dumps SubmitOpts only
	// and never sees a PreparedPod, so it cannot reach K_body.
	Visibility    string `json:"visibility,omitempty"`
	BodyEnc       string `json:"body_enc,omitempty"`        // base64 ciphertext + GCM tag
	BodyEncScheme string `json:"body_enc_scheme,omitempty"` // "aes-256-gcm"
	BodyEncNonce  string `json:"body_enc_nonce,omitempty"`  // base64 (12 bytes)
	BodyKey       string `json:"body_key,omitempty"`        // base64 K_body (32 bytes) — SECRET, TLS-protected, never logged

	// MEM-SEAM (konareef-rinit/v2 spec §3). A memory-bearing --zk
	// publish sends its salt-free v2 leaf table and the publisher's DER
	// signature over SHA-256 of it, both base64. reef-core checks the
	// signature, the pod_hash binding and the cell list against the
	// manifest, stores both beside the row and serves them only to the
	// proving path. Absent for every other publish, so the wire body of
	// those stays byte-identical. Neither field holds the salt.
	MemoryLeafTable          string `json:"memory_leaf_table,omitempty"`
	MemoryLeafTableSignature string `json:"memory_leaf_table_signature,omitempty"`
}

// SubmitOpts groups the post-P1.0 publish-time flags. The zero value
// represents a legacy publish (no opt-ins). Each non-zero field maps
// 1-1 to a `submitRequest` field of the same name.
//
// Round-4 B1: SubmitOpts gains a Witness *Witness field. For ZK
// publishes the caller sets Witness to the sealed witness after
// SealDisclosurePolicy has succeeded, and Submit threads the
// witness's lineage commitment into the wire body (Type-D) and into
// the v2 packer (PRD 4 § B.1). Witness is nil for v1 / non-ZK
// publishes; in that case Submit emits the byte-identical pre-P1.3
// wire body.
//
// Data-path discipline (PRD 4 § B.2): Witness.LineageID flows into
// the publish wire body; Witness.Salt stays LOCAL on the publisher —
// consumed only by the v2 bundle packer for index / value_hash
// derivation, then discarded; NEVER serialised into the public
// bundle output or the submit wire body.
type SubmitOpts struct {
	PublicBundle     bool     // WI-P0-012
	CircuitID        string   // PRD 4 § 4.3.1
	ZkEnabled        bool     // PRD 4 § 4.3.4
	DisclosurePolicy string   // PRD 4 § 4.3.3 — "C" or "D"
	Witness          *Witness // PRD 4 § B.1 — sealed witness for v2 / Type-D path; nil for v1 / non-ZK
}

// Submit POSTs a PreparedPod to `<serverURL>/api/pods`. On 2xx it
// returns the parsed install URL + registration timestamp. Any
// non-2xx status, network failure, or unparseable response is a
// fatal error — there is no retry policy here; the CLI is the
// human-facing wrapper that interprets failures.
//
// SubmitOpts carries the opt-in flags; the zero value preserves
// pre-P1.3 wire shape exactly.
//
// Inputs: serverURL — the reef-core base URL from `--server` /
// `$KONAREEF_SERVER`, validated by internal/serverurl before the body
// is built; p — the prepared (already signed) pod; opts — the publish
// opt-ins. Output: the parsed 201 body, or an error.
func Submit(serverURL string, p *PreparedPod, opts SubmitOpts) (*SubmitResponse, error) {
	// The base URL is validated and the endpoint built FIRST, before the
	// signed body is assembled. The publisher's signature is the
	// credential on this endpoint, so an unvalidated origin means a valid
	// signature + pubkey could be handed to whatever host a typo, a
	// pasted value or a poisoned $KONAREEF_SERVER names. The CLI applies
	// the same gate before Prepare signs anything (resolveServerURL in
	// main.go); this is the library-level fail-closed backstop for any
	// other caller.
	endpoint, err := serverurl.Endpoint(serverURL, "api", "pods")
	if err != nil {
		return nil, err
	}

	pubBytes, err := hex.DecodeString(p.PublicKeyHex)
	if err != nil {
		return nil, fmt.Errorf("decode publisher pubkey hex: %w", err)
	}

	body := submitRequest{
		Handle:            p.Handle,
		PodName:           p.PodName,
		PodVersion:        p.PodVersion,
		PodHash:           hex.EncodeToString(p.PodHash[:]),
		ManifestCanonical: base64.StdEncoding.EncodeToString(p.CanonicalBytes),
		Signature:         base64.StdEncoding.EncodeToString(p.Signature),
		PublisherPubkey:   base64.StdEncoding.EncodeToString(pubBytes),
		PublicBundle:      opts.PublicBundle,
		CircuitID:         opts.CircuitID,
		ZkEnabled:         opts.ZkEnabled,
		DisclosurePolicy:  opts.DisclosurePolicy,
	}
	// Round-4 B1: thread the sealed witness's lineage commitment into
	// the wire body for Type-D publishes. Witness.Salt is NEVER
	// serialised here per PRD 4 § B.2.
	if opts.Witness != nil && opts.Witness.LineageID != ([16]byte{}) {
		body.LineageID = hex.EncodeToString(opts.Witness.LineageID[:])
	}
	if len(p.MemoryLeafTable) > 0 {
		body.MemoryLeafTable = base64.StdEncoding.EncodeToString(p.MemoryLeafTable)
		body.MemoryLeafTableSignature = base64.StdEncoding.EncodeToString(p.MemoryLeafTableSignature)
	}
	// Task B2: the tarball rides as base64, same encoding convention
	// as every other byte field on this struct. Omitted entirely when
	// empty rather than emitting an empty string, matching omitempty.
	if len(p.ContentTarball) > 0 {
		body.ContentTarball = base64.StdEncoding.EncodeToString(p.ContentTarball)
	}
	// Closed pod: the sealed body replaces content_tarball entirely.
	// Guarded on Sealed != nil rather than on Visibility so an
	// unsealed-but-closed PreparedPod can never emit a `visibility`
	// marker with no body behind it — reef-core would then have a
	// closed row it can never materialize.
	if p.Sealed != nil {
		body.Visibility = p.Visibility
		body.BodyEnc = base64.StdEncoding.EncodeToString(p.Sealed.Ciphertext)
		body.BodyEncScheme = p.Sealed.Scheme
		body.BodyEncNonce = base64.StdEncoding.EncodeToString(p.Sealed.Nonce)
		body.BodyKey = base64.StdEncoding.EncodeToString(p.Sealed.Key)
	}
	bodyJSON, err := json.Marshal(body)
	if err != nil {
		return nil, fmt.Errorf("marshal submit request: %w", err)
	}

	req, err := http.NewRequest(http.MethodPost, endpoint, bytes.NewReader(bodyJSON))
	if err != nil {
		return nil, fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := submitClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("POST %s: %w", endpoint, err)
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(resp.Body)
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("POST %s: status %d: %s",
			endpoint, resp.StatusCode, strings.TrimSpace(string(respBody)))
	}

	var out SubmitResponse
	if err := json.Unmarshal(respBody, &out); err != nil {
		return nil, fmt.Errorf("parse response body: %w", err)
	}
	return &out, nil
}
