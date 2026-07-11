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
)

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
	// break.
	ContentTarball string `json:"content_tarball,omitempty"`
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
func Submit(serverURL string, p *PreparedPod, opts SubmitOpts) (*SubmitResponse, error) {
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
	// Task B2: the tarball rides as base64, same encoding convention
	// as every other byte field on this struct. Omitted entirely when
	// empty rather than emitting an empty string, matching omitempty.
	if len(p.ContentTarball) > 0 {
		body.ContentTarball = base64.StdEncoding.EncodeToString(p.ContentTarball)
	}
	bodyJSON, err := json.Marshal(body)
	if err != nil {
		return nil, fmt.Errorf("marshal submit request: %w", err)
	}

	url := strings.TrimRight(serverURL, "/") + "/api/pods"
	req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(bodyJSON))
	if err != nil {
		return nil, fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("POST %s: %w", url, err)
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(resp.Body)
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("POST %s: status %d: %s",
			url, resp.StatusCode, strings.TrimSpace(string(respBody)))
	}

	var out SubmitResponse
	if err := json.Unmarshal(respBody, &out); err != nil {
		return nil, fmt.Errorf("parse response body: %w", err)
	}
	return &out, nil
}
