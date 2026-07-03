// rotation_submit.go — POST a signed rotation attestation to
// reef-core's `/api/publishers/:handle/rotate`.
//
// The body shape and accepted error codes are defined by
// `ReefCoreWeb.PublisherRotationController :: create/2`. The
// signature is base64-encoded on the wire; the attestation is the
// nested object whose canonical-JSON form (see Canonical/1) is what
// the publisher actually signed. reef-core re-canonicalises on the
// server and re-verifies the signature under the registered
// publisher pubkey, so the bytes the producer signs and the bytes
// the verifier checks MUST match — Canonical is the single source
// of truth for those bytes.

package identity

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
)

// RotationResponse is the parsed 201 body from
// `POST /api/publishers/:handle/rotate`.
type RotationResponse struct {
	RotationID   string `json:"rotation_id"`
	RegisteredAt string `json:"registered_at"`
}

// SubmitRotation POSTs a signed key-rotation attestation to reef-core.
//
// The `attestation` object in the request body uses the same field
// names as the canonical bytes Canonical/1 emits — so the server can
// reconstruct those bytes deterministically and re-verify
// `signature_by_old_key` under the registered publisher pubkey.
// `reason` is dropped from the request when empty; this matches
// Canonical's omit-when-nil rule and prevents a `"reason":""` field
// from sneaking into the JSON the server hashes.
//
// On 201 returns the decoded RotationResponse. On any non-2xx the
// server's `{"error": "<atom>"}` body is surfaced verbatim in the
// returned error so the CLI can show it without re-parsing.
func SubmitRotation(serverURL, handle string, att RotationAttestation, sig []byte) (*RotationResponse, error) {
	url := strings.TrimRight(serverURL, "/") + "/api/publishers/" + handle + "/rotate"

	attMap := map[string]string{
		"kind":           att.Kind,
		"handle":         att.Handle,
		"old_pubkey_hex": att.OldPubkeyHex,
		"new_pubkey_hex": att.NewPubkeyHex,
		"rotated_at":     att.RotatedAt,
	}
	if att.Reason != "" {
		attMap["reason"] = att.Reason
	}

	body, err := json.Marshal(map[string]any{
		"attestation":          attMap,
		"signature_by_old_key": base64.StdEncoding.EncodeToString(sig),
	})
	if err != nil {
		return nil, fmt.Errorf("marshal rotation body: %w", err)
	}

	resp, err := http.Post(url, "application/json", bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("POST %s: %w", url, err)
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(resp.Body)

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("POST %s: status %d: %s",
			url, resp.StatusCode, strings.TrimSpace(string(respBody)))
	}

	var out RotationResponse
	if err := json.Unmarshal(respBody, &out); err != nil {
		return nil, fmt.Errorf("parse rotation response: %w", err)
	}
	return &out, nil
}
