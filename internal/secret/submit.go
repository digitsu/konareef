// Copyright 2026 Jerry David Chan, Konareef.ai
// SPDX-License-Identifier: Apache-2.0

// submit.go — the network half of `konareef pod secret`.
//
// Each call signs Canonical(envelope, op) with the publisher identity and
// sends the fields plus the signature to reef-core. The server rebuilds
// the preimage from the body and verifies it against the pubkey bound to
// the handle. The routes and bodies are the signed-envelope contract
// documented in docs/reference/pod-toml-network.md ("Binding a secret").

package secret

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/digitsu/konareef/internal/identity"
	"github.com/digitsu/konareef/internal/serverurl"
)

// submitClient never follows a redirect (the signature is the credential
// and must not be re-sent to a host a redirect names) and bounds the
// whole exchange with one timeout. Same posture as internal/listing.
var submitClient = &http.Client{
	CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	},
	Timeout: 60 * time.Second,
}

// SetResponse is the parsed 201 body of a set.
type SetResponse struct {
	Name      string    `json:"name"`
	RotatedAt time.Time `json:"rotated_at"`
}

// Entry is one row of a list response.
type Entry struct {
	Name      string    `json:"name"`
	RotatedAt time.Time `json:"rotated_at"`
}

// wireBody is the JSON body for all three operations. Fields that do not
// apply are omitted. Byte fields ride as base64.
type wireBody struct {
	Handle          string `json:"handle"`
	PodName         string `json:"pod_name"`
	Name            string `json:"name,omitempty"`
	ValueSHA256     string `json:"value_sha256,omitempty"`
	Nonce           string `json:"nonce"`
	TS              int64  `json:"ts"`
	Value           string `json:"value,omitempty"`
	Signature       string `json:"signature"`
	PublisherPubkey string `json:"publisher_pubkey"`
}

// Set uploads value under envelope.Name for envelope.Handle/PodName.
// It refuses, before any network call, an empty value (an empty value
// would marshal to a wire body with no "value" key at all, since the
// field is `omitempty`, turning a client-side mistake into a malformed
// request the server has to reject) and a value whose SHA-256 is not
// envelope.ValueSHA256. Inputs: the reef-core base URL, the publisher
// identity, the envelope, and the raw value. Output: the parsed 201 body.
func Set(serverURL string, id *identity.Identity, envelope Envelope, value []byte) (*SetResponse, error) {
	if len(value) == 0 {
		return nil, errors.New("secret value is empty")
	}
	digest := sha256.Sum256(value)
	if hex.EncodeToString(digest[:]) != envelope.ValueSHA256 {
		return nil, errors.New("secret value does not match the envelope digest")
	}
	endpoint, err := serverurl.Endpoint(serverURL, "api", "pods", envelope.Handle, envelope.PodName, "secrets")
	if err != nil {
		return nil, err
	}
	body, err := signedBody(id, envelope, OpSet)
	if err != nil {
		return nil, err
	}
	body.Value = base64.StdEncoding.EncodeToString(value)

	var response SetResponse
	if err := send(http.MethodPost, endpoint, body, http.StatusCreated, &response, "set"); err != nil {
		return nil, err
	}
	return &response, nil
}

// Remove deletes envelope.Name from envelope.Handle/PodName.
func Remove(serverURL string, id *identity.Identity, envelope Envelope) error {
	endpoint, err := serverurl.Endpoint(serverURL, "api", "pods", envelope.Handle, envelope.PodName, "secrets", envelope.Name)
	if err != nil {
		return err
	}
	body, err := signedBody(id, envelope, OpRm)
	if err != nil {
		return err
	}
	body.ValueSHA256 = ""
	var response struct {
		Name    string `json:"name"`
		Removed bool   `json:"removed"`
	}
	return send(http.MethodDelete, endpoint, body, http.StatusOK, &response, "rm")
}

// List returns the names and rotation times bound to envelope.Handle/
// PodName. envelope.Name and envelope.ValueSHA256 are ignored.
func List(serverURL string, id *identity.Identity, envelope Envelope) ([]Entry, error) {
	endpoint, err := serverurl.Endpoint(serverURL, "api", "pods", envelope.Handle, envelope.PodName, "secrets", "list")
	if err != nil {
		return nil, err
	}
	envelope.Name = ""
	envelope.ValueSHA256 = ""
	body, err := signedBody(id, envelope, OpLs)
	if err != nil {
		return nil, err
	}
	var response struct {
		Secrets []Entry `json:"secrets"`
	}
	if err := send(http.MethodPost, endpoint, body, http.StatusOK, &response, "ls"); err != nil {
		return nil, err
	}
	return response.Secrets, nil
}

// signedBody signs Canonical(envelope, op) and fills the wire fields.
func signedBody(id *identity.Identity, envelope Envelope, op Operation) (*wireBody, error) {
	preimage, err := Canonical(envelope, op)
	if err != nil {
		return nil, err
	}
	signature, err := id.Sign(preimage)
	if err != nil {
		return nil, fmt.Errorf("sign secret envelope: %w", err)
	}
	pubkey, err := hex.DecodeString(id.PublicKeyHex)
	if err != nil {
		return nil, fmt.Errorf("decode publisher pubkey hex: %w", err)
	}
	return &wireBody{
		Handle:          envelope.Handle,
		PodName:         envelope.PodName,
		Name:            envelope.Name,
		ValueSHA256:     envelope.ValueSHA256,
		Nonce:           envelope.Nonce,
		TS:              envelope.TS,
		Signature:       base64.StdEncoding.EncodeToString(signature),
		PublisherPubkey: base64.StdEncoding.EncodeToString(pubkey),
	}, nil
}

// send marshals body, performs method on endpoint, requires wantStatus,
// and decodes the JSON reply into out. A non-matching status becomes an
// error carrying the server's {"error": code} when present. opName is
// for the error text only.
func send(method, endpoint string, body *wireBody, wantStatus int, out any, opName string) error {
	raw, err := json.Marshal(body)
	if err != nil {
		return fmt.Errorf("marshal secret envelope: %w", err)
	}
	request, err := http.NewRequest(method, endpoint, bytes.NewReader(raw))
	if err != nil {
		return err
	}
	request.Header.Set("Content-Type", "application/json")
	response, err := submitClient.Do(request)
	if err != nil {
		return fmt.Errorf("pod secret %s: %w", opName, err)
	}
	defer response.Body.Close()
	replyBytes, err := io.ReadAll(io.LimitReader(response.Body, 1<<20))
	if err != nil {
		return fmt.Errorf("read reef-core reply: %w", err)
	}
	if response.StatusCode != wantStatus {
		var refusal struct {
			Error string `json:"error"`
		}
		if json.Unmarshal(replyBytes, &refusal) == nil && refusal.Error != "" {
			return fmt.Errorf("reef-core refused pod secret %s: %s", opName, refusal.Error)
		}
		return fmt.Errorf("reef-core refused pod secret %s: HTTP %d", opName, response.StatusCode)
	}
	if err := json.Unmarshal(replyBytes, out); err != nil {
		return fmt.Errorf("decode reef-core reply: %w", err)
	}
	return nil
}
