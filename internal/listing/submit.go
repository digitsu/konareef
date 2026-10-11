// Copyright 2026 Jerry David Chan, Konareef.ai
// SPDX-License-Identifier: Apache-2.0

// submit.go — the network half of `konareef pod listing publish`.
//
// Submit signs the canonical listing bytes and PUTs them to reef-core at
// `PUT <server>/api/pods/:handle/:pod_name/listing`. As with publish,
// the signature IS the authentication — there is no session token. The
// server re-derives Canonical(f) from the fields in this body and checks
// the signature against the pubkey already bound to the handle, so the
// wire fields and the preimage fields must never drift apart.

package listing

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

	"github.com/digitsu/konareef/internal/identity"
	"github.com/digitsu/konareef/internal/serverurl"
)

// submitClient is the HTTP client used to PUT a signed listing.
//
// It deliberately does NOT follow redirects. The publisher's signature
// IS the credential on this endpoint, so re-sending the body to whatever
// host a redirect names would hand a valid signature + pubkey to that
// host — and Go's default client would then parse the redirect target's
// response and report success to the publisher. Returning
// ErrUseLastResponse makes the 3xx visible to Submit, which surfaces it
// as a failure like any other non-2xx.
//
// The timeout bounds the whole exchange (dial through body read); the
// default client has none, so a hung server would block the CLI forever.
var submitClient = &http.Client{
	CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	},
	Timeout: 60 * time.Second,
}

// SubmitResponse is the parsed 2xx body from
// `PUT /api/pods/:handle/:pod_name/listing`.
type SubmitResponse struct {
	Handle        string    `json:"handle"`
	PodName       string    `json:"pod_name"`
	Revision      int64     `json:"revision"`
	AuthorFeeSats int       `json:"author_fee_sats"`
	Status        string    `json:"status"`
	UpdatedAt     time.Time `json:"updated_at"`
}

// putRequest is the wire body. Byte fields ride as base64, matching the
// publish endpoint's convention (internal/publish/submit.go). The field
// names mirror the canonical preimage keys one-for-one so the server can
// rebuild the signed bytes from this body alone.
type putRequest struct {
	Handle          string `json:"handle"`
	PodName         string `json:"pod_name"`
	Revision        int64  `json:"revision"`
	AuthorFeeSats   int    `json:"author_fee_sats"`
	ExecutionClass  string `json:"execution_class"`
	Category        string `json:"category"`
	Description     string `json:"display_description"`
	Signature       string `json:"signature"`        // base64 DER ECDSA
	PublisherPubkey string `json:"publisher_pubkey"` // base64 33-byte compressed
}

// Submit signs Canonical(f) with id and PUTs it to
// <serverURL>/api/pods/<handle>/<pod_name>/listing. Any non-2xx is a
// fatal error carrying the server's {"error": "<code>"} body when
// present, and the raw status otherwise. There is no retry policy here;
// the CLI is the human-facing wrapper that interprets failures.
//
// Inputs: serverURL — the reef-core base URL from `--server` /
// `$KONAREEF_SERVER`; f — the listing fields; id — the publisher
// identity whose key signs them. Output: the parsed 2xx body, or an
// error.
func Submit(serverURL string, f Fields, id *identity.Identity) (*SubmitResponse, error) {
	// The base URL is validated and the endpoint built FIRST, before
	// anything is signed. The publisher's signature is the credential on
	// this endpoint, so an unvalidated origin means a valid signature +
	// pubkey could be handed to whatever host a typo, a pasted value or
	// a poisoned $KONAREEF_SERVER names. Failing here means no signature
	// is ever produced, let alone transmitted.
	//
	// Both identifier segments come from a manifest / identity file, so
	// serverurl.Endpoint escapes them rather than concatenating: an
	// unescaped "?" or "#" would rewrite the request target and silently
	// swallow the "/listing" suffix into a query string. Separators and
	// traversal tokens are refused outright — literal "/", "\" and "..",
	// and any "%", because a percent-escape survives URL building intact
	// and would make the escaped wire path and the decoded path name
	// different routes ("a%2Fb" ships as one segment, decodes as two).
	// Canonical does not constrain these characters, so this is the only
	// gate between a hostile manifest identifier and a signed request.
	endpoint, err := serverurl.Endpoint(serverURL, "api", "pods", f.Handle, f.PodName, "listing")
	if err != nil {
		return nil, err
	}

	// OpUpsert: this signature authorises a PUT and nothing else. The
	// operation is part of the signed bytes, so it cannot be replayed
	// against the DELETE route.
	//
	// Canonical also validates f; a field carrying a delimiter would make
	// the signed bytes ambiguous, so nothing is signed or sent then.
	preimage, err := Canonical(f, OpUpsert)
	if err != nil {
		return nil, err
	}
	sig, err := id.Sign(preimage)
	if err != nil {
		return nil, fmt.Errorf("sign listing: %w", err)
	}
	pubBytes, err := hex.DecodeString(id.PublicKeyHex)
	if err != nil {
		return nil, fmt.Errorf("decode publisher pubkey hex: %w", err)
	}

	bodyJSON, err := json.Marshal(putRequest{
		Handle:          f.Handle,
		PodName:         f.PodName,
		Revision:        *f.Revision,
		AuthorFeeSats:   f.AuthorFeeSats,
		ExecutionClass:  f.ExecutionClass,
		Category:        f.Category,
		Description:     f.Description,
		Signature:       base64.StdEncoding.EncodeToString(sig),
		PublisherPubkey: base64.StdEncoding.EncodeToString(pubBytes),
	})
	if err != nil {
		return nil, fmt.Errorf("marshal listing: %w", err)
	}

	req, err := http.NewRequest(http.MethodPut, endpoint, bytes.NewReader(bodyJSON))
	if err != nil {
		return nil, fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := submitClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("PUT %s: %w", endpoint, err)
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(resp.Body)

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		var errBody struct {
			Error string `json:"error"`
			// Held raw, not as *int64, so a non-numeric value cannot
			// fail the whole decode and take the `error` code down with
			// it — a server sending {"current_revision":"7"} must still
			// produce a stale_revision message, just without a number.
			CurrentRevision json.RawMessage `json:"current_revision"`
		}
		if json.Unmarshal(respBody, &errBody) == nil && errBody.Error != "" {
			// stale_revision is the one code a publisher can act on
			// directly, so it gets a message that says how.
			if errBody.Error == "stale_revision" {
				return nil, staleRevisionError(f, endpoint, errBody.CurrentRevision)
			}
			return nil, &RefusalError{Endpoint: endpoint, Status: resp.StatusCode, Code: errBody.Error}
		}
		return nil, fmt.Errorf("PUT %s: status %d: %s",
			endpoint, resp.StatusCode, strings.TrimSpace(string(respBody)))
	}

	var out SubmitResponse
	if err := json.Unmarshal(respBody, &out); err != nil {
		return nil, fmt.Errorf("parse listing response: %w", err)
	}
	if err := checkEcho(f, out); err != nil {
		return nil, err
	}
	return &out, nil
}

// RefusalError is a non-2xx listing response that carried a server
// error code. Code is the server's `error` string, verbatim; Diagnose
// maps the egress gate codes to author guidance. The error text is the
// same "PUT <endpoint>: status <n>: <code>" line older releases printed.
type RefusalError struct {
	Endpoint string // the PUT URL the request went to
	Status   int    // the HTTP status
	Code     string // the server's error code
}

// Error renders the refusal as one line.
func (e *RefusalError) Error() string {
	return fmt.Sprintf("PUT %s: status %d: %s", e.Endpoint, e.Status, e.Code)
}

// staleRevisionError renders the rejection a publisher can actually act
// on, using reef-core's optional `current_revision` when it is usable.
//
// Inputs: f — the listing that was rejected; endpoint — the PUT URL the
// request went to; raw — the raw `current_revision` JSON value, which
// may be absent or unusable. Output: the error to return.
//
// This matters most for a pod the publisher delisted themselves: the
// public detail endpoint 404s delisted and suspended listings and
// DELETE returns 204 with no body, so for that pod this error is the
// only place the number is recoverable. When the server does not supply
// it, point at the detail endpoint rather than inventing a value — a
// wrong number is worse than none, because the publisher would sign a
// revision certain to be rejected again.
//
// There is deliberately no auto-retry. Re-signing at a bumped revision
// behind the user would assert a freshness claim they never made, on a
// money-carrying write — the same mistake as auto-incrementing.
func staleRevisionError(f Fields, endpoint string, raw json.RawMessage) error {
	if current, ok := currentRevision(raw); ok {
		if current >= MaxRevision {
			// No next value exists; do not suggest an out-of-range one.
			return fmt.Errorf(
				"listing was not updated: the stored revision is %d, already the maximum (%d), "+
					"so no higher revision can be signed", current, MaxRevision)
		}
		return fmt.Errorf(
			"listing was not updated: the stored revision is %d — "+
				"re-run with --revision %d (or higher)", current, current+1)
	}
	base := strings.TrimSuffix(endpoint, "/api/pods/"+f.Handle+"/"+f.PodName+"/listing")
	return fmt.Errorf(
		"listing rejected as stale: revision %d is not greater than the revision "+
			"reef-core already has for %s/%s.\n"+
			"  Read the current value from GET %s/api/listings/%s/%s "+
			"and retry with --revision <current+1>",
		*f.Revision, f.Handle, f.PodName, base, f.Handle, f.PodName)
}

// currentRevision interprets the optional `current_revision` field.
//
// Input: raw — the field's raw JSON, absent when the server predates it.
// Output: the revision and true only when it is a JSON integer inside
// the same 0..MaxRevision range a signable revision must satisfy.
//
// Everything else — absent, null, a string, a float, a bool, an object,
// out of range, or wider than int64 — reports false and is treated as
// absent. Unmarshalling into int64 does most of that work: it rejects
// "7", 7.5 and true, and overflows on anything beyond int64.
//
// JSON null is checked separately and FIRST, because encoding/json
// treats null as a no-op for a numeric target: it returns a nil error
// and leaves the int64 at its zero value, which would otherwise be
// reported as a stored revision of 0 — the fabricated number this
// function exists to avoid.
func currentRevision(raw json.RawMessage) (int64, bool) {
	if len(raw) == 0 || string(bytes.TrimSpace(raw)) == "null" {
		return 0, false
	}
	var n int64
	if err := json.Unmarshal(raw, &n); err != nil {
		return 0, false
	}
	if n < 0 || n > MaxRevision {
		return 0, false
	}
	return n, true
}

// checkEcho verifies the server described back the listing that was
// actually sent, so a 2xx that stored nothing cannot read as success.
//
// Without this, a captive portal, an unwired route, or a proxy replying
// "200 {}" is indistinguishable from a stored listing: the response
// decodes into a zero-valued struct and the CLI prints a confirmation
// for a write that never happened. reef-core's render_listing always
// returns handle, pod_name, author_fee_sats and status, so requiring
// them costs nothing against a real server.
//
// The fee is checked because it is the money field: if the server
// stored a different price than the publisher asked for, that must
// surface as an error rather than as a cheerful confirmation line.
//
// Deliberately NOT validated: that Status is one of the known status
// values. Pinning the enum client-side would break older CLIs the day
// reef-core adds a status, and the handle/pod_name/fee echo already
// rules out the fail-open cases this guards against.
func checkEcho(sent Fields, got SubmitResponse) error {
	switch {
	case got.Status == "":
		return fmt.Errorf(
			"listing response carried no status; the server did not confirm the write " +
				"(is the URL a real reef-core instance?)")
	case got.Handle != sent.Handle:
		return fmt.Errorf("listing response is for handle %q, but %q was submitted",
			got.Handle, sent.Handle)
	case got.PodName != sent.PodName:
		return fmt.Errorf("listing response is for pod %q, but %q was submitted",
			got.PodName, sent.PodName)
	case got.AuthorFeeSats != sent.AuthorFeeSats:
		return fmt.Errorf("server stored an author fee of %d sats, but %d was submitted",
			got.AuthorFeeSats, sent.AuthorFeeSats)
	case sent.Revision != nil && got.Revision != *sent.Revision:
		// The stored revision must be the one just signed. Anything else
		// means the write that landed was not this one, and the next
		// mutation would be signed against a revision that has already
		// been superseded.
		return fmt.Errorf("server stored revision %d, but %d was submitted",
			got.Revision, *sent.Revision)
	}
	return nil
}
