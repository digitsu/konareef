// Copyright 2026 Jerry David Chan, Konareef.ai
// SPDX-License-Identifier: Apache-2.0

// rotation_submit_test.go — wire-shape test for the
// POST /api/publishers/:handle/rotate submit helper.

package identity

import (
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// The body POSTed to reef-core is fixed by
// `ReefCoreWeb.PublisherRotationController :: create/2`:
//
//	{ "attestation": { kind, handle, old_pubkey_hex,
//	                    new_pubkey_hex, rotated_at, reason },
//	  "signature_by_old_key": "<base64 DER ECDSA>" }
//
// A drift in this shape breaks every rotation in the field, so the
// test pins each surface field rather than just checking the request
// completes.
func TestSubmitRotation_PostsExpectedWireShape(t *testing.T) {
	var capturedPath string
	var captured map[string]any

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedPath = r.URL.Path
		body, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(body, &captured)
		w.WriteHeader(201)
		_ = json.NewEncoder(w).Encode(map[string]string{
			"rotation_id":   "abc-123",
			"registered_at": "2026-05-19T11:22:00.000000Z",
		})
	}))
	defer srv.Close()

	att := RotationAttestation{
		Kind:         "konareef-key-rotation/v1",
		Handle:       "alice",
		OldPubkeyHex: "02aa",
		NewPubkeyHex: "03bb",
		RotatedAt:    "2026-05-19T11:22:00.000000Z",
		Reason:       "scheduled key rotation",
	}
	sig := []byte{0x30, 0x44, 0x01, 0x02}

	resp, err := SubmitRotation(srv.URL, "alice", att, sig)
	if err != nil {
		t.Fatalf("SubmitRotation: %v", err)
	}

	if capturedPath != "/api/publishers/alice/rotate" {
		t.Errorf("path = %q", capturedPath)
	}
	gotAtt, _ := captured["attestation"].(map[string]any)
	if gotAtt["kind"] != att.Kind {
		t.Errorf("kind = %v", gotAtt["kind"])
	}
	if gotAtt["handle"] != att.Handle {
		t.Errorf("handle = %v", gotAtt["handle"])
	}
	if gotAtt["old_pubkey_hex"] != att.OldPubkeyHex {
		t.Errorf("old_pubkey_hex = %v", gotAtt["old_pubkey_hex"])
	}
	if gotAtt["new_pubkey_hex"] != att.NewPubkeyHex {
		t.Errorf("new_pubkey_hex = %v", gotAtt["new_pubkey_hex"])
	}
	if gotAtt["rotated_at"] != att.RotatedAt {
		t.Errorf("rotated_at = %v", gotAtt["rotated_at"])
	}
	if gotAtt["reason"] != att.Reason {
		t.Errorf("reason = %v", gotAtt["reason"])
	}

	wantSig := base64.StdEncoding.EncodeToString(sig)
	if captured["signature_by_old_key"] != wantSig {
		t.Errorf("signature_by_old_key = %v, want %v", captured["signature_by_old_key"], wantSig)
	}

	if resp.RotationID != "abc-123" {
		t.Errorf("rotation_id = %q", resp.RotationID)
	}
	if resp.RegisteredAt != "2026-05-19T11:22:00.000000Z" {
		t.Errorf("registered_at = %q", resp.RegisteredAt)
	}
}

// `reason` is omitted from the canonical sign bytes when empty;
// it must also be omitted from the POSTed JSON so the server's
// signature check (which recomputes Canonical on its side) lands
// on the same bytes. An empty-string reason in the request body
// would slip past our Canonical filter and break the signature.
func TestSubmitRotation_OmitsEmptyReason(t *testing.T) {
	var captured map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(body, &captured)
		w.WriteHeader(201)
		_ = json.NewEncoder(w).Encode(map[string]string{
			"rotation_id":   "r1",
			"registered_at": "2026-05-19T11:22:00.000000Z",
		})
	}))
	defer srv.Close()

	att := RotationAttestation{
		Kind:         "konareef-key-rotation/v1",
		Handle:       "alice",
		OldPubkeyHex: "02aa",
		NewPubkeyHex: "03bb",
		RotatedAt:    "2026-05-19T11:22:00.000000Z",
		// Reason intentionally omitted.
	}
	if _, err := SubmitRotation(srv.URL, "alice", att, []byte{1}); err != nil {
		t.Fatalf("SubmitRotation: %v", err)
	}

	gotAtt, _ := captured["attestation"].(map[string]any)
	if _, present := gotAtt["reason"]; present {
		t.Fatalf("reason key should be absent when empty; got body %v", captured)
	}
}

// Non-2xx surfaces the server's error atom in the returned error
// so the CLI can show it without manually parsing JSON.
func TestSubmitRotation_Non2xx_Errors(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(400)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "signature_invalid"})
	}))
	defer srv.Close()

	att := RotationAttestation{
		Kind: "konareef-key-rotation/v1", Handle: "alice",
		OldPubkeyHex: "02", NewPubkeyHex: "03",
		RotatedAt: "2026-05-19T11:22:00.000000Z",
	}
	_, err := SubmitRotation(srv.URL, "alice", att, []byte{1})
	if err == nil {
		t.Fatal("expected error on 400, got nil")
	}
	if !strings.Contains(err.Error(), "signature_invalid") {
		t.Errorf("expected error to surface %q, got %q", "signature_invalid", err.Error())
	}
}
