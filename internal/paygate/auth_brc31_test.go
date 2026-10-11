// Copyright 2026 Jerry David Chan, Konareef.ai
// SPDX-License-Identifier: Apache-2.0

// internal/paygate/auth_brc31_test.go — identity + per-request header.
package paygate_test

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/digitsu/konareef/internal/paygate"
)

func TestNewBRC31IdentityPersistsKey(t *testing.T) {
	dir := t.TempDir()
	id1, err := paygate.LoadOrCreateBRC31Identity(filepath.Join(dir, "identity.key"))
	if err != nil {
		t.Fatalf("first load: %v", err)
	}
	id2, err := paygate.LoadOrCreateBRC31Identity(filepath.Join(dir, "identity.key"))
	if err != nil {
		t.Fatalf("second load: %v", err)
	}
	if id1.PubKeyHex() != id2.PubKeyHex() {
		t.Errorf("identity key not persisted across loads: %q vs %q", id1.PubKeyHex(), id2.PubKeyHex())
	}
}

func TestBRC31SessionHeaderShape(t *testing.T) {
	id, _ := paygate.LoadOrCreateBRC31Identity(filepath.Join(t.TempDir(), "k"))
	sess := &paygate.BRC31Session{ID: "sess-abc", Identity: id}
	hdr := sess.AuthorizationHeader([]byte("POST /v1/prove/nova-fold"))
	if !strings.HasPrefix(hdr, "Brc31 ") {
		t.Errorf("header = %q, want prefix Brc31 ", hdr)
	}
	if !strings.Contains(hdr, "sess-abc") {
		t.Errorf("header missing session id: %q", hdr)
	}
}
