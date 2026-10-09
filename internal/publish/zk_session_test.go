// Copyright 2026 Jerry David Chan, Konareef.ai
// SPDX-License-Identifier: Apache-2.0

// zk_session_test.go — P1.3 ZK-session orchestration tests.
package publish

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/digitsu/konareef/internal/pod"
	"github.com/digitsu/konareef/internal/saltstore"
	"github.com/digitsu/konareef/internal/vkeystore"
)

// TestValidateZKFlagsMatrix exercises the parse-time fail-closed
// matrix from PRD 4 § 4.3.4. The matrix is 4 boolean inputs (--zk,
// --circuit-id present, --disclosure-policy present, --pin-circuit-
// vkey) × valid-value variations.
func TestValidateZKFlagsMatrix(t *testing.T) {
	cases := []struct {
		name    string
		flags   ZKFlags
		wantErr error
	}{
		// Legacy publish (no ZK opt-in): all four flags absent → OK.
		{"legacy-no-flags", ZKFlags{}, nil},

		// --zk without --circuit-id → reject.
		{"zk-without-circuit-id",
			ZKFlags{ZK: true, DisclosurePolicy: "C"},
			ErrZkRequiresCircuitID},

		// --zk without --disclosure-policy → reject.
		{"zk-without-disclosure-policy",
			ZKFlags{ZK: true, CircuitID: "konareef-pod-step-v1"},
			ErrZkRequiresDisclosurePolicy},

		// --zk with disclosure-policy "X" → reject.
		{"zk-invalid-disclosure",
			ZKFlags{ZK: true, CircuitID: "c1", DisclosurePolicy: "X"},
			ErrInvalidDisclosurePolicy},

		// Post-normalisation, lowercase reaching ValidateZKFlags is
		// an internal contract violation (the CLI normalises to
		// UPPERCASE before constructing ZKFlags).
		{"zk-disclosure-lowercase-rejected-post-normalise",
			ZKFlags{ZK: true, CircuitID: "c1", DisclosurePolicy: "c"},
			ErrInvalidDisclosurePolicy},

		// Full ZK quad (C) → OK.
		{"zk-full-typeC",
			ZKFlags{ZK: true, CircuitID: "c1", DisclosurePolicy: "C"},
			nil},

		// Full ZK quad (D) → OK.
		{"zk-full-typeD",
			ZKFlags{ZK: true, CircuitID: "c1", DisclosurePolicy: "D"},
			nil},

		// --pin-circuit-vkey standalone (no --circuit-id) → REJECT
		// (round-6 B1): the runtime path fetches the discovery
		// manifest and looks up VkeySha256For(flags.CircuitID) before
		// anchoring, so an empty CircuitID is internally inconsistent.
		{"pin-anchor-standalone-rejected",
			ZKFlags{PinCircuitVkey: true},
			ErrCircuitIDRequiredForPinCircuitVkey},

		// --pin-circuit-vkey + --circuit-id (no --zk) → OK.
		{"pin-anchor-with-circuit",
			ZKFlags{PinCircuitVkey: true, CircuitID: "c1"},
			nil},

		// --pin-circuit-vkey + --zk + full quad → OK; combined.
		{"pin-anchor-combined",
			ZKFlags{PinCircuitVkey: true, ZK: true, CircuitID: "c1", DisclosurePolicy: "C"},
			nil},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := ValidateZKFlags(c.flags)
			if c.wantErr == nil {
				if err != nil {
					t.Fatalf("ValidateZKFlags(%+v) = %v, want nil", c.flags, err)
				}
				return
			}
			if !errors.Is(err, c.wantErr) {
				t.Fatalf("ValidateZKFlags(%+v) = %v, want %v", c.flags, err, c.wantErr)
			}
		})
	}
}

// TestValidateZKFlagsAcceptsCircuitWhenZKAbsent — --circuit-id alone
// (no --zk, no --pin-circuit-vkey) is OK at parse time.
func TestValidateZKFlagsAcceptsCircuitWhenZKAbsent(t *testing.T) {
	err := ValidateZKFlags(ZKFlags{CircuitID: "c1"})
	if err != nil {
		t.Fatalf("ValidateZKFlags(--circuit-id alone) = %v, want nil", err)
	}
}

// --- PreflightPinCheck tests (Task 3) ---

// discoveryManifest is the slice of the PRD 2 § 5.3 manifest this
// package consumes for tests.
type discoveryManifest struct {
	PaygateZKDomain string `json:"paygate_zk_domain"`
	Circuits        []struct {
		CircuitID  string `json:"circuit_id"`
		VkeySha256 string `json:"vkey_sha256"`
	} `json:"circuits"`
}

// PaygateZKDomainHost satisfies the publish.DiscoveryManifest interface.
func (m discoveryManifest) PaygateZKDomainHost() string { return m.PaygateZKDomain }

// VkeySha256For satisfies the publish.DiscoveryManifest interface.
func (m discoveryManifest) VkeySha256For(circuitID string) (string, bool) {
	for _, c := range m.Circuits {
		if c.CircuitID == circuitID {
			return c.VkeySha256, true
		}
	}
	return "", false
}

func loadFixtureManifest(t *testing.T, name string) discoveryManifest {
	t.Helper()
	body, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatalf("read fixture %s: %v", name, err)
	}
	var m discoveryManifest
	if err := json.Unmarshal(body, &m); err != nil {
		t.Fatalf("decode %s: %v", name, err)
	}
	return m
}

// newPinCheckHarness wires a Resolver against an httptest.Server that
// serves a 256-byte 0x42 vkey at /.well-known/circuits/<id>/vkey, plus
// a tmpdir-rooted local cache.
//
// Returns the Resolver and a discovery-shaped paygate_zk_domain
// placeholder ("paygate-zk.example.com"). PublisherBaseDomain strips
// the `paygate-zk.` prefix to "example.com" before passing to the
// resolver; the Tier-1 backend's BaseURLOverride routes the actual
// fetch to the httptest.Server, and the base satisfies
// ResolveRequest.Validate() (which rejects host:port strings).
func newPinCheckHarness(t *testing.T) (*vkeystore.Resolver, string) {
	t.Helper()
	t.Setenv("KONAREEF_STATE_DIR", t.TempDir())
	cache, err := vkeystore.NewLocalCache()
	if err != nil {
		t.Fatalf("NewLocalCache: %v", err)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		want := "/.well-known/circuits/konareef-pod-step-v1/vkey"
		if r.URL.Path != want {
			http.NotFound(w, r)
			return
		}
		body := make([]byte, 256)
		for i := range body {
			body[i] = 0x42
		}
		_, _ = w.Write(body)
	}))
	t.Cleanup(srv.Close)
	tier1 := vkeystore.NewTier1HTTPSBackend(srv.Client())
	tier1.BaseURLOverride = srv.URL
	// Tier 2 returns ErrAnchorNotFound so the resolver does not
	// require an anchor in this fixture.
	tier2 := vkeystore.AnchorLookupFunc(func(_ context.Context, _ string) (string, error) {
		return "", vkeystore.ErrAnchorNotFound
	})
	return &vkeystore.Resolver{
		Cache: cache,
		Tier1: tier1,
		Tier2: tier2,
	}, "paygate-zk.example.com"
}

func TestPreflightPinCheckPasses(t *testing.T) {
	resolver, host := newPinCheckHarness(t)
	m := loadFixtureManifest(t, "manifest-matching-pin.json")
	m.PaygateZKDomain = host // rebind to the test server

	flags := ZKFlags{
		ZK:               true,
		CircuitID:        "konareef-pod-step-v1",
		DisclosurePolicy: "C",
	}
	if err := PreflightPinCheck(context.Background(), resolver, flags, m); err != nil {
		t.Fatalf("PreflightPinCheck on matching fixture: %v", err)
	}
}

func TestPreflightPinCheckHaltsOnMismatch(t *testing.T) {
	resolver, host := newPinCheckHarness(t)
	m := loadFixtureManifest(t, "manifest-mismatched-pin.json")
	m.PaygateZKDomain = host

	flags := ZKFlags{
		ZK:               true,
		CircuitID:        "konareef-pod-step-v1",
		DisclosurePolicy: "C",
	}
	err := PreflightPinCheck(context.Background(), resolver, flags, m)
	if !errors.Is(err, vkeystore.ErrCircuitPinMismatch) {
		t.Fatalf("PreflightPinCheck on mismatched fixture: err=%v, want ErrCircuitPinMismatch", err)
	}
}

func TestPreflightPinCheckHaltsWhenManifestMissingCircuit(t *testing.T) {
	resolver, host := newPinCheckHarness(t)
	m := discoveryManifest{PaygateZKDomain: host} // empty circuits[]

	flags := ZKFlags{
		ZK:               true,
		CircuitID:        "konareef-pod-step-v1",
		DisclosurePolicy: "C",
	}
	err := PreflightPinCheck(context.Background(), resolver, flags, m)
	if err == nil {
		t.Fatal("PreflightPinCheck on empty manifest must error")
	}
}

func TestPreflightPinCheckSkippedWhenZKAbsent(t *testing.T) {
	// Legacy publish — no resolver call needed.
	flags := ZKFlags{} // ZK false
	if err := PreflightPinCheck(context.Background(), nil, flags, nil); err != nil {
		t.Fatalf("PreflightPinCheck(legacy) = %v, want nil", err)
	}
}

// --- SealDisclosurePolicy tests (Task 4) ---

func TestSealDisclosurePolicyTypeC(t *testing.T) {
	w := &Witness{}
	flags := ZKFlags{ZK: true, CircuitID: "c1", DisclosurePolicy: "C"}
	if err := SealDisclosurePolicy(flags, w); err != nil {
		t.Fatalf("SealDisclosurePolicy: %v", err)
	}
	if w.DisclosurePolicy != "C" {
		t.Errorf("witness policy = %q, want C", w.DisclosurePolicy)
	}
	if !w.Sealed {
		t.Errorf("witness must be marked Sealed after first call")
	}
}

func TestSealDisclosurePolicyTypeD(t *testing.T) {
	w := &Witness{}
	flags := ZKFlags{ZK: true, CircuitID: "c1", DisclosurePolicy: "D"}
	if err := SealDisclosurePolicy(flags, w); err != nil {
		t.Fatalf("SealDisclosurePolicy: %v", err)
	}
	if w.DisclosurePolicy != "D" {
		t.Errorf("witness policy = %q, want D", w.DisclosurePolicy)
	}
}

func TestSealDisclosurePolicyIrrevocable(t *testing.T) {
	w := &Witness{}
	flags := ZKFlags{ZK: true, CircuitID: "c1", DisclosurePolicy: "C"}
	if err := SealDisclosurePolicy(flags, w); err != nil {
		t.Fatalf("first seal: %v", err)
	}
	err := SealDisclosurePolicy(flags, w)
	if !errors.Is(err, ErrDisclosurePolicySealed) {
		t.Fatalf("second seal: err=%v, want ErrDisclosurePolicySealed", err)
	}
	if w.DisclosurePolicy != "C" {
		t.Errorf("policy mutated after sealed: %q", w.DisclosurePolicy)
	}
}

func TestSealDisclosurePolicyNoOpWhenZKAbsent(t *testing.T) {
	w := &Witness{}
	flags := ZKFlags{} // ZK false
	if err := SealDisclosurePolicy(flags, w); err != nil {
		t.Fatalf("SealDisclosurePolicy(non-zk) = %v, want nil", err)
	}
	if w.Sealed {
		t.Errorf("non-zk publish must not seal witness")
	}
	if w.DisclosurePolicy != "" {
		t.Errorf("non-zk publish set policy = %q", w.DisclosurePolicy)
	}
}

// --- EnsureSaltForTypeD tests (Task 6) ---

func TestEnsureSaltForTypeDProvisionsNewSalt(t *testing.T) {
	t.Setenv("KONAREEF_STATE_DIR", t.TempDir())
	mock := saltstore.NewMockBackend()
	spec := &pod.Spec{
		Pod: pod.Identity{
			Name:      "research-bot",
			Version:   "1.0.0",
			LineageID: "01020304050607080910111213141516",
		},
	}
	flags := ZKFlags{ZK: true, CircuitID: "c1", DisclosurePolicy: "D"}

	lineageID, salt, err := EnsureSaltForTypeD(flags, spec, mock)
	if err != nil {
		t.Fatalf("EnsureSaltForTypeD: %v", err)
	}
	if lineageID == [16]byte{} {
		t.Error("lineage_id is zero")
	}
	if salt == [32]byte{} {
		t.Error("salt is zero")
	}
	// Idempotent: a second call returns the same salt.
	_, salt2, err := EnsureSaltForTypeD(flags, spec, mock)
	if err != nil {
		t.Fatalf("EnsureSaltForTypeD (idempotent): %v", err)
	}
	if salt != salt2 {
		t.Error("idempotent call returned a different salt")
	}
}

func TestEnsureSaltForTypeDSkippedForTypeC(t *testing.T) {
	spec := &pod.Spec{Pod: pod.Identity{Name: "x", Version: "1"}}
	flags := ZKFlags{ZK: true, CircuitID: "c1", DisclosurePolicy: "C"}
	_, _, err := EnsureSaltForTypeD(flags, spec, nil)
	if err != nil {
		t.Errorf("Type-C path must not require saltstore; got %v", err)
	}
}

func TestEnsureSaltForTypeDPropagatesUnavailable(t *testing.T) {
	spec := &pod.Spec{Pod: pod.Identity{Name: "x", Version: "1",
		LineageID: "01020304050607080910111213141516"}}
	flags := ZKFlags{ZK: true, CircuitID: "c1", DisclosurePolicy: "D"}
	// Pass nil backend → simulate Resolve failure path.
	_, _, err := EnsureSaltForTypeD(flags, spec, nil)
	if !errors.Is(err, saltstore.ErrSaltStorageUnavailable) {
		t.Fatalf("nil backend must surface ErrSaltStorageUnavailable; got %v", err)
	}
}
