// Copyright 2026 Jerry David Chan, Konareef.ai
// SPDX-License-Identifier: Apache-2.0

// internal/paygate/stubserver_smoke_test.go — basic stub server smoke
// tests. The full M-1..M-8 cases live in their own files.
package paygate_test

import (
	"context"
	"net/http"
	"strings"
	"testing"

	"github.com/digitsu/konareef/internal/paygate"
	"github.com/digitsu/konareef/internal/paygate/stubserver"
	"github.com/digitsu/konareef/internal/vkeystore"
)

func TestStubManifestEndpointReturnsActive(t *testing.T) {
	s := stubserver.New(stubserver.Options{ManifestProfile: "active"})
	defer s.Close()
	mc := &paygate.ManifestCache{BaseURL: s.URL(), HTTP: &http.Client{}}
	m, err := mc.Get(context.Background())
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if m.Service != "paygate-zk" {
		t.Errorf("service = %q", m.Service)
	}
}

func TestStubSubmitNovaFoldReturns202(t *testing.T) {
	s := stubserver.New(stubserver.Options{ManifestProfile: "active"})
	defer s.Close()
	c := newSmokeClient(t, s)
	sess, err := c.Open(context.Background(), paygate.OpenSessionInput{CircuitID: "konareef-pod-step-v1", DisclosurePolicy: paygate.DisclosureTypeC})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	rb, err := c.SubmitFold(context.Background(), sess, paygate.FoldStepInput{StepIndex: 0, HP: [32]byte{0xaa}, BSVUSDRate: 15.0})
	if err != nil {
		t.Fatalf("SubmitFold: %v", err)
	}
	if len(rb.AccumulatorOut) == 0 {
		t.Errorf("AccumulatorOut empty")
	}
}

// TestStubManifestAdvertisesBothPodStepIDs checks that the stub discovery
// manifest lists both pod-step ids (VHASH-FU, script-verify/paygate-zk#13),
// that v1.1 carries the pinned SHA-256(vkey) and its own vkey URL, and that
// both ids are priced.
func TestStubManifestAdvertisesBothPodStepIDs(t *testing.T) {
	s := stubserver.New(stubserver.Options{ManifestProfile: "active"})
	defer s.Close()
	mc := &paygate.ManifestCache{BaseURL: s.URL(), HTTP: &http.Client{}}
	m, err := mc.Get(context.Background())
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	for _, id := range vkeystore.SupportedCircuitIDs() {
		if _, err := m.ActiveSchedule(id, "spartan-compress"); err != nil {
			t.Errorf("%s: ActiveSchedule: %v", id, err)
		}
	}
	v11, ok := m.Circuits[vkeystore.CircuitIDPodStepV1_1]
	if !ok {
		t.Fatalf("manifest does not advertise %s", vkeystore.CircuitIDPodStepV1_1)
	}
	pin, _ := vkeystore.KnownVkeySha256For(vkeystore.CircuitIDPodStepV1_1)
	if v11.VkeySha256 != pin {
		t.Errorf("v1.1 vkey_sha256 = %q, want pin %q", v11.VkeySha256, pin)
	}
	if !strings.HasSuffix(v11.VkeyURL, "/.well-known/circuits/"+vkeystore.CircuitIDPodStepV1_1+"/vkey") {
		t.Errorf("v1.1 vkey_url = %q", v11.VkeyURL)
	}
	// konareef-pod-step-v1.2 (CL-4-live) is advertised with its pinned
	// SHA-256(vkey).
	v12, ok := m.Circuits[vkeystore.CircuitIDPodStepV1_2]
	pin12, _ := vkeystore.KnownVkeySha256For(vkeystore.CircuitIDPodStepV1_2)
	if !ok || v12.VkeySha256 != pin12 {
		t.Errorf("v1.2 not advertised with its pin: ok=%v vkey_sha256=%q", ok, v12.VkeySha256)
	}
}
