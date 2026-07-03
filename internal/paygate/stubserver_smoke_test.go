// internal/paygate/stubserver_smoke_test.go — basic stub server smoke
// tests. The full M-1..M-8 cases live in their own files.
package paygate_test

import (
	"context"
	"net/http"
	"testing"

	"github.com/digitsu/konareef/internal/paygate"
	"github.com/digitsu/konareef/internal/paygate/stubserver"
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
