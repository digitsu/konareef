package vkeystore_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/digitsu/konareef/internal/vkeystore"
)

func loadFixtureVkey(t *testing.T) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", "vkey_fixture.bin"))
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	return data
}

// fixtureHandler serves vkey bytes for one circuit_id at the expected
// well-known path; everything else returns 404.
func fixtureHandler(t *testing.T, wantCircuit string, body []byte) http.Handler {
	t.Helper()
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		want := "/.well-known/circuits/" + wantCircuit + "/vkey"
		if r.Method != http.MethodGet || r.URL.Path != want {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/octet-stream")
		_, _ = w.Write(body)
	})
}

func newTier1FromTestServer(t *testing.T, srv *httptest.Server) (*vkeystore.Tier1HTTPSBackend, string) {
	t.Helper()
	u, _ := url.Parse(srv.URL)
	be := vkeystore.NewTier1HTTPSBackend(srv.Client())
	be.BaseURLOverride = srv.URL // test seam: avoid hard-coded https://paygate-zk.*
	return be, u.Host
}

func TestTier1Fetch200OK(t *testing.T) {
	body := loadFixtureVkey(t)
	srv := httptest.NewServer(fixtureHandler(t, "konareef-pod-step-v1", body))
	defer srv.Close()
	be, host := newTier1FromTestServer(t, srv)
	got, err := be.Fetch(context.Background(), "konareef-pod-step-v1", host)
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if string(got) != string(body) {
		t.Errorf("body mismatch: got %d bytes, want %d", len(got), len(body))
	}
}

func TestTier1Fetch404ReturnsVkeyUnavailable(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.NotFound(w, r)
	}))
	defer srv.Close()
	be, host := newTier1FromTestServer(t, srv)
	_, err := be.Fetch(context.Background(), "circ-missing", host)
	if !errors.Is(err, vkeystore.ErrVkeyUnavailable) {
		t.Fatalf("404 must yield ErrVkeyUnavailable; got %v", err)
	}
}

func TestTier1Fetch500ReturnsVkeyUnavailable(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "boom", http.StatusInternalServerError)
	}))
	defer srv.Close()
	be, host := newTier1FromTestServer(t, srv)
	_, err := be.Fetch(context.Background(), "circ-x", host)
	if !errors.Is(err, vkeystore.ErrVkeyUnavailable) {
		t.Fatalf("500 must yield ErrVkeyUnavailable; got %v", err)
	}
}

func TestTier1NetworkErrorReturnsVkeyUnavailable(t *testing.T) {
	be := vkeystore.NewTier1HTTPSBackend(nil)
	// http://0.0.0.0:1 is reserved and refuses connections.
	be.BaseURLOverride = "http://0.0.0.0:1"
	_, err := be.Fetch(context.Background(), "circ-x", "0.0.0.0:1")
	if !errors.Is(err, vkeystore.ErrVkeyUnavailable) {
		t.Fatalf("conn refused must yield ErrVkeyUnavailable; got %v", err)
	}
}

func TestTier1BodyTooLargeReturnsVkeyUnavailable(t *testing.T) {
	// Body 5 MB; backend cap is 4 MB.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		buf := make([]byte, 5*1024*1024)
		_, _ = w.Write(buf)
	}))
	defer srv.Close()
	be, host := newTier1FromTestServer(t, srv)
	_, err := be.Fetch(context.Background(), "circ-huge", host)
	if !errors.Is(err, vkeystore.ErrVkeyUnavailable) {
		t.Fatalf("oversized body must yield ErrVkeyUnavailable; got %v", err)
	}
}

func TestTier1URLConstructionUsesPaygateZkPrefix(t *testing.T) {
	// When BaseURLOverride is unset, Fetch builds
	// https://paygate-zk.{publisherDomain}/.well-known/circuits/{id}/vkey.
	// The input is the publisher BASE domain (e.g. example.com), NOT the
	// full paygate-zk.example.com service host.
	be := vkeystore.NewTier1HTTPSBackend(nil)
	got, err := be.BuildURL("konareef-pod-step-v1", "example.com")
	if err != nil {
		t.Fatalf("BuildURL: %v", err)
	}
	want := "https://paygate-zk.example.com/.well-known/circuits/konareef-pod-step-v1/vkey"
	if got != want {
		t.Errorf("BuildURL = %q, want %q", got, want)
	}
}

func TestTier1URLConstructionRejectsAlreadyPrefixedDomain(t *testing.T) {
	// Passing the full service host instead of the base domain would
	// otherwise produce paygate-zk.paygate-zk.example.com.
	be := vkeystore.NewTier1HTTPSBackend(nil)
	_, err := be.BuildURL("circ", "paygate-zk.example.com")
	if !errors.Is(err, vkeystore.ErrDomainAlreadyPrefixed) {
		t.Fatalf("BuildURL(paygate-zk.example.com) = %v; want ErrDomainAlreadyPrefixed", err)
	}
}

func TestTier1URLConstructionRejectsInvalidCircuitID(t *testing.T) {
	be := vkeystore.NewTier1HTTPSBackend(nil)
	_, err := be.BuildURL("../../../etc/passwd", "example.com")
	if !errors.Is(err, vkeystore.ErrCircuitIDInvalid) {
		t.Fatalf("BuildURL(traversal circuit_id) = %v; want ErrCircuitIDInvalid", err)
	}
}

func TestTier1URLConstructionOverrideRespected(t *testing.T) {
	be := vkeystore.NewTier1HTTPSBackend(nil)
	be.BaseURLOverride = "http://127.0.0.1:1234"
	got, err := be.BuildURL("circ", "example.com")
	if err != nil {
		t.Fatalf("BuildURL: %v", err)
	}
	want := "http://127.0.0.1:1234/.well-known/circuits/circ/vkey"
	if got != want {
		t.Errorf("override BuildURL = %q, want %q", got, want)
	}
}

func TestTier1FetchPropagatesContextCancellation(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-r.Context().Done()
	}))
	defer srv.Close()
	be, host := newTier1FromTestServer(t, srv)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := be.Fetch(ctx, "circ", host)
	if err == nil || !strings.Contains(err.Error(), "ERR_VKEY_UNAVAILABLE") {
		t.Fatalf("cancelled ctx must surface ErrVkeyUnavailable; got %v", err)
	}
}
