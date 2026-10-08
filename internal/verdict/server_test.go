package verdict

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func req(target string) *http.Request { return httptest.NewRequest(http.MethodGet, target, nil) }

func TestResolveSourceBuildsBundleURL(t *testing.T) {
	s := &Server{ReefcoreURL: "http://reefcore:4000/", DefaultHash: strings.Repeat("a", 64)}
	src, hash, label, err := s.resolveSource(req("/api/verdict"))
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	want := "http://reefcore:4000/api/public/proofs/" + strings.Repeat("a", 64) + "/bundle"
	if src != want {
		t.Errorf("src = %s\nwant %s", src, want)
	}
	if hash != strings.Repeat("a", 64) || label != "http://reefcore:4000/" {
		t.Errorf("hash/label = %s / %s", hash, label)
	}
}

func TestResolveSourceQueryHashOverridesDefault(t *testing.T) {
	s := &Server{ReefcoreURL: "http://rc:4000", DefaultHash: strings.Repeat("a", 64)}
	override := strings.Repeat("b", 64)
	src, hash, _, err := s.resolveSource(req("/api/verdict?hash=" + override))
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if hash != override || !strings.Contains(src, override) {
		t.Errorf("override not honoured: %s", src)
	}
}

func TestResolveSourceRejectsBadHash(t *testing.T) {
	s := &Server{ReefcoreURL: "http://rc:4000"}
	for _, bad := range []string{"xyz", strings.Repeat("a", 63), strings.Repeat("g", 64), "../etc/passwd"} {
		if _, _, _, err := s.resolveSource(req("/api/verdict?hash=" + bad)); err == nil {
			t.Errorf("hash %q should be rejected", bad)
		}
	}
}

func TestResolveSourceBundlePathPrecedence(t *testing.T) {
	s := &Server{ReefcoreURL: "http://rc:4000", DefaultHash: strings.Repeat("a", 64)}
	src, _, label, err := s.resolveSource(req("/api/verdict?bundle=/tmp/b.cbor"))
	if err != nil || src != "/tmp/b.cbor" || label != "local file" {
		t.Fatalf("bundle path not honoured: src=%s label=%s err=%v", src, label, err)
	}
}

func TestResolveSourceMissingHashErrors(t *testing.T) {
	if _, _, _, err := (&Server{ReefcoreURL: "http://rc:4000"}).resolveSource(req("/api/verdict")); err == nil {
		t.Error("expected error when no hash and no default")
	}
	if _, _, _, err := (&Server{DefaultHash: strings.Repeat("a", 64)}).resolveSource(req("/api/verdict")); err == nil {
		t.Error("expected error when no reef-core URL configured")
	}
}

func TestHandleIndexServesEmbeddedPage(t *testing.T) {
	rr := httptest.NewRecorder()
	(&Server{}).Routes().ServeHTTP(rr, req("/"))
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d", rr.Code)
	}
	body := rr.Body.String()
	if !strings.Contains(body, "<title>") || !strings.Contains(body, "konareef") {
		t.Error("index did not serve the embedded verdict page")
	}
	if ct := rr.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/html") {
		t.Errorf("content-type = %s", ct)
	}
}

func TestHandleVerdictBadHashReturns400JSON(t *testing.T) {
	rr := httptest.NewRecorder()
	s := &Server{ReefcoreURL: "http://rc:4000"}
	s.Routes().ServeHTTP(rr, req("/api/verdict?hash=nothex"))
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rr.Code)
	}
	if !strings.Contains(rr.Body.String(), "error") {
		t.Errorf("expected JSON error body, got %s", rr.Body.String())
	}
}

// A live fetch failure must surface as a non-2xx JSON error — never a 200 with
// a green captured-proof verdict. This is the server-side contract the page's
// renderFailure() path depends on: the client only falls back to the sample on
// a non-JSON (offline) response, so a JSON {error} status must not read as ok.
func TestHandleVerdictFetchFailureReturns502NotGreen(t *testing.T) {
	rr := httptest.NewRecorder()
	// Valid 64-hex hash, but the reef-core host is unreachable (port 1 →
	// connection refused), so the live bundle fetch fails.
	s := &Server{ReefcoreURL: "http://127.0.0.1:1/"}
	h := strings.Repeat("a", 64)
	s.Routes().ServeHTTP(rr, req("/api/verdict?hash="+h))
	if rr.Code == http.StatusOK {
		t.Fatalf("live fetch failure returned 200 (would render a green verdict); body=%s", rr.Body.String())
	}
	if rr.Code != http.StatusBadGateway {
		t.Fatalf("status = %d, want 502", rr.Code)
	}
	body := rr.Body.String()
	if !strings.Contains(body, "error") {
		t.Errorf("expected JSON error body, got %s", body)
	}
	if strings.Contains(body, "\"ok\":true") {
		t.Errorf("error response must not contain a green ok=true verdict: %s", body)
	}
}

func TestUnknownPathIs404(t *testing.T) {
	rr := httptest.NewRecorder()
	(&Server{}).Routes().ServeHTTP(rr, req("/nope"))
	if rr.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404", rr.Code)
	}
}
