// load.go — read a konareef-bundle/v1 document from a file path or
// an HTTP(S) URL, parse it, and gate on the version header. The
// cryptographic re-checks happen in verify.go; Load is just the I/O
// + format gate, kept separate so the CLI can `--dry-run` a parse
// before doing the expensive re-hashing.

package verify

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
)

// BundleVersion is the only version tag this verifier accepts. A v2
// bundle would ship alongside v1 with its own verifier; for now any
// other header is a fatal mismatch.
const BundleVersion = "konareef-bundle/v1"

// Load reads pathOrURL — either an http(s) URL or a filesystem path
// — and returns the parsed Bundle. Failure modes:
//
//   - I/O error reading the file or making the HTTP request.
//   - Non-2xx HTTP status.
//   - Malformed JSON.
//   - Bundle version != BundleVersion.
//
// Load does NOT verify the bundle cryptographically. Call Verify on
// the returned *Bundle to do that.
func Load(pathOrURL string) (*Bundle, error) {
	body, err := readSource(pathOrURL)
	if err != nil {
		return nil, err
	}
	return LoadFromBytes(body)
}

// LoadFromBytes parses already-fetched raw bytes as a konareef-bundle/v1
// JSON document and applies the same version gate as Load. It performs NO
// I/O — the caller is responsible for fetching the bytes (exactly once).
//
// This is the bytes-based core shared with Load so a caller that has
// already read the source (e.g. the CLI peeking the first byte to route
// between the v2 CBOR verifier and the v1 JSON loader) can parse the SAME
// bytes WITHOUT re-fetching the URL. Re-fetching a single-use / expiring /
// mutable URL can fail or return different bytes than were format-peeked.
//
// Failure modes: malformed JSON; bundle version != BundleVersion. The
// output, error wording, and version gating match Load exactly.
func LoadFromBytes(body []byte) (*Bundle, error) {
	var b Bundle
	if err := json.Unmarshal(body, &b); err != nil {
		return nil, fmt.Errorf("parse bundle JSON: %w", err)
	}
	if b.Version != BundleVersion {
		return nil, fmt.Errorf(
			"unsupported bundle version %q (this verifier handles %q only)",
			b.Version, BundleVersion,
		)
	}
	return &b, nil
}

// ReadSource fetches pathOrURL as raw bytes, dispatching on whether the
// argument looks like an HTTP(S) URL or a local filesystem path. It performs
// NO format parsing or version gating — it is the shared byte-source used by
// the CLI to peek the first byte and route between the v2 CBOR verifier and
// the legacy v1 JSON loader BEFORE committing to a format. v1 callers should
// continue to use Load (which re-fetches and parses); v2 callers feed the
// returned bytes to VerifyV2Production.
//
// Inputs:
//   - pathOrURL: an http(s) URL or a local path.
//
// Returns the raw body bytes, or an I/O / HTTP-status error.
func ReadSource(pathOrURL string) ([]byte, error) {
	return readSource(pathOrURL)
}

// readSource fetches pathOrURL as bytes, dispatching on whether the
// argument looks like an HTTP(S) URL or a local path.
func readSource(pathOrURL string) ([]byte, error) {
	if strings.HasPrefix(pathOrURL, "http://") || strings.HasPrefix(pathOrURL, "https://") {
		return readHTTP(pathOrURL)
	}
	return os.ReadFile(pathOrURL)
}

func readHTTP(url string) ([]byte, error) {
	resp, err := http.Get(url)
	if err != nil {
		return nil, fmt.Errorf("GET %s: %w", url, err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("GET %s: status %d: %s",
			url, resp.StatusCode, strings.TrimSpace(string(body)))
	}
	return body, nil
}
