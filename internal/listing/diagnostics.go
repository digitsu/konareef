// Copyright 2026 Jerry David Chan, Konareef.ai
// SPDX-License-Identifier: Apache-2.0

// diagnostics.go — author guidance for a listing the server refused.
//
// A listing server can refuse a listing at two egress gates. Gate 5
// requires the latest published revision to declare its egress (any
// [network] table). Gate 6 requires a current server egress review of
// that revision that is clean, or flagged and approved by an operator.
// Each refusal has its own code. This file maps each code to one message
// and one next step, and names the revision the server checked.
//
// Two rules keep the messages honest:
//
//   - The listing response carries a refusal code and nothing else about
//     review. It does not say whether the gates are in force or only
//     logged, so no message here states or implies either. A success says
//     nothing about review.
//   - An unknown code, for example from a newer server, has no
//     diagnosis. The caller prints the raw code.
//
// Contents: Diagnosis and Diagnose (code → guidance), PublishedRevision and
// LatestRevision (the public lookup of the latest published revision),
// and RefusalReport (the text the CLI prints).
package listing

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
	"unicode"

	"github.com/digitsu/konareef/internal/serverurl"
)

// Diagnosis is the author guidance for one server refusal code.
type Diagnosis struct {
	Code     string // the server's code, verbatim
	Gate     string // which check refused: "egress declaration" or "egress review"
	Summary  string // what the server found, in one sentence
	NextStep string // what the author can do about it
}

// reviewLimit is appended to every egress review message. A review reads
// the pod's text; it is not a proof of what the pod reaches at run time.
const reviewLimit = "A server egress review reads the pod's own text. It is not proof of which hosts the pod reaches at run time."

// diagnoses maps each gate 5/6 refusal code to its guidance.
var diagnoses = map[string]Diagnosis{
	"egress_undeclared": {
		Gate:    "egress declaration",
		Summary: "the latest published revision has no [network] table, so it does not declare its egress.",
		NextStep: "add a [network] table to pod.toml (`[network]` with `egress = []` declares a pod that " +
			"reaches no host), publish a new version, then list again.",
	},
	"egress_review_missing": {
		Gate:    "egress review",
		Summary: "the server has no egress review of the latest published revision.",
		NextStep: "a review is written after each publish; retry the listing later. " +
			"If this persists, ask the server operator to run the review for this revision.",
	},
	"egress_review_pending": {
		Gate:     "egress review",
		Summary:  "the egress review of the latest published revision has not finished.",
		NextStep: "retry the listing when the review completes.",
	},
	"egress_review_error": {
		Gate: "egress review",
		Summary: "the egress review of the latest published revision could not complete " +
			"(for example, a declared context source could not be read, or a scan limit was reached).",
		NextStep: "run `konareef pod safety <pod-dir>` and `konareef pod validate <pod-dir>`, fix what they " +
			"report, and publish a new version. The server operator can see the review's error code.",
	},
	"egress_review_stale": {
		Gate: "egress review",
		Summary: "the server's egress review of the latest published revision was made by an older " +
			"scanner version and no longer counts.",
		NextStep: "nothing in the pod needs to change for this; ask the server operator to review the " +
			"revision again, then retry the listing.",
	},
	"egress_review_flagged": {
		Gate: "egress review",
		Summary: "the egress review of the latest published revision has findings (an undeclared host, " +
			"a wildcard, an IP-literal host or a non-TLS port) and no operator has approved it.",
		NextStep: "run `konareef pod safety <pod-dir>` and `konareef pod validate <pod-dir>` to see the " +
			"findings in your copy; fix them and publish a new version, or ask the server operator to " +
			"review and approve this revision.",
	},
}

// Diagnose returns the guidance for a server refusal code. Input: the
// code from the server's {"error": "<code>"} body. Output: the diagnosis
// and true for a known egress gate code; false for any other code.
func Diagnose(code string) (Diagnosis, bool) {
	diagnosis, ok := diagnoses[code]
	if !ok {
		return Diagnosis{}, false
	}
	diagnosis.Code = code
	return diagnosis, true
}

// PublishedRevision identifies one published revision of a pod.
type PublishedRevision struct {
	PodVersion string // the version string the publisher gave it
	PodHashHex string // the 64-character lowercase hex pod_hash
}

// hashPrefixLength is how many hex characters of pod_hash a report shows:
// enough to tell revisions apart, short enough to read.
const hashPrefixLength = 12

// maxLookupBytes bounds the lookup response. It carries the manifest and,
// for an open pod, the content tarball; only two short fields are read,
// so a response larger than this is refused rather than read in full.
const maxLookupBytes = 16 << 20

// lookupClient bounds the lookup, which is best effort: a slow or failing
// lookup must not hold the CLI after the listing is already refused. It
// follows a redirect only to the same scheme and host, so a server cannot
// send the CLI to another host and have that host's answer printed as the
// revision it checked.
var lookupClient = &http.Client{
	Timeout: 15 * time.Second,
	CheckRedirect: func(req *http.Request, via []*http.Request) error {
		if len(via) >= 5 {
			return errors.New("too many redirects")
		}
		first := via[0].URL
		if req.URL.Scheme != first.Scheme || req.URL.Host != first.Host {
			return fmt.Errorf("refusing a redirect to another origin (%s://%s)", req.URL.Scheme, req.URL.Host)
		}
		return nil
	},
}

// maxVersionBytes bounds the pod_version the CLI prints. A version is
// printed to the author's terminal, so a value from the server with a
// control character (an escape sequence) or of unbounded length is
// refused.
const maxVersionBytes = 128

// LatestRevision fetches the latest published revision of handle/podName
// from the public `GET /api/pods/<handle>/<pod>/latest` lookup. It sends
// no credential. Input: the server base URL, the handle and the pod name.
// Output: the revision, or an error for any failure — a non-2xx status,
// an oversized or malformed body, a missing, over-long or control-bearing
// version, a pod_hash that is not 32 bytes of lowercase hex, or a
// redirect to another origin.
func LatestRevision(serverURL, handle, podName string) (*PublishedRevision, error) {
	endpoint, err := serverurl.Endpoint(serverURL, "api", "pods", handle, podName, "latest")
	if err != nil {
		return nil, err
	}
	resp, err := lookupClient.Get(endpoint)
	if err != nil {
		return nil, fmt.Errorf("GET %s: %w", endpoint, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("GET %s: status %d", endpoint, resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxLookupBytes+1))
	if err != nil {
		return nil, fmt.Errorf("GET %s: %w", endpoint, err)
	}
	if len(body) > maxLookupBytes {
		return nil, fmt.Errorf("GET %s: response larger than %d bytes", endpoint, maxLookupBytes)
	}
	var wire struct {
		PodVersion string `json:"pod_version"`
		PodHash    string `json:"pod_hash"`
	}
	if err := json.Unmarshal(body, &wire); err != nil {
		return nil, fmt.Errorf("parse lookup response: %w", err)
	}
	if wire.PodVersion == "" {
		return nil, errors.New("lookup response has no pod_version")
	}
	if len(wire.PodVersion) > maxVersionBytes ||
		strings.IndexFunc(wire.PodVersion, unicode.IsControl) >= 0 {
		return nil, errors.New("lookup response has a pod_version this CLI will not print")
	}
	if raw, err := hex.DecodeString(wire.PodHash); err != nil || len(raw) != 32 ||
		wire.PodHash != strings.ToLower(wire.PodHash) {
		return nil, errors.New("lookup response has no valid pod_hash")
	}
	return &PublishedRevision{PodVersion: wire.PodVersion, PodHashHex: wire.PodHash}, nil
}

// RefusalReport renders the guidance for a known egress gate code.
//
// The revision it names is the latest one at lookup time, which is the
// one the server checked unless the author published again in between.
//
// Inputs: code — the server's refusal code; latest — the latest
// published revision, or nil when the lookup failed; localVersion — the
// version in the local pod.toml, or ""; lookupErr — why latest is nil,
// or nil. Output: multi-line text, without a trailing newline. For a code
// Diagnose does not know, the report is the raw code alone.
func RefusalReport(code string, latest *PublishedRevision, localVersion string, lookupErr error) string {
	diagnosis, ok := Diagnose(code)
	if !ok {
		return "server refusal code: " + code
	}
	var lines []string
	lines = append(lines, fmt.Sprintf("The server refused the listing at its %s check (%s): %s",
		diagnosis.Gate, diagnosis.Code, diagnosis.Summary))
	switch {
	case latest != nil:
		prefix := latest.PodHashHex
		if len(prefix) > hashPrefixLength {
			prefix = prefix[:hashPrefixLength]
		}
		lines = append(lines, fmt.Sprintf("  Latest published revision now: version %s, pod_hash %s…", latest.PodVersion, prefix))
		if localVersion != "" && localVersion != latest.PodVersion {
			lines = append(lines, fmt.Sprintf(
				"  Your local pod.toml says version %s. The server checks only the latest published "+
					"revision; publish %s first if that is the one you meant to list.", localVersion, localVersion))
		}
	default:
		reason := "unknown error"
		if lookupErr != nil {
			reason = lookupErr.Error()
		}
		lines = append(lines, "  Latest published revision: not available ("+reason+"). "+
			"The server checks the latest published revision.")
	}
	lines = append(lines, "  Next step: "+diagnosis.NextStep)
	if diagnosis.Gate == "egress review" {
		lines = append(lines, "  "+reviewLimit)
	}
	return strings.Join(lines, "\n")
}
