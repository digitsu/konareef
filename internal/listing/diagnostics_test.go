// Copyright 2026 Jerry David Chan, Konareef.ai
// SPDX-License-Identifier: Apache-2.0

package listing

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/digitsu/konareef/internal/identity"
)

// serverEgressGateCodes is every refusal code the server's listing gates
// 5 and 6 can return. It is copied from the server's controller mapping
// (the atoms after author_fee_out_of_range), so a new server code shows
// up here as a missing diagnosis.
var serverEgressGateCodes = []string{
	"egress_undeclared",
	"egress_review_missing",
	"egress_review_pending",
	"egress_review_error",
	"egress_review_stale",
	"egress_review_flagged",
}

// Every gate 5/6 code has exactly one diagnosis, with a next step.
func TestDiagnoseCoversEveryEgressGateCode(t *testing.T) {
	for _, code := range serverEgressGateCodes {
		diagnosis, ok := Diagnose(code)
		if !ok {
			t.Errorf("no diagnosis for %s", code)
			continue
		}
		if diagnosis.Code != code || diagnosis.Summary == "" || diagnosis.NextStep == "" {
			t.Errorf("diagnosis for %s is incomplete: %+v", code, diagnosis)
		}
	}
}

// An unknown code — for example from a newer server — has no diagnosis,
// so the caller prints the raw code rather than a guess.
func TestDiagnoseUnknownCode(t *testing.T) {
	for _, code := range []string{"", "egress_review_quarantined", "execution_class_mismatch"} {
		if _, ok := Diagnose(code); ok {
			t.Errorf("Diagnose(%q) returned a diagnosis", code)
		}
	}
}

// The report names the revision the server gated: its version and a
// pod_hash prefix. It warns when the local manifest names another
// version, since the server gates the latest published revision only.
func TestRefusalReportNamesRevision(t *testing.T) {
	latest := &PublishedRevision{PodVersion: "1.2.0", PodHashHex: strings.Repeat("ab", 32)}
	report := RefusalReport("egress_review_flagged", latest, "1.3.0", nil)
	for _, want := range []string{
		"egress_review_flagged",
		"version 1.2.0",
		"pod_hash " + strings.Repeat("ab", 6),
		"1.3.0",
	} {
		if !strings.Contains(report, want) {
			t.Errorf("report does not contain %q:\n%s", want, report)
		}
	}
	if strings.Contains(report, strings.Repeat("ab", 32)) {
		t.Errorf("report prints the full pod_hash; a prefix is enough:\n%s", report)
	}
}

// When the lookup failed the report says so and still gives the next
// step; it never invents a version.
func TestRefusalReportWithoutRevision(t *testing.T) {
	report := RefusalReport("egress_undeclared", nil, "0.1.0", errors.New("GET failed"))
	if !strings.Contains(report, "not available") || !strings.Contains(report, "[network]") {
		t.Errorf("report:\n%s", report)
	}
}

// The listing API does not report whether gates 5 and 6 are enforced or
// only reported, so no message may claim either. A refusal is described
// as a refusal, which is the only fact the response carries.
func TestRefusalReportNeverClaimsEnforcementMode(t *testing.T) {
	for _, code := range serverEgressGateCodes {
		report := strings.ToLower(RefusalReport(code, nil, "", nil))
		for _, word := range []string{"enforced", "enforcement", "report mode", ":report"} {
			if strings.Contains(report, word) {
				t.Errorf("%s report claims a gate mode (%q):\n%s", code, word, report)
			}
		}
	}
}

// Submit returns a typed refusal for a server error code, so the CLI can
// branch on the code. The error text is unchanged for older callers.
func TestSubmitReturnsRefusalError(t *testing.T) {
	id, err := identity.Generate("alice")
	if err != nil {
		t.Fatalf("identity: %v", err)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"error":"egress_review_pending"}`))
	}))
	defer srv.Close()

	_, err = Submit(srv.URL, validListing(), id)
	var refusal *RefusalError
	if !errors.As(err, &refusal) {
		t.Fatalf("error %v is not a *RefusalError", err)
	}
	if refusal.Code != "egress_review_pending" || refusal.Status != http.StatusBadRequest {
		t.Errorf("refusal = %+v", refusal)
	}
	if !strings.Contains(err.Error(), "status 400: egress_review_pending") {
		t.Errorf("error text changed: %v", err)
	}
}

// LatestRevision reads pod_version and pod_hash from the public lookup.
func TestLatestRevision(t *testing.T) {
	hash := strings.Repeat("0f", 32)
	var gotPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		_, _ = w.Write([]byte(`{"handle":"alice","pod_name":"research-bot","pod_version":"2.0.1","pod_hash":"` + hash + `"}`))
	}))
	defer srv.Close()

	revision, err := LatestRevision(srv.URL, "alice", "research-bot")
	if err != nil {
		t.Fatalf("LatestRevision: %v", err)
	}
	if gotPath != "/api/pods/alice/research-bot/latest" {
		t.Errorf("path = %q", gotPath)
	}
	if revision.PodVersion != "2.0.1" || revision.PodHashHex != hash {
		t.Errorf("revision = %+v", revision)
	}
}

// A lookup that fails, or answers with a malformed hash, is an error and
// not a revision.
func TestLatestRevisionFailures(t *testing.T) {
	for name, handler := range map[string]http.HandlerFunc{
		"404": func(w http.ResponseWriter, r *http.Request) { http.NotFound(w, r) },
		"bad hash": func(w http.ResponseWriter, r *http.Request) {
			_, _ = w.Write([]byte(`{"pod_version":"1.0.0","pod_hash":"xyz"}`))
		},
		"no version": func(w http.ResponseWriter, r *http.Request) {
			_, _ = w.Write([]byte(`{"pod_hash":"` + strings.Repeat("00", 32) + `"}`))
		},
		"escape in version": func(w http.ResponseWriter, r *http.Request) {
			_, _ = w.Write([]byte(`{"pod_version":"1.0\u001b[2J","pod_hash":"` + strings.Repeat("00", 32) + `"}`))
		},
		"over-long version": func(w http.ResponseWriter, r *http.Request) {
			_, _ = w.Write([]byte(`{"pod_version":"` + strings.Repeat("9", 200) + `","pod_hash":"` + strings.Repeat("00", 32) + `"}`))
		},
	} {
		t.Run(name, func(t *testing.T) {
			srv := httptest.NewServer(handler)
			defer srv.Close()
			if revision, err := LatestRevision(srv.URL, "alice", "research-bot"); err == nil {
				t.Fatalf("LatestRevision = %+v, want an error", revision)
			}
		})
	}
}

// The lookup follows a redirect only to the same origin. It sends no
// credential, but a server must not be able to point the CLI at an
// arbitrary host and have its answer printed as the checked revision.
func TestLatestRevisionRefusesCrossOriginRedirect(t *testing.T) {
	other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"pod_version":"6.6.6","pod_hash":"` + strings.Repeat("00", 32) + `"}`))
	}))
	defer other.Close()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, other.URL+r.URL.Path, http.StatusFound)
	}))
	defer srv.Close()

	if revision, err := LatestRevision(srv.URL, "alice", "research-bot"); err == nil {
		t.Fatalf("LatestRevision followed a cross-origin redirect: %+v", revision)
	}
}
