// Copyright 2026 Jerry David Chan, Konareef.ai
// SPDX-License-Identifier: Apache-2.0

package run

// Tests for the run_outcome check in collectRun (reef-core#98): a failed
// run that settled LLM calls has a custody proof too, so a custody proof
// alone must not be reported as a completed run. A custody proof with no
// readable run_outcome beside it fails closed for the same reason.

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/digitsu/konareef/internal/api"
)

// outcomeProof builds a run_outcome proof row with the given run_status.
func outcomeProof(status string) api.Proof {
	return api.Proof{
		ProofType: "run_outcome",
		Hash:      "outcomehash",
		Data:      `RUN_OUTCOME: v1` + "\n" + `{"deliverable_states":[],"exit_code":1,"run_status":"` + status + `","stop_reason":"runtime_error"}`,
	}
}

// proofServer serves the given proofs at /api/proofs and an empty
// deliverable list. It records whether the deliverables were listed.
func proofServer(t *testing.T, proofs []api.Proof, listed *bool) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/api/proofs":
			json.NewEncoder(w).Encode(api.ProofsResponse{Proofs: proofs})
		case r.Method == http.MethodGet && r.URL.Path == "/api/agents/agent-1/deliverables":
			*listed = true
			json.NewEncoder(w).Encode(api.DeliverablesResponse{})
		default:
			t.Fatalf("unexpected request: %s %s", r.Method, r.URL.Path)
		}
	}))
}

func collect(t *testing.T, srv *httptest.Server) error {
	t.Helper()
	client := api.NewClient(srv.URL).WithToken("tok")
	return collectRun(context.Background(), client, "agent-1", Config{
		BaseURL: srv.URL, OutDir: t.TempDir(), Timeout: time.Second, PollInterval: 10 * time.Millisecond,
	})
}

func TestCollectRunFailedOutcomeWithCustodyIsAnError(t *testing.T) {
	listed := false
	srv := proofServer(t, []api.Proof{outcomeProof("failed"), {ProofType: "custody", Hash: "custodyhash"}}, &listed)
	defer srv.Close()

	err := collect(t, srv)
	if !errors.Is(err, ErrRunFailed) {
		t.Fatalf("want ErrRunFailed, got %v", err)
	}
	if !strings.Contains(err.Error(), `"failed"`) || !strings.Contains(err.Error(), "custodyhash") {
		t.Fatalf("error should name the outcome and the custody proof: %v", err)
	}
	if listed {
		t.Fatal("deliverables were listed for a failed run")
	}
}

func TestCollectRunCompletedOutcomeSucceeds(t *testing.T) {
	listed := false
	srv := proofServer(t, []api.Proof{outcomeProof("completed"), {ProofType: "custody", Hash: "h"}}, &listed)
	defer srv.Close()

	if err := collect(t, srv); err != nil {
		t.Fatalf("collectRun: %v", err)
	}
	if !listed {
		t.Fatal("deliverables were not listed for a completed run")
	}
}

// A custody proof with no run_outcome beside it fails closed (Hermes
// re-review of !161): the CLI cannot tell a completed run from a failed
// one, so it must not list deliverables.
func TestCollectRunWithoutOutcomeFailsClosed(t *testing.T) {
	listed := false
	srv := proofServer(t, []api.Proof{{ProofType: "custody", Hash: "custodyhash"}}, &listed)
	defer srv.Close()

	err := collect(t, srv)
	if !errors.Is(err, ErrRunOutcomeMissing) {
		t.Fatalf("want ErrRunOutcomeMissing, got %v", err)
	}
	if !strings.Contains(err.Error(), "no run_outcome") || !strings.Contains(err.Error(), "custodyhash") {
		t.Fatalf("error should say the outcome is missing and name the custody proof: %v", err)
	}
	if listed {
		t.Fatal("deliverables were listed with no run_outcome")
	}
}

// An unreadable run_outcome fails closed the same way, and is not
// reported as a failed run: the status is unknown, not "failed".
func TestCollectRunUnreadableOutcomeFailsClosed(t *testing.T) {
	listed := false
	srv := proofServer(t, []api.Proof{
		{ProofType: "run_outcome", Hash: "outcomehash", Data: "RUN_OUTCOME: v2\n{}"},
		{ProofType: "custody", Hash: "custodyhash"},
	}, &listed)
	defer srv.Close()

	err := collect(t, srv)
	if !errors.Is(err, ErrRunOutcomeMissing) || errors.Is(err, ErrRunFailed) {
		t.Fatalf("want ErrRunOutcomeMissing and not ErrRunFailed, got %v", err)
	}
	if !strings.Contains(err.Error(), "not readable") || !strings.Contains(err.Error(), "custodyhash") {
		t.Fatalf("error should say the outcome is unreadable and name the custody proof: %v", err)
	}
	if listed {
		t.Fatal("deliverables were listed with an unreadable run_outcome")
	}
}

func TestRunOutcomeStatus(t *testing.T) {
	cases := []struct {
		name   string
		proofs []api.Proof
		want   string
	}{
		{"none", []api.Proof{{ProofType: "custody"}}, ""},
		{"completed", []api.Proof{outcomeProof("completed")}, "completed"},
		{"failed", []api.Proof{outcomeProof("failed")}, "failed"},
		{"wrong version", []api.Proof{{ProofType: "run_outcome", Data: "RUN_OUTCOME: v2\n{}"}}, "unreadable"},
		{"bad json", []api.Proof{{ProofType: "run_outcome", Data: "RUN_OUTCOME: v1\n{"}}, "unreadable"},
		{"no status", []api.Proof{{ProofType: "run_outcome", Data: "RUN_OUTCOME: v1\n{}"}}, "unreadable"},
	}
	for _, c := range cases {
		if got := runOutcomeStatus(c.proofs); got != c.want {
			t.Errorf("%s: got %q, want %q", c.name, got, c.want)
		}
	}
}
