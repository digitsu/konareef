// Copyright 2026 Jerry David Chan, Konareef.ai
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestListAgents(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != "/api/agents" {
			t.Fatalf("unexpected request: %s %s", r.Method, r.URL.Path)
		}
		json.NewEncoder(w).Encode(AgentsResponse{
			Agents: []Agent{
				{ID: "a1", Name: "dolphin-01", Status: "running"},
			},
		})
	}))
	defer srv.Close()

	c := NewClient(srv.URL)
	agents, err := c.ListAgents()
	if err != nil {
		t.Fatalf("ListAgents: %v", err)
	}
	if len(agents) != 1 || agents[0].ID != "a1" {
		t.Fatalf("unexpected agents: %+v", agents)
	}
}

func TestSpawnAgentSendsBundleAndAuthHeader(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/api/agents" {
			t.Fatalf("unexpected request: %s %s", r.Method, r.URL.Path)
		}

		if auth := r.Header.Get("Authorization"); auth != "Bearer test-token-abc" {
			t.Fatalf("expected Bearer test-token-abc, got %q", auth)
		}

		var body SpawnRequest
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Fatalf("decode: %v", err)
		}
		if body.Task != "build a todo app" {
			t.Fatalf("unexpected task: %s", body.Task)
		}
		if body.PodKind != "lobster" {
			t.Fatalf("unexpected pod_kind: %s", body.PodKind)
		}
		if len(body.StructuredMemory) != 1 || body.StructuredMemory["projects/goals.md"] == "" {
			t.Fatalf("structured_memory not propagated: %+v", body.StructuredMemory)
		}

		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(SpawnResponse{
			AgentID:         "agent-1",
			PodID:           "pod-1",
			TaskID:          "task-1",
			SnapshotID:      "snap-1",
			BundleHash:      "dc7d90b43b93e9fb",
			BundleFileCount: 1,
		})
	}))
	defer srv.Close()

	c := NewClient(srv.URL).WithToken("test-token-abc")
	resp, err := c.SpawnAgent(SpawnRequest{
		Task:    "build a todo app",
		PodKind: "lobster",
		StructuredMemory: map[string]string{
			"projects/goals.md": "# Goals\nship v1",
		},
	})
	if err != nil {
		t.Fatalf("SpawnAgent: %v", err)
	}
	if resp.AgentID != "agent-1" || resp.TaskID != "task-1" || resp.BundleFileCount != 1 {
		t.Fatalf("unexpected spawn response: %+v", resp)
	}
}

func TestSpawnAgentRequiresToken(t *testing.T) {
	c := NewClient("http://ignored")
	_, err := c.SpawnAgent(SpawnRequest{Task: "anything"})
	if err == nil || !strings.Contains(err.Error(), "session token required") {
		t.Fatalf("expected session token required error, got %v", err)
	}
}

func TestKillAgent(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodDelete || r.URL.Path != "/api/agents/a1" {
			t.Fatalf("unexpected request: %s %s", r.Method, r.URL.Path)
		}
		if r.Header.Get("Authorization") != "Bearer tok" {
			t.Fatalf("missing auth header")
		}
		json.NewEncoder(w).Encode(map[string]string{"status": "killed"})
	}))
	defer srv.Close()

	c := NewClient(srv.URL).WithToken("tok")
	if err := c.KillAgent("a1"); err != nil {
		t.Fatalf("KillAgent: %v", err)
	}
}

func TestKillAgentNotFound(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		json.NewEncoder(w).Encode(APIError{Error: "not found"})
	}))
	defer srv.Close()

	c := NewClient(srv.URL).WithToken("tok")
	err := c.KillAgent("missing")
	if err == nil || !strings.Contains(err.Error(), "not found") {
		t.Fatalf("expected 'not found' error, got %v", err)
	}
}

func TestGetProofs(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != "/api/proofs" {
			t.Fatalf("unexpected request: %s %s", r.Method, r.URL.Path)
		}
		if r.URL.Query().Get("limit") != "10" {
			t.Fatalf("expected limit=10, got %s", r.URL.Query().Get("limit"))
		}
		json.NewEncoder(w).Encode(ProofsResponse{
			Proofs: []Proof{
				{
					ProofType:       "custody",
					Hash:            "abc123",
					PrevHash:        "def456",
					AgentID:         "a1",
					TaskID:          "t1",
					BroadcastStatus: "pending",
				},
			},
		})
	}))
	defer srv.Close()

	c := NewClient(srv.URL)
	proofs, err := c.GetProofs(10)
	if err != nil {
		t.Fatalf("GetProofs: %v", err)
	}
	if len(proofs) != 1 || proofs[0].Hash != "abc123" || proofs[0].ProofType != "custody" {
		t.Fatalf("unexpected proofs: %+v", proofs)
	}
}

func TestGetProofsByTaskFilter(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("task_id") != "task-abc" {
			t.Fatalf("expected task_id=task-abc, got %s", r.URL.Query().Get("task_id"))
		}
		json.NewEncoder(w).Encode(ProofsResponse{Proofs: []Proof{{TaskID: "task-abc"}}})
	}))
	defer srv.Close()

	c := NewClient(srv.URL)
	proofs, err := c.GetProofsByTask("task-abc")
	if err != nil {
		t.Fatalf("GetProofsByTask: %v", err)
	}
	if len(proofs) != 1 || proofs[0].TaskID != "task-abc" {
		t.Fatalf("unexpected proofs: %+v", proofs)
	}
}

func TestDownloadDeliverableEscapesPathSegments(t *testing.T) {
	body := []byte("payload-bytes")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		want := "/api/agents/agent-1/deliverables/output/weird%20name%3F.bin"
		if r.URL.RequestURI() != want {
			t.Fatalf("unexpected request URI: got %q want %q", r.URL.RequestURI(), want)
		}
		if r.URL.Path != "/api/agents/agent-1/deliverables/output/weird name?.bin" {
			t.Fatalf("unexpected decoded path: %q", r.URL.Path)
		}
		w.Write(body)
	}))
	defer srv.Close()

	c := NewClient(srv.URL).WithToken("tok")
	got, err := c.DownloadDeliverable("agent-1", "output/weird name?.bin")
	if err != nil {
		t.Fatalf("DownloadDeliverable: %v", err)
	}
	if string(got) != string(body) {
		t.Fatalf("unexpected body: got %q want %q", got, body)
	}
}

func TestEscapePathSegmentsPreservesSeparators(t *testing.T) {
	got := escapePathSegments("output/sub dir/weird?name.bin")
	want := "output/sub%20dir/weird%3Fname.bin"
	if got != want {
		t.Fatalf("escapePathSegments = %q, want %q", got, want)
	}
}
