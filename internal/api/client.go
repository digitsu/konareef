// Package api provides an HTTP client for the reef-core REST API.
//
// # Authentication
//
// Most endpoints that mutate state (spawn, kill, send_task) require an
// Authorization: Bearer <base64-session-token> header. The session token
// is a 32-byte secret base64-encoded. Get one in dev via:
//
//	cd reef-core && mix reef_core.dev_session -q
//
// Production auth is not yet wired (reef-core's :require_session_token
// plug is currently the only gate). Real OAuth/passkey will layer on top.
package api

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Client talks to a reef-core instance over HTTP.
//
// Set SessionToken to the base64-encoded session token to authenticate
// mutating requests. Leaving it empty is fine for read-only calls (list
// agents, get budget, get proofs).
type Client struct {
	BaseURL      string
	SessionToken string
	HTTPClient   *http.Client
}

// NewClient creates a Client pointing at the given reef-core base URL.
func NewClient(baseURL string) *Client {
	return &Client{
		BaseURL:    baseURL,
		HTTPClient: &http.Client{Timeout: 30 * time.Second},
	}
}

// WithToken returns a copy of the client with the given session token set.
func (c *Client) WithToken(token string) *Client {
	cp := *c
	cp.SessionToken = token
	return &cp
}

// ── Agents ──────────────────────────────────────────────────────────

// ListAgents returns all agents in the pod.
func (c *Client) ListAgents() ([]Agent, error) {
	var out AgentsResponse
	if err := c.doJSON("GET", "/api/agents", nil, &out); err != nil {
		return nil, fmt.Errorf("list agents: %w", err)
	}
	return out.Agents, nil
}

// SpawnAgent creates a new pod with the given task and returns the full
// spawn response (all five IDs + bundle metadata).
//
// Requires a session token.
func (c *Client) SpawnAgent(req SpawnRequest) (*SpawnResponse, error) {
	if c.SessionToken == "" {
		return nil, fmt.Errorf("spawn agent: session token required")
	}
	var out SpawnResponse
	if err := c.doJSON("POST", "/api/agents", req, &out); err != nil {
		return nil, fmt.Errorf("spawn agent: %w", err)
	}
	return &out, nil
}

// KillAgent stops and removes an agent by ID.
//
// Requires a session token.
func (c *Client) KillAgent(id string) error {
	if c.SessionToken == "" {
		return fmt.Errorf("kill agent: session token required")
	}
	return c.doJSON("DELETE", "/api/agents/"+id, nil, nil)
}

// SendTask dispatches a task string to a running agent.
//
// NOTE: with the current one-shot spawn model, a pod's task is set at
// spawn time and the runtime exits after it completes. This endpoint
// remains for future long-running dolphin pods that can accept additional
// tasks; for lobster pods in v1 it is rarely useful.
//
// Requires a session token.
func (c *Client) SendTask(id, task string) error {
	if c.SessionToken == "" {
		return fmt.Errorf("send task: session token required")
	}
	body := map[string]string{"task": task}
	return c.doJSON("POST", "/api/agents/"+id+"/task", body, nil)
}

// GetEventLog returns the buffered event log for an agent. Events are
// in chronological order (oldest first), up to 200 entries.
func (c *Client) GetEventLog(agentID string) ([]AgentEvent, error) {
	path := "/api/agents/" + agentID + "/log"
	var out EventLogResponse
	if err := c.doJSON("GET", path, nil, &out); err != nil {
		return nil, fmt.Errorf("get event log: %w", err)
	}
	return out.Events, nil
}

// ── Budget ──────────────────────────────────────────────────────────

// GetBudget returns the pod-wide budget summary.
func (c *Client) GetBudget() (*Budget, error) {
	var out Budget
	if err := c.doJSON("GET", "/api/budget", nil, &out); err != nil {
		return nil, fmt.Errorf("get budget: %w", err)
	}
	return &out, nil
}

// ── Proofs ──────────────────────────────────────────────────────────

// GetProofs returns the most recent proof commitments, up to limit.
func (c *Client) GetProofs(limit int) ([]Proof, error) {
	path := fmt.Sprintf("/api/proofs?limit=%d", limit)
	var out ProofsResponse
	if err := c.doJSON("GET", path, nil, &out); err != nil {
		return nil, fmt.Errorf("get proofs: %w", err)
	}
	return out.Proofs, nil
}

// GetProofsByTask returns the chain of proof commitments for a specific
// task. For a completed task this will be the full 4-link custody chain:
// structured_bundle → openbrain_snapshot → [capture_commitment] → custody.
//
// Note: the structured_bundle and openbrain_snapshot proofs are tagged
// with agent_id (not task_id) because they're emitted at spawn time
// before the task exists. GetProofsByTask only returns the task-scoped
// links (capture_commitment + custody). Use GetProofsByAgent to walk
// the whole chain.
func (c *Client) GetProofsByTask(taskID string) ([]Proof, error) {
	path := fmt.Sprintf("/api/proofs?limit=100&task_id=%s", taskID)
	var out ProofsResponse
	if err := c.doJSON("GET", path, nil, &out); err != nil {
		return nil, fmt.Errorf("get proofs by task: %w", err)
	}
	return out.Proofs, nil
}

// GetProofsByAgent returns all proof commitments for a specific agent,
// including the spawn-time links (structured_bundle, openbrain_snapshot)
// that don't carry a task_id.
func (c *Client) GetProofsByAgent(agentID string) ([]Proof, error) {
	path := fmt.Sprintf("/api/proofs?limit=100&agent_id=%s", agentID)
	var out ProofsResponse
	if err := c.doJSON("GET", path, nil, &out); err != nil {
		return nil, fmt.Errorf("get proofs by agent: %w", err)
	}
	return out.Proofs, nil
}

// ── Memory ──────────────────────────────────────────────────────────

// ListMemoryEntries returns Layer 1 / Layer 2 knowledge entries from
// reef-core's knowledge store, filtered by the optional fields in the
// MemoryFilter argument. Empty fields are omitted from the query string.
//
// Used by the lifecycle smoke (--memory-roundtrip) to verify that
// structural extraction actually persisted entries after agent_exited.
func (c *Client) ListMemoryEntries(filter MemoryFilter) ([]MemoryEntry, error) {
	var queryParts []string
	if filter.PodRunID != "" {
		queryParts = append(queryParts, "pod_run_id="+url.QueryEscape(filter.PodRunID))
	}
	if filter.Project != "" {
		queryParts = append(queryParts, "project="+url.QueryEscape(filter.Project))
	}
	if filter.Layer != "" {
		queryParts = append(queryParts, "layer="+url.QueryEscape(filter.Layer))
	}
	if filter.Limit > 0 {
		queryParts = append(queryParts, fmt.Sprintf("limit=%d", filter.Limit))
	}

	path := "/api/memory/entries"
	if len(queryParts) > 0 {
		path += "?" + strings.Join(queryParts, "&")
	}

	var resp MemoryEntriesResponse
	if err := c.doJSON("GET", path, nil, &resp); err != nil {
		return nil, fmt.Errorf("list memory entries: %w", err)
	}
	return resp.Entries, nil
}

// ── HTTP plumbing ────────────────────────────────────────────────────

// doJSON issues an HTTP request, setting Authorization if a token is
// present, and decodes a JSON response into `out` when out != nil.
// A 4xx/5xx response is parsed as an APIError.
func (c *Client) doJSON(method, path string, body, out any) error {
	var reader io.Reader
	if body != nil {
		buf, err := json.Marshal(body)
		if err != nil {
			return fmt.Errorf("marshal: %w", err)
		}
		reader = bytes.NewReader(buf)
	}

	req, err := http.NewRequest(method, c.BaseURL+path, reader)
	if err != nil {
		return fmt.Errorf("new request: %w", err)
	}

	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	if c.SessionToken != "" {
		req.Header.Set("Authorization", "Bearer "+c.SessionToken)
	}

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return fmt.Errorf("http: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		var apiErr APIError
		if err := json.NewDecoder(resp.Body).Decode(&apiErr); err == nil && apiErr.Error != "" {
			return fmt.Errorf("http %d: %s", resp.StatusCode, apiErr.Error)
		}
		return fmt.Errorf("http %d", resp.StatusCode)
	}

	if out == nil {
		return nil
	}

	if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
		return fmt.Errorf("decode: %w", err)
	}
	return nil
}
