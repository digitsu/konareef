// Package api provides an HTTP client for the reef-core REST API.
package api

// Agent is a summary row returned by GET /api/agents.
//
// This shape is loose — reef-core's list endpoint is still a dev/debug
// view and its fields may evolve. Only ID and Name are stable.
type Agent struct {
	ID           string `json:"id"`
	Name         string `json:"name"`
	Status       string `json:"status"`
	StartedAt    string `json:"started_at,omitempty"`
	LastActivity string `json:"last_activity,omitempty"`
}

// Budget is the pod-wide budget summary from GET /api/budget.
type Budget struct {
	TotalBudget int64            `json:"total_budget"`
	TotalSpent  int64            `json:"total_spent"`
	Remaining   int64            `json:"remaining"`
	Utilization float64          `json:"utilization"`
	AgentSpend  map[string]int64 `json:"agent_spend"`
}

// Proof is a proof commitment row from GET /api/proofs.
//
// Matches reef-core's v3 custody chain shape emitted by
// ReefCoreWeb.ProofController.serialize/1.
type Proof struct {
	ID              string `json:"id"`
	ProofType       string `json:"proof_type"`
	Hash            string `json:"hash"`
	PrevHash        string `json:"prev_hash"`
	Data            string `json:"data"`
	Timestamp       string `json:"timestamp"`
	Txid            string `json:"txid"`
	BroadcastStatus string `json:"broadcast_status"`
	AgentID         string `json:"agent_id"`
	TaskID          string `json:"task_id"`
	InsertedAt      string `json:"inserted_at"`
}

// SpawnRequest is the JSON body for POST /api/agents.
//
// Requires a valid session token in the Authorization header.
type SpawnRequest struct {
	Task             string            `json:"task"`
	PodKind          string            `json:"pod_kind,omitempty"`
	Model            string            `json:"model,omitempty"`
	BudgetSats       int64             `json:"budget_sats,omitempty"`
	MaxIterations    int               `json:"max_iterations,omitempty"`
	StructuredMemory map[string]string `json:"structured_memory,omitempty"`

	// PodAttestation, when non-nil, carries the publisher signing
	// metadata for a cached signed pod. reef-core's spawn flow
	// populates the resulting structured_bundle commitment's
	// pod_hash, pod_version, publisher_id, publisher_signature
	// columns so the custody chain can be tied back to a signed
	// manifest. Absence is the v0 unsigned-spawn path. See
	// prd-p0-3-spawn-attestation-wiring.md §"Required request shape".
	PodAttestation *PodAttestation `json:"pod_attestation,omitempty"`
}

// PodAttestation is the wire shape reef-core's spawn endpoint
// expects. Binary fields ride as: pod_hash → 64-char lowercase
// hex; publisher_signature, publisher_pubkey → standard base64.
//
// All five fields are required when PodAttestation is non-nil;
// reef-core's AttestationParser returns 422 with
// `pod_attestation_invalid` + the offending field name on any
// missing or malformed subfield.
type PodAttestation struct {
	PodHash            string `json:"pod_hash"`
	PodVersion         string `json:"pod_version"`
	PublisherID        string `json:"publisher_id"`
	PublisherSignature string `json:"publisher_signature"`
	PublisherPubkey    string `json:"publisher_pubkey"`
}

// SpawnResponse is the response body from POST /api/agents.
//
// All five IDs are returned so the caller can audit and verify the
// resulting proof chain afterwards.
type SpawnResponse struct {
	AgentID         string `json:"agent_id"`
	PodID           string `json:"pod_id"`
	TaskID          string `json:"task_id"`
	SnapshotID      string `json:"snapshot_id"`
	BundleHash      string `json:"bundle_hash"`
	BundleFileCount int    `json:"bundle_file_count"`
}

// AgentsResponse wraps GET /api/agents.
type AgentsResponse struct {
	Agents []Agent `json:"agents"`
}

// ProofsResponse wraps GET /api/proofs.
type ProofsResponse struct {
	Proofs []Proof `json:"proofs"`
}

// AgentEvent is a single event from an agent's buffered log.
type AgentEvent struct {
	Event   string         `json:"event"`
	Payload map[string]any `json:"payload"`
	At      string         `json:"at"`
}

// EventLogResponse wraps GET /api/agents/:id/log.
type EventLogResponse struct {
	Events []AgentEvent `json:"events"`
}

// MemoryEntry is a single Layer 1 / Layer 2 knowledge entry returned by
// reef-core's GET /api/memory/entries endpoint. It mirrors the fields of
// ReefCore.Knowledge.KnowledgeEntry serialized by MemoryController.
type MemoryEntry struct {
	ID              string   `json:"id"`
	Category        string   `json:"category"`
	Layer           string   `json:"layer"`
	FlaggedCategory string   `json:"flagged_category,omitempty"`
	Tags            []string `json:"tags"`
	Content         string   `json:"content"`
	Why             string   `json:"why,omitempty"`
	Source          string   `json:"source"`
	Project         string   `json:"project,omitempty"`
	PodRunID        string   `json:"pod_run_id,omitempty"`
	SourceSessionID string   `json:"source_session_id,omitempty"`
	ProofHash       string   `json:"proof_hash,omitempty"`
	InsertedAt      string   `json:"inserted_at"`
	UpdatedAt       string   `json:"updated_at"`
}

// MemoryEntriesResponse wraps the {"entries": [...]} envelope returned
// by GET /api/memory/entries.
type MemoryEntriesResponse struct {
	Entries []MemoryEntry `json:"entries"`
}

// MemoryFilter applies optional query-string filters when listing memory
// entries. Empty fields are omitted from the request.
type MemoryFilter struct {
	PodRunID string // ?pod_run_id=...
	Project  string // ?project=...
	Layer    string // "structural" | "flagged" | ""
	Limit    int    // 0 means server default (50)
}

// APIError wraps a JSON error response body from reef-core.
type APIError struct {
	Error string `json:"error"`
}
