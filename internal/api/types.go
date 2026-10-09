// Copyright 2026 Jerry David Chan, Konareef.ai
// SPDX-License-Identifier: Apache-2.0

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

	// No pod_attestation field: POST /api/agents runs a task, not pod
	// content, so reef-core refuses an attestation on it (reef-core#99).
	// A signed pod runs through SpawnPodRequest (`konareef pod run`).
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

	// ZKRequested and ExecutedPod are set only by POST /api/pods/spawn
	// on a reef-core that honours `zk_requested` (ZK-002, reef-core
	// !231). The server sets ZKRequested to true and names the published
	// pod it actually ran in ExecutedPod. A server without ZK-002 sends
	// neither field, so `konareef pod run --zk` reads their absence as
	// "the request was ignored" and stops the run.
	ZKRequested bool         `json:"zk_requested"`
	ExecutedPod *ExecutedPod `json:"executed_pod"`
}

// ExecutedPod is the published pod identity a ZK-requested spawn ran
// (reef-core ZK-002 option A: the server runs the published row's own
// signed body, never client-supplied content). PodHash is lower-case
// hex.
type ExecutedPod struct {
	Handle  string `json:"handle"`
	Pod     string `json:"pod"`
	Version string `json:"version"`
	PodHash string `json:"pod_hash"`
}

// SpawnPodRequest is the JSON body for POST /api/pods/spawn (Mode A):
// spawn straight from a pod manifest + its content files, rather than
// the free-form task string POST /api/agents (SpawnRequest) expects.
//
// Used by `konareef pod run` against a pod previously installed and
// signature-verified by `konareef install`: PodToml + Files come from
// the install cache's content/ directory, Inputs are the buyer's
// --input k=v flags, and PodAttestation is attached when the cache
// also holds a signed manifest (nil for an unsigned/dev pod).
//
// A CLOSED pod uses mode C instead: PodRef alone, with PodToml and
// Files left empty. The two shapes are mutually exclusive — reef-core
// rejects a request carrying both a pod_ref and inline content — which
// is why PodToml and Files are `omitempty`: an empty inline field must
// not appear on the wire at all next to a pod_ref. Open-pod requests
// are unaffected, since a pod with no pod.toml never gets this far
// (LoadContentFiles fails first) and its files map is never empty.
type SpawnPodRequest struct {
	PodToml        string            `json:"pod_toml,omitempty"`
	Inputs         map[string]string `json:"inputs,omitempty"`
	Files          map[string]string `json:"files,omitempty"`
	PodRef         *PodRef           `json:"pod_ref,omitempty"`
	PodAttestation *PodAttestation   `json:"pod_attestation,omitempty"`
	// ZKRequested asks reef-core for a ZK attestation of this run
	// (`konareef pod run --zk`, reef-core ZK-002). reef-core accepts it
	// only for an open, published, zk-enabled pod on circuit
	// konareef-pod-step-v1.1 and refuses every other case with 422
	// zk_request_refused. omitempty: a run without --zk sends no key,
	// so the request body is byte-for-byte what it was before.
	ZKRequested bool `json:"zk_requested,omitempty"`
}

// PodRef references an already-published pod by identity instead of
// shipping its content inline (mode C). Required for closed pods: the
// commissioner does not hold the body — that is the point — so
// reef-core resolves the pod server-side from published_pods and
// materializes it inside its own process.
//
// PodHash is no longer normally the only field `konareef pod run`
// sets: the manifest does not name its publisher, so several handles
// can register byte-identical content, and PodHash alone no longer
// decides which row runs. reef-core resolves {pod_hash, handle,
// optional version, pod} to that publisher's live row, and a bare
// pod_hash only when exactly one live row has it — otherwise it
// refuses with 422 pod_ref_ambiguous (reef-core !254, owner decision
// F2). `konareef pod run` already knows Handle/Pod/Version from the
// `<handle>/<pod>@<version>` it was given, so it sends all four
// alongside the hash: PodHash keeps the trust decision client-side
// (it is the hash the local install already re-derived and
// signature-checked), and Handle/Pod/Version name the publisher so a
// bare-hash collision never reaches this client. All four are
// omitempty so reef-core never has to tell "" apart from "not
// supplied".
type PodRef struct {
	PodHash string `json:"pod_hash,omitempty"`
	Handle  string `json:"handle,omitempty"`
	Pod     string `json:"pod,omitempty"`
	Version string `json:"version,omitempty"`
}

// Deliverable is a single output-file row from GET
// /api/agents/:id/deliverables (reef-core's agent-deliverables-api,
// MR !21). Path carries the "output/" workspace prefix verbatim; pass
// it unmodified to DownloadDeliverable.
type Deliverable struct {
	Path string `json:"path"`
	Size int64  `json:"size"`
}

// DeliverablesResponse wraps GET /api/agents/:id/deliverables.
type DeliverablesResponse struct {
	Deliverables []Deliverable `json:"deliverables"`
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
