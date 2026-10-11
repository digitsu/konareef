// Copyright 2026 Jerry David Chan, Konareef.ai
// SPDX-License-Identifier: Apache-2.0

// internal/ws/protocol.go

// Package ws provides a Phoenix Channel client over WebSocket for
// consuming real-time agent events from reef-core.
package ws

import "time"

// PhoenixMsg is the JSON envelope used by Phoenix Channels.
// Every message over the WebSocket uses this shape.
type PhoenixMsg struct {
	JoinRef string `json:"join_ref"`
	Ref     string `json:"ref"`
	Topic   string `json:"topic"`
	Event   string `json:"event"`
	Payload any    `json:"payload"`
}

// Typed payload structs for events we care about.

// StreamPayload carries agent text output.
type StreamPayload struct {
	Data string `json:"data"`
}

// ToolCallPayload carries a tool invocation event.
type ToolCallPayload struct {
	Tool string `json:"tool"`
}

// CostPayload carries a spend event.
type CostPayload struct {
	Sats int64 `json:"sats"`
}

// CompletePayload carries a task completion event.
type CompletePayload struct {
	Result string `json:"result"`
}

// ErrorPayload carries an agent error event.
type ErrorPayload struct {
	Message string `json:"message"`
}

// LifecyclePayload carries agent started/exited events on pod:events.
type LifecyclePayload struct {
	AgentID string `json:"agent_id"`
	Name    string `json:"name,omitempty"`
	Code    int    `json:"code,omitempty"`
}

// Phoenix protocol constants.
const (
	HeartbeatInterval = 30 * time.Second
	HeartbeatTimeout  = 10 * time.Second
	ReconnectMin      = 1 * time.Second
	ReconnectMax      = 30 * time.Second
)
