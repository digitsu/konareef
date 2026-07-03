// internal/smoke/ws_collector.go
//
// Package smoke — this file provides EventCollector, a non-Bubble-Tea WebSocket
// client that subscribes to reef-core's Phoenix Channel endpoint and buffers
// every inbound event for use in smoke and integration tests. It speaks the
// Phoenix v1 wire protocol (JSON objects), sends periodic heartbeats, and
// exposes a blocking Expect API so tests can await specific events with a
// timeout while still seeing events that arrived before the call.

package smoke

import (
	"context"
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/coder/websocket"
	"github.com/coder/websocket/wsjson"
)

// phoenixMsg is the JSON envelope used by Phoenix Channels v1.
// Every message on the wire uses this shape.
type phoenixMsg struct {
	JoinRef string `json:"join_ref"`
	Ref     string `json:"ref"`
	Topic   string `json:"topic"`
	Event   string `json:"event"`
	Payload any    `json:"payload"`
}

// Event is a single WebSocket event captured from reef-core.
type Event struct {
	// Topic is the Phoenix channel topic, e.g. "pod:events" or "agent:<id>".
	Topic string
	// EventType is the Phoenix event name, e.g. "agent_started", "stream", "cost".
	EventType string
	// AgentID is extracted from the topic when the topic is "agent:<id>",
	// or from payload["agent_id"] for lifecycle events on "pod:events".
	AgentID string
	// Payload is the raw parsed payload map from the Phoenix message.
	Payload map[string]any
	// ReceivedAt is the wall-clock time at which the event was buffered.
	ReceivedAt time.Time
}

// EventCollector subscribes to reef-core's Phoenix Channel WebSocket
// and buffers every inbound event for test assertions.
type EventCollector struct {
	serverURL  string
	token      string
	conn       *websocket.Conn
	connCtx    context.Context
	connCancel context.CancelFunc

	refCounter atomic.Int64
	// joinRefs maps topic → join_ref string so subsequent sends on a topic
	// include the correct join_ref per Phoenix spec.
	joinRefs map[string]string
	// pendingReplies maps a Phoenix message ref to a channel on which the
	// corresponding phx_reply will be delivered by readLoop. Used by
	// joinTopicAndWait to block for a join ACK without racing readLoop for
	// reads on the websocket connection.
	pendingReplies map[string]chan phoenixMsg

	mu     sync.Mutex
	events []Event
	// waiters is a list of channels that the read-loop signals each time a
	// new event is appended. Expect registers and deregisters these.
	waiters []chan struct{}
}

// NewEventCollector creates a collector pointed at the reef-core HTTP base URL
// (e.g. "http://localhost:4000"). The token is a base64-encoded reef-core
// session token. Does not connect; call Start to open the connection.
func NewEventCollector(serverURL, token string) *EventCollector {
	return &EventCollector{
		serverURL:      serverURL,
		token:          token,
		joinRefs:       make(map[string]string),
		pendingReplies: make(map[string]chan phoenixMsg),
	}
}

// nextRef increments the atomic counter and returns the new value as a string.
// Used for Phoenix message ref and join_ref fields.
func (collector *EventCollector) nextRef() string {
	return strconv.FormatInt(collector.refCounter.Add(1), 10)
}

// buildWSURL converts the HTTP base URL to a WebSocket URL for reef-core's
// Phoenix socket endpoint, appending the token and vsn query parameters.
func (collector *EventCollector) buildWSURL() string {
	base := strings.TrimRight(collector.serverURL, "/")
	base = strings.Replace(base, "https://", "wss://", 1)
	base = strings.Replace(base, "http://", "ws://", 1)

	parsed, _ := url.Parse(base + "/socket/websocket")
	queryParams := parsed.Query()
	queryParams.Set("token", collector.token)
	queryParams.Set("vsn", "1.0.0")
	parsed.RawQuery = queryParams.Encode()
	return parsed.String()
}

// Start opens the WebSocket connection and joins "pod:events". It blocks until
// the join is confirmed or the context is cancelled. Once confirmed, it spawns
// a background read-loop goroutine that exits when ctx is cancelled or the
// connection drops. Returns an error if the dial or join fails.
func (collector *EventCollector) Start(ctx context.Context) error {
	wsURL := collector.buildWSURL()
	conn, _, err := websocket.Dial(ctx, wsURL, nil)
	if err != nil {
		return fmt.Errorf("ws dial: %w", err)
	}
	conn.SetReadLimit(1 << 20)

	connCtx, connCancel := context.WithCancel(ctx)

	collector.mu.Lock()
	collector.conn = conn
	collector.connCtx = connCtx
	collector.connCancel = connCancel
	collector.joinRefs = make(map[string]string)
	collector.pendingReplies = make(map[string]chan phoenixMsg)
	collector.mu.Unlock()

	// Start the background loops BEFORE the first join. joinTopicAndWait
	// registers a reply-waiter channel and readLoop is the sole owner of
	// wsjson.Read — running the join synchronously before readLoop exists
	// would work for pod:events but would then race readLoop on every
	// subsequent JoinAgent call. Uniform dispatch via readLoop avoids
	// two goroutines reading the same connection concurrently.
	go collector.heartbeatLoop(connCtx)
	go collector.readLoop(connCtx)

	if err := collector.joinTopicAndWait(ctx, "pod:events"); err != nil {
		connCancel()
		conn.Close(websocket.StatusNormalClosure, "join failed")
		return fmt.Errorf("join pod:events: %w", err)
	}

	return nil
}

// JoinAgent also joins the per-agent channel "agent:<agentID>". Safe to call
// after Start. Returns once the join is confirmed or the context stored at
// Start time is cancelled.
func (collector *EventCollector) JoinAgent(agentID string) error {
	collector.mu.Lock()
	ctx := collector.connCtx
	collector.mu.Unlock()
	if ctx == nil {
		return fmt.Errorf("collector not started")
	}
	return collector.joinTopicAndWait(ctx, "agent:"+agentID)
}

// joinTopicAndWait sends a phx_join on the given topic and blocks until the
// corresponding phx_reply arrives via readLoop's dispatch path, ctx is
// cancelled, the underlying connection drops, or a 10-second join timeout
// elapses. The reply is delivered through a per-ref channel registered in
// pendingReplies before the join is sent, so this function never reads the
// websocket directly — readLoop remains the sole reader.
func (collector *EventCollector) joinTopicAndWait(ctx context.Context, topic string) error {
	collector.mu.Lock()
	conn := collector.conn
	connCtx := collector.connCtx
	collector.mu.Unlock()
	if conn == nil {
		return fmt.Errorf("not connected")
	}

	joinRef := collector.nextRef()
	replyCh := make(chan phoenixMsg, 1)

	collector.mu.Lock()
	collector.joinRefs[topic] = joinRef
	collector.pendingReplies[joinRef] = replyCh
	collector.mu.Unlock()

	defer func() {
		collector.mu.Lock()
		delete(collector.pendingReplies, joinRef)
		collector.mu.Unlock()
	}()

	joinMsg := phoenixMsg{
		JoinRef: joinRef,
		Ref:     joinRef,
		Topic:   topic,
		Event:   "phx_join",
		Payload: map[string]any{},
	}

	writeCtx, writeCancel := context.WithTimeout(ctx, 5*time.Second)
	err := wsjson.Write(writeCtx, conn, joinMsg)
	writeCancel()
	if err != nil {
		return fmt.Errorf("send join: %w", err)
	}

	select {
	case reply := <-replyCh:
		payload, _ := reply.Payload.(map[string]any)
		status, _ := payload["status"].(string)
		if status == "error" {
			return fmt.Errorf("server rejected join for %s: %v", topic, payload["response"])
		}
		return nil
	case <-time.After(10 * time.Second):
		return fmt.Errorf("timeout waiting for join reply on %s", topic)
	case <-connCtx.Done():
		return fmt.Errorf("connection closed before join reply on %s", topic)
	case <-ctx.Done():
		return ctx.Err()
	}
}

// readLoop runs in its own goroutine after Start. It is the sole owner of
// wsjson.Read on the connection: it reads every Phoenix message, dispatches
// phx_reply frames to any join waiter registered in pendingReplies, decodes
// non-reply frames into Event values, appends them to the buffer, and signals
// any active Expect waiters. It returns when ctx is cancelled or the connection
// drops; on exit it cancels connCtx so pending joinTopicAndWait callers
// unblock with a connection-closed error instead of hanging. It does not
// reconnect — smoke tests want failures to be visible.
func (collector *EventCollector) readLoop(ctx context.Context) {
	collector.mu.Lock()
	conn := collector.conn
	connCancel := collector.connCancel
	collector.mu.Unlock()
	if connCancel != nil {
		defer connCancel()
	}

	for {
		var msg phoenixMsg
		if err := wsjson.Read(ctx, conn, &msg); err != nil {
			return
		}

		// phx_reply: dispatch to the join waiter whose ref matches, if any.
		// Drop silently if no waiter is registered (e.g. a heartbeat reply).
		if msg.Event == "phx_reply" {
			collector.mu.Lock()
			replyCh, ok := collector.pendingReplies[msg.Ref]
			collector.mu.Unlock()
			if ok {
				select {
				case replyCh <- msg:
				default:
					// Waiter already received its reply; ignore duplicate.
				}
			}
			continue
		}

		// Skip other internal Phoenix control frames.
		if msg.Event == "phx_close" || msg.Event == "phx_error" {
			continue
		}
		if msg.Topic == "phoenix" {
			continue
		}

		payload, _ := msg.Payload.(map[string]any)
		if payload == nil {
			payload = make(map[string]any)
		}

		agentID := extractAgentID(msg.Topic, msg.Event, payload)

		event := Event{
			Topic:      msg.Topic,
			EventType:  msg.Event,
			AgentID:    agentID,
			Payload:    payload,
			ReceivedAt: time.Now(),
		}

		collector.mu.Lock()
		collector.events = append(collector.events, event)
		// Notify all active Expect callers that a new event arrived.
		for _, waiterCh := range collector.waiters {
			select {
			case waiterCh <- struct{}{}:
			default:
				// Waiter channel is full — the Expect goroutine has already
				// been notified and hasn't consumed the signal yet; that is
				// fine, it will re-scan on wake-up.
			}
		}
		collector.mu.Unlock()
	}
}

// heartbeatLoop sends a Phoenix heartbeat every 30 seconds to keep the
// server-side connection alive. It exits when ctx is cancelled.
func (collector *EventCollector) heartbeatLoop(ctx context.Context) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			collector.mu.Lock()
			conn := collector.conn
			collector.mu.Unlock()
			if conn == nil {
				return
			}

			heartbeatMsg := phoenixMsg{
				Topic:   "phoenix",
				Event:   "heartbeat",
				Ref:     collector.nextRef(),
				Payload: map[string]any{},
			}
			writeCtx, writeCancel := context.WithTimeout(ctx, 10*time.Second)
			err := wsjson.Write(writeCtx, conn, heartbeatMsg)
			writeCancel()
			if err != nil {
				return
			}
		}
	}
}

// Expect blocks until an event matching topic, eventType, and agentID arrives,
// or the timeout expires. Events that arrived before Expect was called are also
// eligible — the collector buffers everything since Start. Pass an empty string
// for topic, eventType, or agentID to match any value in that field. Returns
// the matched Event and nil on success, or a zero Event and an error on timeout.
func (collector *EventCollector) Expect(topic, eventType, agentID string, timeout time.Duration) (Event, error) {
	deadline := time.Now().Add(timeout)

	// Register a notification channel so the read-loop wakes us up when new
	// events arrive, then scan from the beginning of the buffer each time
	// (cheap for test-scale event counts).
	notifyCh := make(chan struct{}, 1)

	collector.mu.Lock()
	collector.waiters = append(collector.waiters, notifyCh)
	// Do an initial scan of already-buffered events before blocking.
	matchedEvent, found := scanForMatch(collector.events, topic, eventType, agentID)
	collector.mu.Unlock()

	if found {
		collector.removeWaiter(notifyCh)
		return matchedEvent, nil
	}

	defer collector.removeWaiter(notifyCh)

	for {
		remaining := time.Until(deadline)
		if remaining <= 0 {
			return Event{}, fmt.Errorf("timeout waiting for event (topic=%q eventType=%q agentID=%q)", topic, eventType, agentID)
		}

		timer := time.NewTimer(remaining)
		select {
		case <-notifyCh:
			timer.Stop()
		case <-timer.C:
			return Event{}, fmt.Errorf("timeout waiting for event (topic=%q eventType=%q agentID=%q)", topic, eventType, agentID)
		}

		collector.mu.Lock()
		matchedEvent, found = scanForMatch(collector.events, topic, eventType, agentID)
		collector.mu.Unlock()

		if found {
			return matchedEvent, nil
		}
	}
}

// scanForMatch iterates the buffered events and returns the first one that
// matches all non-empty filter values. Called with mu held.
func scanForMatch(events []Event, topic, eventType, agentID string) (Event, bool) {
	for _, event := range events {
		if topic != "" && event.Topic != topic {
			continue
		}
		if eventType != "" && event.EventType != eventType {
			continue
		}
		if agentID != "" && event.AgentID != agentID {
			continue
		}
		return event, true
	}
	return Event{}, false
}

// removeWaiter removes notifyCh from the waiters slice. Called without mu held.
func (collector *EventCollector) removeWaiter(notifyCh chan struct{}) {
	collector.mu.Lock()
	defer collector.mu.Unlock()
	filtered := collector.waiters[:0]
	for _, existing := range collector.waiters {
		if existing != notifyCh {
			filtered = append(filtered, existing)
		}
	}
	collector.waiters = filtered
}

// All returns a snapshot copy of every event received so far. Safe to call
// from any goroutine; the returned slice is independent of the internal buffer.
func (collector *EventCollector) All() []Event {
	collector.mu.Lock()
	defer collector.mu.Unlock()
	snapshot := make([]Event, len(collector.events))
	copy(snapshot, collector.events)
	return snapshot
}

// SumCost returns the sum of "sats" values across every "agent_cost" event
// seen on the "pod:events" topic — the canonical pod-wide feed BudgetModel
// consumes. Use this to reconcile against REST budget deltas in lifecycle
// tests.
//
// reef-core broadcasts each :agent_cost PubSub event to BOTH "pod:events"
// (this feed) and the per-agent "agent:<id>" topic (where it surfaces as a
// "cost" wire event consumed by the Inspector). Counting both feeds would
// double-count every spend; a single source is the right reconciliation
// target. The smoke test asserts both feeds independently to keep coverage
// of the per-agent path.
func (collector *EventCollector) SumCost() int64 {
	collector.mu.Lock()
	defer collector.mu.Unlock()

	var total int64
	for _, event := range collector.events {
		if event.Topic == "pod:events" && event.EventType == "agent_cost" {
			sats, _ := event.Payload["sats"].(float64)
			total += int64(sats)
		}
	}
	return total
}

// Close shuts the WebSocket connection down gracefully and cancels the
// read-loop and heartbeat goroutines. Idempotent — safe to call multiple times.
func (collector *EventCollector) Close() error {
	collector.mu.Lock()
	conn := collector.conn
	cancel := collector.connCancel
	collector.conn = nil
	collector.mu.Unlock()

	if cancel != nil {
		cancel()
	}
	if conn != nil {
		return conn.Close(websocket.StatusNormalClosure, "collector closed")
	}
	return nil
}

// extractAgentID derives the AgentID for an event. For "agent:<id>" topics the
// ID is the topic suffix. For lifecycle events on "pod:events" the ID comes from
// payload["agent_id"]. All other events return an empty string.
func extractAgentID(topic, eventType string, payload map[string]any) string {
	if strings.HasPrefix(topic, "agent:") {
		return strings.TrimPrefix(topic, "agent:")
	}
	if topic == "pod:events" {
		agentID, _ := payload["agent_id"].(string)
		return agentID
	}
	return ""
}
