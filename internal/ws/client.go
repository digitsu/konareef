// internal/ws/client.go

package ws

import (
	"context"
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/coder/websocket"
	"github.com/coder/websocket/wsjson"
)

// Client manages a WebSocket connection to reef-core's Phoenix Channel
// endpoint. It joins channels, sends heartbeats, and dispatches incoming
// events as Bubble Tea messages via program.Send().
type Client struct {
	serverURL    string
	token        string
	program      *tea.Program
	conn         *websocket.Conn
	ctx          context.Context
	cancel       context.CancelFunc
	currentAgent string
	mu           sync.Mutex
	refCounter   atomic.Int64
	joinRefs     map[string]string
}

// New creates a Client. Call Connect to start the connection.
func New(serverURL, token string) *Client {
	return &Client{
		serverURL: serverURL,
		token:     token,
		joinRefs:  make(map[string]string),
	}
}

func (c *Client) nextRef() string {
	return strconv.FormatInt(c.refCounter.Add(1), 10)
}

// Connect opens the WebSocket, starts heartbeat, joins pod:events, and
// begins reading messages. Handles reconnection internally with
// exponential backoff. Must be called from a goroutine.
func (c *Client) Connect(p *tea.Program) {
	c.program = p
	c.ctx, c.cancel = context.WithCancel(context.Background())

	delay := ReconnectMin
	for {
		err := c.connectOnce()
		if c.ctx.Err() != nil {
			return
		}

		if p != nil {
			p.Send(WsDisconnectedMsg{Err: err})
		}

		select {
		case <-time.After(delay):
			delay *= 2
			if delay > ReconnectMax {
				delay = ReconnectMax
			}
		case <-c.ctx.Done():
			return
		}
	}
}

func (c *Client) connectOnce() error {
	wsURL := c.wsURL()
	conn, _, err := websocket.Dial(c.ctx, wsURL, nil)
	if err != nil {
		return fmt.Errorf("dial: %w", err)
	}
	conn.SetReadLimit(1 << 20)

	c.mu.Lock()
	c.conn = conn
	c.joinRefs = make(map[string]string)
	c.mu.Unlock()

	defer func() {
		conn.Close(websocket.StatusNormalClosure, "bye")
		c.mu.Lock()
		c.conn = nil
		c.mu.Unlock()
	}()

	if err := c.joinTopic("pod:events"); err != nil {
		return fmt.Errorf("join pod:events: %w", err)
	}

	c.mu.Lock()
	agent := c.currentAgent
	c.mu.Unlock()
	if agent != "" {
		if err := c.joinTopic("agent:" + agent); err != nil {
			return fmt.Errorf("rejoin agent: %w", err)
		}
	}

	if c.program != nil {
		c.program.Send(WsConnectedMsg{})
	}

	heartCtx, heartCancel := context.WithCancel(c.ctx)
	defer heartCancel()
	go c.heartbeatLoop(heartCtx)

	return c.readLoop()
}

func (c *Client) wsURL() string {
	base := strings.TrimRight(c.serverURL, "/")
	base = strings.Replace(base, "https://", "wss://", 1)
	base = strings.Replace(base, "http://", "ws://", 1)

	u, _ := url.Parse(base + "/socket/websocket")
	q := u.Query()
	q.Set("token", c.token)
	q.Set("vsn", "1.0.0")
	u.RawQuery = q.Encode()
	return u.String()
}

func (c *Client) joinTopic(topic string) error {
	c.mu.Lock()
	conn := c.conn
	c.mu.Unlock()
	if conn == nil {
		return fmt.Errorf("not connected")
	}

	ref := c.nextRef()
	c.mu.Lock()
	c.joinRefs[topic] = ref
	c.mu.Unlock()

	msg := PhoenixMsg{
		JoinRef: ref,
		Ref:     ref,
		Topic:   topic,
		Event:   "phx_join",
		Payload: map[string]any{},
	}
	ctx, cancel := context.WithTimeout(c.ctx, 5*time.Second)
	defer cancel()
	return wsjson.Write(ctx, conn, msg)
}

func (c *Client) leaveTopic(topic string) error {
	c.mu.Lock()
	conn := c.conn
	delete(c.joinRefs, topic)
	c.mu.Unlock()
	if conn == nil {
		return nil
	}

	msg := PhoenixMsg{
		Ref:   c.nextRef(),
		Topic: topic,
		Event: "phx_leave",
	}
	ctx, cancel := context.WithTimeout(c.ctx, 5*time.Second)
	defer cancel()
	return wsjson.Write(ctx, conn, msg)
}

// JoinAgent joins the agent:<id> channel, leaving any previously joined
// agent channel. Safe to call from any goroutine.
func (c *Client) JoinAgent(agentID string) error {
	c.mu.Lock()
	prev := c.currentAgent
	c.currentAgent = agentID
	c.mu.Unlock()

	if prev != "" && prev != agentID {
		c.leaveTopic("agent:" + prev)
	}
	if agentID == "" {
		return nil
	}

	c.mu.Lock()
	conn := c.conn
	c.mu.Unlock()
	if conn == nil {
		return nil
	}

	return c.joinTopic("agent:" + agentID)
}

// LeaveAgent leaves the current agent channel.
func (c *Client) LeaveAgent() error {
	return c.JoinAgent("")
}

// Close shuts down the WebSocket client gracefully.
func (c *Client) Close() {
	if c.cancel != nil {
		c.cancel()
	}
}

func (c *Client) heartbeatLoop(ctx context.Context) {
	ticker := time.NewTicker(HeartbeatInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			c.mu.Lock()
			conn := c.conn
			c.mu.Unlock()
			if conn == nil {
				return
			}

			msg := PhoenixMsg{
				Topic:   "phoenix",
				Event:   "heartbeat",
				Ref:     c.nextRef(),
				Payload: map[string]any{},
			}
			wCtx, cancel := context.WithTimeout(ctx, HeartbeatTimeout)
			err := wsjson.Write(wCtx, conn, msg)
			cancel()
			if err != nil {
				return
			}
		}
	}
}

func (c *Client) readLoop() error {
	for {
		c.mu.Lock()
		conn := c.conn
		c.mu.Unlock()
		if conn == nil {
			return fmt.Errorf("connection closed")
		}

		var msg PhoenixMsg
		if err := wsjson.Read(c.ctx, conn, &msg); err != nil {
			return fmt.Errorf("read: %w", err)
		}

		c.dispatchMsg(msg)
	}
}

func (c *Client) dispatchMsg(msg PhoenixMsg) {
	if c.program == nil {
		return
	}

	if msg.Event == "phx_reply" || msg.Event == "phx_close" {
		return
	}

	payload, _ := msg.Payload.(map[string]any)
	if payload == nil {
		return
	}

	agentID := ""
	if strings.HasPrefix(msg.Topic, "agent:") {
		agentID = strings.TrimPrefix(msg.Topic, "agent:")
	}

	switch msg.Event {
	case "stream":
		data, _ := payload["data"].(string)
		c.program.Send(WsStreamMsg{AgentID: agentID, Data: data})

	case "tool_call":
		tool, _ := payload["tool"].(string)
		c.program.Send(WsToolCallMsg{AgentID: agentID, Tool: tool})

	case "cost":
		sats, _ := payload["sats"].(float64)
		c.program.Send(WsCostMsg{AgentID: agentID, Sats: int64(sats)})

	case "error":
		message, _ := payload["message"].(string)
		c.program.Send(WsErrorMsg{AgentID: agentID, Message: message})

	// Lifecycle events come exclusively from PodEventsChannel (not AgentChannel)
	// to avoid duplication.
	case "agent_started":
		id, _ := payload["agent_id"].(string)
		name, _ := payload["name"].(string)
		c.program.Send(WsAgentStarted{AgentID: id, Name: name})

	case "agent_exited":
		id, _ := payload["agent_id"].(string)
		code, _ := payload["code"].(float64)
		c.program.Send(WsAgentExited{AgentID: id, Code: int(code)})

	case "agent_complete":
		id, _ := payload["agent_id"].(string)
		c.program.Send(WsCompleteMsg{AgentID: id})

	// Pod-wide cost deltas from PodEventsChannel, used by the Budget
	// tab to update its totals without waiting for the next REST poll.
	// The per-agent AgentChannel emits "cost" (consumed by the Inspector);
	// this is the pod-wide feed with agent_id embedded in the payload.
	case "agent_cost":
		id, _ := payload["agent_id"].(string)
		sats, _ := payload["sats"].(float64)
		c.program.Send(WsPodCostMsg{AgentID: id, Sats: int64(sats)})
	}
}

// Exported Bubble Tea message types sent from the WS client goroutine
// into the TUI via program.Send().

// WsConnectedMsg signals the WebSocket connected successfully.
type WsConnectedMsg struct{}

// WsDisconnectedMsg signals the WebSocket disconnected.
type WsDisconnectedMsg struct{ Err error }

// WsStreamMsg carries streaming text output from an agent.
type WsStreamMsg struct{ AgentID, Data string }

// WsToolCallMsg carries a tool invocation event.
type WsToolCallMsg struct{ AgentID, Tool string }

// WsCostMsg carries a per-agent spend event from the AgentChannel. It is
// only delivered while an agent:<id> topic is joined — typically when the
// Inspector is open on that agent.
type WsCostMsg struct {
	AgentID string
	Sats    int64
}

// WsPodCostMsg carries a pod-wide spend event from the PodEventsChannel.
// It is delivered for every agent_cost broadcast regardless of which
// (if any) agent channel is currently joined, so the Budget tab stays
// live even when no Inspector is open.
type WsPodCostMsg struct {
	AgentID string
	Sats    int64
}

// WsCompleteMsg signals task completion.
type WsCompleteMsg struct{ AgentID, Result string }

// WsErrorMsg carries an agent error.
type WsErrorMsg struct{ AgentID, Message string }

// WsAgentStarted signals a new agent joined the pod.
type WsAgentStarted struct{ AgentID, Name string }

// WsAgentExited signals an agent left the pod.
type WsAgentExited struct {
	AgentID string
	Code    int
}
