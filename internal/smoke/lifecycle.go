// Copyright 2026 Jerry David Chan, Konareef.ai
// SPDX-License-Identifier: Apache-2.0

// Package smoke runs end-to-end smoke tests against a reef-core instance.
//
// This file implements the full pod lifecycle smoke test: spawn a lobster pod,
// observe live WebSocket events (stream, tool_call, cost), reconcile the cost
// against the REST budget delta, kill the pod, and confirm a terminal status.
package smoke

import (
	"context"
	"fmt"
	"math"
	"time"

	"github.com/digitsu/konareef/internal/api"
)

// terminalStatuses is the set of agent status values that indicate the pod
// has stopped running after a kill.
var terminalStatuses = map[string]bool{
	"stopped":   true,
	"exited":    true,
	"killed":    true,
	"completed": true,
}

// RunLifecycle executes the full pod lifecycle smoke test against reef-core.
//
// The test proceeds through ten steps:
//  1. Preflight: confirm reef-core is reachable via ListAgents.
//  2. Snapshot the pre-spawn budget via GetBudget.
//  3. Spawn a lobster pod with cfg.Task (defaulting to a canned capture-thought task).
//  4. Open a WebSocket collector, join pod:events and agent:<id>.
//  5. Expect a "stream" wire event on the per-agent channel within cfg.Timeout.
//  6. Expect a "tool_call" wire event within cfg.Timeout (optional; warns if absent).
//  7. Expect an "agent_cost" event on pod:events within cfg.Timeout.
//  8. Reconcile WS-reported cost against the REST budget delta (5% tolerance).
//  9. Kill the agent via KillAgent and expect agent_exited on pod:events.
//  10. Confirm the agent status is terminal via ListAgents.
//
// cfg must have a non-empty SessionToken. cfg.Task may be empty, in which case
// the default capture-thought task from Default() is used.
//
// Returns nil on success, or a descriptive wrapped error on any failure.
func RunLifecycle(cfg Config) error {
	if cfg.SessionToken == "" {
		return fmt.Errorf("session token required (pass --token or KONAREEF_TOKEN env)")
	}
	if cfg.Task == "" {
		cfg.Task = Default().Task
	}

	testStart := time.Now()
	totalTimeout := cfg.Timeout * 3
	ctx, cancel := context.WithTimeout(context.Background(), totalTimeout)
	defer cancel()

	fmt.Printf("\n=== konareef lifecycle smoke test ===\n\n")
	fmt.Printf("reef-core:  %s\n", cfg.BaseURL)
	fmt.Printf("token:      (present, %d bytes)\n", len(cfg.SessionToken))
	fmt.Printf("task:       %q\n\n", truncate(cfg.Task, 60))

	client := api.NewClient(cfg.BaseURL).WithToken(cfg.SessionToken)

	// Step 1: preflight
	if _, err := client.ListAgents(); err != nil {
		return fmt.Errorf("step 1 preflight: reef-core unreachable at %s: %w", cfg.BaseURL, err)
	}
	fmt.Printf("Step 1: server reachable [%.1fs] ✓\n", time.Since(testStart).Seconds())

	// Step 2: pre-spawn budget snapshot
	budgetBefore, err := client.GetBudget()
	if err != nil {
		return fmt.Errorf("step 2 budget snapshot: %w", err)
	}
	fmt.Printf("Step 2: pre-spawn budget snapshot (total_spent=%d sats) [%.1fs] ✓\n",
		budgetBefore.TotalSpent, time.Since(testStart).Seconds())

	// Step 3: spawn the lobster pod
	spawnResp, err := client.SpawnAgent(api.SpawnRequest{
		Task:             cfg.Task,
		PodKind:          "lobster",
		Model:            "claude-sonnet-4-5",
		BudgetSats:       1_000_000,
		MaxIterations:    5,
		StructuredMemory: CannedBundle,
		PodAttestation:   cfg.PodAttestation,
	})
	if err != nil {
		return fmt.Errorf("step 3 spawn: %w", err)
	}
	agentID := spawnResp.AgentID
	fmt.Printf("Step 3: spawned agent agent_id=%s pod_id=%s [%.1fs] ✓\n",
		agentID, spawnResp.PodID, time.Since(testStart).Seconds())

	// Step 4: open WS collector, join channels
	collector := NewEventCollector(cfg.BaseURL, cfg.SessionToken)
	defer collector.Close()

	if err := collector.Start(ctx); err != nil {
		return fmt.Errorf("step 4 ws start: %w", err)
	}
	if err := collector.JoinAgent(agentID); err != nil {
		return fmt.Errorf("step 4 ws join agent: %w", err)
	}
	fmt.Printf("Step 4: WebSocket collector started and joined pod:events + agent:%s [%.1fs] ✓\n",
		agentID, time.Since(testStart).Seconds())

	// Step 5: expect a stream event on the per-agent channel. reef-core's
	// AgentChannel translates the internal :agent_stream PubSub event into
	// the wire event named "stream" — using "agent_stream" here would miss.
	_, err = collector.Expect("agent:"+agentID, "stream", agentID, cfg.Timeout)
	if err != nil {
		return fmt.Errorf("step 5 stream: %w", err)
	}
	fmt.Printf("Step 5: stream event received [%.1fs] ✓\n", time.Since(testStart).Seconds())

	// Step 6: expect a tool_call wire event (optional — a lobster pod may
	// complete without any tool use, in which case we warn and continue).
	_, toolCallErr := collector.Expect("agent:"+agentID, "tool_call", agentID, cfg.Timeout)
	if toolCallErr != nil {
		fmt.Printf("[WARN] no tool_call observed within timeout; continuing\n")
	} else {
		fmt.Printf("Step 6: tool_call event received [%.1fs] ✓\n", time.Since(testStart).Seconds())
	}

	// Step 7a: pod-wide agent_cost event on pod:events. This is the feed
	// BudgetModel consumes for live totals; it is the canonical source
	// SumCost reconciles against in step 8.
	_, err = collector.Expect("pod:events", "agent_cost", agentID, cfg.Timeout)
	if err != nil {
		return fmt.Errorf("step 7a agent_cost (pod:events): %w", err)
	}
	fmt.Printf("Step 7a: agent_cost event received on pod:events [%.1fs] ✓\n", time.Since(testStart).Seconds())

	// Step 7b: per-agent cost event on agent:<id>. This is the feed the
	// Inspector model consumes. reef-core broadcasts each :agent_cost to
	// BOTH topics (agent_process.ex:241-242), so this event arrives in
	// the same window as 7a; asserting it explicitly keeps coverage of
	// the per-agent channel after SumCost was tightened to count pod:events
	// only (no double-counting).
	_, err = collector.Expect("agent:"+agentID, "cost", agentID, cfg.Timeout)
	if err != nil {
		return fmt.Errorf("step 7b cost (agent:%s): %w", agentID, err)
	}
	fmt.Printf("Step 7b: cost event received on agent:%s [%.1fs] ✓\n", agentID, time.Since(testStart).Seconds())

	// Step 8: budget reconciliation — REST delta vs WS-reported sum
	budgetAfter, err := client.GetBudget()
	if err != nil {
		return fmt.Errorf("step 8 budget reconciliation snapshot: %w", err)
	}
	restDelta := budgetAfter.TotalSpent - budgetBefore.TotalSpent
	wsSumCost := collector.SumCost()

	if err := checkBudgetReconciliation(wsSumCost, restDelta); err != nil {
		return fmt.Errorf("step 8 budget reconciliation: %w", err)
	}
	fmt.Printf("Step 8: budget reconciliation passed (WS sum=%d sats, REST delta=%d sats) [%.1fs] ✓\n",
		wsSumCost, restDelta, time.Since(testStart).Seconds())

	// Step 9: kill the agent, expect agent_exited on pod:events
	if err := client.KillAgent(agentID); err != nil {
		return fmt.Errorf("step 9 kill agent: %w", err)
	}
	_, err = collector.Expect("pod:events", "agent_exited", agentID, cfg.Timeout)
	if err != nil {
		return fmt.Errorf("step 9 agent_exited: %w", err)
	}
	fmt.Printf("Step 9: kill sent and agent_exited received [%.1fs] ✓\n", time.Since(testStart).Seconds())

	// Step 10: confirm terminal status via ListAgents
	agents, err := client.ListAgents()
	if err != nil {
		return fmt.Errorf("step 10 list agents: %w", err)
	}
	status, found := findAgentStatus(agents, agentID)
	if !found {
		// If the agent is no longer in the list, it has been cleaned up — acceptable.
		fmt.Printf("Step 10: agent %s not present in agent list (fully cleaned up) [%.1fs] ✓\n",
			agentID, time.Since(testStart).Seconds())
	} else if !terminalStatuses[status] {
		return fmt.Errorf("step 10 status check: agent %s has non-terminal status %q after kill", agentID, status)
	} else {
		fmt.Printf("Step 10: agent %s status=%q (terminal) [%.1fs] ✓\n",
			agentID, status, time.Since(testStart).Seconds())
	}

	// Step 11 (optional, opt-in via cfg.MemoryRoundtrip): verify Layer 1
	// structural memory entries actually persisted for this pod_run.
	// Phase 1.5 wired StructuralExtractor into PodManager's :agent_exited
	// handler asynchronously (Task.start), so we poll with a short
	// backoff to give the extraction Task time to run.
	if cfg.MemoryRoundtrip {
		if err := assertMemoryRoundtrip(client, agentID, testStart); err != nil {
			return fmt.Errorf("step 11 memory roundtrip: %w", err)
		}
	}

	elapsed := time.Since(testStart)
	fmt.Printf("\nlifecycle smoke test passed in %.1fs\n\n", elapsed.Seconds())
	return nil
}

// assertMemoryRoundtrip polls GET /api/memory/entries?pod_run_id=<agentID>
// for up to 5 seconds, succeeding the moment a structural session-summary
// entry appears. Phase 1.5's PodManager wiring kicks off extraction in a
// fire-and-forget Task.start, so the result may not be visible
// immediately after :agent_exited fires.
func assertMemoryRoundtrip(client *api.Client, agentID string, testStart time.Time) error {
	deadline := time.Now().Add(5 * time.Second)
	backoff := 200 * time.Millisecond

	for time.Now().Before(deadline) {
		entries, err := client.ListMemoryEntries(api.MemoryFilter{
			PodRunID: agentID,
			Layer:    "structural",
		})
		if err != nil {
			return fmt.Errorf("list memory entries: %w", err)
		}

		for _, entry := range entries {
			if entry.Category == "session" {
				fmt.Printf("Step 11: memory roundtrip verified (%d entries, session summary present) [%.1fs] ✓\n",
					len(entries), time.Since(testStart).Seconds())
				return nil
			}
		}

		time.Sleep(backoff)
	}

	// Timed out — surface what we did see, if anything, for diagnostics.
	entries, _ := client.ListMemoryEntries(api.MemoryFilter{PodRunID: agentID})
	return fmt.Errorf(
		"no structural session-summary entry within 5s for agent %s (saw %d entries total)",
		agentID, len(entries),
	)
}

// checkBudgetReconciliation verifies that the absolute difference between
// wsSumSats and restDeltaSats does not exceed max(5% of wsSumSats, 100 sats).
//
// Returns a descriptive error when the tolerance is exceeded.
func checkBudgetReconciliation(wsSumSats, restDeltaSats int64) error {
	diff := wsSumSats - restDeltaSats
	if diff < 0 {
		diff = -diff
	}
	tolerance := int64(math.Round(float64(wsSumSats) * 0.05))
	if tolerance < 100 {
		tolerance = 100
	}
	if diff > tolerance {
		return fmt.Errorf("budget reconciliation: WS sum=%d sats, REST delta=%d sats, diff=%d exceeds tolerance=%d",
			wsSumSats, restDeltaSats, diff, tolerance)
	}
	return nil
}

// findAgentStatus searches agents for the given agentID and returns its Status.
// Returns ("", false) when no matching agent is found.
func findAgentStatus(agents []api.Agent, agentID string) (string, bool) {
	for _, a := range agents {
		if a.ID == agentID {
			return a.Status, true
		}
	}
	return "", false
}
