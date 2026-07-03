// Package smoke runs a non-TUI end-to-end smoke test against a reef-core
// instance. It exercises the full Phase 3 custody chain: structured_bundle
// → openbrain_snapshot → capture_commitment → custody.
//
// Preconditions:
//   - reef-core running on the target URL (default http://localhost:4000)
//   - A valid session token (get one via: cd reef-core && mix reef_core.dev_session -q)
//   - opencode on reef-core's PATH
//   - ANTHROPIC_API_KEY set on reef-core's side (not konareef's)
//
// Flow:
//  1. POST /api/agents with structured memory bundle + capture-thought task
//  2. Server validates session, stores bundle, emits structured_bundle proof,
//     takes Open Brain snapshot, spawns opencode, runs LLM call, captures
//     thought, emits capture_commitment + custody proofs
//  3. Client polls GET /api/proofs?agent_id=... until a custody proof appears
//     or the timeout hits
//  4. Print chain summary + result
package smoke

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/digitsu/konareef/internal/api"
)

// Config configures a smoke test run.
//
// MemoryRoundtrip is opt-in (default false) because it requires a
// reef-core build that includes the Phase 1.5 memory subsystem (the
// MemoryHook teardown wiring + GET /api/memory/entries). When false,
// the lifecycle smoke skips the memory verification step entirely so
// it can still pass against older reef-core deployments.
type Config struct {
	BaseURL         string
	SessionToken    string
	Task            string
	Timeout         time.Duration
	PollInterval    time.Duration
	MemoryRoundtrip bool

	// PodAttestation, when non-nil, attaches publisher signing
	// metadata to the spawn request so the resulting structured_bundle
	// commitment's pod_hash / publisher_signature columns are populated.
	// The caller supplies this from `install.LoadCachedAttestation`
	// when spawning a previously installed signed pod (P0.3R).
	PodAttestation *api.PodAttestation
}

// Default returns sensible defaults for an interactive smoke test.
func Default() Config {
	return Config{
		BaseURL: "http://localhost:4000",
		Task: `Use the open_brain.capture_thought tool to record the following thought:

  content: "konareef smoke: TUI talked to reef-core and back"
  kind: "pod_observation"

Then reply with the single word "done" and stop.`,
		Timeout:      120 * time.Second,
		PollInterval: 500 * time.Millisecond,
	}
}

// CannedBundle is a canned structured memory bundle for the smoke test.
// Three small files mimicking what an orchestrator would upload before
// spawning a pod.
var CannedBundle = map[string]string{
	"projects/goals.md": `# Goals

Prove that konareef can spawn a pod on reef-core and receive a valid
custody proof chain back.
`,
	"projects/decisions.md": `# Decisions

- 2026-04-15: First end-to-end konareef → reef-core smoke test
- 2026-04-15: TUI spawn flow deferred; smoke is a separate subcommand
`,
	"preferences/coding-style.md": `# Coding style

- Go: tab indent, gofmt, no comments on obvious code
- Elixir: match CLAUDE.md conventions
`,
}

// Run executes the smoke test. Returns nil on success (custody proof
// observed, chain of length 3 or 4 verified), or an error on any failure.
func Run(cfg Config) error {
	if cfg.SessionToken == "" {
		return fmt.Errorf("session token required (pass --token or KONAREEF_TOKEN env)")
	}

	fmt.Printf("\n=== konareef smoke test ===\n\n")
	fmt.Printf("reef-core:  %s\n", cfg.BaseURL)
	fmt.Printf("token:      (present, %d bytes)\n", len(cfg.SessionToken))
	fmt.Printf("bundle:     %d files, %d bytes\n", len(CannedBundle), bundleBytes(CannedBundle))
	fmt.Printf("task:       %q\n", truncate(cfg.Task, 60))
	if cfg.PodAttestation != nil {
		fmt.Printf("attestation: %s/%s (pod_hash %s…)\n",
			cfg.PodAttestation.PublisherID,
			cfg.PodAttestation.PodVersion,
			truncate(cfg.PodAttestation.PodHash, 16))
	}
	fmt.Println()

	client := api.NewClient(cfg.BaseURL).WithToken(cfg.SessionToken)

	// ── Preflight: is the server up? ────────────────────────────────
	if _, err := client.ListAgents(); err != nil {
		return fmt.Errorf("preflight: reef-core unreachable at %s: %w", cfg.BaseURL, err)
	}
	fmt.Println("Step 1: server reachable ✓")

	// ── Spawn ───────────────────────────────────────────────────────
	fmt.Println("Step 2: POST /api/agents")

	resp, err := client.SpawnAgent(api.SpawnRequest{
		Task:             cfg.Task,
		PodKind:          "lobster",
		Model:            "claude-sonnet-4-5",
		BudgetSats:       1_000_000,
		MaxIterations:    5,
		StructuredMemory: CannedBundle,
		PodAttestation:   cfg.PodAttestation,
	})
	if err != nil {
		return fmt.Errorf("spawn: %w", err)
	}

	fmt.Printf("  agent_id=%s pod_id=%s task_id=%s\n", resp.AgentID, resp.PodID, resp.TaskID)
	fmt.Printf("  snapshot_id=%s\n", resp.SnapshotID)
	fmt.Printf("  bundle_hash=%s (%d files)\n",
		truncate(resp.BundleHash, 16), resp.BundleFileCount)

	// ── Poll for custody proof ──────────────────────────────────────
	fmt.Printf("\nStep 3: polling for custody proof (timeout %s)\n", cfg.Timeout)

	deadline := time.Now().Add(cfg.Timeout)
	var chain []api.Proof
	custodyIdx := -1
	lastReported := 0
	start := time.Now()

	for time.Now().Before(deadline) {
		proofs, err := client.GetProofsByAgent(resp.AgentID)
		if err != nil {
			return fmt.Errorf("poll proofs: %w", err)
		}

		custodyIdx = findCustodyIndex(proofs)
		if custodyIdx >= 0 {
			chain = proofs
			break
		}

		// Report only when the number of proofs changes to keep output quiet.
		if len(proofs) != lastReported && len(proofs) > 0 {
			lastReported = len(proofs)
			fmt.Printf("  [%5.1fs] %d proofs so far: %s\n",
				time.Since(start).Seconds(),
				len(proofs),
				summarizeChain(proofs))
		}

		time.Sleep(cfg.PollInterval)
	}

	if custodyIdx < 0 {
		return fmt.Errorf("timeout waiting for custody proof after %s", cfg.Timeout)
	}

	// ── Topological sort via prev_hash ──────────────────────────────
	ordered, err := sortChainByPrevHash(chain)
	if err != nil {
		return fmt.Errorf("chain topology: %w", err)
	}

	// ── Report ──────────────────────────────────────────────────────
	fmt.Printf("\nStep 4: chain found (length %d, topologically ordered):\n", len(ordered))
	for _, p := range ordered {
		fmt.Printf("  - %-22s hash=%s... prev=%s...\n",
			p.ProofType,
			truncate(p.Hash, 16),
			truncate(p.PrevHash, 16),
		)
	}

	if err := verifyChainTypes(ordered); err != nil {
		return fmt.Errorf("chain types: %w", err)
	}

	fmt.Printf("\n✓ konareef drove reef-core end-to-end. custody chain is healthy.\n\n")
	return nil
}

// ── helpers ──────────────────────────────────────────────────────────

func findCustodyIndex(proofs []api.Proof) int {
	for i, p := range proofs {
		if p.ProofType == "custody" {
			return i
		}
	}
	return -1
}

// sortChainByPrevHash walks the prev_hash pointers from head to tail,
// producing a chronologically-ordered slice. The head is the proof with
// an empty prev_hash; subsequent proofs are found by matching each link's
// hash against the next link's prev_hash.
//
// Returns an error if the chain is malformed (missing head, dangling link,
// duplicate hashes).
func sortChainByPrevHash(proofs []api.Proof) ([]api.Proof, error) {
	if len(proofs) == 0 {
		return nil, fmt.Errorf("empty chain")
	}

	byHash := make(map[string]api.Proof, len(proofs))
	for _, p := range proofs {
		if _, dup := byHash[p.Hash]; dup {
			return nil, fmt.Errorf("duplicate hash %s", p.Hash)
		}
		byHash[p.Hash] = p
	}

	// Find head: the proof with no prev_hash, or whose prev_hash points
	// to something outside this set (e.g. an earlier task's custody).
	var head *api.Proof
	for _, p := range proofs {
		p := p
		if p.PrevHash == "" {
			if head != nil {
				return nil, fmt.Errorf("multiple chain heads (empty prev_hash)")
			}
			head = &p
		}
	}
	if head == nil {
		// No empty prev_hash — look for a proof whose prev_hash isn't in
		// the set. That's the head of *this* query's chain.
		for _, p := range proofs {
			p := p
			if _, exists := byHash[p.PrevHash]; !exists {
				if head != nil {
					return nil, fmt.Errorf("multiple potential heads")
				}
				head = &p
			}
		}
	}
	if head == nil {
		return nil, fmt.Errorf("no chain head found")
	}

	// Build nextByPrev: hash → proof whose prev_hash equals that hash
	nextByPrev := make(map[string]api.Proof, len(proofs))
	for _, p := range proofs {
		if p.PrevHash != "" {
			nextByPrev[p.PrevHash] = p
		}
	}

	ordered := []api.Proof{*head}
	current := *head
	for {
		next, ok := nextByPrev[current.Hash]
		if !ok {
			break
		}
		ordered = append(ordered, next)
		current = next
		if len(ordered) > len(proofs) {
			return nil, fmt.Errorf("chain cycle detected")
		}
	}

	if len(ordered) != len(proofs) {
		return nil, fmt.Errorf("chain is disconnected: walked %d of %d proofs", len(ordered), len(proofs))
	}

	return ordered, nil
}

// verifyChainTypes checks that the topologically-sorted chain matches
// one of the valid Phase 3 shapes:
//   - [structured_bundle, openbrain_snapshot, custody]           (no captures)
//   - [structured_bundle, openbrain_snapshot, capture_commitment, custody]
func verifyChainTypes(proofs []api.Proof) error {
	types := make([]string, len(proofs))
	for i, p := range proofs {
		types[i] = p.ProofType
	}

	valid4 := []string{"structured_bundle", "openbrain_snapshot", "capture_commitment", "custody"}
	valid3 := []string{"structured_bundle", "openbrain_snapshot", "custody"}

	if slicesEqual(types, valid4) || slicesEqual(types, valid3) {
		return nil
	}

	return fmt.Errorf("unexpected chain shape: %s", strings.Join(types, " → "))
}

func slicesEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func summarizeChain(proofs []api.Proof) string {
	var parts []string
	for _, p := range proofs {
		parts = append(parts, p.ProofType)
	}
	return strings.Join(parts, " → ")
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}

func bundleBytes(bundle map[string]string) int {
	total := 0
	for _, content := range bundle {
		total += len(content)
	}
	return total
}

// TokenFromEnv reads the session token from KONAREEF_TOKEN, allowing
// shells to `export KONAREEF_TOKEN=$(cd ../reef-core && mix reef_core.dev_session -q)`.
func TokenFromEnv() string {
	return os.Getenv("KONAREEF_TOKEN")
}
