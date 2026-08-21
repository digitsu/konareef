// Copyright 2026 Jerry David Chan, Konareef.ai
// SPDX-License-Identifier: Apache-2.0

// Package run implements the buyer-side "Execute" step of the
// konareef demo flow: `konareef pod run <handle>/<pod>@<version>`.
//
// It spawns a previously installed pod, polls reef-core until the run
// finishes, and downloads every deliverable it produced into a local
// directory.
//
// How the pod reaches reef-core depends on how it was published:
//
//   - An OPEN pod spawns from its local install cache — the pod.toml +
//     every content file under
//     `<home>/.konareef/installed/<handle>/<pod>/<version>/content/`,
//     plus the cached publisher attestation when one exists (Task B3,
//     `internal/install`). This is Mode A, the counterpart to
//     internal/smoke's Mode-B spawn (free-form task string): Run POSTs
//     to /api/pods/spawn with the pod's own manifest and inputs rather
//     than a canned task.
//
//   - A CLOSED pod spawns by reference (Mode C). Its body is encrypted
//     at publish and never served to the commissioner, so there is no
//     content/ dir to send; Run instead names the pod_hash the install
//     already verified and reef-core materializes the body server-side.
//     Nothing about the pod's contents crosses the wire in either
//     direction — only its declared deliverables come back.
//
// Everything downstream of the spawn call (polling, deliverable
// listing, download) is identical for both modes.
package run

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/digitsu/konareef/internal/api"
	"github.com/digitsu/konareef/internal/install"
)

// DefaultPollInterval is how often Run polls reef-core for the
// completion signal (a custody proof) when Config.PollInterval is
// left at zero. Pod runs in the demo are short-lived, one-shot
// executions, so a short interval favors CLI responsiveness over
// server load.
const DefaultPollInterval = 2 * time.Second

// DefaultTimeout is the poll timeout applied when Config.Timeout is
// left at zero.
const DefaultTimeout = 10 * time.Minute

// Config configures a `konareef pod run` invocation.
type Config struct {
	BaseURL      string
	SessionToken string

	// Home is the install-cache root (normally $HOME). Empty means
	// os.UserHomeDir(). Overridable so tests don't touch the real
	// user's ~/.konareef.
	Home string

	Handle  string
	PodName string
	Version string

	// Inputs are the buyer-supplied pod inputs (--input k=v flags,
	// already parsed via ParseInputs).
	Inputs map[string]string

	// OutDir is the directory deliverables are downloaded into.
	OutDir string

	Timeout      time.Duration
	PollInterval time.Duration
}

// InputFlags collects repeated `--input key=value` flag occurrences
// into a slice — flag.Value doesn't natively support repeatable
// string flags, so main.go wires `fs.Var(&inputs, "input", ...)`
// against this type, and each --input on the command line appends
// here. ParseInputs then converts the accumulated slice into the
// wire-shape inputs map.
type InputFlags []string

// String renders the accumulated flags for flag.Value's diagnostic
// output (e.g. `-help`); it is not used to reconstruct the flags.
func (f *InputFlags) String() string {
	return strings.Join(*f, ",")
}

// Set appends one more `key=value` occurrence. Always succeeds —
// "key=value" validation happens later, in ParseInputs, so a single
// malformed entry can be reported alongside all the others instead of
// aborting flag parsing on the first bad one.
func (f *InputFlags) Set(value string) error {
	*f = append(*f, value)
	return nil
}

// ParseInputs converts "key=value" strings (as collected by repeated
// --input flags) into the inputs map the spawn wire expects. Returns
// an error naming the offending entry if any lack an "=" separator.
// A repeated key keeps its last value.
func ParseInputs(pairs []string) (map[string]string, error) {
	out := make(map[string]string, len(pairs))
	for _, pair := range pairs {
		eq := strings.IndexByte(pair, '=')
		if eq < 0 {
			return nil, fmt.Errorf("--input %q is not in key=value form", pair)
		}
		out[pair[:eq]] = pair[eq+1:]
	}
	return out, nil
}

// LoadContentFiles reads a pod's install-cache content/ directory:
// pod.toml (returned separately, since the spawn wire carries it as
// its own top-level field) plus every file in the tree — including
// pod.toml itself — keyed by its "./"-prefixed relative path, matching
// the Mode-A spawn body's `files` map convention (e.g.
// "./prompts/system.md"; see the PRD's pinned interface contracts).
//
// Returns an error if contentDir doesn't exist or contains no
// pod.toml.
func LoadContentFiles(contentDir string) (podToml string, files map[string]string, err error) {
	if _, statErr := os.Stat(contentDir); statErr != nil {
		return "", nil, fmt.Errorf("content cache dir %s: %w", contentDir, statErr)
	}

	files = make(map[string]string)
	walkErr := filepath.WalkDir(contentDir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		rel, err := filepath.Rel(contentDir, path)
		if err != nil {
			return err
		}
		body, err := os.ReadFile(path)
		if err != nil {
			return fmt.Errorf("read %s: %w", path, err)
		}
		files["./"+filepath.ToSlash(rel)] = string(body)
		return nil
	})
	if walkErr != nil {
		return "", nil, fmt.Errorf("walk content dir: %w", walkErr)
	}

	podToml, ok := files["./pod.toml"]
	if !ok {
		return "", nil, fmt.Errorf("content cache dir %s has no pod.toml", contentDir)
	}
	return podToml, files, nil
}

// Run executes `konareef pod run`:
//
//  1. Read the install cache's meta.json to pick a spawn mode: an open
//     pod loads its cached content/ dir and attestation (error naming
//     `konareef install` if either the install or the content is
//     missing); a closed pod loads neither, because it has no local
//     body by design.
//  2. POST /api/pods/spawn — Mode A with the manifest, files, inputs
//     and attestation for an open pod; Mode C with just a pod_ref and
//     inputs for a closed one.
//  3. Poll for completion — a custody proof appearing for the spawned
//     agent, the same terminal signal internal/smoke's Run polls for
//     after spawn. (Its custody-lookup helper, findCustodyIndex, is
//     unexported, so the poll loop is mirrored here rather than
//     imported — see the task report for the reuse discussion.)
//  4. List and download every deliverable into Config.OutDir.
//
// Prints the demo's Execute-step UX to stdout as it proceeds. Returns
// a descriptive error on any failure.
func Run(cfg Config) error {
	if cfg.SessionToken == "" {
		return fmt.Errorf("session token required (pass --token or KONAREEF_TOKEN env)")
	}
	if cfg.Version == "" {
		return fmt.Errorf("explicit @<version> required (no @latest against the install cache)")
	}

	home := cfg.Home
	if home == "" {
		h, err := os.UserHomeDir()
		if err != nil {
			return fmt.Errorf("locate home directory: %w", err)
		}
		home = h
	}

	versionDir := filepath.Join(home, ".konareef", "installed", cfg.Handle, cfg.PodName, cfg.Version)

	// Checked before anything cache-shaped: a closed pod has no
	// content/ dir by design, so "not installed" and "installed but
	// bodyless" are genuinely different diagnoses and must not share
	// one message.
	if _, err := os.Stat(versionDir); err != nil {
		return fmt.Errorf("%s/%s@%s is not installed — run `konareef install %s/%s@%s` first",
			cfg.Handle, cfg.PodName, cfg.Version, cfg.Handle, cfg.PodName, cfg.Version)
	}

	// meta.json decides which spawn mode applies, so it is read before
	// the content/ stat. Its absence is not an error: an unsigned/dev
	// pod installs with content/ and no metadata at all, and that path
	// predates closed pods — absent metadata means an open pod.
	meta, err := install.LoadCachedMeta(home, cfg.Handle, cfg.PodName, cfg.Version)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}

	req, err := buildSpawnRequest(home, versionDir, meta, cfg)
	if err != nil {
		return err
	}

	client := api.NewClient(cfg.BaseURL).WithToken(cfg.SessionToken)

	resp, err := client.SpawnPod(req)
	if err != nil {
		return fmt.Errorf("spawn: %w", err)
	}
	fmt.Printf("agent_id=%s pod_id=%s bundle_hash=%s\n", resp.AgentID, resp.PodID, resp.BundleHash)

	timeout := cfg.Timeout
	if timeout == 0 {
		timeout = DefaultTimeout
	}
	pollInterval := cfg.PollInterval
	if pollInterval == 0 {
		pollInterval = DefaultPollInterval
	}

	proof, err := waitForCustodyProof(client, resp.AgentID, timeout, pollInterval)
	if err != nil {
		return fmt.Errorf("wait for completion: %w", err)
	}

	listed, err := client.ListDeliverables(resp.AgentID)
	if err != nil {
		return fmt.Errorf("list deliverables: %w", err)
	}

	parts := make([]string, 0, len(listed))
	for _, d := range listed {
		// Validate the destination path before touching the network:
		// a server-controlled path escaping --out is a hard stop for
		// the whole run, not a skip-and-continue.
		local, err := safeLocalPath(cfg.OutDir, d.Path)
		if err != nil {
			return fmt.Errorf("deliverable %s: %w", d.Path, err)
		}
		body, err := client.DownloadDeliverable(resp.AgentID, d.Path)
		if err != nil {
			return fmt.Errorf("download %s: %w", d.Path, err)
		}
		if dir := filepath.Dir(local); dir != "." {
			if err := os.MkdirAll(dir, 0o755); err != nil {
				return fmt.Errorf("create %s: %w", dir, err)
			}
		}
		if err := os.WriteFile(local, body, 0o644); err != nil {
			return fmt.Errorf("write %s: %w", local, err)
		}
		parts = append(parts, fmt.Sprintf("%s (%s)", local, humanSize(d.Size)))
	}

	fmt.Printf("✔ deliverables: %s\n", strings.Join(parts, ", "))
	fmt.Printf("✔ proof: %s\n", proof.Hash)
	if proof.Txid != "" {
		fmt.Printf("✔ anchored: %s  https://whatsonchain.com/tx/%s\n", proof.Txid, proof.Txid)
	}
	fmt.Printf("  verify offline:  konareef verify --strict <(curl -s %s/api/public/proofs/%s/bundle)\n",
		strings.TrimRight(cfg.BaseURL, "/"), proof.Hash)

	return nil
}

// buildSpawnRequest assembles the POST /api/pods/spawn body for an
// installed pod, choosing between the two mutually exclusive spawn
// modes on the cached pod's publication mode:
//
//   - CLOSED (mode C) — reference the pod by the pod_hash the local
//     install already re-derived from the manifest bytes and checked
//     the publisher signature over. Nothing about the body is sent,
//     because the commissioner does not have it; reef-core resolves the
//     pod server-side and materializes it in its own process. Referring
//     to the verified hash rather than to a handle/pod/version the
//     server would re-resolve is what keeps the client's trust decision
//     local: the server cannot substitute a different pod under a name
//     the client asked for.
//
//   - OPEN (everything else, including a legacy install with no
//     meta.json) — the unchanged inline path: pod.toml plus every
//     cached content file, with the cached attestation attached when one
//     exists.
//
// No attestation is attached in mode C: reef-core already holds the
// signed manifest for the pod it resolves, so a client-supplied copy
// would attest to nothing the server does not already know.
//
// Prints the closed-pod disclosure line before returning, so the user
// sees what commissioning a private pod means before the network call.
func buildSpawnRequest(home, versionDir string, meta *install.CachedMeta, cfg Config) (api.SpawnPodRequest, error) {
	if meta.IsClosed() {
		fmt.Printf("Commissioning a hosted run of %s/%s@%s.\n", cfg.Handle, cfg.PodName, cfg.Version)
		fmt.Println("This pod's contents stay on konareef's infrastructure; you receive only")
		fmt.Println("its declared deliverables.")
		return api.SpawnPodRequest{
			PodRef: &api.PodRef{PodHash: meta.PodHash},
			Inputs: cfg.Inputs,
		}, nil
	}

	contentDir := filepath.Join(versionDir, "content")
	if _, err := os.Stat(contentDir); err != nil {
		return api.SpawnPodRequest{}, fmt.Errorf(
			"no installed content cache for %s/%s@%s — run `konareef install %s/%s@%s` first",
			cfg.Handle, cfg.PodName, cfg.Version, cfg.Handle, cfg.PodName, cfg.Version)
	}
	podToml, files, err := LoadContentFiles(contentDir)
	if err != nil {
		return api.SpawnPodRequest{}, fmt.Errorf("load content cache: %w", err)
	}

	// Attestation is optional: only attach one when the install cache
	// actually holds meta.json (a signed-pod install). Its absence is
	// the unsigned-spawn path, not an error.
	var attestation *api.PodAttestation
	if meta != nil {
		attestation, err = install.LoadCachedAttestation(home, cfg.Handle, cfg.PodName, cfg.Version)
		if err != nil {
			return api.SpawnPodRequest{}, fmt.Errorf("load cached attestation: %w", err)
		}
	}

	return api.SpawnPodRequest{
		PodToml:        podToml,
		Inputs:         cfg.Inputs,
		Files:          files,
		PodAttestation: attestation,
	}, nil
}

// waitForCustodyProof polls GET /api/proofs?agent_id=... (via
// client.GetProofsByAgent) until a "custody" proof appears for
// agentID, or timeout elapses. This mirrors internal/smoke's Run
// polling loop; its equivalent lookup, findCustodyIndex, is
// unexported there, so the search is duplicated here rather than
// imported.
func waitForCustodyProof(client *api.Client, agentID string, timeout, pollInterval time.Duration) (*api.Proof, error) {
	deadline := time.Now().Add(timeout)
	for {
		proofs, err := client.GetProofsByAgent(agentID)
		if err != nil {
			return nil, fmt.Errorf("poll proofs: %w", err)
		}
		for i := range proofs {
			if proofs[i].ProofType == "custody" {
				return &proofs[i], nil
			}
		}
		if time.Now().After(deadline) {
			return nil, fmt.Errorf("timeout waiting for custody proof after %s", timeout)
		}
		time.Sleep(pollInterval)
	}
}

// safeLocalPath maps a server-reported deliverable path (which
// carries reef-core's internal "output/" workspace prefix) onto a
// destination path under the user's --out directory, stripping that
// prefix so `results/speech.mp3` reads naturally rather than
// `results/output/speech.mp3`.
//
// The deliverables list is untrusted input from the server — the
// same threat class the deliverables endpoint's own server-side
// traversal defense exists for, just facing the other direction: a
// malicious or compromised reef-core could list a path like
// "output/../../.bashrc" and try to make this CLI overwrite files
// outside --out on the buyer's machine. safeLocalPath refuses that:
//
//   - an absolute remaining path is rejected outright;
//   - every "/"-separated component of the remaining path is checked
//     against the literal string ".." (a per-component check, not a
//     substring scan — a file legitimately named "..foo" or "foo.."
//     is not a traversal attempt and must not be rejected);
//   - the resulting path is resolved to an absolute, cleaned form and
//     must stay under the absolute, cleaned --out directory.
//
// Returns an error instead of a path on any violation. Callers MUST
// abort the whole download step on that error rather than skip the
// offending entry and continue — a hostile server could otherwise
// probe skip-vs-fail behavior for other openings.
//
// The returned path is relative-or-absolute in the same way outDir
// is (it's built with filepath.Join(outDir, ...), not forced
// absolute) so the demo's `results/speech.mp3`-style display output
// is unaffected by this check; the absolute form is only computed
// internally, to make the boundary comparison unambiguous.
func safeLocalPath(outDir, remotePath string) (string, error) {
	rel := strings.TrimPrefix(remotePath, "output/")
	if filepath.IsAbs(rel) {
		return "", fmt.Errorf("unsafe deliverable path %q: absolute path", remotePath)
	}
	for _, part := range strings.Split(rel, "/") {
		if part == ".." {
			return "", fmt.Errorf("unsafe deliverable path %q: contains a \"..\" component", remotePath)
		}
	}

	local := filepath.Join(outDir, filepath.FromSlash(rel))

	absOut, err := filepath.Abs(outDir)
	if err != nil {
		return "", fmt.Errorf("resolve --out directory %s: %w", outDir, err)
	}
	absLocal, err := filepath.Abs(local)
	if err != nil {
		return "", fmt.Errorf("resolve deliverable path %q: %w", remotePath, err)
	}

	boundary := absOut
	if !strings.HasSuffix(boundary, string(filepath.Separator)) {
		boundary += string(filepath.Separator)
	}
	if absLocal != absOut && !strings.HasPrefix(absLocal, boundary) {
		return "", fmt.Errorf("unsafe deliverable path %q: escapes --out directory", remotePath)
	}

	return local, nil
}

// humanSize renders a byte count as a compact binary-prefixed string
// (B / KiB / MiB) for the final deliverables summary line.
func humanSize(n int64) string {
	switch {
	case n >= 1<<20:
		return fmt.Sprintf("%.1f MiB", float64(n)/(1<<20))
	case n >= 1<<10:
		return fmt.Sprintf("%d KiB", n/(1<<10))
	default:
		return fmt.Sprintf("%d B", n)
	}
}
