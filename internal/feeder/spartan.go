// Package feeder is the konareef Pod-Trust-Domain sidecar: it reads the
// relayed step data, assembles the PS-1 PodRecord, calls the prover, and
// POSTs the artifact to reef-core. It is the witness-of-record; reef-core
// never assembles a PodRecord.
package feeder

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"time"
)

// SpartanCompressResult is the PS-1 ProveResponse (paygate-zk wire.rs:55-63).
// All byte fields are base64-encoded strings in the wire format and decoded
// to []byte by the JSON unmarshaler.
type SpartanCompressResult struct {
	SpartanSnark          []byte `json:"spartan_snark"`
	FirstStepPublicInputs []byte `json:"first_step_public_inputs"`
	LastStepPublicInputs  []byte `json:"last_step_public_inputs"`
	VkeyHash              []byte `json:"vkey_hash"`
	GenesisFieldsRoot     []byte `json:"genesis_fields_root"`
	// Z0 and Vkey are the raw genesis fold state (Z_ARITY=23 lanes × 32 = 736
	// bytes) and the raw 32-byte verifier key (pp.digest() LE; vkey_hash =
	// SHA-256(vkey)). PS-1 emits both on the ProveResponse (paygate-zk !54);
	// reef-core ingest persists them for the complete konareef-bundle/v2
	// artifact. The feeder forwards them byte-for-byte; it does not derive them.
	Z0        []byte `json:"z0"`
	Vkey      []byte `json:"vkey"`
	CircuitID string `json:"circuit_id"`
}

// httpClient is the shared HTTP client for PS-1 calls. 5-minute timeout allows
// the prover ~20s to complete with headroom. B3 will reuse this for other
// prover operations.
var httpClient = &http.Client{Timeout: 5 * time.Minute}

// Capped-backoff retry parameters for the PS-1 single-flight 503 case
// (spec §6/§1). PS-1 serialises proving behind a Semaphore, so a 503
// ERR_BUSY is EXPECTED whenever two runs finish near-simultaneously; a
// bounded retry turns that into a transparent wait rather than a spurious
// run failure. The cap bounds total wall-clock to ~1+2+4+8+15 = 30s.
const spartanMaxAttempts = 5

// spartanBackoffBase / spartanBackoffMaxWait are package vars (not consts) so
// tests can shrink the backoff to keep the retry suite fast. Production code
// never reassigns them; the defaults give 1s,2s,4s,8s waits capped at 15s.
var (
	spartanBackoffBase    = 1 * time.Second
	spartanBackoffMaxWait = 15 * time.Second
)

// errPS1Busy sentinels the PS-1 single-flight 503 so the retry loop can
// distinguish it from a generic non-200 (which is terminal). The message
// carries the response body for the final give-up error.
type errPS1Busy struct {
	body       string
	retryAfter time.Duration // honoured Retry-After header, 0 if absent
}

func (e *errPS1Busy) Error() string { return fmt.Sprintf("feeder: PS-1 busy (503): %s", e.body) }

// SpartanCompress issues POST {base}/v1/prove/spartan-compress to the PS-1
// prover, submitting a PodRecord and receiving a SpartanCompressResult.
// PS-1 is unauthenticated/local in the C1 first slice (paygate-zk http.rs);
// BRC-31 payment is a PaaS-hardening concern, not this slice.
//
// On a 503 ERR_BUSY (PS-1 single-flight), the call is retried up to
// spartanMaxAttempts times with capped exponential backoff (honouring a
// Retry-After header when present); after the cap it returns the busy error.
// Any other non-200 (4xx/5xx) is an immediate terminal error. The passed
// ctx cancels both the in-flight request and the inter-attempt wait.
func SpartanCompress(ctx context.Context, base, circuitID string, pr PodRecord) (*SpartanCompressResult, error) {
	body, err := json.Marshal(map[string]any{"circuit_id": circuitID, "pod_record": pr})
	if err != nil {
		return nil, err
	}

	var lastBusy *errPS1Busy
	for attempt := 0; attempt < spartanMaxAttempts; attempt++ {
		res, err := spartanCompressOnce(ctx, base, body)
		if err == nil {
			// VHASH: PS-1 serves two pod-step circuits, so the response must
			// be for the circuit that was asked for. A mismatch would ingest a
			// proof under the wrong id and vkey. Terminal, not retried.
			if circuitID != "" && res.CircuitID != circuitID {
				return nil, fmt.Errorf("feeder: PS-1 answered circuit_id %q, requested %q", res.CircuitID, circuitID)
			}
			return res, nil
		}
		var busy *errPS1Busy
		if !errors.As(err, &busy) {
			// Generic non-200 or transport/parse error: terminal.
			return nil, err
		}
		lastBusy = busy
		// Don't sleep after the final attempt — fall through to give up.
		if attempt == spartanMaxAttempts-1 {
			break
		}
		wait := busy.retryAfter
		if wait <= 0 {
			wait = spartanBackoff(attempt)
		} else if wait > spartanBackoffMaxWait {
			wait = spartanBackoffMaxWait
		}
		timer := time.NewTimer(wait)
		select {
		case <-ctx.Done():
			timer.Stop()
			return nil, fmt.Errorf("feeder: spartan-compress canceled while waiting for PS-1: %w", ctx.Err())
		case <-timer.C:
		}
	}
	return nil, fmt.Errorf("feeder: PS-1 busy after %d attempts: %w", spartanMaxAttempts, lastBusy)
}

// spartanBackoff returns the capped exponential backoff for the given
// zero-based attempt index: 1s, 2s, 4s, 8s, ... capped at spartanBackoffMaxWait.
func spartanBackoff(attempt int) time.Duration {
	wait := spartanBackoffBase << attempt
	if wait > spartanBackoffMaxWait || wait <= 0 {
		return spartanBackoffMaxWait
	}
	return wait
}

// spartanCompressOnce performs a single POST attempt. It returns *errPS1Busy
// on a 503 (so the caller can retry), a generic terminal error on any other
// non-200, and validates the floor fields of the decoded response so a
// malformed PS-1 body fails at the producer rather than forwarding JSON null
// into the reef-core seam.
func spartanCompressOnce(ctx context.Context, base string, body []byte) (*SpartanCompressResult, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, base+"/v1/prove/spartan-compress", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("feeder: spartan-compress: %w", err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	if resp.StatusCode == http.StatusServiceUnavailable {
		return nil, &errPS1Busy{body: string(raw), retryAfter: parseRetryAfter(resp.Header.Get("Retry-After"))}
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("feeder: PS-1 %d: %s", resp.StatusCode, string(raw))
	}
	var res SpartanCompressResult
	if err := json.Unmarshal(raw, &res); err != nil {
		return nil, fmt.Errorf("feeder: parse PS-1 response: %w", err)
	}
	if err := validateSpartanResult(&res); err != nil {
		return nil, err
	}
	return &res, nil
}

// z0FullWidth is the exact byte width of the genesis fold state the
// konareef-pod-step-v1 and -v1.1 circuits fold: Z_ARITY = 23 lanes × 32 bytes = 736
// (post-CL-6; paygate-zk circuit.rs). The feeder forwards z0 verbatim to
// reef-core, and konareef-bundle/v2 + the verifier require exactly this width,
// so the producer rejects any other size here rather than deferring a
// malformed fold-state carrier to a downstream consumer.
const z0FullWidth = 23 * 32

// validateSpartanResult asserts the required floor fields are present (and
// vkey is exactly 32 bytes, z0 exactly 736 bytes) so a malformed PS-1 body
// (e.g. a JSON null/empty or wrong-width field) fails here instead of
// forwarding into the ingest seam. genesis_fields_root is intentionally
// optional (it is empty for the genesis step); z0 and vkey are required
// (PS-1 !54 always emits them).
func validateSpartanResult(res *SpartanCompressResult) error {
	switch {
	case res.CircuitID == "":
		return fmt.Errorf("feeder: PS-1 response missing circuit_id")
	case len(res.SpartanSnark) == 0:
		return fmt.Errorf("feeder: PS-1 response missing spartan_snark")
	case len(res.FirstStepPublicInputs) == 0:
		return fmt.Errorf("feeder: PS-1 response missing first_step_public_inputs")
	case len(res.LastStepPublicInputs) == 0:
		return fmt.Errorf("feeder: PS-1 response missing last_step_public_inputs")
	case len(res.VkeyHash) == 0:
		return fmt.Errorf("feeder: PS-1 response missing vkey_hash")
	case len(res.Z0) != z0FullWidth:
		return fmt.Errorf("feeder: PS-1 response z0 must be %d bytes (23 lanes × 32), got %d", z0FullWidth, len(res.Z0))
	case len(res.Vkey) != 32:
		return fmt.Errorf("feeder: PS-1 response vkey must be 32 bytes, got %d", len(res.Vkey))
	}
	return nil
}

// parseRetryAfter parses the delay-seconds form of a Retry-After header
// (the only form PS-1 emits). An absent/unparseable/negative value yields 0,
// signalling the caller to fall back to exponential backoff.
func parseRetryAfter(v string) time.Duration {
	if v == "" {
		return 0
	}
	secs, err := strconv.Atoi(v)
	if err != nil || secs <= 0 {
		return 0
	}
	return time.Duration(secs) * time.Second
}
