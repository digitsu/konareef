// Package verify — Task 5 production SpartanVerifier: a subprocess shim
// to the Rust arecibo `verify` binary.
//
// # Why a subprocess
//
// There is no Go-native arecibo implementation. The `CompressedSNARK`
// is serialized with bincode from Rust types that only deserialize in
// Rust, and `CompressedSNARK::verify` needs `PublicParams` (regenerated
// deterministically from the circuit shape) — not just the vkey. So the
// only real verifier is a cross-process shim to the Task 2 Step 6 Rust
// `verify` binary (paygate-zk `crates/konareef-circuit/src/bin/verify.rs`).
//
// # Framing
//
// This wiring produces a *verifiable proof artifact with out-of-circuit
// commitment checks* — the Go side re-hashes the disclosed bytes
// (fields_root, h_p/h_r, t_root) and the Rust subprocess verifies the
// CompressedSNARK over the carried z0. It is NOT a claim that the proof
// alone binds the pod execution; trustless in-circuit public-X binding is
// v1.5/CL-7.
//
// # Data transported
//
// Per Finding A the Rust binary regenerates pp/vk itself, so Go transports
// NO proving/verifying key — only `spartan_snark`, `vkey_hash`, the two
// 298-byte offset buffers, and the full 22-lane `z0` (704 bytes, read from
// the bundle's SpartanCompressResult.Z0 — Finding B). Bytes are passed
// through verbatim; the Rust side owns all interpretation. The Go shim
// never re-encodes or flips z0 lanes or digests.
//
// # Fail-closed contract
//
//   - exit 0           → (true, nil)   accept
//   - exit 1           → (false, nil)  reject (proof or vkey_hash parity)
//   - spawn/other exit → (false, err)  fail-closed (missing binary, exit 2
//     usage/parse, signal, etc.)
package verify

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"time"
)

// VerifyBinEnv is the environment variable naming the Rust `verify`
// binary on disk. When unset (and no explicit path supplied to the
// constructor), the production path stays fail-closed.
const VerifyBinEnv = "KONAREEF_VERIFY_BIN"

// z0LaneWidth is the canonical width of a single z0 lane (LE Fq repr).
const z0LaneWidth = 32

// z0LaneCount is the fixed number of z0 lanes the konareef-pod-step-v1
// circuit folds (PRD 1; the verify binary expects exactly 22).
const z0LaneCount = 22

// verifyEnvelope is the on-disk JSON input read by `verify.rs`'s
// VerifyEnvelope. Field names and shapes match that struct EXACTLY
// (verify.rs:58-81): all byte fields serialize as JSON arrays of
// numbers (Go []byte marshals to a base64 string under encoding/json,
// so we MUST marshal byte slices as explicit []int — see toByteArray).
//
//	snark      : byte array  (bincode-serialized CompressedSNARK)
//	vkey       : byte array  (pp.digest() LE bytes; parity bookkeeping)
//	first_step : byte array  (298-byte z0 offset buffer)
//	last_step  : byte array  (298-byte zi offset buffer)
//	vkey_hash  : byte array  (32-byte SHA-256 of pp.digest() LE bytes)
//	circuit_id : string
//	z0_lanes   : array of 22 arrays of 32 bytes (LE Fq lanes)
type verifyEnvelope struct {
	Snark     []int   `json:"snark"`
	Vkey      []int   `json:"vkey"`
	FirstStep []int   `json:"first_step"`
	LastStep  []int   `json:"last_step"`
	VkeyHash  []int   `json:"vkey_hash"`
	CircuitID string  `json:"circuit_id"`
	Z0Lanes   [][]int `json:"z0_lanes"`
}

// toByteArray converts a Go byte slice into the []int shape serde_json
// deserializes into a Rust Vec<u8>. encoding/json would otherwise emit a
// base64 string for []byte, which serde would reject.
func toByteArray(b []byte) []int {
	out := make([]int, len(b))
	for i, v := range b {
		out[i] = int(v)
	}
	return out
}

// subprocessVerifier is the production SpartanVerifier. It holds the full
// SpartanCompressResult so it can read the 704-byte z0 (which the 4-arg
// SpartanVerifier interface does not carry) and the carried vkey, then
// shells out to the Rust `verify` binary.
type subprocessVerifier struct {
	// binPath is the resolved path to the Rust `verify` binary.
	binPath string
	// scr is the decoded carrier holding z0 and the public-input buffers.
	scr SpartanCompressResult
	// vkey is the bundle-carried vkey (pp.digest() LE bytes); transported
	// for envelope completeness — the Rust binary regenerates pp/vk and
	// only uses vkey_hash for the parity check.
	vkey []byte
	// timeout bounds the subprocess. A real 173k-constraint verify can
	// take tens of seconds; the default is generous.
	timeout time.Duration
}

// Verify implements SpartanVerifier. The interface args (snark,
// firstStep, lastStep, vkey) are honoured, but z0 — which the interface
// cannot carry — is read from the held SpartanCompressResult.Z0. The
// held scr's snark/buffers are authoritative and identical to the args
// (both come from the same decoded bundle); we use the args where the
// interface supplies them and the scr for z0.
func (v subprocessVerifier) Verify(snark, firstStepPublicInputs, lastStepPublicInputs, vkey []byte) (bool, error) {
	if v.binPath == "" {
		return false, fmt.Errorf("%w: %s not set", ErrSnarkVerifierNotConfigured, VerifyBinEnv)
	}

	z0 := v.scr.Z0
	if len(z0) != z0LaneCount*z0LaneWidth {
		return false, fmt.Errorf("%w: z0 length=%d, want %d (22 lanes × 32 bytes)",
			ErrProofRejected, len(z0), z0LaneCount*z0LaneWidth)
	}

	lanes := make([][]int, z0LaneCount)
	for i := 0; i < z0LaneCount; i++ {
		lane := z0[i*z0LaneWidth : (i+1)*z0LaneWidth]
		lanes[i] = toByteArray(lane)
	}

	env := verifyEnvelope{
		Snark:     toByteArray(snark),
		Vkey:      toByteArray(vkey),
		FirstStep: toByteArray(firstStepPublicInputs),
		LastStep:  toByteArray(lastStepPublicInputs),
		VkeyHash:  toByteArray(v.scr.VkeyHash),
		CircuitID: v.scr.CircuitID,
		Z0Lanes:   lanes,
	}

	envBytes, err := json.Marshal(env)
	if err != nil {
		return false, fmt.Errorf("%w: marshal verify envelope: %v", ErrProofRejected, err)
	}

	tmp, err := os.CreateTemp("", "konareef-verify-*.json")
	if err != nil {
		return false, fmt.Errorf("%w: create temp envelope: %v", ErrProofRejected, err)
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath)
	if _, err := tmp.Write(envBytes); err != nil {
		tmp.Close()
		return false, fmt.Errorf("%w: write temp envelope: %v", ErrProofRejected, err)
	}
	if err := tmp.Close(); err != nil {
		return false, fmt.Errorf("%w: close temp envelope: %v", ErrProofRejected, err)
	}

	exitCode, runErr := runVerifyBinary(v.binPath, tmpPath, v.timeout)
	if runErr != nil {
		// Spawn failure / signal / timeout — fail-closed with the error.
		return false, fmt.Errorf("%w: spawn %s: %v", ErrProofRejected, v.binPath, runErr)
	}

	switch exitCode {
	case 0:
		return true, nil
	case 1:
		// The Rust verifier rejected (proof invalid or vkey_hash parity
		// failure). This is the Negative-DoD path: a corrupted snark byte
		// lands here, NOT via a Go short-circuit.
		return false, nil
	default:
		// Exit 2 (usage/parse/malformed z0) or any other code is a
		// fail-closed error, not a clean reject.
		return false, fmt.Errorf("%w: verify binary exit code %d", ErrProofRejected, exitCode)
	}
}

// runVerifyBinary spawns the Rust verify binary against the envelope file
// and returns its exit code. A non-nil error means the process could not
// be run to a clean exit (spawn failure, killed by signal, timeout) —
// distinct from a clean non-zero exit code, which is returned with a nil
// error so the caller maps it via the fail-closed switch above.
func runVerifyBinary(binPath, envelopePath string, timeout time.Duration) (int, error) {
	ctx := context.Background()
	if timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, timeout)
		defer cancel()
	}

	cmd := exec.CommandContext(ctx, binPath, envelopePath)
	cmd.Stderr = os.Stderr // surface the Rust binary's diagnostics

	err := cmd.Run()
	if err == nil {
		return 0, nil
	}
	if exitErr, ok := err.(*exec.ExitError); ok {
		// Clean non-zero exit. ExitCode() is -1 only if killed by signal,
		// which we treat as a spawn-class failure (error path).
		code := exitErr.ExitCode()
		if code >= 0 {
			return code, nil
		}
		return code, fmt.Errorf("verify binary terminated by signal: %v", err)
	}
	// Could not start the process at all (missing binary, perm, etc.).
	return -1, err
}

// newSubprocessVerifier builds a subprocessVerifier from a decoded bundle
// and an explicit binary path. binPath must be non-empty; callers resolve
// it from the env / flag.
func newSubprocessVerifier(b *BundleV2, binPath string) subprocessVerifier {
	return subprocessVerifier{
		binPath: binPath,
		scr:     b.SpartanCompressResult,
		vkey:    b.Vkey,
		timeout: 5 * time.Minute,
	}
}

// ProductionVerifyOptions builds the live-path VerifyOptions for a decoded
// bundle. When KONAREEF_VERIFY_BIN is set, it wires the subprocess Spartan
// verifier; when unset, Spartan stays nil so VerifyV2 falls back to the
// failClosedVerifier (production default) — the verdict cannot be PASS
// without a real verifier. This is the NON-TEST constructor referenced by
// the live TUI/CLI path; it never returns the accepting stub.
//
// durable threads the existing --durable knob through unchanged.
func ProductionVerifyOptions(b *BundleV2, durable bool) VerifyOptions {
	opts := VerifyOptions{Durable: durable}
	if binPath := os.Getenv(VerifyBinEnv); binPath != "" {
		opts.Spartan = newSubprocessVerifier(b, binPath)
	}
	return opts
}

// VerifyV2Production decodes konareef-bundle/v2 bytes and verifies them on
// the LIVE path with a real Spartan verifier when KONAREEF_VERIFY_BIN is
// set (fail-closed otherwise). It is the production analogue of VerifyV2:
// VerifyV2 takes pre-built opts (so the verifier must be known before the
// bundle is decoded), but the subprocess verifier needs the decoded
// bundle's z0 — so this entry decodes first, then constructs the verifier
// around the decoded bundle.
//
// First-byte dispatch and divergence semantics match VerifyV2 exactly;
// only the konareef-bundle/v2 CBOR branch differs in that it injects the
// subprocess verifier.
func VerifyV2Production(input []byte, durable bool) *ResultV2 {
	r := &ResultV2{OK: true}
	if len(input) == 0 {
		r.diverge(ErrMalformedCBOR, "empty input")
		return r
	}

	first := input[0]
	switch {
	case first >= 0xA0 && first <= 0xBB:
		b, err := decodeBundleV2(input)
		if err != nil {
			r.OK = false
			r.Divergences = append(r.Divergences, Divergence{Err: err, Msg: err.Error()})
			return r
		}
		r.ChainLength = len(b.Chain)
		verifySnarkPhase(b, ProductionVerifyOptions(b, durable), r)
		return r
	case first == 0x7B:
		r.diverge(ErrMalformedCBOR, "v1 JSON bundle on V2 entry; use legacy Verify(b *Bundle)")
	default:
		r.diverge(ErrMalformedCBOR, fmt.Sprintf("unrecognized first byte 0x%02X", first))
	}
	return r
}
