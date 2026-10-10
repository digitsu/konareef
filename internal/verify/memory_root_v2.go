// Copyright 2026 Jerry David Chan, Konareef.ai
// SPDX-License-Identifier: Apache-2.0

// memory_root_v2.go — the verifier's memory-root check for a
// memory-bearing konareef-rinit/v2 bundle (CL-4-live, reef-core#84;
// docs/reference/konareef-rinit-v2-spec.md R-M28 to R-M31).
//
// A public bundle carries no salt, no leaf table and no touched cell
// (spec §3, §8, D5 = P-A). What it carries is the proof's r_in and r_out
// public inputs. For a konareef-pod-step-v1.2 proof the circuit binds r_in
// to z0[Z_R_MEM] (the genesis r_init) and r_out to the final memory root,
// in both the first_step and the last_step buffers (paygate-zk!74). So the
// verifier checks, in this order:
//
//  1. the manifest names konareef-rinit/v2       (MEMORY_RINIT_V1_RETIRED, R-M30)
//  2. the bundle's circuit_id is v1.2            (MEMORY_CIRCUIT_REQUIRED, R-M31)
//  3. both buffers carry one r_in and one r_out,
//     and r_in equals z0[Z_R_MEM]                (MEMORY_ROOT_LANE_MISMATCH)
//  4. r_out = r_in (a read, W-A)                 (MEMORY_WRITE_REFUSED)
//  5. the manifest's declared models, tools and c_max over r_in reproduce
//     the committed fields_root                  (MEMORY_ROOT_NOT_COMMITTED)
//
// Step 5 binds the proven r_init to the publisher-signed trailer, which is
// the same binding a memory-free bundle gets over E20. Whether r_init is
// the konareef-rinit/v2 root of the declared memory is not checkable here:
// that needs the salt or the leaf table, which stay off the public bundle.
// The feeder checks it before proving (R-M20).
//
// A memory-free committed manifest gets checkMemoryFreeLanes (independent
// review of konareef!174 at 4ce611a): its circuit is not v1.2 (R-M31), and
// both buffers carry one r_in, equal to z0[Z_R_MEM] and to the
// memory-free root of the manifest's class (E20, or zero for a legacy
// zero-root manifest). r_out is not compared with r_in for a memory-free
// step: v1, v1.1 and a memory-free v1.2 step keep the synthetic write, so
// r_out != r_in there (paygate-zk a3284518 circuit.rs, the mem_free
// selector doc at lines 141-146; verify.rs check_read_only, which skips
// r_in == E20).
//
// These checks are Type-C only: they run in the canonical-v2/v3 fields_root
// block of verifySnarkPhase. Type-D memory classification is a follow-up.
package verify

import (
	"bytes"
	"errors"
	"fmt"

	"github.com/digitsu/konareef/internal/commission"
	"github.com/digitsu/konareef/internal/vkeystore"
)

// Named reasons of the memory-root checks. Each is reported inside an
// ErrFieldsRootMismatch divergence.
var (
	ErrMemoryRInitV1Retired   = errors.New("MEMORY_RINIT_V1_RETIRED")
	ErrMemoryCircuitRequired  = errors.New("MEMORY_CIRCUIT_REQUIRED")
	ErrMemoryFreeCircuitV1_2  = errors.New("MEMORY_FREE_CIRCUIT_MISMATCH")
	ErrMemoryRootLaneMismatch = errors.New("MEMORY_ROOT_LANE_MISMATCH")
	ErrMemoryWriteRefused     = errors.New("MEMORY_WRITE_REFUSED")
	ErrMemoryRootNotCommitted = errors.New("MEMORY_ROOT_NOT_COMMITTED")
)

// Public-input and z0 offsets the check reads (paygate-zk result.rs
// OFF_R_IN / OFF_R_OUT, circuit.rs Z_R_MEM).
const (
	offRIn      = 0
	offROut     = 32
	zRMemLane   = 18
	zLaneBytes  = 32
	z0FullBytes = 23 * zLaneBytes
)

// checkMemoryBearingCommitment runs the five steps in the file header for
// a bundle whose manifest commits a populated memory root
// (commission.CheckManifestCommitment returned
// ErrManifestCommitmentUnverifiable).
//
// Inputs: the decoded bundle. Output: nil when every step passes, or an
// error wrapping the named reason of the first failing step. The error
// never carries a root or a lane value.
func checkMemoryBearingCommitment(b *BundleV2) error {
	rIn, err := sharedRootLanes(b)
	// Step 1 is reported first and needs only the manifest. The same call
	// gives step 5's result, used after the lane checks.
	commitErr := commission.CheckManifestMemoryCommitment(b.Manifest, rIn)
	if errors.Is(commitErr, commission.ErrManifestMemoryRInitV1) {
		return fmt.Errorf("%w: %v", ErrMemoryRInitV1Retired, commitErr)
	}
	if b.CircuitID != vkeystore.CircuitIDPodStepV1_2 {
		return fmt.Errorf("%w: a memory-bearing konareef-rinit/v2 manifest is proved only by %s, bundle names %q",
			ErrMemoryCircuitRequired, vkeystore.CircuitIDPodStepV1_2, b.CircuitID)
	}
	if err != nil {
		return err
	}
	if !bytes.Equal(b.SpartanCompressResult.FirstStepPublicInputs[offROut:offROut+32], rIn[:]) {
		return fmt.Errorf("%w: a memory-bearing konareef-pod-step-v1.2 proof must serve r_out = r_in", ErrMemoryWriteRefused)
	}
	if commitErr != nil {
		return fmt.Errorf("%w: %v", ErrMemoryRootNotCommitted, commitErr)
	}
	return nil
}

// checkMemoryFreeLanes checks the memory lanes of a bundle whose committed
// manifest is memory-free (commission.CheckManifestCommitment returned nil
// for a manifest that commits a fields_root).
//
// Inputs: the decoded bundle and the memory-free root its manifest
// commits (commission.CommittedMemoryFreeRoot). Output: nil, or an error
// wrapping ErrMemoryFreeCircuitV1_2 (a memory-free manifest proved by
// konareef-pod-step-v1.2, R-M31), ErrMemoryRootLaneMismatch (the buffers
// disagree, or r_in is not z0[Z_R_MEM]) or ErrMemoryRootNotCommitted (r_in
// is not the committed memory-free root). r_out is not checked; see the
// file header.
func checkMemoryFreeLanes(b *BundleV2, committed [32]byte) error {
	if b.CircuitID == vkeystore.CircuitIDPodStepV1_2 {
		return fmt.Errorf("%w: a memory-free manifest is proved by %s, not %s (R-M31)",
			ErrMemoryFreeCircuitV1_2, vkeystore.CircuitIDPodStepV1_1, vkeystore.CircuitIDPodStepV1_2)
	}
	rIn, err := sharedRootLanes(b)
	if err != nil {
		return err
	}
	if rIn != committed {
		return fmt.Errorf("%w: r_in is not the memory-free root the manifest commits", ErrMemoryRootNotCommitted)
	}
	return nil
}

// sharedRootLanes reads r_in and checks the lanes both memory checks
// share: both public-input buffers are publicInputsWidth bytes and carry
// the same r_in and the same r_out, and r_in equals z0[Z_R_MEM].
//
// Input: the decoded bundle. Output: r_in (zero when a buffer is too
// short), and nil or an error wrapping ErrMemoryRootLaneMismatch.
func sharedRootLanes(b *BundleV2) ([32]byte, error) {
	var rIn [32]byte
	scr := b.SpartanCompressResult
	first, last := scr.FirstStepPublicInputs, scr.LastStepPublicInputs
	if len(first) >= offROut+32 {
		copy(rIn[:], first[offRIn:offRIn+32])
	}
	if len(first) != publicInputsWidth || len(last) != publicInputsWidth {
		return rIn, fmt.Errorf("%w: public-input buffers must be %d bytes", ErrMemoryRootLaneMismatch, publicInputsWidth)
	}
	if !bytes.Equal(first[offRIn:offRIn+32], last[offRIn:offRIn+32]) || !bytes.Equal(first[offROut:offROut+32], last[offROut:offROut+32]) {
		return rIn, fmt.Errorf("%w: first_step and last_step carry different r_in or r_out", ErrMemoryRootLaneMismatch)
	}
	if len(scr.Z0) != z0FullBytes || !bytes.Equal(scr.Z0[zRMemLane*zLaneBytes:(zRMemLane+1)*zLaneBytes], rIn[:]) {
		return rIn, fmt.Errorf("%w: r_in is not z0[Z_R_MEM]", ErrMemoryRootLaneMismatch)
	}
	return rIn, nil
}
