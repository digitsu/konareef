// internal/membridge/capacity.go — PRD 4 §3.4 capacity enforcement.
//
// EnforceHardCap fails closed at k>500 per §3.4.1.
// GenesisAssign samples pod_salt up to R_max=8 attempts seeking a
// pairwise-distinct index assignment for the initial thought set
// (§3.4.2). The caller provides a sampler closure so callers can
// inject CSPRNG, deterministic test fixtures, or a brute-force search.
// AssignCapture handles the intra-lineage capture path (§3.4.3): a
// derived-index collision fails closed without relocation.
package membridge

import "fmt"

// EnforceHardCap returns ErrCellCapExceeded when k > HardCapK.
func EnforceHardCap(k int) error {
	if k > HardCapK {
		return ErrCellCapExceeded
	}
	return nil
}

// SaltSampler is the runtime hook that produces a candidate pod_salt.
// attempt is zero-based (first call: 0). Returning a salt of length
// != 32 causes GenesisAssign to surface ErrCellSaltLen.
type SaltSampler func(attempt int) ([]byte, error)

// GenesisAssign performs the §3.4.2 reseed loop. Returns the accepted
// salt, the number of attempts taken (1-indexed for the success
// attempt), or ErrGenesisReseedCollision after RMax exhaustion.
//
// Per §3.4.1 the input set size is also bounded; callers MUST gate
// k ≤ HardCapK before invoking GenesisAssign.
func GenesisAssign(sampler SaltSampler, thoughtIDs []uint64) ([]byte, int, error) {
	if err := EnforceHardCap(len(thoughtIDs)); err != nil {
		return nil, 0, err
	}
	for attempt := 0; attempt < RMax; attempt++ {
		salt, err := sampler(attempt)
		if err != nil {
			return nil, attempt + 1, fmt.Errorf("sampler attempt %d: %w", attempt, err)
		}
		if len(salt) != 32 {
			return nil, attempt + 1, ErrCellSaltLen
		}
		seen := make(map[uint32]bool, len(thoughtIDs))
		collision := false
		for _, tid := range thoughtIDs {
			idx, derErr := CellIndex(salt, tid)
			if derErr != nil {
				return nil, attempt + 1, derErr
			}
			if seen[idx] {
				collision = true
				break
			}
			seen[idx] = true
		}
		if !collision {
			return salt, attempt + 1, nil
		}
	}
	return nil, RMax, ErrGenesisReseedCollision
}

// AssignCapture derives the index for thoughtID under the fixed
// lineage salt and rejects with ErrCellIndexCollision when the slot is
// occupied. On success, returns the index; the caller is responsible
// for inserting into `occupied`. occupied is not mutated on failure.
func AssignCapture(occupied map[uint32]uint64, podSalt []byte, thoughtID uint64) (uint32, error) {
	idx, err := CellIndex(podSalt, thoughtID)
	if err != nil {
		return 0, err
	}
	if _, taken := occupied[idx]; taken {
		return idx, ErrCellIndexCollision
	}
	return idx, nil
}
