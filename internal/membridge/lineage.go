// internal/membridge/lineage.go — PRD 4 §B.6 lineage operations.
//
// Salt-handling matrix:
//
//	Clone      → preserve salt (read-only copy)
//	Fork       → preserve salt for both branches
//	Migrate    → preserve salt (same lineage, new runtime)
//	NewLineage → reseed via genesis assign (R_max=8)
//
// Mid-lineage reseed is prohibited in all non-NewLineage operations.
package membridge

// Clone returns a defensive copy of src — preserves the pod_salt bytes
// without aliasing the underlying buffer.
func Clone(src []byte) []byte {
	out := make([]byte, len(src))
	copy(out, src)
	return out
}

// Fork returns two independent copies of src — both branches preserve
// the original salt; each may evolve r_init independently.
func Fork(src []byte) ([]byte, []byte) {
	return Clone(src), Clone(src)
}

// Migrate returns a defensive copy of src — same lineage, new runtime
// host; salt invariant.
func Migrate(src []byte) []byte {
	return Clone(src)
}

// NewLineage runs §3.4.2 genesis assign to produce a fresh salt for a
// deliberately-new lineage. Use the runtime CSPRNG-backed sampler in
// production; tests inject deterministic sequences.
func NewLineage(sampler SaltSampler, initialThoughtIDs []uint64) ([]byte, int, error) {
	return GenesisAssign(sampler, initialThoughtIDs)
}
