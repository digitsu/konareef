// fieldsroot.go — the konareef-toml/v2 manifest field-commitment
// (`fields_root`), issue #3 item #4 slice 4a. The canonicalizer commits the
// four manifest fields the pod-step circuit consumes (declared_models,
// declared_tools, c_max, r_init) into a Poseidon `fields_root` the circuit can
// prove inclusion against (PRD 1 §5.3 Approach B), instead of parsing canonical
// TOML text in-circuit. The construction is byte-identical to the in-circuit
// inclusion gadget (4b) and reuses internal/poseidon throughout.
package canon

import (
	"encoding/binary"
	"fmt"
	"sort"
	"unicode/utf8"

	"github.com/digitsu/konareef/internal/poseidon"
)

// MaxModels / MaxTools are the fixed-max fields_root tree leaf counts, equal to
// the circuit's PRD 1 §7 v1 input caps (crates/konareef-circuit circuit.rs
// MAX_MODELS=16 / MAX_TOOLS=32). The trees are always padded to these counts so
// the in-circuit inclusion proof has a constant depth (vkey-stable).
const (
	MaxModels = 16
	MaxTools  = 32
)

// FieldsRoot computes the konareef-toml/v2 fields_root commitment:
//
//	fields_root = InternalHash( InternalHash(models_root, tools_root),
//	                            InternalHash(leaf(c_max), leaf(r_init)) )
//
// models_root / tools_root are fixed-max (16 / 32) Z-padded balanced Poseidon
// trees over leaf(id) = LeafHash(RecordToField(id_utf8)) for each id, sorted
// ascending by canonical UTF-8 bytes with duplicates rejected. leaf(c_max) and
// leaf(r_init) are LeafHash over the directly-packed fixed-width field elements
// (c_max as an 8-byte LE u64 in a 32-byte word; r_init as its 32-byte LE field
// element). Returns an error if a list exceeds its cap, contains duplicates, or
// if r_init is a non-canonical field element.
func FieldsRoot(models, tools []string, cMax uint64, rInit [32]byte) ([32]byte, error) {
	p := poseidon.Default()

	modelsRoot, err := idTreeRoot(p, models, MaxModels)
	if err != nil {
		return [32]byte{}, fmt.Errorf("declared_models: %w", err)
	}
	toolsRoot, err := idTreeRoot(p, tools, MaxTools)
	if err != nil {
		return [32]byte{}, fmt.Errorf("declared_tools: %w", err)
	}

	var cMaxWord [32]byte
	binary.LittleEndian.PutUint64(cMaxWord[0:8], cMax)
	cMaxLeaf, err := p.LeafHash(cMaxWord)
	if err != nil {
		return [32]byte{}, fmt.Errorf("c_max leaf: %w", err)
	}
	rInitLeaf, err := p.LeafHash(rInit)
	if err != nil {
		return [32]byte{}, fmt.Errorf("r_init leaf (non-canonical?): %w", err)
	}

	left, err := p.InternalHash(modelsRoot, toolsRoot)
	if err != nil {
		return [32]byte{}, err
	}
	right, err := p.InternalHash(cMaxLeaf, rInitLeaf)
	if err != nil {
		return [32]byte{}, err
	}
	return p.InternalHash(left, right)
}

// idTreeRoot builds the fixed-max Z-padded balanced Poseidon tree over the
// sorted, deduplicated id leaves. cap must be a power of two.
func idTreeRoot(p *poseidon.Params, ids []string, cap int) ([32]byte, error) {
	if len(ids) > cap {
		return [32]byte{}, fmt.Errorf("%d entries exceeds cap %d", len(ids), cap)
	}
	seen := make(map[string]struct{}, len(ids))
	for _, id := range ids {
		// Reject empty ids: an empty id leaf goes through the same
		// RecordToField path as the empty-record Z padding and would be
		// indistinguishable from an unused slot — an unsafe fixed-max
		// commitment contract.
		if id == "" {
			return [32]byte{}, fmt.Errorf("empty id is not allowed (collides with the padding leaf)")
		}
		// The v2 spec commits ids as utf8(s) and sorts by canonical UTF-8
		// bytes; reject non-UTF-8 so cross-impl/circuit canonicalization is
		// well-defined (the publish-time API may receive values not parsed
		// directly from TOML).
		if !utf8.ValidString(id) {
			return [32]byte{}, fmt.Errorf("id %q is not valid UTF-8", id)
		}
		if _, dup := seen[id]; dup {
			return [32]byte{}, fmt.Errorf("duplicate entry %q", id)
		}
		seen[id] = struct{}{}
	}

	sorted := append([]string(nil), ids...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i] < sorted[j] })

	// The §5.4 empty-record zero-leaf Z pads unused slots.
	z, err := leafOfRecord(p, nil)
	if err != nil {
		return [32]byte{}, err
	}

	level := make([][32]byte, cap)
	for i := 0; i < cap; i++ {
		if i < len(sorted) {
			leaf, err := leafOfRecord(p, []byte(sorted[i]))
			if err != nil {
				return [32]byte{}, err
			}
			level[i] = leaf
		} else {
			level[i] = z
		}
	}

	for len(level) > 1 {
		next := make([][32]byte, len(level)/2)
		for i := 0; i < len(level); i += 2 {
			node, err := p.InternalHash(level[i], level[i+1])
			if err != nil {
				return [32]byte{}, err
			}
			next[i/2] = node
		}
		level = next
	}
	return level[0], nil
}

// leafOfRecord is the variable-length id leaf: LeafHash(RecordToField(bytes)),
// the same §5.4 fold the tool-log leaves use (also the empty-record Z when
// record is nil/empty).
func leafOfRecord(p *poseidon.Params, record []byte) ([32]byte, error) {
	rf, err := p.RecordToField(record)
	if err != nil {
		return [32]byte{}, err
	}
	return p.LeafHash(rf)
}
