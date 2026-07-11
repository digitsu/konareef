// Copyright 2026 Jerry David Chan, Konareef.ai
// SPDX-License-Identifier: Apache-2.0

// fieldsroot.go — the konareef-toml/v2 manifest field-commitment
// (`fields_root`), issue #3 item #4 slice 4a. The canonicalizer commits the
// four manifest fields the pod-step circuit consumes (declared_models,
// declared_tools, c_max, r_init) into a Poseidon `fields_root` the circuit can
// prove inclusion against (PRD 1 §5.3 Approach B), instead of parsing canonical
// TOML text in-circuit. The construction is byte-identical to the in-circuit
// inclusion gadget (4b) and reuses internal/poseidon throughout.
package canon

import (
	"crypto/sha256"
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
// trees, sorted ascending by canonical UTF-8 NAME bytes with duplicates
// rejected. leaf(c_max) and leaf(r_init) are LeafHash over the
// directly-packed fixed-width field elements (c_max as an 8-byte LE u64 in a
// 32-byte word; r_init as its 32-byte LE field element). Returns an error if
// a list exceeds its cap, contains duplicates, or if r_init is a
// non-canonical field element.
//
// AMENDED 2026-07-05 — tools_root leaves commit the tool digest (decision
// 2026-07-05-konareef-digest-tool-ids, PRD 1 §5.3 amendment):
//
//	leaf(model_j) = LeafHash(RecordToField(utf8(model_j)))          UNCHANGED
//	leaf(tool_j)  = LeafHash(RecordToField(tool_id_digest_j))       tool_id_digest_j = SHA-256(utf8(tool_j))
//
// tools_root leaves now fold tool_id_digest_j = SHA-256(UTF-8 NFC name
// bytes), not the name bytes directly, so they agree digest-to-digest with
// the §5.4 T_log record's tool_id_digest field (Stage-2 tool_incl parity,
// paygate-zk crates/konareef-circuit/src/gadgets/troot_sha.rs
// tool_id_digest). models_root leaves are UNCHANGED — m_id does not appear
// in per-record encodings, so there is no record-side digest to keep parity
// with. Sort order for both trees is unaffected (tools are still
// sorted/deduped by NAME, since declared_tools is a name array) — only the
// tool leaf PREIMAGE changes.
func FieldsRoot(models, tools []string, cMax uint64, rInit [32]byte) ([32]byte, error) {
	p := poseidon.Default()

	modelsRoot, err := idTreeRoot(p, models, MaxModels, modelLeaf)
	if err != nil {
		return [32]byte{}, fmt.Errorf("declared_models: %w", err)
	}
	toolsRoot, err := idTreeRoot(p, tools, MaxTools, toolLeaf)
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
// sorted, deduplicated id leaves. cap must be a power of two. leafOf selects
// the per-tree leaf construction (modelLeaf or toolLeaf) — the only thing
// that differs between the two trees since the 2026-07-05 digest-tool-ids
// amendment; sorting is always by canonical UTF-8 NAME bytes.
func idTreeRoot(p *poseidon.Params, ids []string, cap int, leafOf func(*poseidon.Params, string) ([32]byte, error)) ([32]byte, error) {
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
			leaf, err := leafOf(p, sorted[i])
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

// modelLeaf is the models_root leaf: LeafHash(RecordToField(utf8(id))).
// UNCHANGED by the 2026-07-05 digest-tool-ids amendment (see FieldsRoot's
// doc-comment asymmetry note) — m_id does not appear in per-record
// encodings, so there is no record-side digest to keep parity with.
func modelLeaf(p *poseidon.Params, id string) ([32]byte, error) {
	return leafOfRecord(p, []byte(id))
}

// toolLeaf is the tools_root leaf: LeafHash(RecordToField(toolIDDigest(id)))
// (AMENDED 2026-07-05, decision 2026-07-05-konareef-digest-tool-ids, PRD 1
// §5.3): folds the SHA-256 name digest rather than the name bytes, so the
// committed leaf agrees digest-to-digest with the §5.4 T_log record's
// tool_id_digest field (Stage-2 tool_incl parity).
func toolLeaf(p *poseidon.Params, id string) ([32]byte, error) {
	d := toolIDDigest(id)
	return leafOfRecord(p, d[:])
}

// toolIDDigest is tool_id_digest (§5.4, amended 2026-07-05): the raw SHA-256
// of the bare UTF-8 NFC tool-name bytes, with no length prefix — mirrors
// paygate-zk crates/konareef-circuit/src/gadgets/troot_sha.rs
// tool_id_digest. id MUST already be validated UTF-8 (idTreeRoot rejects
// invalid UTF-8 before this is called); normalization to NFC is the
// caller's responsibility upstream of FieldsRoot.
func toolIDDigest(id string) [32]byte {
	return sha256.Sum256([]byte(id))
}
