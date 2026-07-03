package poseidon

import (
	"encoding/binary"
	"fmt"
	"math/big"
)

// bytesPerChunk is the payload group size for the value_hash / record fold:
// 31 bytes packed into a 32-byte little-endian word guarantees the chunk value
// is < 2^248 < p by construction, so no in-range constraint is needed.
const bytesPerChunk = 31

// valueHashMaxPayload is the pinned cap for value_hash (sponge arity-4: one
// length element + up to three 31-byte content chunks).
const valueHashMaxPayload = 93

// leBytesToInt interprets b as a little-endian unsigned integer.
func leBytesToInt(b []byte) *big.Int {
	r := make([]byte, len(b))
	for i := range b {
		r[i] = b[len(b)-1-i]
	}
	return new(big.Int).SetBytes(r)
}

// intToLE32 serializes a field element (already reduced mod p, hence < 2^255)
// to 32-byte little-endian, matching the Python oracle's _to_le32.
func intToLE32(v *big.Int) [32]byte {
	var be [32]byte
	v.FillBytes(be[:]) // big-endian, left zero-padded to 32 bytes
	var le [32]byte
	for i := 0; i < 32; i++ {
		le[i] = be[31-i]
	}
	return le
}

// parseField is the canonical wire field-element parse: 32-byte little-endian,
// rejected iff the decoded integer is >= p (non-canonical). Mirrors the Python
// oracle's parse_field.
func (pr *Params) parseField(b [32]byte) (*big.Int, error) {
	v := leBytesToInt(b[:])
	if v.Cmp(pr.p) >= 0 {
		return nil, fmt.Errorf("non-canonical field element: integer >= p")
	}
	return v, nil
}

// sbox computes the quintic S-box x^5 mod p.
func (pr *Params) sbox(x *big.Int) *big.Int {
	return new(big.Int).Exp(x, big.NewInt(5), pr.p)
}

// mdsMul returns the MDS matrix-vector product: out[i] = sum_j mds[i][j]*state[j] mod p.
func (in *instance) mdsMul(state []*big.Int, p *big.Int) []*big.Int {
	out := make([]*big.Int, in.t)
	for i := 0; i < in.t; i++ {
		acc := new(big.Int)
		term := new(big.Int)
		for j := 0; j < in.t; j++ {
			term.Mul(in.mds[i][j], state[j])
			acc.Add(acc, term)
		}
		out[i] = acc.Mod(acc, p)
	}
	return out
}

// permute applies the neptune Correct-mode Poseidon permutation: RF/2 full
// rounds, RP partial rounds, RF/2 full rounds. Round constants are consumed
// contiguously (t per round). state[0] is the domain tag on entry.
func (pr *Params) permute(in *instance, state []*big.Int) []*big.Int {
	for i := range state {
		state[i] = new(big.Int).Mod(state[i], pr.p)
	}
	off := 0
	half := in.fullRounds / 2

	fullRound := func() {
		next := make([]*big.Int, in.t)
		for i := 0; i < in.t; i++ {
			x := new(big.Int).Add(state[i], in.rc[off+i])
			x.Mod(x, pr.p)
			next[i] = pr.sbox(x)
		}
		off += in.t
		state = in.mdsMul(next, pr.p)
	}

	partialRound := func() {
		next := make([]*big.Int, in.t)
		for i := 0; i < in.t; i++ {
			x := new(big.Int).Add(state[i], in.rc[off+i])
			next[i] = x.Mod(x, pr.p)
		}
		off += in.t
		next[0] = pr.sbox(next[0])
		state = in.mdsMul(next, pr.p)
	}

	for r := 0; r < half; r++ {
		fullRound()
	}
	for r := 0; r < in.partialRounds; r++ {
		partialRound()
	}
	for r := 0; r < half; r++ {
		fullRound()
	}
	return state
}

// fixedHash runs a single fixed-width permutation: state = [domain_tag, inputs...]
// (len(inputs) == t-1), and returns state[1] serialized as 32-byte little-endian.
func (pr *Params) fixedHash(in *instance, inputs []*big.Int) ([32]byte, error) {
	if len(inputs) != in.t-1 {
		return [32]byte{}, fmt.Errorf("expected %d inputs, got %d", in.t-1, len(inputs))
	}
	state := make([]*big.Int, in.t)
	state[0] = new(big.Int).Set(in.domainTag)
	for i, x := range inputs {
		state[i+1] = new(big.Int).Mod(x, pr.p)
	}
	state = pr.permute(in, state)
	return intToLE32(state[1]), nil
}

// InternalHash is the arity-2 node hash over preimage [l, r]. Both inputs must
// be canonical 32-byte little-endian field elements.
func (pr *Params) InternalHash(l, r [32]byte) ([32]byte, error) {
	lv, err := pr.parseField(l)
	if err != nil {
		return [32]byte{}, fmt.Errorf("left input: %w", err)
	}
	rv, err := pr.parseField(r)
	if err != nil {
		return [32]byte{}, fmt.Errorf("right input: %w", err)
	}
	return pr.fixedHash(pr.node, []*big.Int{lv, rv})
}

// LeafHash is the arity-2 leaf hash over preimage [vh, 0].
func (pr *Params) LeafHash(vh [32]byte) ([32]byte, error) {
	v, err := pr.parseField(vh)
	if err != nil {
		return [32]byte{}, fmt.Errorf("value hash input: %w", err)
	}
	return pr.fixedHash(pr.leaf, []*big.Int{v, big.NewInt(0)})
}

// payloadChunks splits a payload into field-element ints per the pinned rule:
// chunk[0] encodes (u64 LE length, byte[8]=0x10), followed by 31-byte LE groups,
// each right-zero-padded into a 32-byte LE word.
func payloadChunks(payload []byte) []*big.Int {
	out := make([]*big.Int, 0, 1+len(payload)/bytesPerChunk+1)
	lenWord := make([]byte, 32)
	binary.LittleEndian.PutUint64(lenWord[0:8], uint64(len(payload)))
	lenWord[8] = 0x10
	out = append(out, leBytesToInt(lenWord))
	for i := 0; i < len(payload); i += bytesPerChunk {
		end := i + bytesPerChunk
		if end > len(payload) {
			end = len(payload)
		}
		word := make([]byte, 32)
		copy(word, payload[i:end])
		out = append(out, leBytesToInt(word))
	}
	return out
}

// ValueHash is the arity-4 sponge hash over [length_element, c0, c1, c2], with
// chunks beyond those produced by payloadChunks zero-padded to fill the 4 lanes.
func (pr *Params) ValueHash(payload []byte) ([32]byte, error) {
	if len(payload) > valueHashMaxPayload {
		return [32]byte{}, fmt.Errorf("payload %d bytes exceeds value_hash cap %d", len(payload), valueHashMaxPayload)
	}
	c := payloadChunks(payload)
	inputs := make([]*big.Int, pr.sponge.t-1) // 4
	for i := range inputs {
		if i < len(c) {
			inputs[i] = c[i]
		} else {
			inputs[i] = big.NewInt(0)
		}
	}
	return pr.fixedHash(pr.sponge, inputs)
}

// MaxRecordBytes is the pinned per-record cap (PRD 1 §5.4 / troot_poseidon.rs
// MAX_RECORD_BYTES). Records beyond this could not have been proven in-circuit.
const MaxRecordBytes = 330

// MaxTLogRecords is the pinned tool-log record cap (PRD 1 §7 v1 / troot_poseidon.rs
// MAX_TLOG_RECORDS). Logs beyond this could not have been proven in-circuit.
const MaxTLogRecords = 16

// domainElement builds a 32-byte LE field element with a u64 little-endian value
// in bytes 0..8 and a domain tag in byte 8 (the 0x13 record-fold / 0x03
// length-binding tags, carried as DATA, not Poseidon capacity params).
func domainElement(value int, tag byte) [32]byte {
	var le [32]byte
	binary.LittleEndian.PutUint64(le[0:8], uint64(value))
	le[8] = tag
	return le
}

// recordChunks splits record bytes into 31-byte little-endian chunk field
// elements (final group right-zero-padded into a 32-byte LE word).
func recordChunks(record []byte) [][32]byte {
	var out [][32]byte
	for i := 0; i < len(record); i += bytesPerChunk {
		end := i + bytesPerChunk
		if end > len(record) {
			end = len(record)
		}
		var word [32]byte
		copy(word[:], record[i:end])
		out = append(out, word)
	}
	return out
}

// recordToFieldRaw folds the per-record bytes into a single field element via the
// arity-2 node hash, seeded with the 0x13 domain+length element. No cap check
// (used for the empty Z record); callers enforce MaxRecordBytes.
func (pr *Params) recordToFieldRaw(record []byte) ([32]byte, error) {
	d := domainElement(len(record), 0x13)
	chunks := recordChunks(record)
	var first [32]byte // zero when the record is empty (m == 0)
	if len(chunks) > 0 {
		first = chunks[0]
	}
	acc, err := pr.InternalHash(d, first)
	if err != nil {
		return [32]byte{}, err
	}
	for i := 1; i < len(chunks); i++ {
		if acc, err = pr.InternalHash(acc, chunks[i]); err != nil {
			return [32]byte{}, err
		}
	}
	return acc, nil
}

// RecordToField folds one tool-log record's canonical bytes into a single field
// element (§5.4). Rejects records over MaxRecordBytes (fail-closed: the circuit
// could not have proven them).
func (pr *Params) RecordToField(record []byte) ([32]byte, error) {
	if len(record) > MaxRecordBytes {
		return [32]byte{}, fmt.Errorf("record %d bytes exceeds cap %d", len(record), MaxRecordBytes)
	}
	return pr.recordToFieldRaw(record)
}

// zLeaf is the empty-record zero-leaf Z = LeafHash(RecordToField([])), used to
// right-pad the leaf level to a power of two.
func (pr *Params) zLeaf() ([32]byte, error) {
	rf, err := pr.recordToFieldRaw(nil)
	if err != nil {
		return [32]byte{}, err
	}
	return pr.LeafHash(rf)
}

// treeRootTop builds the balanced tree over LeafHash(RecordToField(record))
// leaves, right-padded with Z to the next power of two. |T|==0 -> Z.
func (pr *Params) treeRootTop(records [][]byte) ([32]byte, error) {
	z, err := pr.zLeaf()
	if err != nil {
		return [32]byte{}, err
	}
	if len(records) == 0 {
		return z, nil
	}
	level := make([][32]byte, 0, len(records))
	for i, r := range records {
		if len(r) > MaxRecordBytes {
			return [32]byte{}, fmt.Errorf("record %d: %d bytes exceeds cap %d", i, len(r), MaxRecordBytes)
		}
		rf, err := pr.recordToFieldRaw(r)
		if err != nil {
			return [32]byte{}, err
		}
		leaf, err := pr.LeafHash(rf)
		if err != nil {
			return [32]byte{}, err
		}
		level = append(level, leaf)
	}
	for n := nextPow2(len(level)); len(level) < n; {
		level = append(level, z)
	}
	for len(level) > 1 {
		next := make([][32]byte, 0, len(level)/2)
		for i := 0; i < len(level); i += 2 {
			node, err := pr.InternalHash(level[i], level[i+1])
			if err != nil {
				return [32]byte{}, err
			}
			next = append(next, node)
		}
		level = next
	}
	return level[0], nil
}

// nextPow2 returns the smallest power of two >= n (>= 1).
func nextPow2(n int) int {
	p := 1
	for p < n {
		p <<= 1
	}
	return p
}

// TRoot reconstructs the normative Poseidon t_root (§5.4):
// t_root = InternalHash(length_binding_element(|T|), tree_root_top(records)),
// where the length element carries the 0x03 count tag. Rejects logs over
// MaxTLogRecords fail-closed.
func (pr *Params) TRoot(records [][]byte) ([32]byte, error) {
	if len(records) > MaxTLogRecords {
		return [32]byte{}, fmt.Errorf("tool-log %d records exceeds cap %d", len(records), MaxTLogRecords)
	}
	top, err := pr.treeRootTop(records)
	if err != nil {
		return [32]byte{}, err
	}
	return pr.InternalHash(domainElement(len(records), 0x03), top)
}

// EmptyRoots returns the 21 empty-subtree roots E0..E20, where E0 = LeafHash(0)
// and E_k = InternalHash(E_{k-1}, E_{k-1}).
func (pr *Params) EmptyRoots() [][32]byte {
	roots := make([][32]byte, 0, 21)
	e0, err := pr.LeafHash([32]byte{})
	if err != nil {
		panic("poseidon: EmptyRoots: " + err.Error()) // zero is canonical; unreachable
	}
	roots = append(roots, e0)
	for k := 0; k < 20; k++ {
		prev := roots[len(roots)-1]
		e, err := pr.InternalHash(prev, prev)
		if err != nil {
			panic("poseidon: EmptyRoots: " + err.Error()) // prior roots are canonical; unreachable
		}
		roots = append(roots, e)
	}
	return roots
}
