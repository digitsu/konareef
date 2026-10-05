// Copyright 2026 Jerry David Chan, Konareef.ai
// SPDX-License-Identifier: Apache-2.0

// tx.go — raw BSV transaction parsing, only as far as the chain-head
// anchor needs it: the outputs (to find the OP_RETURN) and the exact
// byte range (to compute the txid).

package spv

// Output is one transaction output.
type Output struct {
	// Satoshis is the output value.
	Satoshis uint64
	// LockingScript is the output script, byte for byte.
	LockingScript []byte
}

// Tx is a parsed raw transaction.
type Tx struct {
	// Raw is the exact serialized bytes the transaction was parsed from.
	Raw []byte
	// InputCount is the number of inputs (always at least one).
	InputCount int
	// Outputs lists the outputs in order.
	Outputs []Output
}

// TxID returns the transaction id in internal byte order: the double
// SHA-256 of the raw bytes.
// Output: 32 bytes; reverse it (Reverse32) for the display order.
func (t *Tx) TxID() [32]byte { return DoubleSHA256(t.Raw) }

// ParseTx parses one raw transaction that fills all of raw.
// Input: raw, the serialized transaction.
// Output: the parsed Tx, or an error wrapping ErrMalformed (truncation,
// trailing bytes, zero inputs, or the BRC-30 extended format).
func ParseTx(raw []byte) (*Tx, error) {
	r := &reader{buf: raw}
	tx, err := readTx(r)
	if err != nil {
		return nil, err
	}
	if r.remaining() != 0 {
		return nil, malformed("%d trailing bytes after the transaction", r.remaining())
	}
	return tx, nil
}

// readTx reads one transaction from r and records its exact bytes.
func readTx(r *reader) (*Tx, error) {
	start := r.off
	if _, err := r.uint32LE("tx version"); err != nil {
		return nil, err
	}
	// Smallest input: 32 prevout + 4 index + 1 script length + 4 sequence.
	nIn, err := r.count("tx input", 41)
	if err != nil {
		return nil, err
	}
	if nIn == 0 {
		// A zero input count is also the BRC-30 extended-format marker.
		// Neither is a transaction this package accepts.
		return nil, malformed("transaction has no inputs (or uses the extended format)")
	}
	for i := 0; i < nIn; i++ {
		if _, err := r.bytes(36, "tx outpoint"); err != nil {
			return nil, err
		}
		n, err := r.count("input script byte", 1)
		if err != nil {
			return nil, err
		}
		if _, err := r.bytes(n, "input script"); err != nil {
			return nil, err
		}
		if _, err := r.bytes(4, "input sequence"); err != nil {
			return nil, err
		}
	}
	// Smallest output: 8 value + 1 script length.
	nOut, err := r.count("tx output", 9)
	if err != nil {
		return nil, err
	}
	outputs := make([]Output, 0, nOut)
	for i := 0; i < nOut; i++ {
		v, err := r.bytes(8, "output value")
		if err != nil {
			return nil, err
		}
		n, err := r.count("output script byte", 1)
		if err != nil {
			return nil, err
		}
		script, err := r.bytes(n, "output script")
		if err != nil {
			return nil, err
		}
		var sats uint64
		for j := 7; j >= 0; j-- {
			sats = sats<<8 | uint64(v[j])
		}
		outputs = append(outputs, Output{Satoshis: sats, LockingScript: script})
	}
	if _, err := r.uint32LE("tx lock time"); err != nil {
		return nil, err
	}
	return &Tx{Raw: r.buf[start:r.off], InputCount: nIn, Outputs: outputs}, nil
}
