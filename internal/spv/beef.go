// Copyright 2026 Jerry David Chan, Konareef.ai
// SPDX-License-Identifier: Apache-2.0

// beef.go — BRC-95 Atomic BEEF, carrying a BRC-62 (V1) or BRC-96 (V2)
// BEEF body.
//
// Atomic envelope: the 4 bytes 01 01 01 01, then the 32-byte subject
// txid in internal order, then the BEEF.
//
// BEEF body: a uint32 LE version (0xEFBE0001 for V1, 0xEFBE0002 for
// V2); a VarInt BUMP count and the BUMPs; a VarInt transaction count and
// the transactions.
//
//   - V1 transaction: raw tx, then one byte (0 or 1) saying whether a
//     BUMP index follows, then the VarInt index.
//   - V2 transaction: one format byte. 0: raw tx. 1: VarInt BUMP index,
//     then raw tx. 2: a 32-byte txid only (no raw tx).

package spv

import "bytes"

// BEEF versions and the Atomic BEEF prefix.
const (
	BEEFV1       uint32 = 0xEFBE0001
	BEEFV2       uint32 = 0xEFBE0002
	atomicPrefix uint32 = 0x01010101
)

// V2 transaction formats (BRC-96).
const (
	beefV2RawTx         byte = 0
	beefV2RawTxAndBump  byte = 1
	beefV2TxIDOnly      byte = 2
	beefNoBumpIndex          = -1
	maxBEEFTransactions      = 10_000
)

// BEEFTx is one transaction entry of a BEEF.
type BEEFTx struct {
	// Tx is the parsed transaction; nil for a V2 txid-only entry.
	Tx *Tx
	// TxID is the transaction id in internal order.
	TxID [32]byte
	// BumpIndex is the index into AtomicBEEF.Bumps, or -1 for none.
	BumpIndex int
}

// AtomicBEEF is a parsed BRC-95 Atomic BEEF.
type AtomicBEEF struct {
	// Subject is the subject txid in internal order.
	Subject [32]byte
	// Version is BEEFV1 or BEEFV2.
	Version uint32
	// Bumps lists the merkle paths.
	Bumps []*BUMP
	// Txs lists the transactions in wire order.
	Txs []BEEFTx
}

// ParseAtomicBEEF parses an Atomic BEEF that fills all of raw.
// Input: raw.
// Output: the parsed envelope, or an error wrapping ErrMalformed. The
// subject must appear exactly once as a full transaction; a BUMP index
// must name an existing BUMP.
func ParseAtomicBEEF(raw []byte) (*AtomicBEEF, error) {
	r := &reader{buf: raw}
	prefix, err := r.uint32LE("atomic beef prefix")
	if err != nil {
		return nil, err
	}
	if prefix != atomicPrefix {
		return nil, malformed("not an atomic beef (prefix 0x%08x)", prefix)
	}
	a := &AtomicBEEF{}
	if a.Subject, err = r.hash32("atomic beef subject txid"); err != nil {
		return nil, err
	}
	if a.Version, err = r.uint32LE("beef version"); err != nil {
		return nil, err
	}
	if a.Version != BEEFV1 && a.Version != BEEFV2 {
		return nil, malformed("beef version 0x%08x unknown", a.Version)
	}
	nBumps, err := r.count("beef bump", 3)
	if err != nil {
		return nil, err
	}
	for i := 0; i < nBumps; i++ {
		b, err := readBUMP(r)
		if err != nil {
			return nil, err
		}
		a.Bumps = append(a.Bumps, b)
	}
	nTxs, err := r.count("beef transaction", 1)
	if err != nil {
		return nil, err
	}
	if nTxs == 0 || nTxs > maxBEEFTransactions {
		return nil, malformed("beef transaction count %d out of range", nTxs)
	}
	for i := 0; i < nTxs; i++ {
		entry, err := readBEEFTx(r, a.Version, len(a.Bumps))
		if err != nil {
			return nil, err
		}
		a.Txs = append(a.Txs, entry)
	}
	if r.remaining() != 0 {
		return nil, malformed("%d trailing bytes after the beef", r.remaining())
	}
	found := 0
	for _, t := range a.Txs {
		if t.TxID == a.Subject {
			if t.Tx == nil {
				return nil, malformed("atomic beef subject is carried as a txid only")
			}
			found++
		}
	}
	if found != 1 {
		return nil, malformed("atomic beef subject appears %d times, want 1", found)
	}
	return a, nil
}

// readBEEFTx reads one transaction entry of the given BEEF version.
func readBEEFTx(r *reader, version uint32, nBumps int) (BEEFTx, error) {
	entry := BEEFTx{BumpIndex: beefNoBumpIndex}
	readIndex := func() error {
		idx, err := r.varInt("beef bump index")
		if err != nil {
			return err
		}
		if idx >= uint64(nBumps) {
			return malformed("beef bump index %d out of range (have %d)", idx, nBumps)
		}
		entry.BumpIndex = int(idx)
		return nil
	}
	readRaw := func() error {
		tx, err := readTx(r)
		if err != nil {
			return err
		}
		entry.Tx = tx
		entry.TxID = tx.TxID()
		return nil
	}
	if version == BEEFV1 {
		if err := readRaw(); err != nil {
			return entry, err
		}
		has, err := r.byte1("beef has-bump flag")
		if err != nil {
			return entry, err
		}
		switch has {
		case 0:
		case 1:
			if err := readIndex(); err != nil {
				return entry, err
			}
		default:
			return entry, malformed("beef has-bump flag %d invalid", has)
		}
		return entry, nil
	}
	format, err := r.byte1("beef v2 tx format")
	if err != nil {
		return entry, err
	}
	switch format {
	case beefV2RawTx:
		return entry, readRaw()
	case beefV2RawTxAndBump:
		if err := readIndex(); err != nil {
			return entry, err
		}
		return entry, readRaw()
	case beefV2TxIDOnly:
		h, err := r.hash32("beef v2 txid")
		if err != nil {
			return entry, err
		}
		entry.TxID = h
		return entry, nil
	default:
		return entry, malformed("beef v2 tx format %d unknown", format)
	}
}

// SubjectTx returns the subject transaction entry.
// Output: the entry (ParseAtomicBEEF guarantees it exists and has a Tx).
func (a *AtomicBEEF) SubjectTx() BEEFTx {
	for _, t := range a.Txs {
		if t.TxID == a.Subject && t.Tx != nil {
			return t
		}
	}
	return BEEFTx{BumpIndex: beefNoBumpIndex}
}

// SubjectBUMP returns the BUMP of the subject transaction, or nil when
// the subject has none.
func (a *AtomicBEEF) SubjectBUMP() *BUMP {
	t := a.SubjectTx()
	if t.BumpIndex < 0 {
		return nil
	}
	return a.Bumps[t.BumpIndex]
}

// FindOutput returns the index of the first output of tx whose locking
// script equals script, or -1.
// Inputs: tx, script. Output: the output index or -1.
func FindOutput(tx *Tx, script []byte) int {
	for i, o := range tx.Outputs {
		if bytes.Equal(o.LockingScript, script) {
			return i
		}
	}
	return -1
}

// OpReturnScript returns the 35-byte BRC-18 script
// OP_FALSE OP_RETURN PUSH32 <hash> that reef-core broadcasts.
// Input: the 32-byte hash. Output: the script.
func OpReturnScript(hash []byte) []byte {
	return append([]byte{0x00, 0x6a, 0x20}, hash...)
}
