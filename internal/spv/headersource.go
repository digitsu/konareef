// Copyright 2026 Jerry David Chan, Konareef.ai
// SPDX-License-Identifier: Apache-2.0

// headersource.go — where a verifier gets block headers.
//
// Implementations:
//
//   - PinnedFile: headers from a local file. Works offline.
//   - Remote: one HTTP header service with a WhatsOnChain-style JSON API.
//   - Agreeing: several sources that must return the same bytes.
//   - First: tries sources in order and uses the first that has the
//     header.
//   - Memory: an in-memory set, for tests and embedding.
//
// The reef-core node whose anchor is being checked must never be a
// header source: it is the party being checked.

package spv

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"
)

// ErrHeaderUnavailable means a source has no header for the height (or
// no tip). It is not evidence of tampering.
var ErrHeaderUnavailable = errors.New("spv: header unavailable")

// ErrHeaderDisagreement means two sources returned different headers for
// the same height, or a source returned a header inconsistent with
// itself. A verifier must not trust either.
var ErrHeaderDisagreement = errors.New("spv: header sources disagree")

// HeaderSource returns block headers for SPV checks.
type HeaderSource interface {
	// HeaderAt returns the 80-byte header at height, or an error
	// wrapping ErrHeaderUnavailable.
	HeaderAt(ctx context.Context, height uint64) ([HeaderSize]byte, error)
	// TipHeight returns the best-chain height, or an error wrapping
	// ErrHeaderUnavailable.
	TipHeight(ctx context.Context) (uint64, error)
}

// ── Memory ──────────────────────────────────────────────────────────

// Memory is an in-memory header source.
type Memory struct {
	// Headers maps a height to its header.
	Headers map[uint64][HeaderSize]byte
	// Tip is the reported tip height.
	Tip uint64
}

// HeaderAt implements HeaderSource.
func (m *Memory) HeaderAt(_ context.Context, height uint64) ([HeaderSize]byte, error) {
	h, ok := m.Headers[height]
	if !ok {
		return h, fmt.Errorf("%w: height %d", ErrHeaderUnavailable, height)
	}
	return h, nil
}

// TipHeight implements HeaderSource.
func (m *Memory) TipHeight(context.Context) (uint64, error) {
	if len(m.Headers) == 0 {
		return 0, ErrHeaderUnavailable
	}
	return m.Tip, nil
}

// ── PinnedFile ──────────────────────────────────────────────────────

// PinnedFileMagic opens a pinned headers file.
const PinnedFileMagic = "KRHDRS1\n"

// maxPinnedHeaders bounds a pinned file (about 80 MB of headers).
const maxPinnedHeaders = 1_000_000

// EncodePinnedFile serializes headers for PinnedFile: the magic, the
// start height as a uint64 LE, then the 80-byte headers in height order.
// Inputs: start, the height of headers[0]; headers. Output: the file bytes.
func EncodePinnedFile(start uint64, headers [][HeaderSize]byte) []byte {
	out := []byte(PinnedFileMagic)
	out = binary.LittleEndian.AppendUint64(out, start)
	for _, h := range headers {
		out = append(out, h[:]...)
	}
	return out
}

// LoadPinnedFile reads and checks a pinned headers file.
// Input: path. Output: a Memory source whose tip is the last header, or
// an error. Each header must name the previous one as its parent, so a
// file cannot splice unrelated headers together.
func LoadPinnedFile(path string) (*Memory, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("spv: read headers file: %w", err)
	}
	return ParsePinnedFile(raw)
}

// ParsePinnedFile parses pinned-file bytes (see EncodePinnedFile).
// Input: raw. Output: a Memory source, or an error.
func ParsePinnedFile(raw []byte) (*Memory, error) {
	head := len(PinnedFileMagic) + 8
	if len(raw) < head || string(raw[:len(PinnedFileMagic)]) != PinnedFileMagic {
		return nil, malformed("not a pinned headers file")
	}
	body := raw[head:]
	if len(body) == 0 || len(body)%HeaderSize != 0 || len(body)/HeaderSize > maxPinnedHeaders {
		return nil, malformed("pinned headers file body is %d bytes", len(body))
	}
	start := binary.LittleEndian.Uint64(raw[len(PinnedFileMagic):head])
	m := &Memory{Headers: make(map[uint64][HeaderSize]byte, len(body)/HeaderSize)}
	var prevHash [32]byte
	for i := 0; i*HeaderSize < len(body); i++ {
		var h [HeaderSize]byte
		copy(h[:], body[i*HeaderSize:(i+1)*HeaderSize])
		parsed, _ := ParseHeader(h[:])
		if i > 0 && parsed.PrevBlock != prevHash {
			return nil, fmt.Errorf("%w: pinned header at height %d does not follow its predecessor",
				ErrHeaderDisagreement, start+uint64(i))
		}
		prevHash = parsed.Hash()
		m.Headers[start+uint64(i)] = h
		m.Tip = start + uint64(i)
	}
	return m, nil
}

// ── Remote ──────────────────────────────────────────────────────────

// maxRemoteBody bounds a remote response. A block response also lists
// txids, about 70 bytes each: WhatsOnChain block 950000 (514 txs) is
// 35,968 bytes, and WhatsOnChain puts txids on separate pages only above
// a count limit. 64 KiB was too small for a block with about 930 or more
// txids, so the cap is 256 KiB. WhatsOnChain /block/{id}/header returns
// the same header fields without txids (632 bytes), and it accepted a
// height in a test on 2026-10-01. It is not used here: its documentation
// gives it for a block hash only, and Bitails does not serve it.
const maxRemoteBody = 256 << 10

// Remote reads headers from an HTTP service with a WhatsOnChain-style
// API:
//
//	GET {BaseURL}/block/height/{height} → {"hash", "version", "merkleroot",
//	    "time", "bits", "nonce", "previousblockhash", ...}
//	GET {BaseURL}/chain/info            → {"blocks": <tip height>, ...}
//
// Some services give the tip at another path with the same "blocks"
// field (Bitails uses /network/info); TipPath names that path. JSON
// field names match without regard to case, so "previousBlockHash"
// also reads as "previousblockhash".
//
// The 80-byte header is rebuilt from the fields, and its hash must equal
// the "hash" the service returned.
type Remote struct {
	// BaseURL is the API root, for example
	// "https://api.whatsonchain.com/v1/bsv/main".
	BaseURL string
	// Client is the HTTP client; nil means one with a 10 s timeout.
	Client *http.Client
	// TipPath is the path, below BaseURL, of the tip endpoint. It must
	// return JSON with a "blocks" field. Empty means DefaultTipPath.
	TipPath string
}

// DefaultTipPath is the WhatsOnChain tip endpoint path.
const DefaultTipPath = "chain/info"

// remoteBlock is the subset of the block JSON Remote reads.
type remoteBlock struct {
	Hash              string          `json:"hash"`
	Version           uint32          `json:"version"`
	MerkleRoot        string          `json:"merkleroot"`
	Time              uint32          `json:"time"`
	Bits              json.RawMessage `json:"bits"`
	Nonce             uint32          `json:"nonce"`
	PreviousBlockHash string          `json:"previousblockhash"`
}

// client returns the configured HTTP client.
func (s *Remote) client() *http.Client {
	if s.Client != nil {
		return s.Client
	}
	return &http.Client{Timeout: 10 * time.Second}
}

// get fetches url and decodes a JSON body into out. A transport failure
// or a non-200 status is ErrHeaderUnavailable.
func (s *Remote) get(ctx context.Context, url string, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrHeaderUnavailable, err)
	}
	resp, err := s.client().Do(req)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrHeaderUnavailable, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("%w: %s returned %d", ErrHeaderUnavailable, url, resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxRemoteBody+1))
	if err != nil || len(body) > maxRemoteBody {
		return fmt.Errorf("%w: %s body unreadable or too large", ErrHeaderUnavailable, url)
	}
	if err := json.Unmarshal(body, out); err != nil {
		return fmt.Errorf("%w: %s body: %v", ErrHeaderUnavailable, url, err)
	}
	return nil
}

// displayHash decodes a 64-hex display-order hash into internal order.
func displayHash(s string) ([32]byte, error) {
	var out [32]byte
	b, err := hex.DecodeString(s)
	if err != nil || len(b) != 32 {
		return out, fmt.Errorf("bad hash %q", s)
	}
	copy(out[:], b)
	return Reverse32(out), nil
}

// parseBits reads "bits" as a hex string ("1d00ffff") or a number.
func parseBits(raw json.RawMessage) (uint32, error) {
	var s string
	if err := json.Unmarshal(raw, &s); err == nil {
		v, err := strconv.ParseUint(strings.TrimPrefix(s, "0x"), 16, 32)
		return uint32(v), err
	}
	var n uint32
	err := json.Unmarshal(raw, &n)
	return n, err
}

// HeaderAt implements HeaderSource.
func (s *Remote) HeaderAt(ctx context.Context, height uint64) ([HeaderSize]byte, error) {
	var out [HeaderSize]byte
	var blk remoteBlock
	url := fmt.Sprintf("%s/block/height/%d", strings.TrimRight(s.BaseURL, "/"), height)
	if err := s.get(ctx, url, &blk); err != nil {
		return out, err
	}
	hash, err := displayHash(blk.Hash)
	if err != nil {
		return out, fmt.Errorf("%w: %v", ErrHeaderDisagreement, err)
	}
	root, err := displayHash(blk.MerkleRoot)
	if err != nil {
		return out, fmt.Errorf("%w: %v", ErrHeaderDisagreement, err)
	}
	prev, err := displayHash(blk.PreviousBlockHash)
	if err != nil {
		return out, fmt.Errorf("%w: %v", ErrHeaderDisagreement, err)
	}
	bits, err := parseBits(blk.Bits)
	if err != nil {
		return out, fmt.Errorf("%w: bits: %v", ErrHeaderDisagreement, err)
	}
	binary.LittleEndian.PutUint32(out[0:4], blk.Version)
	copy(out[4:36], prev[:])
	copy(out[36:68], root[:])
	binary.LittleEndian.PutUint32(out[68:72], blk.Time)
	binary.LittleEndian.PutUint32(out[72:76], bits)
	binary.LittleEndian.PutUint32(out[76:80], blk.Nonce)
	if DoubleSHA256(out[:]) != hash {
		return out, fmt.Errorf("%w: %s: rebuilt header does not hash to the returned block hash",
			ErrHeaderDisagreement, s.BaseURL)
	}
	return out, nil
}

// TipHeight implements HeaderSource.
func (s *Remote) TipHeight(ctx context.Context) (uint64, error) {
	var info struct {
		Blocks uint64 `json:"blocks"`
	}
	tipPath := s.TipPath
	if tipPath == "" {
		tipPath = DefaultTipPath
	}
	url := strings.TrimRight(s.BaseURL, "/") + "/" + strings.TrimLeft(tipPath, "/")
	if err := s.get(ctx, url, &info); err != nil {
		return 0, err
	}
	if info.Blocks == 0 {
		return 0, fmt.Errorf("%w: %s reported no tip", ErrHeaderUnavailable, url)
	}
	return info.Blocks, nil
}

// ── Agreeing / First ────────────────────────────────────────────────

// Agreeing asks every source. All must return the same header; the tip
// is the lowest tip any source reports.
type Agreeing struct {
	// Sources are queried in order; at least one is required.
	Sources []HeaderSource
}

// HeaderAt implements HeaderSource. Any unavailable source makes the
// header unavailable; different bytes are ErrHeaderDisagreement.
func (a *Agreeing) HeaderAt(ctx context.Context, height uint64) ([HeaderSize]byte, error) {
	var first [HeaderSize]byte
	if len(a.Sources) == 0 {
		return first, ErrHeaderUnavailable
	}
	for i, src := range a.Sources {
		h, err := src.HeaderAt(ctx, height)
		if err != nil {
			return first, err
		}
		if i == 0 {
			first = h
		} else if !bytes.Equal(first[:], h[:]) {
			return first, fmt.Errorf("%w: height %d", ErrHeaderDisagreement, height)
		}
	}
	return first, nil
}

// TipHeight implements HeaderSource.
func (a *Agreeing) TipHeight(ctx context.Context) (uint64, error) {
	if len(a.Sources) == 0 {
		return 0, ErrHeaderUnavailable
	}
	var tip uint64
	for i, src := range a.Sources {
		t, err := src.TipHeight(ctx)
		if err != nil {
			return 0, err
		}
		if i == 0 || t < tip {
			tip = t
		}
	}
	return tip, nil
}

// First tries sources in order and uses the first that has the header.
type First struct {
	// Sources are tried in order.
	Sources []HeaderSource
}

// HeaderAt implements HeaderSource. Only ErrHeaderUnavailable moves on to
// the next source; any other error is returned.
func (f *First) HeaderAt(ctx context.Context, height uint64) ([HeaderSize]byte, error) {
	var zero [HeaderSize]byte
	for _, src := range f.Sources {
		h, err := src.HeaderAt(ctx, height)
		if err == nil {
			return h, nil
		}
		if !errors.Is(err, ErrHeaderUnavailable) {
			return zero, err
		}
	}
	return zero, ErrHeaderUnavailable
}

// TipFor returns the tip reported by the same source that HeaderAt uses
// for height (the first source that has that header), so a source that
// did not supply the header cannot inflate the confirmation count.
// Input: height. Output: the tip, or ErrHeaderUnavailable.
func (f *First) TipFor(ctx context.Context, height uint64) (uint64, error) {
	for _, src := range f.Sources {
		if _, err := src.HeaderAt(ctx, height); err != nil {
			if errors.Is(err, ErrHeaderUnavailable) {
				continue
			}
			return 0, err
		}
		return src.TipHeight(ctx)
	}
	return 0, ErrHeaderUnavailable
}

// TipHeight implements HeaderSource: the lowest tip any available
// source reports. The anchor check uses TipFor instead.
func (f *First) TipHeight(ctx context.Context) (uint64, error) {
	var tip uint64
	found := false
	for _, src := range f.Sources {
		t, err := src.TipHeight(ctx)
		if err != nil {
			if errors.Is(err, ErrHeaderUnavailable) {
				continue
			}
			return 0, err
		}
		if !found || t < tip {
			tip, found = t, true
		}
	}
	if !found {
		return 0, ErrHeaderUnavailable
	}
	return tip, nil
}
