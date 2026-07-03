// known.go — `~/.konareef/known_publishers.json` ops and the
// fingerprint helper.
//
// The hybrid TOFU + marketplace-directory trust model
// (install-path-design v0 §"Trust Model") stores every publisher
// pubkey the user has explicitly trusted in a small JSON file at
// the user's home. The local record is authoritative — when a
// future install hits a known publisher, reef-core's pubkey claim is
// silently verified against this file, not the other way around.
//
// File format (v1):
//
//   {
//     "version": "konareef-known-publishers/v1",
//     "publishers": {
//       "alice": {
//         "pubkey_hex":         "02a3…",
//         "fingerprint":        "02a3:f9b4:c5d6",
//         "first_seen_at":      "2026-04-18T09:13:00Z",
//         "last_verified_at":   "2026-05-21T13:42:08Z",
//         "key_history": [
//           { "pubkey_hex": "02a3…", "active_from": "…", "active_to": null, "rotated_to": null }
//         ]
//       }
//     }
//   }
//
// Permissions: 0644 — this file is NOT secret (it records public
// keys the user has trusted) but is a critical local trust anchor;
// the user can hand-edit it if a publisher needs to be removed.

package install

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

const (
	// KnownPublishersVersion is the on-disk schema tag for v1.
	KnownPublishersVersion = "konareef-known-publishers/v1"

	knownDirName  = ".konareef"
	knownFileName = "known_publishers.json"
	knownFileMode = os.FileMode(0o644)
	knownDirMode  = os.FileMode(0o700)
)

// KnownPublishers is the in-memory view of known_publishers.json.
type KnownPublishers struct {
	Version    string                      `json:"version"`
	Publishers map[string]*PublisherRecord `json:"publishers"`
}

// PublisherRecord is one publisher's local trust record.
type PublisherRecord struct {
	PubkeyHex      string            `json:"pubkey_hex"`
	Fingerprint    string            `json:"fingerprint"`
	FirstSeenAt    time.Time         `json:"first_seen_at"`
	LastVerifiedAt time.Time         `json:"last_verified_at"`
	KeyHistory     []KeyHistoryEntry `json:"key_history"`
}

// KeyHistoryEntry is one row in the per-publisher key-rotation log.
// `active_to == nil` means the key is current; `rotated_to == nil`
// means we never recorded a successor (e.g., admin recovery wiped
// it). New entries are appended; existing rows are never mutated.
type KeyHistoryEntry struct {
	PubkeyHex  string     `json:"pubkey_hex"`
	ActiveFrom time.Time  `json:"active_from"`
	ActiveTo   *time.Time `json:"active_to"`
	RotatedTo  *string    `json:"rotated_to"`
}

// TrustStatus is the outcome of matching a fetched pubkey against
// the local trust record. The three values map 1:1 to the three UX
// flows in install-path-design v0 §"What the User Sees".
type TrustStatus int

const (
	// TrustNew — no record for this handle. First-contact flow:
	// extra warnings + default-N confirmation prompt.
	TrustNew TrustStatus = iota

	// TrustOK — recorded pubkey matches the fetched one. Repeat-
	// install flow: brief "known publisher" line + default-Y prompt.
	TrustOK

	// TrustChange — recorded pubkey differs from the fetched one.
	// Key-change flow: refuse install with explicit guidance to
	// `konareef pod trust` after out-of-band confirmation.
	TrustChange
)

// TrustMatch is the structured result of KnownPublishers.Match.
type TrustMatch struct {
	Status TrustStatus
	Known  *PublisherRecord // nil iff Status == TrustNew
}

// ── File path / I/O ────────────────────────────────────────────

// KnownPublishersPath returns <home>/.konareef/known_publishers.json.
func KnownPublishersPath(home string) string {
	return filepath.Join(home, knownDirName, knownFileName)
}

// LoadKnownPublishers reads the known-publishers file. A missing
// file is NOT an error — it returns a fresh empty struct, so the
// caller can treat every install as "first contact" until the first
// Save lands the file on disk.
func LoadKnownPublishers(home string) (*KnownPublishers, error) {
	path := KnownPublishersPath(home)
	body, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return &KnownPublishers{
			Version:    KnownPublishersVersion,
			Publishers: map[string]*PublisherRecord{},
		}, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read known_publishers: %w", err)
	}

	var k KnownPublishers
	if err := json.Unmarshal(body, &k); err != nil {
		return nil, fmt.Errorf("parse known_publishers: %w", err)
	}
	if k.Publishers == nil {
		k.Publishers = map[string]*PublisherRecord{}
	}
	if k.Version == "" {
		k.Version = KnownPublishersVersion
	}
	return &k, nil
}

// Save writes the known-publishers file atomically with mode 0644.
// The parent .konareef directory is created (mode 0700) on first
// save — identity.json already lives in the same directory, so the
// permission profile matches.
func (k *KnownPublishers) Save(home string) error {
	dir := filepath.Join(home, knownDirName)
	if err := os.MkdirAll(dir, knownDirMode); err != nil {
		return fmt.Errorf("create .konareef dir: %w", err)
	}

	body, err := json.MarshalIndent(k, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal known_publishers: %w", err)
	}
	body = append(body, '\n')

	tmp, err := os.CreateTemp(dir, ".known-publishers-*.tmp")
	if err != nil {
		return fmt.Errorf("create temp file: %w", err)
	}
	tmpName := tmp.Name()
	renamed := false
	defer func() {
		if !renamed {
			_ = os.Remove(tmpName)
		}
	}()

	if err := os.Chmod(tmpName, knownFileMode); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("chmod temp: %w", err)
	}
	if _, err := tmp.Write(body); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("write temp: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close temp: %w", err)
	}
	if err := os.Rename(tmpName, KnownPublishersPath(home)); err != nil {
		return fmt.Errorf("rename temp: %w", err)
	}
	renamed = true
	return nil
}

// ── Query / mutate ─────────────────────────────────────────────

// Get returns the record for handle, or nil if unknown.
func (k *KnownPublishers) Get(handle string) *PublisherRecord {
	if k == nil || k.Publishers == nil {
		return nil
	}
	return k.Publishers[handle]
}

// Match decides which of the three trust paths an incoming pubkey
// triggers. The returned TrustMatch.Known is the local record when
// Status is TrustOK or TrustChange; for TrustNew it is nil.
func (k *KnownPublishers) Match(handle, pubkeyHex string) TrustMatch {
	rec := k.Get(handle)
	if rec == nil {
		return TrustMatch{Status: TrustNew}
	}
	if rec.PubkeyHex == pubkeyHex {
		return TrustMatch{Status: TrustOK, Known: rec}
	}
	return TrustMatch{Status: TrustChange, Known: rec}
}

// Record adds or updates the publisher's record.
//
//   - New handle: insert with KeyHistory having one entry.
//   - Same pubkey as recorded: idempotent — only LastVerifiedAt
//     refreshes.
//   - Different pubkey (rotation / trust override): the previous
//     KeyHistory entry's ActiveTo + RotatedTo are populated, a new
//     entry appended, and the top-level PubkeyHex / Fingerprint /
//     LastVerifiedAt switch to the new key. FirstSeenAt stays at
//     the original value — it tracks the publisher, not the key.
func (k *KnownPublishers) Record(handle, pubkeyHex string, now time.Time) {
	if k.Publishers == nil {
		k.Publishers = map[string]*PublisherRecord{}
	}
	fp, _ := Fingerprint(pubkeyHex) // best-effort; bad hex yields empty fp

	rec := k.Publishers[handle]
	if rec == nil {
		k.Publishers[handle] = &PublisherRecord{
			PubkeyHex:      pubkeyHex,
			Fingerprint:    fp,
			FirstSeenAt:    now,
			LastVerifiedAt: now,
			KeyHistory: []KeyHistoryEntry{
				{PubkeyHex: pubkeyHex, ActiveFrom: now},
			},
		}
		return
	}

	if rec.PubkeyHex == pubkeyHex {
		rec.LastVerifiedAt = now
		return
	}

	// Rotation: close out the previous history entry, append a new one.
	if n := len(rec.KeyHistory); n > 0 && rec.KeyHistory[n-1].ActiveTo == nil {
		closed := now
		newPub := pubkeyHex
		rec.KeyHistory[n-1].ActiveTo = &closed
		rec.KeyHistory[n-1].RotatedTo = &newPub
	}
	rec.KeyHistory = append(rec.KeyHistory, KeyHistoryEntry{
		PubkeyHex:  pubkeyHex,
		ActiveFrom: now,
	})
	rec.PubkeyHex = pubkeyHex
	rec.Fingerprint = fp
	rec.LastVerifiedAt = now
}

// ── Fingerprint ────────────────────────────────────────────────

// Fingerprint returns the canonical short identifier for a
// compressed-secp256k1 pubkey: the first 6 bytes of SHA-256 over
// the raw key bytes, formatted as 3 groups of 2 bytes joined by
// `:`. E.g. `02a3:f9b4:c5d6`. Matches the SSH host-key style users
// already recognise.
func Fingerprint(pubKeyHex string) (string, error) {
	pub, err := hex.DecodeString(pubKeyHex)
	if err != nil {
		return "", fmt.Errorf("decode public key hex: %w", err)
	}
	digest := sha256.Sum256(pub)
	return fmt.Sprintf("%02x%02x:%02x%02x:%02x%02x",
		digest[0], digest[1], digest[2], digest[3], digest[4], digest[5]), nil
}
