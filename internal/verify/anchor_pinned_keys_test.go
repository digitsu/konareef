// Copyright 2026 Jerry David Chan, Konareef.ai
// SPDX-License-Identifier: Apache-2.0

// anchor_pinned_keys_test.go: tests for the pinned trusted node keys of
// the chain-head anchor check (US-007). They check that the list holds
// exactly the published keys, that each key is a valid compressed
// secp256k1 key, and that Options trusts a pinned key with no flag and
// no environment variable.
package verify

import (
	"bytes"
	"encoding/hex"
	"testing"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
)

// betaNodeIdentityKey is the identity key of reefcore-beta, observed
// 2026-10-04 (ZK-005) and published in the README section "Trusted
// node keys".
const betaNodeIdentityKey = "02154cc6943aeede702a2d5c8ff51e15cc567eb4522396ebb12e1d5656343f5820"

// TestPinnedTrustedNodeKeys_ExactlyPublishedKeys fails when a key is
// added to or removed from the pinned list without this test (and the
// README publication record) changing too.
func TestPinnedTrustedNodeKeys_ExactlyPublishedKeys(t *testing.T) {
	if len(PinnedTrustedNodeKeys) != 1 || PinnedTrustedNodeKeys[0] != betaNodeIdentityKey {
		t.Fatalf("pinned keys = %v, want exactly [%s]", PinnedTrustedNodeKeys, betaNodeIdentityKey)
	}
}

// TestPinnedTrustedNodeKeys_ParseAsCompressedKeys checks that each
// pinned key is 33 bytes, has a compressed prefix, and is a point on
// the secp256k1 curve.
func TestPinnedTrustedNodeKeys_ParseAsCompressedKeys(t *testing.T) {
	for _, k := range PinnedTrustedNodeKeys {
		raw, err := hex.DecodeString(k)
		if err != nil {
			t.Fatalf("key %s: not hex: %v", k, err)
		}
		if len(raw) != 33 || (raw[0] != 0x02 && raw[0] != 0x03) {
			t.Fatalf("key %s: not a 33-byte compressed key", k)
		}
		pub, err := secp256k1.ParsePubKey(raw)
		if err != nil {
			t.Fatalf("key %s: not a secp256k1 point: %v", k, err)
		}
		if !bytes.Equal(pub.SerializeCompressed(), raw) {
			t.Fatalf("key %s: does not round-trip", k)
		}
	}
}

// TestPinnedTrustedNodeKeys_TrustedWithNoConfig checks that an empty
// AnchorConfig trusts the pinned beta node key.
func TestPinnedTrustedNodeKeys_TrustedWithNoConfig(t *testing.T) {
	opts, err := AnchorConfig{}.Options()
	if err != nil {
		t.Fatalf("Options: %v", err)
	}
	if len(opts.TrustedNodeKeys) != 1 {
		t.Fatalf("trusted keys = %d, want 1 (the pinned key only)", len(opts.TrustedNodeKeys))
	}
	want, _ := hex.DecodeString(betaNodeIdentityKey)
	for _, k := range opts.TrustedNodeKeys {
		if bytes.Equal(k, want) {
			return
		}
	}
	t.Fatalf("beta node key not in trusted keys %x", opts.TrustedNodeKeys)
}
