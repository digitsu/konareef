// Package identity implements the konareef publisher signing identity:
// a secp256k1 keypair plus a publisher handle, persisted as
// `~/.konareef/identity.json` (mode 0600). It is the local credential
// `konareef pod publish` signs manifests with and the only thing that
// proves a re-publish of `<handle>/<pod>` came from the same publisher.
//
// The on-disk format is the publisher-signing-design-v0 §D3 layout:
//
//	{ "version": "konareef-identity/v1",
//	  "scheme":  "secp256k1-ecdsa-der",
//	  "handle":  "alice",
//	  "public_key_hex":  "02…",  // 33-byte compressed point, hex
//	  "private_key_hex": "8c…",  // 32-byte scalar, hex
//	  "created_at": "…Z" }
package identity

import (
	"encoding/hex"
	"fmt"
	"time"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
)

// Version is the on-disk schema tag for the v1 identity file. Bumping
// this string is a breaking format change; new keys are introduced as
// optional JSON fields under the same tag until a v2 is required.
const Version = "konareef-identity/v1"

// Scheme names the signature algorithm bound to this identity. Today
// every v1 identity is secp256k1 ECDSA with DER-encoded signatures —
// the future BRC-100 wallet-backed identity (design §D3) reuses the
// same scheme string and only swaps where the private key lives.
const Scheme = "secp256k1-ecdsa-der"

// Identity is a publisher's signing identity. The JSON tags are the
// stable on-disk schema; renaming a field is a breaking format change.
//
// PrivateKeyHex is the raw 32-byte scalar, hex-encoded. It MUST be
// stored only in mode-0600 files and MUST NEVER be logged or printed —
// the CLI's `identity show` command prints Handle and PublicKeyHex
// only, never PrivateKeyHex.
type Identity struct {
	Version       string    `json:"version"`
	Scheme        string    `json:"scheme"`
	Handle        string    `json:"handle"`
	PublicKeyHex  string    `json:"public_key_hex"`
	PrivateKeyHex string    `json:"private_key_hex"`
	CreatedAt     time.Time `json:"created_at"`
}

// Generate creates a fresh secp256k1 keypair and binds it to handle.
// The underlying secp256k1.GeneratePrivateKey draws from crypto/rand.
//
// The returned Identity is in-memory only; persist it with Save before
// any signing operation, otherwise the key is lost when the process
// exits.
func Generate(handle string) (*Identity, error) {
	priv, err := secp256k1.GeneratePrivateKey()
	if err != nil {
		return nil, fmt.Errorf("generate secp256k1 key: %w", err)
	}
	return &Identity{
		Version:       Version,
		Scheme:        Scheme,
		Handle:        handle,
		PublicKeyHex:  hex.EncodeToString(priv.PubKey().SerializeCompressed()),
		PrivateKeyHex: hex.EncodeToString(priv.Serialize()),
		CreatedAt:     time.Now().UTC(),
	}, nil
}
