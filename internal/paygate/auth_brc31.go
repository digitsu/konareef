// internal/paygate/auth_brc31.go — BRC-31 mutual auth session.
//
// V1 simplification: the BRC-31 header is computed as
//
//	Brc31 session=<sid>; nonce=<hex>; pk=<hex>; sig=<hex>
//
// where sig = secp256k1 ECDSA over the canonical request preamble.
// The full BRC-31 handshake (key exchange, session establishment via
// the /v1/auth path) is wired by the stub server in Task 13 and by
// the live integration tests; v1 does not implement the registration
// dance because PRD 2 § 7.1 inherits it from proof-generation-architecture.md
// without extending the contract.
package paygate

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/decred/dcrd/dcrec/secp256k1/v4/ecdsa"
)

// BRC31Identity is the persistent secp256k1 keypair used to authenticate
// to PayGate ZK. Distinct from the publisher identity per PRD P1.8 § 1.
type BRC31Identity struct {
	priv *secp256k1.PrivateKey
}

// LoadOrCreateBRC31Identity reads the secp256k1 private key from path,
// or generates and persists a new one if path does not exist. Mode 0600.
func LoadOrCreateBRC31Identity(path string) (*BRC31Identity, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}
	if raw, err := os.ReadFile(path); err == nil {
		decoded, err := hex.DecodeString(string(raw))
		if err != nil || len(decoded) != 32 {
			return nil, fmt.Errorf("paygate: identity.key malformed")
		}
		priv := secp256k1.PrivKeyFromBytes(decoded)
		return &BRC31Identity{priv: priv}, nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	var seed [32]byte
	if _, err := rand.Read(seed[:]); err != nil {
		return nil, err
	}
	priv := secp256k1.PrivKeyFromBytes(seed[:])
	if err := os.WriteFile(path, []byte(hex.EncodeToString(seed[:])), 0o600); err != nil {
		return nil, err
	}
	return &BRC31Identity{priv: priv}, nil
}

// PubKeyHex returns the compressed-SEC pubkey as lowercase hex.
func (id *BRC31Identity) PubKeyHex() string {
	return hex.EncodeToString(id.priv.PubKey().SerializeCompressed())
}

// Sign returns the DER-encoded ECDSA signature of msg under the
// identity key.
func (id *BRC31Identity) Sign(msg []byte) []byte {
	return ecdsa.Sign(id.priv, msg).Serialize()
}

// BRC31Session is one BRC-31-scoped session with its server-issued ID.
type BRC31Session struct {
	ID       string
	Identity *BRC31Identity
}

// AuthorizationHeader produces the per-request Brc31 header value for
// the given canonical preamble (e.g. method+path bytes per the wire
// spec). Nonce is fresh per call.
func (s *BRC31Session) AuthorizationHeader(preamble []byte) string {
	var nonce [16]byte
	_, _ = rand.Read(nonce[:])
	signed := append(append([]byte(nil), preamble...), nonce[:]...)
	sig := s.Identity.Sign(signed)
	return fmt.Sprintf(
		"Brc31 session=%s; nonce=%s; pk=%s; sig=%s",
		s.ID,
		hex.EncodeToString(nonce[:]),
		s.Identity.PubKeyHex(),
		hex.EncodeToString(sig),
	)
}
