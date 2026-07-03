// rotation.go — publisher key-rotation attestation primitives.
//
// A rotation attestation is a small signed document the publisher
// creates to transfer control of a handle from one keypair to
// another. The OLD key signs a JSON object declaring the new key;
// reef-core records it, and a buyer-side install that sees a
// pubkey divergence walks the chain of attestations to decide
// whether to accept the new key.
//
// The wire format is locked by reef-core's
// `ReefCore.PublishedPods.RotationCanonical.encode/1`. This Go
// encoder MUST produce byte-identical output for the same fields —
// signatures sign canonical bytes, and any divergence would break
// cross-implementation verification. See `rotation_test.go` for the
// pinned-string parity vectors.
//
// Surface:
//
//   - RotationAttestation — typed view of the attestation fields.
//   - Canonical(att)      — produces the bytes that get signed.
//   - id.SignRotation(att)            — DER-ECDSA signature over those bytes.
//   - VerifyRotationSignature(...)    — buyer-side check during install.

package identity

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/decred/dcrd/dcrec/secp256k1/v4/ecdsa"
)

// RotationAttestation is the typed view of a
// `konareef-key-rotation/v1` document.
//
// All fields except Reason are required; Reason is a free-text
// human note (e.g. "scheduled key rotation",
// "hardware wallet migration") and is omitted from the canonical
// bytes when empty.
type RotationAttestation struct {
	// Kind is the format discriminator. Always
	// "konareef-key-rotation/v1" for v1 attestations; the verifier
	// rejects anything else.
	Kind string

	// Handle is the publisher handle this rotation applies to.
	Handle string

	// OldPubkeyHex / NewPubkeyHex are the compressed-secp256k1 keys
	// as 66-char lowercase hex (33 bytes, leading 02 or 03 prefix).
	// OldPubkeyHex MUST be the key currently bound to Handle in
	// reef-core; the verifier compares against the registered identity.
	OldPubkeyHex string
	NewPubkeyHex string

	// RotatedAt is the publisher-stated time of rotation as a
	// microsecond-precision UTC ISO-8601 string
	// (e.g. "2026-05-19T11:22:00.000000Z"). Inside the signed bytes
	// — server-side overrides would invalidate the signature.
	RotatedAt string

	// Reason is optional free-text. Empty string is treated as
	// absent: omitted from the canonical bytes entirely (not
	// serialized as "" or null) so the byte form matches reef-core's
	// `Enum.reject(is_nil/1)`-style filter.
	Reason string
}

// Canonical returns the byte sequence that is signed and verified.
//
// Encoding rules (a minimal JCS slice for this fixed six-field
// shape — RFC 8785 compatible):
//
//   - Keys sorted ascending bytewise.
//   - No whitespace anywhere outside string values.
//   - `reason` omitted entirely when empty (not emitted as
//     `"reason":""` or `"reason":null`).
//   - String values escaped via encoding/json — the same rules
//     Elixir's Jason library uses, so the byte form is identical
//     across the two signers.
func Canonical(att RotationAttestation) []byte {
	// Build the (key, JSON-encoded-value) pairs in sorted order.
	// Pairs are accumulated rather than emitted directly so we can
	// keep the "skip empty reason" rule out of the join logic.
	type kv struct {
		key string
		val []byte
	}
	pairs := make([]kv, 0, 6)

	// Disable HTML-style escaping (`<`, `>`, `&` → `<` etc.) so
	// the byte form matches Jason. SetEscapeHTML is the only knob
	// where the two encoders' defaults diverge; without it, a reason
	// containing any of those characters would silently break the
	// signature across implementations.
	encodeString := func(s string) []byte {
		var b bytes.Buffer
		enc := json.NewEncoder(&b)
		enc.SetEscapeHTML(false)
		_ = enc.Encode(s)
		// json.Encoder appends a trailing newline; strip it.
		out := b.Bytes()
		if n := len(out); n > 0 && out[n-1] == '\n' {
			out = out[:n-1]
		}
		return out
	}

	add := func(key, value string) {
		pairs = append(pairs, kv{key: key, val: encodeString(value)})
	}

	add("handle", att.Handle)
	add("kind", att.Kind)
	add("new_pubkey_hex", att.NewPubkeyHex)
	add("old_pubkey_hex", att.OldPubkeyHex)
	if att.Reason != "" {
		add("reason", att.Reason)
	}
	add("rotated_at", att.RotatedAt)

	// pairs are already inserted in sorted key order; assemble.
	var buf bytes.Buffer
	buf.WriteByte('{')
	for i, p := range pairs {
		if i > 0 {
			buf.WriteByte(',')
		}
		jk, _ := json.Marshal(p.key)
		buf.Write(jk)
		buf.WriteByte(':')
		buf.Write(p.val)
	}
	buf.WriteByte('}')
	return buf.Bytes()
}

// SignRotation produces the DER-encoded secp256k1 ECDSA signature
// of SHA-256(Canonical(att)) under id's private key. The returned
// bytes are what the producer POSTs to
// `/api/publishers/:handle/rotate` as `signature_by_old_key`
// (base64-encoded on the wire).
//
// The wrapper exists so the rotation flow doesn't need to assemble
// canonical bytes itself; callers pass the typed attestation and
// receive a signature that is by construction over the right input.
func (id *Identity) SignRotation(att RotationAttestation) ([]byte, error) {
	privBytes, err := hex.DecodeString(id.PrivateKeyHex)
	if err != nil {
		return nil, fmt.Errorf("decode private key hex: %w", err)
	}
	if len(privBytes) != 32 {
		return nil, fmt.Errorf("private key is %d bytes, want 32", len(privBytes))
	}
	priv := secp256k1.PrivKeyFromBytes(privBytes)
	digest := sha256.Sum256(Canonical(att))
	return ecdsa.Sign(priv, digest[:]).Serialize(), nil
}

// VerifyRotationSignature reports whether sig is a valid signature
// of Canonical(att) under the compressed-secp256k1 public key
// encoded as pubKeyHex (typically the *old* key in a rotation
// hop, i.e. att.OldPubkeyHex itself).
//
// The (bool, error) split mirrors identity.Verify:
//
//   - (true,  nil)     — valid signature.
//   - (false, nil)     — well-formed inputs; signature is wrong.
//   - (false, non-nil) — inputs malformed (bad hex, unparseable DER,
//     non-secp256k1 pubkey).
func VerifyRotationSignature(pubKeyHex string, att RotationAttestation, sig []byte) (bool, error) {
	pubBytes, err := hex.DecodeString(pubKeyHex)
	if err != nil {
		return false, fmt.Errorf("decode public key hex: %w", err)
	}
	pub, err := secp256k1.ParsePubKey(pubBytes)
	if err != nil {
		return false, fmt.Errorf("parse public key: %w", err)
	}

	// P1.4 — strict-DER + low-S gate. Same surface as identity.Verify
	// for the same reason: a permissive parser at this layer would let
	// a high-S rotation signature land in `publisher_key_rotations`,
	// breaking the wire-form invariant that the verifier and the
	// observed bytes never disagree.
	if StrictDerGateEnabled {
		if _, _, err := ParseStrict(sig); err != nil {
			return false, err
		}
	}

	parsedSig, err := ecdsa.ParseDERSignature(sig)
	if err != nil {
		return false, fmt.Errorf("parse DER signature: %w", err)
	}
	digest := sha256.Sum256(Canonical(att))
	return parsedSig.Verify(digest[:], pub), nil
}
