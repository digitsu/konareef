// Copyright 2026 Jerry David Chan, Konareef.ai
// SPDX-License-Identifier: Apache-2.0

// body_enc.go — sealing a closed pod's body for transport and storage.
//
// A `visibility = "closed"` pod publishes an encrypted body (`body.enc`)
// instead of the plaintext `content_tarball`. The seal is deliberately
// NOT part of the signed manifest and adds no commitment block to it:
// the canonical manifest already binds every body file's SHA-256 through
// the synthetic `[_files]` table, so the publisher's signature over
// pod_hash transitively covers the plaintext body. Encryption here is
// transport/storage metadata layered on top of a commitment that already
// exists — which is why an open pod's canonical bytes are untouched by
// any of this.
//
// Two properties do the security work:
//
//   - AAD = the raw 32 pod_hash bytes. GCM authenticates the AAD without
//     encrypting it, so a body.enc lifted from one pod and replayed under
//     a different HEAD fails to open. Without this an attacker who could
//     substitute the ciphertext of pod A into the published row for pod B
//     would get B's signature vouching for A's body.
//   - K_body is fresh per seal, as is the nonce. GCM is catastrophically
//     broken by (key, nonce) reuse — two messages under one pair leak the
//     XOR of their plaintexts and the authentication subkey. Generating a
//     brand-new key per publish means the nonce space is never reused
//     even in principle, so no counter or state has to be tracked.
//
// K_body itself transits exactly once, inside the TLS-protected publish
// request, and is never written to disk on the publisher's machine. It
// must never be logged; see the redaction note on submitRequest.
package publish

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
)

// BodyEncScheme names the AEAD used to seal a closed pod's body. It
// travels on the wire as `body_enc_scheme` so reef-core selects its
// decryptor from the published record rather than from a hardcoded
// assumption, leaving room for an algorithm change later without a
// silent misparse of old rows.
const BodyEncScheme = "aes-256-gcm"

// bodyKeySize and bodyNonceSize are AES-256-GCM's key and standard
// nonce lengths. Named rather than inlined so the wire-shape assertions
// and the generation sites cannot drift apart.
const (
	bodyKeySize   = 32
	bodyNonceSize = 12
)

// SealedBody is one closed pod's encrypted body plus everything needed
// to open it. Ciphertext includes GCM's 16-byte authentication tag
// (crypto/cipher appends it), so it is always longer than the plaintext.
//
// Key is K_body: secret. It is transmitted once over TLS at publish so
// konareef's infrastructure can materialize the body at spawn time, and
// is never persisted locally or logged.
type SealedBody struct {
	Ciphertext []byte
	Nonce      []byte
	Key        []byte // K_body — transits once over TLS at publish, never stored locally
	Scheme     string
}

// SealBody encrypts bodyTar under a freshly generated AES-256 key,
// binding the result to podHash via GCM's additional authenticated data.
//
// Inputs: bodyTar — the deterministic gzip tar of exactly the `[_files]`
// path set (see PackTarballPaths); podHash — the raw 32-byte SHA-256 of
// the canonical manifest, NOT its hex or base64 rendering.
//
// Output: a SealedBody carrying the ciphertext, the 12-byte nonce, the
// 32-byte key and the scheme name; or an error if the system CSPRNG
// fails or podHash is not a 32-byte digest.
//
// A wrong-length podHash is rejected rather than accepted as a
// degraded AAD: passing the hex string (64 bytes) or an empty slice
// would still produce a valid-looking seal while destroying the
// HEAD-binding property that is the whole point of the AAD.
func SealBody(bodyTar []byte, podHash []byte) (*SealedBody, error) {
	if len(podHash) != sha256.Size {
		return nil, fmt.Errorf(
			"seal body: pod_hash AAD must be the raw %d-byte digest, got %d bytes",
			sha256.Size, len(podHash))
	}

	key := make([]byte, bodyKeySize)
	if _, err := rand.Read(key); err != nil {
		return nil, fmt.Errorf("generate K_body: %w", err)
	}
	aead, err := newBodyAEAD(key)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("generate body nonce: %w", err)
	}
	return &SealedBody{
		Ciphertext: aead.Seal(nil, nonce, bodyTar, podHash),
		Nonce:      nonce,
		Key:        key,
		Scheme:     BodyEncScheme,
	}, nil
}

// OpenBodyForTest reverses SealBody. It exists so this package's tests
// can prove the round-trip and the pod_hash binding; the CLI never
// decrypts a body, and neither does any non-test caller here. reef-core
// is the real decryptor — it holds K_body and materializes the body
// server-side at spawn. Keep it that way: a publisher-side decrypt path
// would mean the plaintext body has a reason to exist on a commissioner's
// machine, which is exactly what a closed pod forbids.
//
// Inputs: sealed — a SealedBody; podHash — the raw 32-byte digest used
// as AAD at seal time. Output: the plaintext body tar, or an error if
// the scheme is unrecognised or authentication fails (wrong key, wrong
// nonce, tampered ciphertext, or a foreign pod_hash).
func OpenBodyForTest(sealed *SealedBody, podHash []byte) ([]byte, error) {
	if sealed == nil {
		return nil, fmt.Errorf("open body: no sealed body")
	}
	if sealed.Scheme != BodyEncScheme {
		return nil, fmt.Errorf("open body: unsupported scheme %q", sealed.Scheme)
	}
	aead, err := newBodyAEAD(sealed.Key)
	if err != nil {
		return nil, err
	}
	plain, err := aead.Open(nil, sealed.Nonce, sealed.Ciphertext, podHash)
	if err != nil {
		return nil, fmt.Errorf("open body: %w", err)
	}
	return plain, nil
}

// newBodyAEAD builds the AES-256-GCM AEAD for key, the single place
// both the seal and open paths construct their cipher so they can never
// disagree about mode or tag size.
func newBodyAEAD(key []byte) (cipher.AEAD, error) {
	if len(key) != bodyKeySize {
		return nil, fmt.Errorf("body key must be %d bytes, got %d", bodyKeySize, len(key))
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("build AES cipher: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("build GCM: %w", err)
	}
	return aead, nil
}
