// internal/saltstore/blob.go — versioned Argon2id + AES-256-GCM export
// blob. Wire layout:
//
//	Magic       "KRSALT01"                              8 B
//	Version     u8 (0x01 for v1)                        1 B
//	KDF params  iters||mem_kib||parallelism (3 × u32LE) 12 B
//	KDF salt    random per-blob                        16 B
//	Nonce       random per-blob (AES-GCM IV)           12 B
//	Ciphertext  AES-256-GCM seal(plaintext, key, nonce, aad)  var B
//	Tag         GCM-appended                           16 B
//
// aad = Magic (8B) || Version (1B)   — exactly 9 bytes.
//
// plaintext (CBOR-encoded):
//
//	{"created_at": <unix-sec u64>,
//	 "entries": [{"lineage_id": <16B bstr>, "salt": <32B bstr>}, ...]}
package saltstore

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"time"

	"github.com/fxamacker/cbor/v2"
	"golang.org/x/crypto/argon2"
)

const (
	blobMagic   = "KRSALT01"
	blobVersion = 0x01
	keyLen      = 32 // AES-256
	kdfSaltLen  = 16
	nonceLen    = 12
	tagLen      = 16

	armorBegin = "-----BEGIN KONAREEF SALT-----"
	armorEnd   = "-----END KONAREEF SALT-----"
)

// Entry is one (lineage_id, salt) pair persisted in or restored from
// a backup blob.
type Entry struct {
	LineageID [16]byte
	Salt      [32]byte
}

// KDFParams names the Argon2id parameters baked into the blob header.
// The production defaults are exported as ProdKDFParams; tests use
// TestKDFParams.
type KDFParams struct {
	Iterations  uint32
	MemoryKiB   uint32
	Parallelism uint32
}

// ProdKDFParams is the production Argon2id parameter set; recorded in
// the blob header so a future parameter bump is transparent to
// existing blobs.
var ProdKDFParams = KDFParams{Iterations: 4, MemoryKiB: 131072, Parallelism: 1}

// TestKDFParams is the test/CI parameter set; documented in the
// conformance vectors. Production code MUST NOT use these.
var TestKDFParams = KDFParams{Iterations: 2, MemoryKiB: 16384, Parallelism: 1}

// KDF parameter bounds enforced before Argon2id execution on import. A
// hostile blob can otherwise request arbitrary CPU/memory by writing
// extreme values into the header; we validate BEFORE the key derivation
// runs so malformed input cannot exhaust local resources prior to
// authentication.
//
// Bounds rationale:
//   - iterations: 1 lower bound (any sane Argon2 cost ≥1); 16 upper
//     bound (≥4× our production default of 4 leaves comfortable headroom
//     for a future parameter bump without risking pathological CPU).
//   - memoryKiB:  1 MiB lower bound (Argon2 below this is meaningless);
//     1 GiB upper bound (≥8× our 128 MiB production default; rejects the
//     multi-GiB allocation a malicious blob would otherwise request).
//   - parallelism: 1 lower bound (Argon2 requires ≥1 lane); 16 upper
//     bound (≥16× our production default of 1; far above realistic
//     deployment, well below ddos-class lane counts).
const (
	minKDFIterations  uint32 = 1
	maxKDFIterations  uint32 = 16
	minKDFMemoryKiB   uint32 = 1024
	maxKDFMemoryKiB   uint32 = 1048576
	minKDFParallelism uint32 = 1
	maxKDFParallelism uint32 = 16
)

// ValidateKDFParams rejects Argon2id parameter sets outside the sane
// window enforced by the import path. Returns ErrSaltBlobKDFParamsInvalid
// (wrapped with a human-readable detail) for any out-of-range value;
// returns nil when all three parameters are inside the bounds documented
// above.
//
// Callers MUST invoke this before passing attacker-controlled header
// values to argon2.IDKey — see ImportBlob.
func ValidateKDFParams(iterations, memoryKiB, parallelism uint32) error {
	if iterations < minKDFIterations || iterations > maxKDFIterations {
		return fmt.Errorf("%w: iterations=%d outside [%d,%d]",
			ErrSaltBlobKDFParamsInvalid, iterations, minKDFIterations, maxKDFIterations)
	}
	if memoryKiB < minKDFMemoryKiB || memoryKiB > maxKDFMemoryKiB {
		return fmt.Errorf("%w: memoryKiB=%d outside [%d,%d]",
			ErrSaltBlobKDFParamsInvalid, memoryKiB, minKDFMemoryKiB, maxKDFMemoryKiB)
	}
	if parallelism < minKDFParallelism || parallelism > maxKDFParallelism {
		return fmt.Errorf("%w: parallelism=%d outside [%d,%d]",
			ErrSaltBlobKDFParamsInvalid, parallelism, minKDFParallelism, maxKDFParallelism)
	}
	return nil
}

// ExportBlob is the production helper: uses ProdKDFParams and the
// current wall-clock for created_at. Returns the raw binary blob.
func ExportBlob(entries []Entry, passphrase []byte) ([]byte, error) {
	return ExportBlobWithParams(entries, passphrase, ProdKDFParams, uint64(time.Now().Unix()))
}

// ExportBlobWithParams is the testable core: callers fix KDFParams and
// created_at for byte-exact conformance vectors. The KDF salt and
// nonce remain CSPRNG (do not weaken production callers).
func ExportBlobWithParams(entries []Entry, passphrase []byte, params KDFParams, createdAt uint64) ([]byte, error) {
	if len(entries) == 0 {
		return nil, fmt.Errorf("saltstore: refuse to export an empty entry set")
	}
	kdfSalt := make([]byte, kdfSaltLen)
	if _, err := rand.Read(kdfSalt); err != nil {
		return nil, fmt.Errorf("kdf salt: %w", err)
	}
	nonce := make([]byte, nonceLen)
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("nonce: %w", err)
	}
	return sealBlob(entries, passphrase, params, createdAt, kdfSalt, nonce)
}

// sealBlob is the deterministic core: callers supply KDF salt and
// nonce explicitly so the conformance vector test can derive a
// byte-exact blob from fixed inputs.
func sealBlob(entries []Entry, passphrase []byte, params KDFParams, createdAt uint64, kdfSalt, nonce []byte) ([]byte, error) {
	if len(kdfSalt) != kdfSaltLen {
		return nil, fmt.Errorf("kdf salt: want %d bytes, got %d", kdfSaltLen, len(kdfSalt))
	}
	if len(nonce) != nonceLen {
		return nil, fmt.Errorf("nonce: want %d bytes, got %d", nonceLen, len(nonce))
	}
	header := buildHeader(params, kdfSalt, nonce)
	aad := []byte(blobMagic + string([]byte{blobVersion})) // exactly 9 B
	key := argon2.IDKey(passphrase, kdfSalt, params.Iterations, params.MemoryKiB, uint8(params.Parallelism), keyLen)
	plaintext, err := encodePlaintext(entries, createdAt)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("aes: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("gcm: %w", err)
	}
	ctAndTag := gcm.Seal(nil, nonce, plaintext, aad)
	out := make([]byte, 0, len(header)+len(ctAndTag))
	out = append(out, header...)
	out = append(out, ctAndTag...)
	return out, nil
}

// SealBlobDeterministic is exported solely for the conformance test;
// callers in production MUST go through ExportBlob / ExportBlobWithParams.
func SealBlobDeterministic(entries []Entry, passphrase []byte, params KDFParams, createdAt uint64, kdfSalt, nonce []byte) ([]byte, error) {
	return sealBlob(entries, passphrase, params, createdAt, kdfSalt, nonce)
}

func buildHeader(params KDFParams, kdfSalt, nonce []byte) []byte {
	hdr := make([]byte, 0, 8+1+12+kdfSaltLen+nonceLen)
	hdr = append(hdr, []byte(blobMagic)...)
	hdr = append(hdr, blobVersion)
	var u32 [4]byte
	binary.LittleEndian.PutUint32(u32[:], params.Iterations)
	hdr = append(hdr, u32[:]...)
	binary.LittleEndian.PutUint32(u32[:], params.MemoryKiB)
	hdr = append(hdr, u32[:]...)
	binary.LittleEndian.PutUint32(u32[:], params.Parallelism)
	hdr = append(hdr, u32[:]...)
	hdr = append(hdr, kdfSalt...)
	hdr = append(hdr, nonce...)
	return hdr
}

func encodePlaintext(entries []Entry, createdAt uint64) ([]byte, error) {
	type cborEntry struct {
		LineageID []byte `cbor:"lineage_id"`
		Salt      []byte `cbor:"salt"`
	}
	type cborDoc struct {
		CreatedAt uint64      `cbor:"created_at"`
		Entries   []cborEntry `cbor:"entries"`
	}
	doc := cborDoc{CreatedAt: createdAt}
	for _, e := range entries {
		doc.Entries = append(doc.Entries, cborEntry{LineageID: e.LineageID[:], Salt: e.Salt[:]})
	}
	enc, err := cbor.CanonicalEncOptions().EncMode()
	if err != nil {
		return nil, fmt.Errorf("cbor canonical mode: %w", err)
	}
	return enc.Marshal(doc)
}

// ImportBlob decodes a binary OR base64-armored blob and decrypts it
// using passphrase. Returns the entries in the order they appeared in
// the plaintext CBOR array.
func ImportBlob(blob, passphrase []byte) ([]Entry, error) {
	blob = bytes.TrimSpace(blob)
	if bytes.HasPrefix(blob, []byte(armorBegin)) {
		decoded, err := decodeArmor(blob)
		if err != nil {
			return nil, fmt.Errorf("%w: %v", ErrSaltBlobMalformed, err)
		}
		blob = decoded
	}
	if len(blob) < 8+1+12+kdfSaltLen+nonceLen+tagLen {
		return nil, ErrSaltBlobMalformed
	}
	if string(blob[:8]) != blobMagic {
		return nil, ErrSaltBlobMalformed
	}
	wireVersion := blob[8]
	if wireVersion != blobVersion {
		return nil, ErrSaltBlobUnsupportedVersion
	}
	off := 9
	iterations := binary.LittleEndian.Uint32(blob[off : off+4])
	memoryKiB := binary.LittleEndian.Uint32(blob[off+4 : off+8])
	parallelism := binary.LittleEndian.Uint32(blob[off+8 : off+12])
	off += 12
	kdfSalt := blob[off : off+kdfSaltLen]
	off += kdfSaltLen
	nonce := blob[off : off+nonceLen]
	off += nonceLen
	ctAndTag := blob[off:]
	if len(ctAndTag) < tagLen {
		return nil, ErrSaltBlobMalformed
	}

	// SECURITY: validate Argon2id parameters BEFORE running argon2.IDKey.
	// A malicious blob can otherwise demand multi-GiB memory or tens of
	// iterations and exhaust the local process before the GCM tag is
	// ever checked. See ValidateKDFParams for the enforced bounds.
	if err := ValidateKDFParams(iterations, memoryKiB, parallelism); err != nil {
		return nil, err
	}

	aad := []byte(blobMagic + string([]byte{blobVersion}))
	key := argon2.IDKey(passphrase, kdfSalt, iterations, memoryKiB, uint8(parallelism), keyLen)
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("%w: aes init", ErrSaltBlobMalformed)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("%w: gcm init", ErrSaltBlobMalformed)
	}
	plaintext, err := gcm.Open(nil, nonce, ctAndTag, aad)
	if err != nil {
		return nil, ErrSaltBlobDecrypt
	}
	return decodePlaintext(plaintext)
}

func decodePlaintext(plaintext []byte) ([]Entry, error) {
	type cborEntry struct {
		LineageID []byte `cbor:"lineage_id"`
		Salt      []byte `cbor:"salt"`
	}
	type cborDoc struct {
		CreatedAt uint64      `cbor:"created_at"`
		Entries   []cborEntry `cbor:"entries"`
	}
	var doc cborDoc
	if err := cbor.Unmarshal(plaintext, &doc); err != nil {
		return nil, fmt.Errorf("%w: cbor decode: %v", ErrSaltBlobMalformed, err)
	}
	out := make([]Entry, 0, len(doc.Entries))
	for i, e := range doc.Entries {
		if len(e.LineageID) != 16 {
			return nil, fmt.Errorf("%w: entry[%d] lineage_id len %d", ErrSaltBlobMalformed, i, len(e.LineageID))
		}
		if len(e.Salt) != 32 {
			return nil, fmt.Errorf("%w: entry[%d] salt len %d", ErrSaltBlobMalformed, i, len(e.Salt))
		}
		var lid [16]byte
		var s [32]byte
		copy(lid[:], e.LineageID)
		copy(s[:], e.Salt)
		out = append(out, Entry{LineageID: lid, Salt: s})
	}
	return out, nil
}

// ArmorBlob wraps a raw binary blob in base64 between PEM-style markers.
func ArmorBlob(raw []byte) []byte {
	encoded := base64.StdEncoding.EncodeToString(raw)
	out := append([]byte(armorBegin+"\n"), encoded...)
	out = append(out, []byte("\n"+armorEnd+"\n")...)
	return out
}

func decodeArmor(armored []byte) ([]byte, error) {
	start := bytes.Index(armored, []byte(armorBegin))
	end := bytes.Index(armored, []byte(armorEnd))
	if start < 0 || end < 0 || end <= start {
		return nil, errors.New("armor markers not found")
	}
	body := armored[start+len(armorBegin) : end]
	body = bytes.TrimSpace(body)
	return base64.StdEncoding.DecodeString(string(body))
}
