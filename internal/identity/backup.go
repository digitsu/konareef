// backup.go — encrypted identity export/import.
//
// Export passphrase-protects an Identity for off-device backup;
// Import restores it. The envelope is a JSON document containing the
// KDF parameters, the nonce, and the AES-256-GCM ciphertext — every
// field a different implementation would need to reproduce the
// decryption without secret knowledge beyond the passphrase.
//
// Algorithm: Argon2id (passphrase-only KDF, no separate pepper) +
// AES-256-GCM. Parameters are baked into the envelope so Import can
// match what Export used without a version table; future
// envelopes that change KDF or cipher bump the `version` string.

package identity

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"golang.org/x/crypto/argon2"
)

// BackupVersion is the on-disk schema tag for v1 backup envelopes.
const BackupVersion = "konareef-identity-backup/v1"

const (
	backupKDFName = "argon2id"
	backupCipher  = "aes-256-gcm"

	// Argon2id parameters. 64 MiB memory + 1 iteration is the
	// modern recommended baseline for interactive workloads — enough
	// to make GPU-cracking expensive without making `identity import`
	// take noticeable seconds on a laptop.
	argon2Time    uint32 = 1
	argon2Memory  uint32 = 64 * 1024 // 64 MiB expressed in KiB
	argon2Threads uint8  = 4
	argon2KeyLen  uint32 = 32 // AES-256 key
)

// backupEnvelope is the on-disk JSON shape. Every field is present
// so Import can verify the file came from a compatible Export and
// reproduce the exact KDF / cipher path without secret knowledge.
type backupEnvelope struct {
	Version      string `json:"version"`
	KDF          string `json:"kdf"`
	KDFSalt      string `json:"kdf_salt"` // hex
	KDFTime      uint32 `json:"kdf_time"`
	KDFMemoryKiB uint32 `json:"kdf_memory_kib"`
	KDFThreads   uint8  `json:"kdf_threads"`
	Cipher       string `json:"cipher"`
	Nonce        string `json:"nonce"`      // hex
	Ciphertext   string `json:"ciphertext"` // base64
}

// Export writes a passphrase-encrypted backup of id to path. The
// passphrase MUST be non-empty (an empty passphrase is rejected
// rather than silently downgraded to "no encryption").
//
// The output file is mode 0600 and written atomically (temp file +
// rename), so a crash mid-write never leaves a partial backup and a
// successful Export never widens the file's permissions.
func (id *Identity) Export(path string, passphrase []byte) error {
	if len(passphrase) == 0 {
		return fmt.Errorf("passphrase must not be empty")
	}

	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return fmt.Errorf("generate salt: %w", err)
	}
	key := argon2.IDKey(passphrase, salt, argon2Time, argon2Memory, argon2Threads, argon2KeyLen)

	plaintext, err := json.Marshal(id)
	if err != nil {
		return fmt.Errorf("marshal identity: %w", err)
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return fmt.Errorf("init AES: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return fmt.Errorf("init GCM: %w", err)
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return fmt.Errorf("generate nonce: %w", err)
	}
	ciphertext := gcm.Seal(nil, nonce, plaintext, nil)

	env := backupEnvelope{
		Version:      BackupVersion,
		KDF:          backupKDFName,
		KDFSalt:      hex.EncodeToString(salt),
		KDFTime:      argon2Time,
		KDFMemoryKiB: argon2Memory,
		KDFThreads:   argon2Threads,
		Cipher:       backupCipher,
		Nonce:        hex.EncodeToString(nonce),
		Ciphertext:   base64.StdEncoding.EncodeToString(ciphertext),
	}

	body, err := json.MarshalIndent(env, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal envelope: %w", err)
	}
	body = append(body, '\n')

	tmp, err := os.CreateTemp(filepath.Dir(path), ".identity-backup-*.tmp")
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

	if err := os.Chmod(tmpName, 0o600); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("chmod temp file: %w", err)
	}
	if _, err := tmp.Write(body); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("write temp file: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close temp file: %w", err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		return fmt.Errorf("rename temp file: %w", err)
	}
	renamed = true
	return nil
}

// Import reads an encrypted backup from path, verifies the version
// + KDF + cipher tags, and decrypts the Identity using passphrase.
// A wrong passphrase, a malformed envelope, or any post-write tamper
// surfaces as an Import error — the AES-GCM auth tag does the
// integrity check; we never return partial / unverified plaintext.
func Import(path string, passphrase []byte) (*Identity, error) {
	body, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read backup file: %w", err)
	}

	var env backupEnvelope
	if err := json.Unmarshal(body, &env); err != nil {
		return nil, fmt.Errorf("parse backup envelope: %w", err)
	}
	if env.Version != BackupVersion {
		return nil, fmt.Errorf(
			"unsupported backup version %q (this build handles %q only)",
			env.Version, BackupVersion,
		)
	}
	if env.KDF != backupKDFName {
		return nil, fmt.Errorf("unsupported KDF %q", env.KDF)
	}
	if env.Cipher != backupCipher {
		return nil, fmt.Errorf("unsupported cipher %q", env.Cipher)
	}

	salt, err := hex.DecodeString(env.KDFSalt)
	if err != nil {
		return nil, fmt.Errorf("decode kdf_salt: %w", err)
	}
	nonce, err := hex.DecodeString(env.Nonce)
	if err != nil {
		return nil, fmt.Errorf("decode nonce: %w", err)
	}
	ciphertext, err := base64.StdEncoding.DecodeString(env.Ciphertext)
	if err != nil {
		return nil, fmt.Errorf("decode ciphertext: %w", err)
	}

	key := argon2.IDKey(passphrase, salt, env.KDFTime, env.KDFMemoryKiB, env.KDFThreads, argon2KeyLen)

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("init AES: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("init GCM: %w", err)
	}
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("decrypt: wrong passphrase or tampered backup")
	}

	var id Identity
	if err := json.Unmarshal(plaintext, &id); err != nil {
		return nil, fmt.Errorf("parse decrypted identity: %w", err)
	}
	return &id, nil
}
