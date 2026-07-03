// internal/saltstore/backend.go — Backend interface + path policy.
//
// Backend is the per-tier storage contract used by the saltstore
// resolver. StoragePaths overrides the default OS-derived storage
// roots, used by integration tests and custom installations.
package saltstore

// Backend stores and retrieves per-lineage 32-byte salts. Each
// implementation handles its own at-rest encryption; the resolver
// does no crypto.
type Backend interface {
	// Name returns a stable lowercase identifier for logging and
	// audit. One of: "keychain", "encrypted-file", "plain-file",
	// "mock".
	Name() string

	// Available returns nil if this backend is usable on the current
	// machine and environment. It MUST be cheap (no disk I/O, no IPC).
	Available() error

	// Put stores salt for lineageID. Returns ErrSaltAlreadyExists if
	// an entry exists; callers must pass --force via Delete+Put.
	Put(lineageID [16]byte, salt [32]byte) error

	// Get retrieves the salt for lineageID. Returns ErrSaltNotFound
	// if no entry exists.
	Get(lineageID [16]byte) ([32]byte, error)

	// Delete removes the salt for lineageID. Irreversible.
	Delete(lineageID [16]byte) error

	// List returns all lineage IDs present in this backend. Used by
	// `konareef salt status`. Order is implementation-defined.
	List() ([][16]byte, error)
}

// StoragePaths overrides default OS-determined storage roots. Used
// by integration tests and custom installation layouts. Nil values
// fall back to the per-platform defaults.
type StoragePaths struct {
	// EncryptedFilePath is the absolute path to the
	// EncryptedFileBackend's salts.enc file. Default:
	//   darwin: ~/Library/Application Support/konareef/salts.enc
	//   linux : ~/.config/konareef/salts.enc
	//   $KONAREEF_STATE_DIR overrides when set.
	EncryptedFilePath string

	// PlainFileRoot is the absolute path to the PlainFileBackend
	// root directory ($ROOT/typed/{lineage_id_hex}/salt.bin lives
	// underneath). Default: ${KONAREEF_STATE_DIR:-~/.konareef}.
	PlainFileRoot string
}

// NewKeychainBackend returns the OS keyring backend (macOS Keychain on
// darwin, Secret Service / libsecret on linux). See keychain.go.
func NewKeychainBackend() Backend { return newKeychainBackend() }

// NewEncryptedFileBackend returns the production encrypted-file backend.
// The passphrase is expected to be cached via an out-of-band TTY prompt
// before any Put/Get call.
func NewEncryptedFileBackend(paths *StoragePaths) Backend {
	return newEncryptedFileBackendForPath(defaultEncryptedFilePath(paths))
}

// NewPlainFileBackend returns the plain-file backend rooted at
// paths.PlainFileRoot (default: ${KONAREEF_STATE_DIR:-~/.konareef}).
func NewPlainFileBackend(paths *StoragePaths) Backend {
	root := defaultPlainFileRoot()
	if paths != nil && paths.PlainFileRoot != "" {
		root = paths.PlainFileRoot
	}
	return newPlainFileBackendForRoot(root)
}
