// Copyright 2026 Jerry David Chan, Konareef.ai
// SPDX-License-Identifier: Apache-2.0

// Package saltstore stores and retrieves per-lineage 32-byte Type-D
// pod salts via a 3-tier OS-conditional backend chain (Keychain →
// EncryptedFile → PlainFile). Public surface:
//
//   - Backend, StoragePaths
//   - Resolve, ResolveOpts
//   - ExportBlob, ImportBlob, Entry
//   - MockBackend (testing)
//
// Every rejection returns a *SaltStoreError whose Code is a stable
// identifier (e.g. ERR_SALT_NOT_FOUND). Callers branch on the code via
// errors.Is(err, ErrSaltNotFound).
package saltstore
