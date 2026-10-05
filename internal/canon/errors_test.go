// Copyright 2026 Jerry David Chan, Konareef.ai
// SPDX-License-Identifier: Apache-2.0

package canon

import "testing"

func TestCommitCodesAreTheSpecStrings(t *testing.T) {
	want := map[string]string{
		"RESERVED_KEY_COMMIT":                  ErrReservedKeyCommit,
		"COMMIT_DUPLICATE_ENTRY":               ErrCommitDuplicateEntry,
		"COMMIT_OVER_CAP":                      ErrCommitOverCap,
		"COMMIT_NONCANONICAL_RINIT":            ErrCommitNonCanonicalRInit,
		"COMMIT_BUDGET_REQUIRED":               ErrCommitBudgetRequired,
		"COMMIT_MODEL_PROVIDER_MISSING":        ErrCommitModelProviderMissing,
		"COMMIT_TOOL_AUTHORITY_UNCOMMITTED":    ErrCommitToolAuthorityUncommitted,
		"COMMIT_EMPTY_ID":                      ErrCommitEmptyID,
		"COMMIT_INVALID_UTF8_ID":               ErrCommitInvalidUTF8ID,
		"COMMIT_NON_NFC_ID":                    ErrCommitNonNFCID,
		"COMMIT_MEMORY_RESOLUTION_UNAVAILABLE": ErrCommitMemoryResolutionUnavailable,
	}
	for literal, constant := range want {
		if literal != constant {
			t.Errorf("code drift: constant is %q, spec says %q", constant, literal)
		}
	}
}
