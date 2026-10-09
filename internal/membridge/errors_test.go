// Copyright 2026 Jerry David Chan, Konareef.ai
// SPDX-License-Identifier: Apache-2.0

// internal/membridge/errors_test.go
package membridge

import (
	"errors"
	"fmt"
	"testing"
)

// TestSentinelCodesStable asserts every PRD 4 §6 code is exported and
// has the exact string identifier the conformance vectors check against.
func TestSentinelCodesStable(t *testing.T) {
	cases := []struct {
		err  error
		code string
	}{
		{ErrCellSaltLen, "ERR_CELL_SALT_LEN"},
		{ErrLeb128NonMinimal, "ERR_LEB128_NONMINIMAL"},
		{ErrCellCapExceeded, "ERR_CELL_CAP_EXCEEDED"},
		{ErrGenesisReseedCollision, "ERR_GENESIS_RESEED_COLLISION"},
		{ErrCellIndexCollision, "ERR_CELL_INDEX_COLLISION"},
		{ErrRInitMismatch, "ERR_RINIT_MISMATCH"},
		{ErrSnapshotImportFailed, "ERR_SNAPSHOT_IMPORT_FAILED"},
		{ErrProvisionalIDMismatch, "ERR_PROVISIONAL_ID_MISMATCH"},
		{ErrTypeDConfidentialLeak, "ERR_TYPE_D_CONFIDENTIAL_LEAK"},
		{ErrSparseIndexOutOfRange, "ERR_SPARSE_INDEX_OUT_OF_RANGE"},
	}
	for _, c := range cases {
		if Code(c.err) != c.code {
			t.Fatalf("Code(%v) = %q, want %q", c.err, Code(c.err), c.code)
		}
	}
}

// TestErrorsIsWrapped asserts wrapped errors still match via errors.Is.
func TestErrorsIsWrapped(t *testing.T) {
	wrapped := fmt.Errorf("derive: %w", ErrCellSaltLen)
	if !errors.Is(wrapped, ErrCellSaltLen) {
		t.Fatalf("errors.Is did not unwrap ErrCellSaltLen")
	}
}
