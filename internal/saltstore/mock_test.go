// Copyright 2026 Jerry David Chan, Konareef.ai
// SPDX-License-Identifier: Apache-2.0

// internal/saltstore/mock_test.go — Put/Get/Delete/List semantics for
// MockBackend, plus the AvailableErr hook used by resolver tests.
package saltstore

import (
	"errors"
	"testing"
)

func TestMockBackendRoundTrip(t *testing.T) {
	mb := NewMockBackend()
	lid := [16]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}
	var salt [32]byte
	for i := range salt {
		salt[i] = byte(i + 1)
	}
	if err := mb.Put(lid, salt); err != nil {
		t.Fatalf("Put: %v", err)
	}
	got, err := mb.Get(lid)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got != salt {
		t.Errorf("Get returned %x, want %x", got, salt)
	}
	if err := mb.Put(lid, salt); !errors.Is(err, ErrSaltAlreadyExists) {
		t.Errorf("re-Put err = %v, want ErrSaltAlreadyExists", err)
	}
	list, err := mb.List()
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(list) != 1 || list[0] != lid {
		t.Errorf("List = %v, want [%x]", list, lid)
	}
	if err := mb.Delete(lid); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if _, err := mb.Get(lid); !errors.Is(err, ErrSaltNotFound) {
		t.Errorf("post-Delete Get err = %v, want ErrSaltNotFound", err)
	}
}

func TestMockBackendAvailableHook(t *testing.T) {
	mb := NewMockBackend()
	mb.AvailableErr = errors.New("simulated unavailable")
	if err := mb.Available(); err == nil {
		t.Fatal("expected non-nil from Available() when AvailableErr set")
	}
}
