// internal/saltstore/mock.go — in-memory MockBackend for unit tests.
//
// MockBackend is goroutine-safe and exposes AvailableErr so tests can
// drive the resolver's fallthrough decision table without spinning up
// real OS backends.
package saltstore

import "sync"

// MockBackend is an in-memory Backend implementation used by unit
// tests and the resolver decision-table fixture. Not safe for use in
// production. The zero value is NOT useful; callers must construct
// via NewMockBackend.
type MockBackend struct {
	// AvailableErr lets tests simulate an unavailable backend.
	// nil  → Available() returns nil.
	// !nil → Available() returns AvailableErr.
	AvailableErr error

	mu      sync.Mutex
	entries map[[16]byte][32]byte
}

// NewMockBackend constructs a ready-to-use mock.
func NewMockBackend() *MockBackend {
	return &MockBackend{entries: map[[16]byte][32]byte{}}
}

// Name returns the stable identifier "mock".
func (m *MockBackend) Name() string { return "mock" }

// Available returns the configured AvailableErr (nil by default).
func (m *MockBackend) Available() error { return m.AvailableErr }

// Put stores salt for lid. Returns ErrSaltAlreadyExists if lid is set.
func (m *MockBackend) Put(lid [16]byte, salt [32]byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.entries[lid]; ok {
		return ErrSaltAlreadyExists
	}
	m.entries[lid] = salt
	return nil
}

// Get returns the salt for lid or ErrSaltNotFound.
func (m *MockBackend) Get(lid [16]byte) ([32]byte, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	salt, ok := m.entries[lid]
	if !ok {
		return [32]byte{}, ErrSaltNotFound
	}
	return salt, nil
}

// Delete removes lid. Returns ErrSaltNotFound if lid is absent.
func (m *MockBackend) Delete(lid [16]byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.entries[lid]; !ok {
		return ErrSaltNotFound
	}
	delete(m.entries, lid)
	return nil
}

// List returns every lid present (unspecified order).
func (m *MockBackend) List() ([][16]byte, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([][16]byte, 0, len(m.entries))
	for k := range m.entries {
		out = append(out, k)
	}
	return out, nil
}
