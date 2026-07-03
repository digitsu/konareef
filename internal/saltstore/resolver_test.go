// internal/saltstore/resolver_test.go — fallthrough decision table for
// the saltstore Resolver. Synthesises a candidate list of MockBackend
// instances so the resolver behaviour is exercised without touching
// real OS keyring / file backends.
package saltstore

import (
	"bytes"
	"errors"
	"log"
	"path/filepath"
	"strings"
	"testing"
)

func TestResolverFallthroughDecision(t *testing.T) {
	// Decision table:
	//   k=ok                    → pick "keychain"
	//   k=err, e=ok, p=ok       → pick "encrypted-file"
	//   k=err, e=err, p=ok      → pick "plain-file"
	//   k=err, e=err, p=err     → ErrSaltStorageUnavailable
	cases := []struct {
		name             string
		kErr, eErr, pErr error
		wantName         string
		wantErr          error
		wantSkipMsgs     []string
	}{
		{"keychain ok", nil, nil, nil, "keychain", nil, nil},
		{"fallthrough enc", errors.New("no keychain"), nil, nil,
			"encrypted-file", nil,
			[]string{"skipping backend keychain"}},
		{"fallthrough plain", errors.New("no keychain"), errors.New("no enc"), nil,
			"plain-file", nil,
			[]string{"skipping backend keychain", "skipping backend encrypted-file"}},
		{"all unavailable", errors.New("a"), errors.New("b"), errors.New("c"),
			"", ErrSaltStorageUnavailable,
			[]string{"skipping backend keychain", "skipping backend encrypted-file", "skipping backend plain-file"}},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			var buf bytes.Buffer
			orig := log.Writer()
			log.SetOutput(&buf)
			defer log.SetOutput(orig)

			k := NewMockBackend()
			k.AvailableErr = tc.kErr
			e := NewMockBackend()
			e.AvailableErr = tc.eErr
			p := NewMockBackend()
			p.AvailableErr = tc.pErr
			candidates := []Backend{
				namedMock{m: k, name: "keychain"},
				namedMock{m: e, name: "encrypted-file"},
				namedMock{m: p, name: "plain-file"},
			}
			b, err := resolveFrom(candidates)
			if tc.wantErr != nil {
				if !errors.Is(err, tc.wantErr) {
					t.Fatalf("err = %v, want %v", err, tc.wantErr)
				}
			} else {
				if err != nil {
					t.Fatalf("err = %v, want nil", err)
				}
				if b.Name() != tc.wantName {
					t.Errorf("picked = %q, want %q", b.Name(), tc.wantName)
				}
			}
			for _, want := range tc.wantSkipMsgs {
				if !strings.Contains(buf.String(), want) {
					t.Errorf("log missing %q\nlog:\n%s", want, buf.String())
				}
			}
		})
	}
}

// namedMock wraps a MockBackend with a custom Name() so the decision
// table can label tiers as "keychain"/"encrypted-file"/"plain-file"
// without instantiating real backends.
type namedMock struct {
	m    *MockBackend
	name string
}

func (n namedMock) Name() string                     { return n.name }
func (n namedMock) Available() error                 { return n.m.Available() }
func (n namedMock) Put(l [16]byte, s [32]byte) error { return n.m.Put(l, s) }
func (n namedMock) Get(l [16]byte) ([32]byte, error) { return n.m.Get(l) }
func (n namedMock) Delete(l [16]byte) error          { return n.m.Delete(l) }
func (n namedMock) List() ([][16]byte, error)        { return n.m.List() }

// TestResolverWithRealBackends_PathOverrideFallsThroughToPlainFile
// exercises Resolve() against the actual keychain / encrypted-file /
// plain-file backends. The keychain backend will either succeed
// (developer machine) or fail (CI without daemon); either outcome is
// acceptable as long as Resolve returns a usable backend rather than
// ErrSaltStorageUnavailable.
func TestResolverWithRealBackends_PathOverrideFallsThroughToPlainFile(t *testing.T) {
	root := t.TempDir()
	encPath := filepath.Join(t.TempDir(), "salts.enc")
	b, err := Resolve(ResolveOpts{
		Paths: &StoragePaths{
			PlainFileRoot:     root,
			EncryptedFilePath: encPath,
		},
		PlainFileOptIn: true,
	})
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if b.Name() == "" {
		t.Errorf("picked backend has empty name")
	}
}

// TestResolver_EncryptedFileSelectedWhenPassphraseProvided is the B1
// regression test: when the resolver is given a passphrase source for
// the encrypted-file tier, the encrypted-file backend must be selected
// in preference to the plain-file backend even on hosts where the
// keychain tier is unavailable.
func TestResolver_EncryptedFileSelectedWhenPassphraseProvided(t *testing.T) {
	// Synthetic candidate list: keychain skipped, encrypted-file wired
	// with a passphrase, plain-file available. The decision table must
	// pick encrypted-file.
	encPath := filepath.Join(t.TempDir(), "salts.enc")
	enc := NewEncryptedFileBackendForTest(encPath, []byte("pw"))
	if err := enc.Available(); err != nil {
		t.Fatalf("encrypted-file Available with passphrase: %v", err)
	}

	keychain := NewMockBackend()
	keychain.AvailableErr = errors.New("no keychain daemon")
	plain := NewMockBackend()
	b, err := resolveFrom([]Backend{
		namedMock{m: keychain, name: "keychain"},
		enc,
		namedMock{m: plain, name: "plain-file"},
	})
	if err != nil {
		t.Fatalf("resolveFrom: %v", err)
	}
	if b.Name() != "encrypted-file" {
		t.Fatalf("picked = %q, want encrypted-file", b.Name())
	}
}

// TestResolver_FailsClosedWithoutPassphraseAndWithoutOptIn ensures the
// B1 silent-plaintext-fall-through is gone: when the keychain tier is
// unavailable, the encrypted-file tier has no passphrase source, and
// PlainFileOptIn is false, Resolve must return
// ErrSaltStorageUnavailable instead of silently picking plain-file.
func TestResolver_FailsClosedWithoutPassphraseAndWithoutOptIn(t *testing.T) {
	// Real EncryptedFileBackend constructed without a passphrase
	// source — Available() must reject it.
	encPath := filepath.Join(t.TempDir(), "salts.enc")
	enc := newEncryptedFileBackendForPath(encPath)
	if err := enc.Available(); err == nil {
		t.Fatalf("encrypted-file without passphrase source: Available()=nil, want error")
	}

	keychain := NewMockBackend()
	keychain.AvailableErr = errors.New("no keychain daemon")

	// Plain-file is intentionally OMITTED from the candidate list,
	// mirroring Resolve()'s PlainFileOptIn=false behaviour.
	_, err := resolveFrom([]Backend{
		namedMock{m: keychain, name: "keychain"},
		enc,
	})
	if !errors.Is(err, ErrSaltStorageUnavailable) {
		t.Fatalf("err = %v, want ErrSaltStorageUnavailable", err)
	}
}

// TestResolver_EncryptedFileProviderInvokedLazily verifies that wiring
// a PassphraseProvider via ResolveOpts.EncryptedFilePassphraseProvider
// makes Available() report true even before the provider runs (so the
// resolver can pick the tier without prompting the user), and that the
// provider is then invoked on first salt access.
func TestResolver_EncryptedFileProviderInvokedLazily(t *testing.T) {
	encPath := filepath.Join(t.TempDir(), "salts.enc")
	var calls int
	b, err := Resolve(ResolveOpts{
		Paths:                           &StoragePaths{EncryptedFilePath: encPath, PlainFileRoot: t.TempDir()},
		EncryptedFilePassphraseProvider: PassphraseProviderFunc(func() ([]byte, error) { calls++; return []byte("test-pw"), nil }),
		PlainFileOptIn:                  true,
	})
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	// The resolver may pick keychain on a developer machine; if it
	// did not pick encrypted-file we cannot assert provider semantics.
	if b.Name() != "encrypted-file" {
		t.Skipf("resolver picked %q (likely keychain available); provider semantics already covered by TestResolver_EncryptedFileSelectedWhenPassphraseProvided", b.Name())
	}
	if calls != 0 {
		t.Errorf("provider invoked %d times before first access, want 0", calls)
	}
	if err := b.Put([16]byte{1}, [32]byte{2}); err != nil {
		t.Fatalf("Put: %v", err)
	}
	if calls != 1 {
		t.Errorf("provider invoked %d times after Put, want 1", calls)
	}
}

// probingProvider is the test-side PassphraseProvider that lets a test
// independently toggle CanProvideNow and observe whether Get was ever
// called. It models the production cliPassphraseProvider's behaviour
// when stdin is not a terminal and KONAREEF_SALT_PASSPHRASE is unset.
type probingProvider struct {
	canProvide bool
	getCalls   int
	pw         []byte
	getErr     error
}

func (p *probingProvider) Get() ([]byte, error) {
	p.getCalls++
	return p.pw, p.getErr
}

func (p *probingProvider) CanProvideNow() bool { return p.canProvide }

// TestResolver_FallthroughWhenProviderCannotProvideNow is the Hermes
// round-2 B1 regression. When the encrypted-file passphrase provider
// reports CanProvideNow() == false (production analogue: no TTY +
// KONAREEF_SALT_PASSPHRASE unset) AND the host has no keychain AND
// KONAREEF_ALLOW_PLAINTEXT_SALT=1 is explicitly opted in, the resolver
// MUST skip the encrypted-file tier and select the plain-file
// backend. Prior to the fix, Available() returned nil whenever a
// provider was wired (regardless of whether it could actually run),
// so the resolver picked encrypted-file and crashed at the first
// Put() call with "no TTY and KONAREEF_SALT_PASSPHRASE unset" —
// rendering the plaintext opt-in unreachable in non-interactive
// environments.
func TestResolver_FallthroughWhenProviderCannotProvideNow(t *testing.T) {
	tmp := t.TempDir()
	encPath := filepath.Join(tmp, "salts.enc")
	plainRoot := filepath.Join(tmp, "plain")

	// Synthesise an unavailable keychain (the namedMock below
	// already wraps a MockBackend with a custom Name()). The
	// resolver is then driven by a real encrypted-file backend
	// configured with a provider whose CanProvideNow() == false, and
	// a real plain-file backend rooted at plainRoot.
	keychainMock := NewMockBackend()
	keychainMock.AvailableErr = errors.New("no keychain")

	prov := &probingProvider{canProvide: false, pw: []byte("never-used")}
	enc := NewEncryptedFileBackendWithProvider(encPath, prov)
	plain := NewPlainFileBackend(&StoragePaths{PlainFileRoot: plainRoot})

	b, err := resolveFrom([]Backend{
		namedMock{m: keychainMock, name: "keychain"},
		enc,
		plain,
	})
	if err != nil {
		t.Fatalf("resolveFrom: %v", err)
	}
	if b.Name() != "plain-file" {
		t.Fatalf("resolver selected %q, want plain-file (Hermes B1 — encrypted-file should be skipped when CanProvideNow()==false)", b.Name())
	}
	if prov.getCalls != 0 {
		t.Errorf("provider.Get called %d times during resolve, want 0 — Available() must be side-effect free", prov.getCalls)
	}

	// Put MUST succeed against the selected plain-file backend.
	// Pre-fix, encrypted-file was selected and Put would have failed
	// inside the provider with "no TTY and KONAREEF_SALT_PASSPHRASE
	// unset".
	if err := b.Put([16]byte{0xAB}, [32]byte{0xCD}); err != nil {
		t.Fatalf("plain-file Put: %v", err)
	}
	got, err := b.Get([16]byte{0xAB})
	if err != nil {
		t.Fatalf("plain-file Get: %v", err)
	}
	if got != ([32]byte{0xCD}) {
		t.Errorf("plain-file Get round-trip salt mismatch")
	}

	// Sanity: flip CanProvideNow on and verify Available now passes
	// — this guards against an over-eager fix that always returns
	// unavailable.
	prov.canProvide = true
	if err := enc.Available(); err != nil {
		t.Errorf("encrypted-file Available() after CanProvideNow=true: %v, want nil", err)
	}
}
