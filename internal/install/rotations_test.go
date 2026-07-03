// rotations_test.go — TDD coverage for the buyer-side rotation
// chain fetch and walk.
//
// The walker is the load-bearing piece of the TrustChange branch of
// install: when local known_publishers shows K_old and reef-core
// reports K_new, the install must walk a verified chain
// K_old → ... → K_new before prompting the user to accept the new
// key. Any chain break, missing link, or bad signature must abort
// with a structured error.

package install

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/digitsu/konareef/internal/identity"
)

// ── Fetch ─────────────────────────────────────────────────────────

// Verifies the fetched shape matches reef-core's wire response —
// attestation is a nested object, signature ships as base64.
func TestFetchRotations_DecodesWireShape(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/publishers/alice/rotations" {
			t.Errorf("path = %q", r.URL.Path)
		}
		body := map[string]any{
			"rotations": []map[string]any{
				{
					"attestation": map[string]any{
						"kind":           "konareef-key-rotation/v1",
						"handle":         "alice",
						"old_pubkey_hex": "02a3",
						"new_pubkey_hex": "0389",
						"rotated_at":     "2026-05-19T11:22:00.000000Z",
						"reason":         "rot",
					},
					"signature_by_old_key": base64.StdEncoding.EncodeToString([]byte{1, 2, 3}),
				},
			},
		}
		w.Header().Set("content-type", "application/json")
		_ = json.NewEncoder(w).Encode(body)
	}))
	defer srv.Close()

	got, err := FetchRotations(srv.URL, "alice")
	if err != nil {
		t.Fatalf("FetchRotations: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("len = %d, want 1", len(got))
	}
	if got[0].Attestation.Handle != "alice" {
		t.Errorf("handle = %q", got[0].Attestation.Handle)
	}
	if got[0].Attestation.OldPubkeyHex != "02a3" {
		t.Errorf("old_pubkey_hex = %q", got[0].Attestation.OldPubkeyHex)
	}
	if string(got[0].SignatureByOldKey) != string([]byte{1, 2, 3}) {
		t.Errorf("signature bytes mismatch: %v", got[0].SignatureByOldKey)
	}
}

// Empty `rotations` list is a valid response (publisher never
// rotated). Returns a zero-length slice + nil error so the caller
// can branch on len.
func TestFetchRotations_EmptyList(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"rotations": []any{}})
	}))
	defer srv.Close()

	got, err := FetchRotations(srv.URL, "alice")
	if err != nil {
		t.Fatalf("FetchRotations: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("len = %d, want 0", len(got))
	}
}

// Non-2xx is fatal. The walker treats any fetch failure as
// "cannot verify the chain → block install".
func TestFetchRotations_Non2xx_Errors(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(500)
	}))
	defer srv.Close()

	if _, err := FetchRotations(srv.URL, "alice"); err == nil {
		t.Fatal("expected error on 500, got nil")
	}
}

// ── WalkRotationChain ─────────────────────────────────────────────

// Build a real signed rotation hop A → B using identity A's key.
// Used to assemble multi-hop test chains without re-implementing
// the signing primitive inline.
func signedHop(t *testing.T, signer *identity.Identity, handle, oldPubHex, newPubHex, rotatedAt, reason string) FetchedRotation {
	t.Helper()
	att := identity.RotationAttestation{
		Kind:         "konareef-key-rotation/v1",
		Handle:       handle,
		OldPubkeyHex: oldPubHex,
		NewPubkeyHex: newPubHex,
		RotatedAt:    rotatedAt,
		Reason:       reason,
	}
	sig, err := signer.SignRotation(att)
	if err != nil {
		t.Fatalf("SignRotation: %v", err)
	}
	return FetchedRotation{Attestation: att, SignatureByOldKey: sig}
}

// Single hop A → B, signed by A, walked from A to B: must succeed
// and return the single-hop sub-chain.
func TestWalkRotationChain_SingleHop_OK(t *testing.T) {
	a, _ := identity.Generate("alice")
	b, _ := identity.Generate("alice")

	hops := []FetchedRotation{
		signedHop(t, a, "alice", a.PublicKeyHex, b.PublicKeyHex, "2026-05-01T00:00:00.000000Z", ""),
	}

	chain, err := WalkRotationChain(hops, "alice", a.PublicKeyHex, b.PublicKeyHex)
	if err != nil {
		t.Fatalf("WalkRotationChain: %v", err)
	}
	if len(chain) != 1 {
		t.Fatalf("len(chain) = %d, want 1", len(chain))
	}
}

// Multi-hop A → B → C with the second hop signed by B: walks from
// A to C, returning both hops in order.
func TestWalkRotationChain_MultiHop_OK(t *testing.T) {
	a, _ := identity.Generate("alice")
	b, _ := identity.Generate("alice")
	c, _ := identity.Generate("alice")

	hops := []FetchedRotation{
		signedHop(t, a, "alice", a.PublicKeyHex, b.PublicKeyHex, "2026-05-01T00:00:00.000000Z", ""),
		signedHop(t, b, "alice", b.PublicKeyHex, c.PublicKeyHex, "2026-05-10T00:00:00.000000Z", ""),
	}

	chain, err := WalkRotationChain(hops, "alice", a.PublicKeyHex, c.PublicKeyHex)
	if err != nil {
		t.Fatalf("WalkRotationChain: %v", err)
	}
	if len(chain) != 2 {
		t.Fatalf("len(chain) = %d, want 2", len(chain))
	}
}

// A hop whose signature was made by the wrong key is rejected. The
// walker must verify each link under the predecessor's pubkey, not
// blindly accept whatever ships in signature_by_old_key.
func TestWalkRotationChain_BadSignature_Rejected(t *testing.T) {
	a, _ := identity.Generate("alice")
	b, _ := identity.Generate("alice")
	forger, _ := identity.Generate("alice")

	// Forger signs an A → B attestation but uses their own key, not A's.
	att := identity.RotationAttestation{
		Kind: "konareef-key-rotation/v1", Handle: "alice",
		OldPubkeyHex: a.PublicKeyHex, NewPubkeyHex: b.PublicKeyHex,
		RotatedAt: "2026-05-01T00:00:00.000000Z",
	}
	badSig, _ := forger.SignRotation(att)

	hops := []FetchedRotation{{Attestation: att, SignatureByOldKey: badSig}}

	_, err := WalkRotationChain(hops, "alice", a.PublicKeyHex, b.PublicKeyHex)
	if err == nil {
		t.Fatal("expected signature error, got nil")
	}
}

// No hop with the right `old_pubkey_hex` is present — the chain
// cannot start. Returns a structured "no hop from X" error.
func TestWalkRotationChain_MissingStartHop_Rejected(t *testing.T) {
	a, _ := identity.Generate("alice")
	b, _ := identity.Generate("alice")
	c, _ := identity.Generate("alice")

	// Hop B → C exists, but we want to walk A → C; nothing starts at A.
	hops := []FetchedRotation{
		signedHop(t, b, "alice", b.PublicKeyHex, c.PublicKeyHex, "2026-05-10T00:00:00.000000Z", ""),
	}

	_, err := WalkRotationChain(hops, "alice", a.PublicKeyHex, c.PublicKeyHex)
	if err == nil {
		t.Fatal("expected missing-hop error, got nil")
	}
}

// Chain reaches a dead end short of the target (A → B exists, but
// no hop from B to C, and the target is C). Must reject.
func TestWalkRotationChain_DeadEndShortOfTarget_Rejected(t *testing.T) {
	a, _ := identity.Generate("alice")
	b, _ := identity.Generate("alice")
	c, _ := identity.Generate("alice")

	hops := []FetchedRotation{
		signedHop(t, a, "alice", a.PublicKeyHex, b.PublicKeyHex, "2026-05-01T00:00:00.000000Z", ""),
	}

	_, err := WalkRotationChain(hops, "alice", a.PublicKeyHex, c.PublicKeyHex)
	if err == nil {
		t.Fatal("expected dead-end error, got nil")
	}
}

// A hop's attestation.handle disagreeing with the walker's handle
// argument is a fatal mismatch — protects against cross-publisher
// attestation reuse on a misconfigured server.
func TestWalkRotationChain_WrongHandle_Rejected(t *testing.T) {
	a, _ := identity.Generate("alice")
	b, _ := identity.Generate("alice")

	// Signed legitimately by A, but the attestation says handle="eve".
	hop := signedHop(t, a, "eve", a.PublicKeyHex, b.PublicKeyHex, "2026-05-01T00:00:00.000000Z", "")
	hops := []FetchedRotation{hop}

	_, err := WalkRotationChain(hops, "alice", a.PublicKeyHex, b.PublicKeyHex)
	if err == nil {
		t.Fatal("expected handle-mismatch error, got nil")
	}
}

// A cycle in the rotation graph (A → B → A) is invalid — the
// walker must not loop infinitely. With from=A and to=B, the
// expected behavior is success on the first hop; with from=A
// to=some unrelated C, the walker must terminate without revisiting.
func TestWalkRotationChain_Cycle_TerminatesAndRejectsUnreachableTarget(t *testing.T) {
	a, _ := identity.Generate("alice")
	b, _ := identity.Generate("alice")
	c, _ := identity.Generate("alice") // unreachable target

	hops := []FetchedRotation{
		signedHop(t, a, "alice", a.PublicKeyHex, b.PublicKeyHex, "2026-05-01T00:00:00.000000Z", ""),
		signedHop(t, b, "alice", b.PublicKeyHex, a.PublicKeyHex, "2026-05-02T00:00:00.000000Z", ""),
	}

	_, err := WalkRotationChain(hops, "alice", a.PublicKeyHex, c.PublicKeyHex)
	if err == nil {
		t.Fatal("expected unreachable-target error, got nil (or hang)")
	}
}
