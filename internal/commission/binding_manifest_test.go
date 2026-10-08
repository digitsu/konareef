// Copyright 2026 Jerry David Chan, Konareef.ai
// SPDX-License-Identifier: Apache-2.0

// binding_manifest_test.go — the four fail-closed directions of
// Binding.ValidateAgainstManifest, plus the two that must pass.
//
// The v2 manifests below are SYNTHESISED, and that is deliberate rather
// than a shortcut around the declined [_commit] fixture blocker
// (decision 2026-08-31-konareef-commit-trailer-fixture-declined-until-v2).
// The distinction is what is being asserted. That blocker refuses a GOLDEN
// fixture — one claiming a particular fields_root is the correct derivation
// of a manifest — because no writer emits such a manifest, so the expected
// value would be a guess wearing a test's authority. Nothing here asserts
// any fields_root is correct. These tests assert only that the gate reaches
// the right VERDICT given agreement, disagreement, presence and absence,
// which is decision logic that does not depend on v2 ever shipping.

package commission

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"strings"
	"testing"
)

// v2Manifest builds a minimal canonical-v2 manifest committing frHex. Its
// declared fields (no model, no tools, [budget].max_sats = 1000) reproduce
// frA with the memory-free r_init E20, so frA is the one root
// CheckManifestCommitment accepts for it.
func v2Manifest(frHex string) []byte {
	return []byte("#!konareef-toml/v2\n" +
		"[pod]\nname = \"probe\"\n\n[budget]\nmax_sats = 1000\n\n" +
		"[_commit]\nfields_root = \"poseidon:" + frHex + "\"\n")
}

func v1Manifest() []byte {
	return []byte("#!konareef-toml/v1\n[pod]\nname = \"probe\"\n")
}

const (
	// frA is FieldsRoot(nil, nil, 1000, E20): the root v2Manifest's fields
	// reproduce. frB is another well-formed root that they do not.
	frA = "17411ea9657dc3a6e68a127f104e064e79e0647796d3ad100f3ddfa9d9410400"
	frB = "25e80065232bae5c6accde72a53d4493cbe472d6e63cf851021fa4d25084270e"
)

func hexToArr(t *testing.T, h string) *[32]byte {
	t.Helper()
	var out [32]byte
	if len(h) != 64 {
		t.Fatalf("bad test hex length %d", len(h))
	}
	for i := 0; i < 32; i++ {
		var b int
		if _, err := fmt.Sscanf(h[i*2:i*2+2], "%02x", &b); err != nil {
			t.Fatalf("bad test hex: %v", err)
		}
		out[i] = byte(b)
	}
	return &out
}

func bindingFor(manifest []byte, fr *[32]byte) Binding {
	return Binding{PodRef: "dave/probe@1.0.0", HManifest: sha256.Sum256(manifest), FieldsRoot: fr}
}

func TestValidateAgainstManifest_AcceptsMatchingPin(t *testing.T) {
	m := v2Manifest(frA)
	if err := bindingFor(m, hexToArr(t, frA)).ValidateAgainstManifest(m); err != nil {
		t.Fatalf("a pin equal to the manifest commitment must be accepted, got %v", err)
	}
}

func TestValidateAgainstManifest_AcceptsUnpinnedNonV2(t *testing.T) {
	m := v1Manifest()
	if err := bindingFor(m, nil).ValidateAgainstManifest(m); err != nil {
		t.Fatalf("a v1 manifest with no pin must be accepted, got %v", err)
	}
}

// The four refusals. Each is a direction in which an earlier version of
// this package would have failed OPEN.
func TestValidateAgainstManifest_RefusesEveryMismatch(t *testing.T) {
	v2 := v2Manifest(frA)
	v1 := v1Manifest()

	cases := []struct {
		name     string
		manifest []byte
		binding  Binding
		want     error
		why      string
	}{
		{
			name:     "v2 manifest, no pin",
			manifest: v2,
			binding:  bindingFor(v2, nil),
			want:     ErrCircuitCommitmentUnpinned,
			why:      "a silent downgrade: the pod publishes a commitment the buyer declines to name",
		},
		{
			name:     "v1 manifest, pinned anyway",
			manifest: v1,
			binding:  bindingFor(v1, hexToArr(t, frA)),
			want:     ErrCircuitCommitmentUnexpected,
			why:      "nothing to check the pin against, so arbitrary bytes would ride inside the signed form",
		},
		{
			name:     "v2 manifest, pin disagrees",
			manifest: v2,
			binding:  bindingFor(v2, hexToArr(t, frB)),
			want:     ErrFieldsRootMismatch,
			why:      "the buyer would sign a commitment this pod does not publish",
		},
		{
			name:     "v2 magic, corrupt [_commit]",
			manifest: []byte("#!konareef-toml/v2\n[pod]\nname = \"probe\"\n\n[_commit]\nfields_root = \"poseidon:zzzz\"\n"),
			binding:  Binding{PodRef: "dave/probe@1.0.0", HManifest: sha256.Sum256([]byte("#!konareef-toml/v2\n[pod]\nname = \"probe\"\n\n[_commit]\nfields_root = \"poseidon:zzzz\"\n"))},
			want:     ErrManifestCommitmentUnreadable,
			why:      "THE fail-open case: ParseCommitFieldsRoot returns one error for 'not v2' and for 'v2 but corrupt', so reading any error as 'not v2' would accept a corrupted manifest as a v1 needing no pin",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.binding.ValidateAgainstManifest(tc.manifest)
			if err == nil {
				t.Fatalf("accepted what it must refuse — %s", tc.why)
			}
			if !errors.Is(err, tc.want) {
				t.Fatalf("got %v, want %v (%s)", err, tc.want, tc.why)
			}
		})
	}
}

// The manifest-hash check must still fire, and must be reported as itself
// rather than as a commitment problem — it moved into this function from
// two separate inline sites and must not have changed meaning in transit.
func TestValidateAgainstManifest_StillRefusesWrongManifestHash(t *testing.T) {
	m := v2Manifest(frA)
	b := bindingFor(m, hexToArr(t, frA))
	b.HManifest = sha256.Sum256([]byte("some other manifest"))
	err := b.ValidateAgainstManifest(m)
	if !errors.Is(err, ErrManifestHashMismatch) {
		t.Fatalf("got %v, want ErrManifestHashMismatch", err)
	}
}

// ManifestFieldsRoot is the sole definition both the drafter and the
// checker use. If it ever answered "no commitment" for a manifest that has
// one, draft would pin nothing and check would then refuse the draft it
// just produced.
func TestManifestFieldsRoot_AgreesWithTheGate(t *testing.T) {
	for _, m := range [][]byte{v2Manifest(frA), v1Manifest()} {
		got, err := ManifestFieldsRoot(m)
		if err != nil {
			t.Fatalf("ManifestFieldsRoot: %v", err)
		}
		// Whatever it says to pin must be exactly what the gate accepts.
		if err := bindingFor(m, got).ValidateAgainstManifest(m); err != nil {
			t.Fatalf("the gate refused the pin the drafter would produce: %v", err)
		}
	}
}

func TestManifestFieldsRoot_CorruptV2IsAnErrorNotAnAbsence(t *testing.T) {
	m := []byte("#!konareef-toml/v2\n[pod]\n\n[_commit]\nfields_root = \"nonsense\"\n")
	got, err := ManifestFieldsRoot(m)
	if err == nil {
		t.Fatal("a corrupt v2 [_commit] must be an error, not a nil 'no commitment'")
	}
	if got != nil {
		t.Fatal("must not return a value alongside an error")
	}
	if !strings.Contains(err.Error(), "konareef-toml/v2") {
		t.Fatalf("error should name the version it refused: %v", err)
	}
}

// PinsCircuitCommitment is what callers use to decide whether they may
// describe constraints as tied to a proof. It must track the pointer.
func TestPinsCircuitCommitment(t *testing.T) {
	if (Binding{}).PinsCircuitCommitment() {
		t.Fatal("an unpinned binding must not claim to pin a circuit commitment")
	}
	if !(Binding{FieldsRoot: &[32]byte{}}).PinsCircuitCommitment() {
		t.Fatal("a binding pinning all-zero bytes still PINS; zero is a value, not an absence")
	}
}

// An unsupported canonical version is NOT "no commitment". A v1 manifest is
// known to carry none; a v4 manifest is one whose commitment, and whose
// commitment semantics, this build knows nothing about. Collapsing the second
// into the first accepts a future manifest as though it published nothing to
// pin — the same version-boundary fail-open aaab88b closed for
// `verify --manifest`, rebuilt one layer down.
func TestValidateAgainstManifest_RefusesUnsupportedVersions(t *testing.T) {
	// v3 is not in this list: it is implemented since MCP-Z03 and carries
	// the v2 trailer (TestValidateAgainstManifest_V3 covers it).
	for _, version := range []string{"v4", "v10", "v999", "v2x", "v3x", "vNext"} {
		t.Run(version, func(t *testing.T) {
			m := []byte("#!konareef-toml/" + version + "\n[pod]\nname = \"probe\"\n")

			// The shape that must not be blessed: hashes correctly, pins no
			// fields_root. Under the old rule this was indistinguishable
			// from a legitimate v1 proposal and was accepted.
			b := bindingFor(m, nil)
			err := b.ValidateAgainstManifest(m)
			if err == nil {
				t.Fatalf("accepted an unsupported canonical version %q as though it committed nothing", version)
			}
			if !errors.Is(err, ErrManifestVersionUnsupported) {
				t.Fatalf("got %v, want ErrManifestVersionUnsupported", err)
			}
			if !strings.Contains(err.Error(), version) {
				t.Fatalf("error should name the version it refused, got %v", err)
			}

			// Pinning one does not rescue it either: the build still cannot
			// know what that version's commitment means.
			if err := bindingFor(m, hexToArr(t, frA)).ValidateAgainstManifest(m); !errors.Is(err, ErrManifestVersionUnsupported) {
				t.Fatalf("pinned unsupported version: got %v, want ErrManifestVersionUnsupported", err)
			}
		})
	}
}

// The two supported no-commitment shapes must keep working, or the fix above
// would have closed the fail-open by breaking every real proposal.
func TestManifestFieldsRoot_SupportedNoCommitmentShapes(t *testing.T) {
	cases := map[string][]byte{
		"v1 canonical": v1Manifest(),
		"no magic":     []byte("[pod]\nname = \"probe\"\n"),
	}
	for name, m := range cases {
		t.Run(name, func(t *testing.T) {
			got, err := ManifestFieldsRoot(m)
			if err != nil {
				t.Fatalf("must be accepted as no-commitment, got %v", err)
			}
			if got != nil {
				t.Fatalf("must report no commitment, got %x", *got)
			}
			if err := bindingFor(m, nil).ValidateAgainstManifest(m); err != nil {
				t.Fatalf("gate refused a legitimate unpinned proposal: %v", err)
			}
		})
	}
}
