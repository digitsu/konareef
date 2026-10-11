// Copyright 2026 Jerry David Chan, Konareef.ai
// SPDX-License-Identifier: Apache-2.0

package commission

import (
	"testing"

	"github.com/digitsu/konareef/internal/envelope"
)

func fixture() Proposal {
	return Proposal{
		Envelope: envelope.Envelope{
			Models: []string{"anthropic/claude-sonnet-5"}, ModelsSet: true,
			Tools: []string{"fs_read"}, ToolsSet: true,
			Labels: []string{"public"}, LabelsSet: true,
			CMax: 4200, CMaxSet: true,
		},
		Binding: Binding{PodRef: "dave/mybot@0.1.0", HManifest: [32]byte{1, 2, 3}},
		Prose:   "Summarise the weekly reports. Do not fetch anything from the web.",
	}
}

func TestCanonical_IsDeterministic(t *testing.T) {
	a, err := fixture().Canonical()
	if err != nil {
		t.Fatal(err)
	}
	b, err := fixture().Canonical()
	if err != nil {
		t.Fatal(err)
	}
	if string(a) != string(b) {
		t.Fatal("canonical form is not deterministic")
	}
}

func TestCanonical_SetOrderDoesNotMatter(t *testing.T) {
	p1 := fixture()
	p1.Envelope.Tools = []string{"fs_read", "web_fetch"}
	p2 := fixture()
	p2.Envelope.Tools = []string{"web_fetch", "fs_read"}
	a, _ := p1.Canonical()
	b, _ := p2.Canonical()
	if string(a) != string(b) {
		t.Fatal("declaration order must not change the canonical form")
	}
}

func TestHCommission_ChangesWithProse(t *testing.T) {
	p1 := fixture()
	p2 := fixture()
	p2.Prose = p1.Prose + "."
	h1, _ := p1.HCommission()
	h2, _ := p2.HCommission()
	if h1 == h2 {
		t.Fatal("prose must be inside the hash")
	}
}

func TestHCommission_ChangesWithEnvelope(t *testing.T) {
	p1 := fixture()
	p2 := fixture()
	p2.Envelope.CMax = 4201
	h1, _ := p1.HCommission()
	h2, _ := p2.HCommission()
	if h1 == h2 {
		t.Fatal("envelope must be inside the hash")
	}
}

func TestHCommission_ChangesWithBinding(t *testing.T) {
	p1 := fixture()
	p2 := fixture()
	p2.Binding.HManifest = [32]byte{9}
	h1, _ := p1.HCommission()
	h2, _ := p2.HCommission()
	if h1 == h2 {
		t.Fatal("binding must be inside the hash")
	}
}

// TestCanonicalFormIgnoresPresenceFlagsAndOrder locks in the three
// properties that make canonicalProposal's design safe: the presence flags
// carry no weight in the hash, set declaration order carries no weight in
// the hash, and repeated encoding of the same proposal is stable. Without
// this test, someone could "fix" canonicalProposal by adding the four
// presence flags and every other test in this file would still pass,
// silently changing every commission hash the system has ever produced.
func TestCanonicalFormIgnoresPresenceFlagsAndOrder(t *testing.T) {
	t.Run("flags do not affect the hash", func(t *testing.T) {
		allSet := fixture()
		allSet.Envelope.ModelsSet = true
		allSet.Envelope.ToolsSet = true
		allSet.Envelope.LabelsSet = true
		allSet.Envelope.CMaxSet = true

		noneSet := fixture()
		noneSet.Envelope.ModelsSet = false
		noneSet.Envelope.ToolsSet = false
		noneSet.Envelope.LabelsSet = false
		noneSet.Envelope.CMaxSet = false

		h1, err := allSet.HCommission()
		if err != nil {
			t.Fatal(err)
		}
		h2, err := noneSet.HCommission()
		if err != nil {
			t.Fatal(err)
		}
		if h1 != h2 {
			t.Fatal("presence flags must not affect the hash")
		}
	})

	t.Run("declaration order does not affect the hash", func(t *testing.T) {
		p1 := fixture()
		p1.Envelope.Tools = []string{"z", "t", "a"}
		p2 := fixture()
		p2.Envelope.Tools = []string{"a", "t", "z"}

		h1, err := p1.HCommission()
		if err != nil {
			t.Fatal(err)
		}
		h2, err := p2.HCommission()
		if err != nil {
			t.Fatal(err)
		}
		if h1 != h2 {
			t.Fatal("set declaration order must not affect the hash")
		}
	})

	t.Run("canonical form is deterministic across repeated encodings", func(t *testing.T) {
		p := fixture()
		first, err := p.HCommission()
		if err != nil {
			t.Fatal(err)
		}
		for i := 0; i < 20; i++ {
			h, err := p.HCommission()
			if err != nil {
				t.Fatal(err)
			}
			if h != first {
				t.Fatalf("iteration %d: canonical hash changed across repeated encodings", i)
			}
		}
	})
}
