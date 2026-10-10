// Copyright 2026 Jerry David Chan, Konareef.ai
// SPDX-License-Identifier: Apache-2.0

package publish

import (
	"strings"
	"testing"

	"github.com/BurntSushi/toml"
	"github.com/digitsu/konareef/internal/canon"
	"github.com/digitsu/konareef/internal/pod"
)

// parseForTest parses body into a pod.Spec plus its toml.MetaData,
// failing the test on any parse error. DeriveCommitParams needs the
// metadata to tell an absent [budget] from an explicit max_sats = 0
// (see commitparams.go).
func parseForTest(t *testing.T, body string) (*pod.Spec, toml.MetaData) {
	t.Helper()
	spec, meta, err := pod.ParseWithMeta([]byte(body))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	return spec, meta
}

func TestDeriveCommitParams(t *testing.T) {
	// The memory-free r_init is E20, the Poseidon empty-tree root
	// (konareef-rinit/v1 D1-A), with the r_init_scheme marker (D2-A). It
	// replaced the provisional all-zero value, which no proof can satisfy.
	emptyRoot := canon.EmptyMemoryRoot()
	t.Run("happy path", func(t *testing.T) {
		spec, meta := parseForTest(t, `
pod_spec_version = "0.1"
[pod]
name = "p"
[model]
provider = "openai"
name = "gpt-4o"
[budget]
max_sats = 1000
[[context.tools]]
source = "bash"
[[context.tools]]
source = "ripgrep"
`)
		got, err := DeriveCommitParams(spec, meta)
		if err != nil {
			t.Fatal(err)
		}
		if len(got.Models) != 1 || got.Models[0] != "openai/gpt-4o" {
			t.Fatalf("models = %v, want [openai/gpt-4o]", got.Models)
		}
		if got.CMax != 1000 {
			t.Fatalf("c_max = %d, want 1000", got.CMax)
		}
		if got.RInit != emptyRoot {
			t.Fatal("r_init must be the empty-memory root E20")
		}
		if got.RInit == ([32]byte{}) {
			t.Fatal("r_init must not be the legacy zero")
		}
		if got.RInitScheme != canon.RInitSchemeV1 {
			t.Fatalf("r_init_scheme = %q, want %q", got.RInitScheme, canon.RInitSchemeV1)
		}
		// Regression guard for the bug Task 8 found: DeriveCommitParams'
		// output must actually be accepted by canon.FieldsRoot, not just
		// look right in isolation. Before the fix, RInit came from
		// membridge.SparseRoot(nil) (a SHA-256 value, non-canonical
		// against the Poseidon-Pallas field) and this call failed with
		// COMMIT_NONCANONICAL_RINIT on every memory-free pod.
		if _, err := canon.FieldsRoot(got.Models, got.Tools, got.CMax, got.RInit); err != nil {
			t.Fatalf("DeriveCommitParams produced a CommitParams canon.FieldsRoot rejects: %v", err)
		}
	})
	t.Run("absent budget is not zero", func(t *testing.T) {
		spec, meta := parseForTest(t, "pod_spec_version = \"0.1\"\n[pod]\nname = \"p\"\n[model]\nprovider=\"o\"\nname=\"m\"\n")
		_, err := DeriveCommitParams(spec, meta)
		if got := canon.Code(err); got != canon.ErrCommitBudgetRequired {
			t.Fatalf("code = %q, want COMMIT_BUDGET_REQUIRED", got)
		}
	})
	t.Run("max_sats = 0 is a real value", func(t *testing.T) {
		spec, meta := parseForTest(t, "pod_spec_version = \"0.1\"\n[pod]\nname=\"p\"\n[model]\nprovider=\"o\"\nname=\"m\"\n[budget]\nmax_sats = 0\n")
		got, err := DeriveCommitParams(spec, meta)
		if err != nil {
			t.Fatalf("an explicit zero must be accepted: %v", err)
		}
		if got.CMax != 0 {
			t.Fatalf("c_max = %d, want 0", got.CMax)
		}
	})
	t.Run("model without provider", func(t *testing.T) {
		spec, meta := parseForTest(t, "pod_spec_version = \"0.1\"\n[pod]\nname=\"p\"\n[model]\nname=\"m\"\n[budget]\nmax_sats=1\n")
		_, err := DeriveCommitParams(spec, meta)
		if got := canon.Code(err); got != canon.ErrCommitModelProviderMissing {
			t.Fatalf("code = %q, want COMMIT_MODEL_PROVIDER_MISSING", got)
		}
	})
	t.Run("model without name", func(t *testing.T) {
		spec, meta := parseForTest(t, "pod_spec_version = \"0.1\"\n[pod]\nname=\"p\"\n[model]\nprovider=\"o\"\n[budget]\nmax_sats=1\n")
		_, err := DeriveCommitParams(spec, meta)
		if got := canon.Code(err); got != canon.ErrCommitModelProviderMissing {
			t.Fatalf("code = %q, want COMMIT_MODEL_PROVIDER_MISSING", got)
		}
	})
	t.Run("non-NFC tool source", func(t *testing.T) {
		// "cafe" + U+0301 combining acute — NFD, not NFC.
		spec, meta := parseForTest(t, "pod_spec_version = \"0.1\"\n[pod]\nname=\"p\"\n[model]\nprovider=\"o\"\nname=\"m\"\n[budget]\nmax_sats=1\n[[context.tools]]\nsource = \"cafe\\u0301\"\n")
		_, err := DeriveCommitParams(spec, meta)
		if got := canon.Code(err); got != canon.ErrCommitNonNFCID {
			t.Fatalf("code = %q, want COMMIT_NON_NFC_ID", got)
		}
	})
	t.Run("tools_allowed naming an uncommitted tool", func(t *testing.T) {
		spec, meta := parseForTest(t, "pod_spec_version = \"0.1\"\n[pod]\nname=\"p\"\n[model]\nprovider=\"o\"\nname=\"m\"\n[budget]\nmax_sats=1\n[[context.tools]]\nsource=\"bash\"\n[directive]\ntools_allowed = [\"curl\"]\n")
		_, err := DeriveCommitParams(spec, meta)
		if got := canon.Code(err); got != canon.ErrCommitToolAuthorityUncommitted {
			t.Fatalf("code = %q, want COMMIT_TOOL_AUTHORITY_UNCOMMITTED", got)
		}
	})
	// D4 (tool-policy semantics ADR): an explicit tools_allowed = []
	// beside a non-empty [[context.tools]] contradicts itself — "this pod
	// uses no tools" and "this pod commits tools" cannot both be true —
	// and refuses distinctly from the "some declared tool" case above.
	t.Run("tools_allowed explicitly empty beside a non-empty context.tools", func(t *testing.T) {
		spec, meta := parseForTest(t, "pod_spec_version = \"0.1\"\n[pod]\nname=\"p\"\n[model]\nprovider=\"o\"\nname=\"m\"\n[budget]\nmax_sats=1\n[[context.tools]]\nsource=\"bash\"\n[directive]\ntools_allowed = []\n")
		_, err := DeriveCommitParams(spec, meta)
		if got := canon.Code(err); got != canon.ErrCommitToolAuthorityContradiction {
			t.Fatalf("code = %q, want COMMIT_TOOL_AUTHORITY_CONTRADICTION", got)
		}
	})
	// An OMITTED tools_allowed beside a non-empty context.tools is not a
	// contradiction — it declares no directive policy at all, distinct
	// from an explicit "[]". This is the presence distinction decision D4
	// asks for: the two must not collapse to the same refusal.
	t.Run("tools_allowed omitted beside a non-empty context.tools is not a contradiction", func(t *testing.T) {
		spec, meta := parseForTest(t, "pod_spec_version = \"0.1\"\n[pod]\nname=\"p\"\n[model]\nprovider=\"o\"\nname=\"m\"\n[budget]\nmax_sats=1\n[[context.tools]]\nsource=\"bash\"\n")
		if _, err := DeriveCommitParams(spec, meta); err != nil {
			t.Fatalf("an omitted tools_allowed must not be refused: %v", err)
		}
	})
	// D5: a name in both tools_allowed and tools_denied is refused as an
	// authoring mistake, distinctly from either single-list rule above.
	t.Run("a name in both tools_allowed and tools_denied", func(t *testing.T) {
		spec, meta := parseForTest(t, "pod_spec_version = \"0.1\"\n[pod]\nname=\"p\"\n[model]\nprovider=\"o\"\nname=\"m\"\n[budget]\nmax_sats=1\n[[context.tools]]\nsource=\"bash\"\n[directive]\ntools_allowed = [\"bash\"]\ntools_denied = [\"bash\"]\n")
		_, err := DeriveCommitParams(spec, meta)
		if got := canon.Code(err); got != canon.ErrCommitToolDenyOverlap {
			t.Fatalf("code = %q, want COMMIT_TOOL_DENY_OVERLAP", got)
		}
	})
	// D5: the NFC rule R-V2.19 already applies to a declared source now
	// also applies to tools_allowed and tools_denied.
	t.Run("non-NFC tools_allowed name", func(t *testing.T) {
		spec, meta := parseForTest(t, "pod_spec_version = \"0.1\"\n[pod]\nname=\"p\"\n[model]\nprovider=\"o\"\nname=\"m\"\n[budget]\nmax_sats=1\n[[context.tools]]\nsource=\"cafe\\u0301\"\n[directive]\ntools_allowed = [\"cafe\\u0301\"]\n")
		_, err := DeriveCommitParams(spec, meta)
		// The declared source itself is non-NFC too, so DeriveCommitParams'
		// own loop over [[context.tools]] refuses first — this still pins
		// COMMIT_NON_NFC_ID as the code either way, so the assertion holds
		// regardless of which of the two NFC checks fires.
		if got := canon.Code(err); got != canon.ErrCommitNonNFCID {
			t.Fatalf("code = %q, want COMMIT_NON_NFC_ID", got)
		}
	})
	t.Run("non-NFC tools_denied name, declared side is clean NFC", func(t *testing.T) {
		spec, meta := parseForTest(t, "pod_spec_version = \"0.1\"\n[pod]\nname=\"p\"\n[model]\nprovider=\"o\"\nname=\"m\"\n[budget]\nmax_sats=1\n[[context.tools]]\nsource=\"bash\"\n[directive]\ntools_denied = [\"cafe\\u0301\"]\n")
		_, err := DeriveCommitParams(spec, meta)
		if got := canon.Code(err); got != canon.ErrCommitNonNFCID {
			t.Fatalf("code = %q, want COMMIT_NON_NFC_ID", got)
		}
	})
}

func TestMemoryBearingPodIsRefused(t *testing.T) {
	spec, meta := parseForTest(t, `
pod_spec_version = "0.1"
[pod]
name = "p"
[model]
provider = "o"
name = "m"
[budget]
max_sats = 1
[[context.memory]]
kind = "snapshot"
snapshot = "s1"
`)
	_, err := DeriveCommitParams(spec, meta)
	if got := canon.Code(err); got != canon.ErrCommitMemoryResolutionUnavailable {
		t.Fatalf("code = %q, want COMMIT_MEMORY_RESOLUTION_UNAVAILABLE", got)
	}
	if !strings.Contains(err.Error(), "companion spec") {
		t.Fatalf("the message must name the blocker: %v", err)
	}
}
