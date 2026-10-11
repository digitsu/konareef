// Copyright 2026 Jerry David Chan, Konareef.ai
// SPDX-License-Identifier: Apache-2.0

package commission

import (
	"errors"
	"strings"
	"testing"

	"github.com/digitsu/konareef/internal/pod"
)

// ModelIDs' identifier is "<provider>/<name>" (spec §4.1, R-V2.5), the
// same form internal/publish.DeriveCommitParams commits and
// internal/install.LoadManifestParams feeds the circuit — all three
// through canon.ModelID. See the doc comment on ModelIDs. Dropping the
// provider, as this site did until 2026-09-21, makes openai/gpt-4o and
// azure/gpt-4o commit identically.
func TestModelIDs_ProviderSlashName(t *testing.T) {
	s := pod.Spec{Model: &pod.Model{Provider: "anthropic", Name: "claude-sonnet-5"}}
	got, err := ModelIDs(s)
	if err != nil {
		t.Fatalf("ModelIDs: %v", err)
	}
	if len(got) != 1 || got[0] != "anthropic/claude-sonnet-5" {
		t.Fatalf("got %v, want [anthropic/claude-sonnet-5]", got)
	}
}

func TestModelIDs_AbsentModelIsEmpty(t *testing.T) {
	got, err := ModelIDs(pod.Spec{})
	if err != nil {
		t.Fatalf("ModelIDs: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("got %v, want empty", got)
	}
}

// A [model] naming only one of the two required parts is refused, not
// silently reduced to "no models declared" — an envelope with an empty
// models dimension would let containment report a pod contained over a
// model it does not name.
func TestModelIDs_HalfDeclaredModelIsRefused(t *testing.T) {
	for _, tc := range []struct {
		name  string
		model pod.Model
	}{
		{"no provider", pod.Model{Name: "gpt-4o"}},
		{"no name", pod.Model{Provider: "openai"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m := tc.model
			if _, err := ModelIDs(pod.Spec{Model: &m}); err == nil {
				t.Fatal("ModelIDs accepted a [model] missing a required part")
			}
			if _, err := FromSpec(pod.Spec{Model: &m}); err == nil {
				t.Fatal("FromSpec accepted a [model] missing a required part")
			}
		})
	}
}

// ToolIDs' source is [[context.tools]].source, matching
// internal/install.LoadManifestParams — see the doc comment on ToolIDs.
// [directive].tools_allowed is not read.
func TestToolIDs_FromContextTools(t *testing.T) {
	s := pod.Spec{Context: &pod.Context{Tools: []pod.ContextTool{
		{Source: "web_fetch"}, {Source: "fs_read"},
	}}}
	got := ToolIDs(s)
	if len(got) != 2 || got[0] != "fs_read" || got[1] != "web_fetch" {
		t.Fatalf("got %v, want sorted [fs_read web_fetch]", got)
	}
}

// tools_allowed is a runtime allow/deny concern, not the declared-tools
// source ToolIDs reads. A manifest that sets only tools_allowed, with no
// [[context.tools]], must derive an empty Tools dimension.
func TestToolIDs_DirectiveToolsAllowedIsNotRead(t *testing.T) {
	s := pod.Spec{Directive: &pod.Directive{ToolsAllowed: []string{"fs_read"}}}
	if got := ToolIDs(s); len(got) != 0 {
		t.Fatalf("got %v, want empty: tools_allowed must not be read", got)
	}
}

func TestFromSpec_CarriesSpendCap(t *testing.T) {
	s := pod.Spec{
		Model:   &pod.Model{Provider: "anthropic", Name: "claude-sonnet-5"},
		Context: &pod.Context{Tools: []pod.ContextTool{{Source: "fs_read"}}},
		Budget:  &pod.Budget{MaxSats: 4200},
	}
	e, err := FromSpec(s)
	if err != nil {
		t.Fatal(err)
	}
	if e.CMax != 4200 {
		t.Fatalf("CMax = %d, want 4200", e.CMax)
	}
}

// The memory-scope dimension has no manifest-side source: the pod schema has
// no provenance-label vocabulary. Derivation must leave it empty rather than
// invent one.
func TestFromSpec_LabelsAreNotDerived(t *testing.T) {
	s := pod.Spec{
		Model:   &pod.Model{Provider: "anthropic", Name: "claude-sonnet-5"},
		Context: &pod.Context{Tools: []pod.ContextTool{{Source: "fs_read"}}, Memory: []pod.ContextMemory{{Kind: "snapshot"}}},
		Budget:  &pod.Budget{MaxSats: 1},
	}
	e, err := FromSpec(s)
	if err != nil {
		t.Fatal(err)
	}
	if len(e.Labels) != 0 || e.LabelsSet {
		t.Fatalf("labels must not be derived, got %v set=%v", e.Labels, e.LabelsSet)
	}
}

func TestFromSpec_NegativeBudgetRefused(t *testing.T) {
	s := pod.Spec{
		Model:   &pod.Model{Provider: "anthropic", Name: "m"},
		Context: &pod.Context{Tools: []pod.ContextTool{{Source: "t"}}},
		Budget:  &pod.Budget{MaxSats: -1},
	}
	if _, err := FromSpec(s); err == nil {
		t.Fatal("want error for negative budget")
	}
}

// A manifest that declares tool authority ONLY through
// [directive].tools_allowed is refused, not silently derived into an empty
// Tools dimension. Deriving it would let a containment check report the pod
// contained while the pod holds four tools the envelope does not name — the
// fail-open ErrToolAuthorityNotCommitted exists to close.
func TestFromSpec_RefusesToolAuthorityOnlyInDirective(t *testing.T) {
	s := pod.Spec{
		Model:     &pod.Model{Provider: "anthropic", Name: "claude-sonnet-5"},
		Directive: &pod.Directive{ToolsAllowed: []string{"git", "filesystem"}},
		Budget:    &pod.Budget{MaxSats: 5000},
	}
	e, err := FromSpec(s)
	if !errors.Is(err, ErrToolAuthorityNotCommitted) {
		t.Fatalf("FromSpec err = %v, want ErrToolAuthorityNotCommitted (envelope was %+v)", err, e)
	}
	// The refusal must not hand back a usable envelope alongside the error:
	// a caller that ignores err would otherwise commission the very shape
	// this refusal exists to stop.
	if len(e.Models) != 0 || len(e.Tools) != 0 || e.CMax != 0 || e.ModelsSet || e.ToolsSet || e.CMaxSet {
		t.Errorf("refused derivation returned envelope %+v, want the zero envelope", e)
	}
	// The message has to tell a pod author what to change.
	if !strings.Contains(err.Error(), "[[context.tools]]") {
		t.Errorf("error message does not name the fix: %q", err)
	}
}

// tools_allowed ALONGSIDE [[context.tools]] is accepted. The
// [[context.tools]] entries do reach fields_root; tools_allowed then narrows
// that committed set at runtime rather than replacing it, so nothing is
// uncommitted and there is nothing to refuse.
func TestFromSpec_AcceptsToolsAllowedBesideContextTools(t *testing.T) {
	s := pod.Spec{
		Context:   &pod.Context{Tools: []pod.ContextTool{{Source: "git"}, {Source: "filesystem"}}},
		Directive: &pod.Directive{ToolsAllowed: []string{"git"}},
	}
	e, err := FromSpec(s)
	if err != nil {
		t.Fatalf("FromSpec err = %v, want nil: tools_allowed beside [[context.tools]] is committable", err)
	}
	// Tools still come from [[context.tools]] only — the acceptance must not
	// have been bought by folding tools_allowed into the derivation, which
	// would redefine the committed tool set of published pods.
	if len(e.Tools) != 2 || e.Tools[0] != "filesystem" || e.Tools[1] != "git" {
		t.Errorf("Tools = %v, want sorted [filesystem git] from [[context.tools]] alone", e.Tools)
	}
}

// A manifest that declares no tool authority at all is accepted: it claims
// nothing, so nothing is uncommitted.
func TestFromSpec_AcceptsNoToolAuthorityAtAll(t *testing.T) {
	s := pod.Spec{Model: &pod.Model{Provider: "anthropic", Name: "claude-sonnet-5"}}
	e, err := FromSpec(s)
	if err != nil {
		t.Fatalf("FromSpec err = %v, want nil", err)
	}
	if len(e.Tools) != 0 || !e.ToolsSet {
		t.Errorf("Tools = %v ToolsSet = %v, want empty-but-stated", e.Tools, e.ToolsSet)
	}
}

// An empty tools_allowed list is not a declaration of authority, so it is
// not refused. Guards the boundary of the non-empty condition.
func TestFromSpec_AcceptsEmptyToolsAllowed(t *testing.T) {
	s := pod.Spec{Directive: &pod.Directive{ToolsAllowed: []string{}}}
	if _, err := FromSpec(s); err != nil {
		t.Fatalf("FromSpec err = %v, want nil: an empty tools_allowed declares no authority", err)
	}
}

// D3 (tool-policy semantics ADR): a tools_allowed name absent from
// [[context.tools]] is refused even when OTHER declared tools exist —
// commission check/sign/verify now apply the same per-name rule v2 publish
// always did (spec R-V2.14), superseding the coarser "some declared tool
// exists" shape decision 2026-08-31 shipped. Before D3 this manifest was
// ACCEPTED (fixture TP-02: v2 publish refused it, commission accepted it —
// exactly the disagreement the ADR names).
func TestFromSpec_RefusesPerNameUncommittedAllowed(t *testing.T) {
	s := pod.Spec{
		Context:   &pod.Context{Tools: []pod.ContextTool{{Source: "bash"}}},
		Directive: &pod.Directive{ToolsAllowed: []string{"curl"}},
	}
	_, err := FromSpec(s)
	if !errors.Is(err, ErrToolAuthorityNotCommitted) {
		t.Fatalf("FromSpec err = %v, want ErrToolAuthorityNotCommitted", err)
	}
}

// D5: comparison is case-sensitive, so an allowed name differing only in
// case from a declared one is still uncommitted.
func TestFromSpec_RefusesCaseMismatch(t *testing.T) {
	s := pod.Spec{
		Context:   &pod.Context{Tools: []pod.ContextTool{{Source: "Bash"}}},
		Directive: &pod.Directive{ToolsAllowed: []string{"bash"}},
	}
	if _, err := FromSpec(s); !errors.Is(err, ErrToolAuthorityNotCommitted) {
		t.Fatalf("FromSpec err = %v, want ErrToolAuthorityNotCommitted (case-sensitive)", err)
	}
}

// D5: commission derivation now applies the same NFC rule v2 publish
// always applied to a declared source (R-V2.19) — fixture TP-08 exposed
// that this used to be skipped entirely on the commission side.
func TestFromSpec_RefusesNonNFCDeclaredSource(t *testing.T) {
	nfd := "café"
	s := pod.Spec{Context: &pod.Context{Tools: []pod.ContextTool{{Source: nfd}}}}
	if _, err := FromSpec(s); !errors.Is(err, ErrToolNameNotNFC) {
		t.Fatalf("FromSpec err = %v, want ErrToolNameNotNFC", err)
	}
}

func TestFromSpec_RefusesNonNFCAllowedName(t *testing.T) {
	nfd := "café"
	s := pod.Spec{
		Context:   &pod.Context{Tools: []pod.ContextTool{{Source: nfd}}},
		Directive: &pod.Directive{ToolsAllowed: []string{nfd}},
	}
	// Both sides carry the SAME (non-NFC) bytes, so a byte comparison alone
	// would call this committed; ErrToolNameNotNFC must still fire because
	// the declared side itself is checked first.
	if _, err := FromSpec(s); !errors.Is(err, ErrToolNameNotNFC) {
		t.Fatalf("FromSpec err = %v, want ErrToolNameNotNFC", err)
	}
}

// tools_denied is not read by commission derivation at all — D5's deny
// rules (overlap, unknown referent) are a pod validate / v2 publish
// concern only, so a manifest whose ONLY problem is in tools_denied must
// still derive an envelope.
func TestFromSpec_DoesNotReadToolsDenied(t *testing.T) {
	s := pod.Spec{
		Context:   &pod.Context{Tools: []pod.ContextTool{{Source: "bash"}}},
		Directive: &pod.Directive{ToolsAllowed: []string{"bash"}, ToolsDenied: []string{"bash", "ghost"}},
	}
	e, err := FromSpec(s)
	if err != nil {
		t.Fatalf("FromSpec err = %v, want nil: tools_denied is not commission's concern", err)
	}
	if len(e.Tools) != 1 || e.Tools[0] != "bash" {
		t.Fatalf("Tools = %v, want [bash]", e.Tools)
	}
}
