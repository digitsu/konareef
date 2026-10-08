// Copyright 2026 Jerry David Chan, Konareef.ai
// SPDX-License-Identifier: Apache-2.0

package pod

import (
	"reflect"
	"testing"
)

// spec builds a minimal Spec for CheckToolPolicy's three inputs, without
// going through TOML at all — these tests are about the pure relation, not
// parsing. A nil slice and an explicit empty slice are equivalent inputs
// here; CheckToolPolicy never distinguishes them (that is decision D4,
// decided with toml.MetaData in internal/publish/commitparams.go, not
// here — see toolpolicy.go's header).
func spec(declared, allowed, denied []string) Spec {
	var s Spec
	if declared != nil {
		s.Context = &Context{}
		for _, d := range declared {
			s.Context.Tools = append(s.Context.Tools, ContextTool{Source: d})
		}
	}
	if allowed != nil || denied != nil {
		s.Directive = &Directive{ToolsAllowed: allowed, ToolsDenied: denied}
	}
	return s
}

func TestCheckToolPolicy_NoDirectiveNoDeclaredIsClean(t *testing.T) {
	if got := CheckToolPolicy(Spec{}); len(got) != 0 {
		t.Fatalf("got %+v, want no issues", got)
	}
}

// D3: an allowed name absent from declared is Uncommitted — the per-name
// rule shared by v2 publish and, since decision D3, commission
// check/sign/verify. A committed name (fixture TP-01's "narrower than
// declared" shape) raises nothing.
func TestCheckToolPolicy_Uncommitted(t *testing.T) {
	got := CheckToolPolicy(spec([]string{"bash"}, []string{"curl"}, nil))
	want := []ToolPolicyIssue{{Code: ToolPolicyUncommitted, Field: ToolPolicyFieldAllowed, Name: "curl"}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %+v, want %+v", got, want)
	}

	if got := CheckToolPolicy(spec([]string{"bash", "curl"}, []string{"bash"}, nil)); len(got) != 0 {
		t.Fatalf("allowed narrower than declared must raise nothing, got %+v", got)
	}
}

// D5: every declared and allowed name must be NFC-normalized. A non-NFC
// name is reported once, as ToolPolicyNonNFC, and is NOT additionally
// reported as Uncommitted even when its raw bytes also fail the
// committed-membership comparison — see toolpolicy.go's header for why a
// second, misleading verdict on the same name would follow from a byte
// comparison against unnormalized input.
func TestCheckToolPolicy_NonNFC(t *testing.T) {
	nfd := "café" // "café" as NFD: e + combining acute
	nfc := "café"  // already NFC

	t.Run("declared side", func(t *testing.T) {
		got := CheckToolPolicy(spec([]string{nfd}, nil, nil))
		want := []ToolPolicyIssue{{Code: ToolPolicyNonNFC, Field: ToolPolicyFieldDeclared, Name: nfd}}
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("got %+v, want %+v", got, want)
		}
	})

	t.Run("allowed side, byte-identical to a non-NFC declared name", func(t *testing.T) {
		// Both declared and allowed carry the SAME non-NFC bytes: a byte
		// comparison alone would call this "committed". It must still be
		// reported as non-NFC, not silently accepted.
		got := CheckToolPolicy(spec([]string{nfd}, []string{nfd}, nil))
		want := []ToolPolicyIssue{
			{Code: ToolPolicyNonNFC, Field: ToolPolicyFieldDeclared, Name: nfd},
			{Code: ToolPolicyNonNFC, Field: ToolPolicyFieldAllowed, Name: nfd},
		}
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("got %+v, want %+v", got, want)
		}
	})

	t.Run("allowed side does not also report uncommitted", func(t *testing.T) {
		// declared is NFC "café"; allowed is the NFD spelling of the same
		// word, so a byte comparison says "not committed" too — but the
		// real, actionable problem is normalization, and only that must
		// be reported.
		got := CheckToolPolicy(spec([]string{nfc}, []string{nfd}, nil))
		want := []ToolPolicyIssue{{Code: ToolPolicyNonNFC, Field: ToolPolicyFieldAllowed, Name: nfd}}
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("got %+v, want %+v", got, want)
		}
	})

	t.Run("denied side", func(t *testing.T) {
		got := CheckToolPolicy(spec([]string{"bash"}, nil, []string{nfd}))
		want := []ToolPolicyIssue{{Code: ToolPolicyNonNFC, Field: ToolPolicyFieldDenied, Name: nfd}}
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("got %+v, want %+v", got, want)
		}
	})
}

// D5: a name in both tools_allowed and tools_denied is DenyOverlap — an
// authoring mistake, reported regardless of whether the name is committed.
func TestCheckToolPolicy_DenyOverlap(t *testing.T) {
	got := CheckToolPolicy(spec([]string{"bash", "read"}, []string{"bash", "read"}, []string{"bash"}))
	want := []ToolPolicyIssue{{Code: ToolPolicyDenyOverlap, Field: ToolPolicyFieldDenied, Name: "bash"}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %+v, want %+v", got, want)
	}
}

// D5: a denied name absent from declared, and not overlapping allowed, is
// DenyUnknown — the code-reviewer example's "secrets_read" shape. Overlap
// takes priority over "unknown" when a name is both denied-and-allowed and
// also absent from declared: it is reported once, as DenyOverlap.
func TestCheckToolPolicy_DenyUnknown(t *testing.T) {
	got := CheckToolPolicy(spec([]string{"bash"}, nil, []string{"secrets_read"}))
	want := []ToolPolicyIssue{{Code: ToolPolicyDenyUnknown, Field: ToolPolicyFieldDenied, Name: "secrets_read"}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %+v, want %+v", got, want)
	}

	t.Run("overlap wins over unknown for the same name", func(t *testing.T) {
		got := CheckToolPolicy(spec(nil, []string{"ghost"}, []string{"ghost"}))
		var overlap, unknown bool
		for _, p := range got {
			if p.Name == "ghost" && p.Code == ToolPolicyDenyOverlap {
				overlap = true
			}
			if p.Name == "ghost" && p.Code == ToolPolicyDenyUnknown {
				unknown = true
			}
		}
		if !overlap || unknown {
			t.Fatalf("got %+v, want DenyOverlap only for %q", got, "ghost")
		}
	})
}

func TestDeclaredToolSources(t *testing.T) {
	if got := DeclaredToolSources(Spec{}); got != nil {
		t.Fatalf("no [context]: got %v, want nil", got)
	}
	if got := DeclaredToolSources(Spec{Context: &Context{}}); got != nil {
		t.Fatalf("[context] with no tools: got %v, want nil", got)
	}
	got := DeclaredToolSources(spec([]string{"bash", "curl"}, nil, nil))
	if !reflect.DeepEqual(got, []string{"bash", "curl"}) {
		t.Fatalf("got %v, want [bash curl] in manifest order", got)
	}
}
