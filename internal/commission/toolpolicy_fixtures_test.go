// Copyright 2026 Jerry David Chan, Konareef.ai
// SPDX-License-Identifier: Apache-2.0

// toolpolicy_fixtures_test.go exercises the three tool-name sets a manifest
// can carry: [[context.tools]].source (declared, committed),
// [directive].tools_allowed and [directive].tools_denied (neither
// committed). The cases live in testdata/toolpolicy/cases.json and are the
// shared fixture set for the tool-policy semantics ADR
// (docs/design/tool-policy-semantics-adr.md, TA-00 konareef#18 / TA-01
// konareef#19).
//
// Each case's "current" block is a frozen historical record of what the
// code on `main` did BEFORE TA-01 — pinned by TA-00, the design task, and
// left untouched here per that task's own instruction ("TA-01 adds the
// approved expectations next to the 'current' block ... a 'current'
// expectation that stops holding is a behaviour change that must be named
// in that MR, not silently re-baselined"). It is no longer exercised
// against live code: TA-01 deliberately changed behaviour away from it for
// TP-02, TP-04, TP-05, TP-07, TP-08 and TP-11 (decisions D3-D5), and this
// file's job from here on is to enforce the "approved" block — the
// contract the owner actually accepted — not to keep re-asserting a
// snapshot the implementation was instructed to move away from.
package commission

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/digitsu/konareef/internal/canon"
	"github.com/digitsu/konareef/internal/envelope"
	"github.com/digitsu/konareef/internal/pod"
	"github.com/digitsu/konareef/internal/publish"
)

// toolPolicyCase is one entry of testdata/toolpolicy/cases.json.
//
// Allowed and Denied are pointers so that JSON null (key omitted from the
// manifest) and JSON [] (key present and empty) stay distinct. That
// distinction is the presence question the ADR asks the owner to settle.
type toolPolicyCase struct {
	ID              string    `json:"id"`
	Note            string    `json:"note"`
	Declared        []string  `json:"declared"`
	Allowed         *[]string `json:"allowed"`
	Denied          *[]string `json:"denied"`
	CommissionTools []string  `json:"commission_tools"`
	Current         struct {
		ValidateWarnings int      `json:"validate_warnings"`
		PublishCode      string   `json:"publish_code"`
		CommissionGuard  string   `json:"commission_guard"`
		EnvelopeTools    []string `json:"envelope_tools"`
		BuyerContains    *bool    `json:"buyer_contains"`
	} `json:"current"`
	// Approved is the TA-01 contract: what pod validate, v2 publish and
	// commission draft/check/sign/verify do once decisions D3-D5 are
	// implemented. ValidateIssues is new relative to Current — decision D5
	// makes a tools_allowed/tools_denied overlap a validate Issue (fails
	// validation), not just a Warning, so a case exercising that shape
	// needs to say so explicitly rather than being assumed schema-valid.
	Approved struct {
		ValidateIssues   int      `json:"validate_issues"`
		ValidateWarnings int      `json:"validate_warnings"`
		PublishCode      string   `json:"publish_code"`
		CommissionGuard  string   `json:"commission_guard"`
		EnvelopeTools    []string `json:"envelope_tools"`
		BuyerContains    *bool    `json:"buyer_contains"`
	} `json:"approved"`
	Relations struct {
		AllowedSubsetDeclared *bool `json:"allowed_subset_declared"`
		DeclaredSubsetAllowed *bool `json:"declared_subset_allowed"`
		DenyOverlapsAllowed   bool  `json:"deny_overlaps_allowed"`
	} `json:"relations"`
}

// loadToolPolicyCases reads and decodes the fixture file.
//
// Input: the test handle. Output: every case, in file order. Fails the
// test on a read or decode error, or on an empty file (a silently empty
// fixture set would make every loop below pass vacuously).
func loadToolPolicyCases(t *testing.T) []toolPolicyCase {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", "toolpolicy", "cases.json"))
	if err != nil {
		t.Fatalf("read fixtures: %v", err)
	}
	var file struct {
		Cases []toolPolicyCase `json:"cases"`
	}
	if err := json.Unmarshal(raw, &file); err != nil {
		t.Fatalf("decode fixtures: %v", err)
	}
	if len(file.Cases) == 0 {
		t.Fatal("no tool-policy fixtures decoded")
	}
	return file.Cases
}

// tomlStringArray renders names as a TOML array of basic strings.
//
// Input: a list of names. Output: the array literal. JSON string escapes
// (\", \\, \uXXXX) are valid TOML basic-string escapes, so a JSON array is
// also a valid TOML array; the bytes of each name survive unchanged, which
// matters for the NFC/NFD cases.
func tomlStringArray(names []string) string {
	if names == nil {
		names = []string{}
	}
	b, err := json.Marshal(names)
	if err != nil {
		panic(err) // []string always marshals
	}
	return string(b)
}

// manifestFor builds a minimal schema-valid pod.toml for one case.
//
// Input: the case. Output: manifest bytes with a [model] and a [budget]
// (so a v2 publish derivation reaches the tool checks), one
// [[context.tools]] entry per declared name, and a [directive] that emits
// tools_allowed / tools_denied only when the case sets them (nil pointer =
// key omitted, empty slice = key present and empty).
func manifestFor(c toolPolicyCase) []byte {
	var b strings.Builder
	b.WriteString("pod_spec_version = \"0.1\"\n")
	b.WriteString("[pod]\nname = \"tool-policy-fixture\"\nversion = \"0.1.0\"\n")
	b.WriteString("[runtime]\nkind = \"orca\"\n")
	b.WriteString("[model]\nprovider = \"anthropic\"\nname = \"claude-sonnet-5\"\n")
	b.WriteString("[budget]\nmax_sats = 1000\n")
	for _, name := range c.Declared {
		fmt.Fprintf(&b, "[[context.tools]]\nsource = %s\n", strings.Trim(tomlStringArray([]string{name}), "[]"))
	}
	b.WriteString("[directive]\ntask = \"fixture\"\n")
	if c.Allowed != nil {
		fmt.Fprintf(&b, "tools_allowed = %s\n", tomlStringArray(*c.Allowed))
	}
	if c.Denied != nil {
		fmt.Fprintf(&b, "tools_denied = %s\n", tomlStringArray(*c.Denied))
	}
	return []byte(b.String())
}

// isSubset reports whether every element of inner is in outer, comparing
// bytes exactly (no case folding, no Unicode normalization) as all current
// Go and Elixir code does.
func isSubset(inner, outer []string) bool {
	set := make(map[string]bool, len(outer))
	for _, v := range outer {
		set[v] = true
	}
	for _, v := range inner {
		if !set[v] {
			return false
		}
	}
	return true
}

// boolPtrString renders an optional fixture boolean for a failure
// message. Input: the pointer. Output: "null", "true" or "false".
func boolPtrString(b *bool) string {
	if b == nil {
		return "null"
	}
	return fmt.Sprint(*b)
}

// TestToolPolicyFixtures_ApprovedBehaviour runs every fixture through the
// four Go surfaces that read tool names — authoring validation, v2 publish
// derivation, the commission guard / envelope derivation, and buyer
// containment — and checks each against the case's "approved" block: the
// tool-policy semantics ADR's decisions D3-D5, as implemented by TA-01.
func TestToolPolicyFixtures_ApprovedBehaviour(t *testing.T) {
	for _, c := range loadToolPolicyCases(t) {
		c := c
		t.Run(c.ID, func(t *testing.T) {
			manifest := manifestFor(c)

			// Surface 1: `konareef pod validate`. Every fixture is
			// schema-valid by construction (tools_allowed/tools_denied are
			// unconstrained string arrays at the schema layer), so any
			// Issue here is a cross-field tool-policy rule — decision D5's
			// tools_allowed/tools_denied overlap is the one case that
			// produces one; everything else is a Warning.
			issues, warnings, err := pod.ValidateWithWarnings(manifest)
			if err != nil {
				t.Fatalf("validate: %v\n%s", err, manifest)
			}
			if len(issues) != c.Approved.ValidateIssues {
				t.Errorf("validate: %d issues %+v, want %d\n%s", len(issues), issues, c.Approved.ValidateIssues, manifest)
			}
			if len(warnings) != c.Approved.ValidateWarnings {
				t.Errorf("validate: %d warnings %+v, want %d", len(warnings), warnings, c.Approved.ValidateWarnings)
			}

			spec, meta, err := pod.ParseWithMeta(manifest)
			if err != nil {
				t.Fatalf("parse: %v", err)
			}

			// Presence: the TOML metadata DOES distinguish an omitted key
			// from an explicit empty list; decision D4 is what makes that
			// distinction meaningful (the tools-allowed-empty-contradicts
			// -declared warning above, and COMMIT_TOOL_AUTHORITY_CONTRADICTION
			// below, both depend on it).
			if got, want := meta.IsDefined("directive", "tools_allowed"), c.Allowed != nil; got != want {
				t.Errorf("meta.IsDefined(directive.tools_allowed) = %v, want %v", got, want)
			}
			if c.Allowed != nil && len(*c.Allowed) == 0 && len(spec.Directive.ToolsAllowed) != 0 {
				t.Errorf("explicit empty tools_allowed decoded as %v", spec.Directive.ToolsAllowed)
			}

			// Surface 2: v2 publish derivation.
			_, perr := publish.DeriveCommitParams(spec, meta)
			if got := canon.Code(perr); got != c.Approved.PublishCode {
				t.Errorf("publish: code %q (err %v), want %q", got, perr, c.Approved.PublishCode)
			}

			// Surface 3: commission draft/check/sign/verify all derive the
			// manifest envelope through FromSpec, which now applies the
			// same per-name rule as v2 publish, plus the D5 NFC check
			// (decision D3).
			env, ferr := FromSpec(*spec)
			switch c.Approved.CommissionGuard {
			case "accept":
				if ferr != nil {
					t.Fatalf("FromSpec: unexpected error %v", ferr)
				}
			case "refuse_uncommitted":
				if !errors.Is(ferr, ErrToolAuthorityNotCommitted) {
					t.Fatalf("FromSpec: want ErrToolAuthorityNotCommitted, got %v", ferr)
				}
				return
			case "refuse_non_nfc":
				if !errors.Is(ferr, ErrToolNameNotNFC) {
					t.Fatalf("FromSpec: want ErrToolNameNotNFC, got %v", ferr)
				}
				return
			default:
				t.Fatalf("unknown commission_guard %q", c.Approved.CommissionGuard)
			}
			if !reflect.DeepEqual(env.Tools, envelope.Normalise(c.Approved.EnvelopeTools)) {
				t.Errorf("envelope Tools = %q, want %q", env.Tools, c.Approved.EnvelopeTools)
			}

			// Surface 4: buyer containment, tools dimension only. The
			// commission copies the manifest envelope and replaces Tools,
			// so any failure is attributable to tools.
			commission := env
			commission.Tools = c.CommissionTools
			res := commission.Contains(env)
			if c.Approved.BuyerContains == nil {
				t.Fatal("buyer_contains must be set when the guard accepts")
			}
			if res.OK != *c.Approved.BuyerContains {
				t.Errorf("Contains = %v (%+v), want %v", res.OK, res.Failures, *c.Approved.BuyerContains)
			}
		})
	}
}

// TestToolPolicyFixtures_Relations checks the recorded relation columns
// against the case inputs, so the ADR's option table cannot quote a
// relation value the inputs do not produce. A null column means the
// relation is undefined because tools_allowed is omitted.
func TestToolPolicyFixtures_Relations(t *testing.T) {
	for _, c := range loadToolPolicyCases(t) {
		c := c
		t.Run(c.ID, func(t *testing.T) {
			r := c.Relations
			if c.Allowed == nil {
				if r.AllowedSubsetDeclared != nil || r.DeclaredSubsetAllowed != nil {
					t.Fatalf("tools_allowed omitted: subset relations must be null")
				}
			} else {
				if r.AllowedSubsetDeclared == nil || *r.AllowedSubsetDeclared != isSubset(*c.Allowed, c.Declared) {
					t.Errorf("allowed_subset_declared recorded %s, inputs give %v", boolPtrString(r.AllowedSubsetDeclared), isSubset(*c.Allowed, c.Declared))
				}
				if r.DeclaredSubsetAllowed == nil || *r.DeclaredSubsetAllowed != isSubset(c.Declared, *c.Allowed) {
					t.Errorf("declared_subset_allowed recorded %s, inputs give %v", boolPtrString(r.DeclaredSubsetAllowed), isSubset(c.Declared, *c.Allowed))
				}
			}
			overlap := false
			if c.Allowed != nil && c.Denied != nil {
				for _, d := range *c.Denied {
					if isSubset([]string{d}, *c.Allowed) {
						overlap = true
					}
				}
			}
			if overlap != r.DenyOverlapsAllowed {
				t.Errorf("deny_overlaps_allowed recorded %v, inputs give %v", r.DenyOverlapsAllowed, overlap)
			}
		})
	}
}

// TestBuyerToolsSuppliesLink3 shows that the buyer-side link of the
// transitivity chain — committed context.tools ⊆ buyer commission.Tools —
// is already decided by the shipped envelope algebra, with no new key,
// circuit input, vkey or fifth envelope dimension. A manifest declaring
// {bash, curl} is contained by a commission permitting {bash, curl} and
// refused, on the tools dimension alone, by one permitting only {bash}.
//
// It does NOT show that recorded runtime calls are members of the
// committed set (link 1, in-circuit) or that the committed set equals the
// manifest the run executed (link 2 plus server admission, IB-00/IB-05).
func TestBuyerToolsSuppliesLink3(t *testing.T) {
	manifest := manifestFor(toolPolicyCase{Declared: []string{"bash", "curl"}})
	spec, err := pod.Parse(manifest)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	env, err := FromSpec(spec)
	if err != nil {
		t.Fatalf("FromSpec: %v", err)
	}

	wide := env
	wide.Tools = []string{"bash", "curl"}
	if res := wide.Contains(env); !res.OK {
		t.Fatalf("commission {bash,curl} must contain manifest {bash,curl}: %+v", res.Failures)
	}

	narrow := env
	narrow.Tools = []string{"bash"}
	res := narrow.Contains(env)
	if res.OK {
		t.Fatal("commission {bash} must not contain manifest {bash,curl}")
	}
	if len(res.Failures) != 1 || res.Failures[0].Dimension != "tools" {
		t.Fatalf("want exactly one tools-dimension failure, got %+v", res.Failures)
	}
}
