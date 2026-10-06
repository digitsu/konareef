// Copyright 2026 Jerry David Chan, Konareef.ai
// SPDX-License-Identifier: Apache-2.0

package commission

import (
	"errors"
	"strings"
	"testing"

	"github.com/digitsu/konareef/internal/identity"
)

func TestParsePodRef_AcceptsAFullyVersionedRef(t *testing.T) {
	handle, podName, version, err := ParsePodRef("dave/mybot@0.1.0")
	if err != nil {
		t.Fatalf("a well-formed ref must parse, got %v", err)
	}
	if handle != "dave" || podName != "mybot" || version != "0.1.0" {
		t.Fatalf("got (%q, %q, %q), want (dave, mybot, 0.1.0)", handle, podName, version)
	}
}

// The unversioned case is called out separately because it is the one a
// reader is most likely to think should pass: `konareef install dave/mybot`
// accepts it and resolves "latest". A commission must not, for the reason
// ErrPodRefMalformed's doc comment gives — "latest" is drift, which is the
// exact thing h_manifest exists to detect.
func TestParsePodRef_RejectsAnUnversionedRef(t *testing.T) {
	if _, _, _, err := ParsePodRef("dave/mybot"); !errors.Is(err, ErrPodRefMalformed) {
		t.Fatalf("an unversioned ref must be refused, got %v", err)
	}
}

func TestParsePodRef_RejectsMalformedRefs(t *testing.T) {
	cases := map[string]string{
		"empty":              "",
		"no slash":           "mybot@0.1.0",
		"no at":              "dave/mybot",
		"empty handle":       "/mybot@0.1.0",
		"empty pod name":     "dave/@0.1.0",
		"empty version":      "dave/mybot@",
		"two slashes":        "dave/team/mybot@0.1.0",
		"two ats":            "dave/mybot@0.1.0@2",
		"at before slash":    "dave@0.1.0/mybot",
		"leading whitespace": " dave/mybot@0.1.0",
		"embedded newline":   "dave/mybot@0.1.0\nmodels = []",
		"embedded space":     "dave/my bot@0.1.0",
	}
	for name, ref := range cases {
		t.Run(name, func(t *testing.T) {
			if _, _, _, err := ParsePodRef(ref); !errors.Is(err, ErrPodRefMalformed) {
				t.Fatalf("ref %q must be refused with ErrPodRefMalformed, got %v", ref, err)
			}
		})
	}
}

// TestSignRefusesMalformedPodRef is the library half of blocker 3. Sign
// used to check the envelope and h_manifest only, so a proposal naming a
// pod ref that no resolver could ever resolve — or none at all — became a
// signed artifact that `verify` then reported as clean.
func TestSignRefusesMalformedPodRef(t *testing.T) {
	id, err := identity.Generate("test-buyer")
	if err != nil {
		t.Fatal(err)
	}
	for name, ref := range map[string]string{
		"empty":       "",
		"unversioned": "dave/mybot",
		"no slash":    "mybot@0.1.0",
	} {
		t.Run(name, func(t *testing.T) {
			p := fixture()
			p.Binding.PodRef = ref
			if _, err := Sign(p, id); !errors.Is(err, ErrPodRefMalformed) {
				t.Fatalf("Sign must refuse pod_ref %q with ErrPodRefMalformed, got %v", ref, err)
			}
		})
	}
}

// TestValidateSignable_IsSignsOnlyGate is the structural guard behind
// signable.go's whole premise: `check` promises that whatever it approves,
// `sign` accepts, and it keeps that promise by calling ValidateSignable
// instead of restating its rules. The promise only holds if Sign has no
// refusal of its own that ValidateSignable does not also make.
//
// So this test asserts the two agree on every proposal it can build by
// breaking one thing at a time: whenever ValidateSignable passes, Sign must
// too, and whenever it refuses, Sign must refuse with the same error. A
// future rule added to Sign alone — which is precisely how `check` and
// `sign` drifted apart twice before — fails here.
func TestValidateSignable_IsSignsOnlyGate(t *testing.T) {
	id, err := identity.Generate("test-buyer")
	if err != nil {
		t.Fatal(err)
	}
	cases := map[string]func(*Proposal){
		"complete":            func(*Proposal) {},
		"models unstated":     func(p *Proposal) { p.Envelope.ModelsSet = false },
		"tools unstated":      func(p *Proposal) { p.Envelope.ToolsSet = false },
		"labels unstated":     func(p *Proposal) { p.Envelope.LabelsSet = false },
		"c_max_sats unstated": func(p *Proposal) { p.Envelope.CMaxSet = false },
		"unpinned":            func(p *Proposal) { p.Binding.HManifest = [32]byte{} },
		"malformed pod_ref":   func(p *Proposal) { p.Binding.PodRef = "nope" },
		"unversioned pod_ref": func(p *Proposal) { p.Binding.PodRef = "dave/mybot" },
	}
	for name, breakIt := range cases {
		t.Run(name, func(t *testing.T) {
			p := fixture()
			breakIt(&p)

			gateErr := ValidateSignable(p)
			_, signErr := Sign(p, id)

			if gateErr == nil {
				if signErr != nil {
					t.Fatalf("ValidateSignable approved a proposal Sign refused (%v); the two verbs would disagree", signErr)
				}
				return
			}
			if signErr == nil {
				t.Fatalf("ValidateSignable refused (%v) but Sign accepted", gateErr)
			}
			// Compared by message, not errors.Is: both sides wrap the same
			// sentinel, so errors.Is would pass even if Sign refused for a
			// different reason within the same class.
			if !strings.Contains(signErr.Error(), gateErr.Error()) {
				t.Fatalf("Sign refused with %q, ValidateSignable with %q; the two must give the buyer the same reason", signErr, gateErr)
			}
		})
	}
}
