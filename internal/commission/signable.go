// Copyright 2026 Jerry David Chan, Konareef.ai
// SPDX-License-Identifier: Apache-2.0

// signable.go — the ONE predicate that decides whether a proposal may
// become a commission, and the pod-reference shape it depends on.
//
// This file exists because the alternative kept failing. `commission check`
// and `commission sign` each grew their own idea of what a valid proposal
// is, and each time one gained a rule the other did not, `check` handed a
// buyer a green light on something `sign` refused: first for an omitted
// `labels` dimension, then again for a zero `h_manifest`. Both were the same
// defect wearing a different field name. So the fix is not another matching
// pair of checks; it is that there is only one check, ValidateSignable, and
// both verbs call it. A rule added here reaches both verbs at once, and the
// two cannot drift apart again.
//
// Every path that reports on an already-signed artifact applies it too,
// because the signed canonical form does not cover the presence flags (see
// canonicalProposal), so a valid signature alone is not evidence that the
// artifact is a valid commission. That is the verbs verify and show, and —
// because the package API is a contract of its own, reachable without going
// through any verb — Commission.VerifyAgainstManifest. Commission.Verify is
// the one deliberate exception: it reports on the signature alone so that
// show can tell a buyer which of the two facts is wrong.

package commission

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"strings"

	"github.com/digitsu/konareef/internal/canon"
)

// ErrPodRefMalformed means Binding.PodRef is not the durable pod reference
// the spec defines, `<handle>/<pod>@<version>`.
//
// The version is REQUIRED here, unlike in `konareef install`, where an
// omitted version means "latest". A commission pins one exact artifact: an
// unversioned ref names whatever the registry serves today, which is the
// same drift h_manifest exists to detect, reintroduced through the field
// beside it.
var ErrPodRefMalformed = errors.New("pod_ref is not <handle>/<pod>@<version>")

// ParsePodRef splits a durable pod reference into its three parts.
//
// All three are required and must be non-empty, and exactly one "/" and one
// "@" may appear, in that order. A ref carrying whitespace is refused as
// well: it is displayed to a buyer at signing time (see renderForSigning),
// and a ref that can hide a line break can misrepresent what is being
// signed.
func ParsePodRef(ref string) (handle, podName, version string, err error) {
	if ref != strings.TrimSpace(ref) || strings.ContainsAny(ref, " \t\r\n") {
		return "", "", "", fmt.Errorf("%w: %q contains whitespace", ErrPodRefMalformed, ref)
	}
	if strings.Count(ref, "/") != 1 || strings.Count(ref, "@") != 1 {
		return "", "", "", fmt.Errorf("%w: %q", ErrPodRefMalformed, ref)
	}
	handle, rest, _ := strings.Cut(ref, "/")
	podName, version, found := strings.Cut(rest, "@")
	if !found {
		// The single "@" was in the handle, before the "/".
		return "", "", "", fmt.Errorf("%w: %q", ErrPodRefMalformed, ref)
	}
	if handle == "" || podName == "" || version == "" {
		return "", "", "", fmt.Errorf("%w: %q has an empty handle, pod name or version", ErrPodRefMalformed, ref)
	}
	return handle, podName, version, nil
}

// Validate reports whether the binding names one exact pod artifact: a
// well-formed, fully-versioned pod_ref, and a non-zero h_manifest.
func (b Binding) Validate() error {
	if _, _, _, err := ParsePodRef(b.PodRef); err != nil {
		return err
	}
	if b.HManifest == ([32]byte{}) {
		return ErrBindingUnpinned
	}
	return nil
}

// ErrCircuitCommitmentUnpinned means the manifest is konareef-toml/v2 and
// therefore commits a fields_root, but the binding pins none. Refused
// rather than tolerated: a proposal that declines to name the commitment
// its pod already publishes is a silent downgrade, and the buyer would sign
// an artifact whose constraints cannot be tied to any proof.
var ErrCircuitCommitmentUnpinned = errors.New("manifest commits a fields_root but the binding pins none")

// ErrCircuitCommitmentUnexpected means the binding pins a fields_root for a
// manifest that publishes none. There is nothing to check such a pin
// against, so accepting it would let an arbitrary 32 bytes ride inside the
// signed canonical form wearing the name of a circuit commitment.
var ErrCircuitCommitmentUnexpected = errors.New("binding pins a fields_root but the manifest commits none")

// ErrFieldsRootMismatch means both sides name a fields_root and they
// disagree — the buyer signed a commitment the pod does not publish.
var ErrFieldsRootMismatch = errors.New("binding fields_root does not match the manifest commitment")

// ErrManifestCommitmentUnreadable means the manifest declares itself
// konareef-toml/v2 but its [_commit] trailer will not parse.
//
// This error exists because canon.ParseCommitFieldsRoot cannot tell the two
// apart on its own: it returns one undifferentiated error for "this is not
// a v2 manifest" and for "this IS v2 and its trailer is corrupt". Reading
// any error as the former would accept a corrupted v2 manifest as a v1 that
// needs no pin — fail-open, and the same zero-versus-absent shape that has
// bitten this package at four separate boundaries. The version magic is
// therefore consulted FIRST, and only a manifest that does not claim v2 is
// allowed to have no commitment.
var ErrManifestCommitmentUnreadable = errors.New("manifest claims konareef-toml/v2 or v3 but its [_commit] trailer will not parse")

// ErrManifestVersionUnsupported means the manifest declares a canonical
// version this build does not read.
//
// It is deliberately NOT folded into "commits no fields_root". The two are
// different states: a v1 manifest is known to carry no commitment, whereas a
// v3 manifest is a manifest whose commitment — and whose commitment
// semantics — this build cannot know anything about. Treating the second as
// the first accepts a future manifest as though it published nothing to pin.
var ErrManifestVersionUnsupported = errors.New("manifest declares a canonical version this build does not support")

// ValidateAgainstManifest reports whether this binding actually names the
// supplied manifest — both the document the buyer read and the commitment
// the circuit consumes.
//
// It is one function, not two checks in two verbs, for the reason this
// file's header describes: `check` and `sign` each grew a private idea of
// what binds a proposal to a manifest, and each divergence handed a buyer a
// green light on something the other verb refused. The h_manifest
// comparison used to live inline in both. It lives here now, and the
// fields_root rule arrives in both places at once because there is only one
// place to put it.
//
// The outcomes are all fail-closed. A v2 or v3 manifest must be pinned,
// the pin must agree, and the committed root must be reproduced by the
// manifest's own declared fields (CheckManifestCommitment); a non-v2 manifest must not be pinned at all; and a manifest
// claiming v2 whose trailer will not parse is an error rather than a
// silently unpinnable v1.
func (b Binding) ValidateAgainstManifest(manifest []byte) error {
	if sha256.Sum256(manifest) != b.HManifest {
		return ErrManifestHashMismatch
	}

	committed, err := ManifestFieldsRoot(manifest)
	if err != nil {
		return err
	}
	switch {
	case committed == nil && b.FieldsRoot != nil:
		version, _ := canon.VersionIdentifier(manifest)
		return fmt.Errorf("%w (manifest version %q)", ErrCircuitCommitmentUnexpected, version)
	case committed != nil && b.FieldsRoot == nil:
		return ErrCircuitCommitmentUnpinned
	case committed != nil && *b.FieldsRoot != *committed:
		return ErrFieldsRootMismatch
	}
	// The pin matches the trailer; now the trailer must match the content.
	// Without this a signed trailer committing a tool the manifest does not
	// declare would be accepted (commitcheck.go).
	if committed != nil {
		if err := CheckManifestCommitment(manifest); err != nil {
			return err
		}
	}
	return nil
}

// ManifestFieldsRoot returns the fields_root commitment a manifest
// publishes, or nil for a manifest that publishes none.
//
// This is the SOLE definition of "does this manifest commit a fields_root",
// and both the producer (`commission draft`, choosing what to pin) and the
// checker (ValidateAgainstManifest, deciding whether a pin is right) call
// it. They must agree by construction: a drafter that pinned under one rule
// while a checker refused under another would reproduce, at the manifest
// boundary, the exact check/sign divergence this file exists to prevent.
//
// A nil return means "no commitment", never "could not tell". The
// distinction matters because canon.ParseCommitFieldsRoot answers both with
// the same error, so the version magic is consulted first: only a manifest
// that does not claim konareef-toml/v2 or v3 may legitimately commit nothing. A
// manifest that DOES claim v2 or v3 and will not parse is an error, because
// reporting it as uncommitted would let a corrupted trailer pass as a v1
// that needs no pin.
//
// A manifest whose first line is a near miss of a magic line
// (canon.CheckMagicLine) is refused first, with an error wrapping both
// ErrManifestVersionUnsupported and the canon MAGIC_NEAR_MISS *Error.
func ManifestFieldsRoot(manifest []byte) (*[32]byte, error) {
	// A near-miss magic line (` #!konareef-toml/v3`, `#!KONAREEF-TOML/V3`,
	// a BOM or blank line before the magic, `#!konareef-toml/v4`, ...)
	// claims a canonical version this build cannot read. Without this
	// check the ones with no exact `#!konareef-toml/` prefix fell into the
	// !hasMagic case below and were read as committing nothing, which
	// hid a v2/v3 [_commit] trailer from every caller (KR-MAGIC).
	version, hasMagic := canon.VersionIdentifier(manifest)
	if err := canon.CheckMagicLine(manifest); err != nil {
		if hasMagic {
			return nil, fmt.Errorf("%w: %q: %w", ErrManifestVersionUnsupported, version, err)
		}
		return nil, fmt.Errorf("%w: %w", ErrManifestVersionUnsupported, err)
	}
	switch {
	case !hasMagic:
		// Not canonicalized at all, so it carries no synthetic sections and
		// commits nothing. Whether a commission may pin such bytes at all is
		// a separate question, decided by the h_manifest comparison above.
		return nil, nil

	case commitVersionIdentifiers[version]:
		fr, err := canon.ParseCommitFieldsRoot(manifest)
		if err != nil {
			return nil, fmt.Errorf("%w: %w", ErrManifestCommitmentUnreadable, err)
		}
		return &fr, nil

	case canon.HasSupportedVersionMagic(manifest):
		// A canonical version this build reads, and which predates the
		// [_commit] trailer: it genuinely commits no fields_root.
		return nil, nil

	default:
		// A canonical version this build does NOT read. It is not "no
		// commitment" — it is unknown whether it carries one, and unknown
		// whether its commitment semantics match. Saying "none" here would
		// let a v999 manifest be accepted by the binding gate as though it
		// published nothing to pin, which is the same version-boundary
		// fail-open aaab88b closed for `verify --manifest`.
		return nil, fmt.Errorf("%w: %q", ErrManifestVersionUnsupported, version)
	}
}

// commitVersionIdentifiers are the canonical versions that carry the
// [_commit] trailer: konareef-toml/v2 and konareef-toml/v3 (v3 shares the
// v2 trailer grammar and differs only in its declared_tools set). They are
// compared against canon.VersionIdentifier's token rather than tested with
// canon.HasSupportedVersionMagic — even though that helper includes both
// (konareef-toml/v2 spec R-V2.11, and v3 spec §0) — because this switch
// needs to distinguish "a trailer version, so parse its trailer" from
// "some OTHER supported version, so it commits nothing" as two different
// actions, not merely gate on "supported vs not".
// canon.HasSupportedVersionMagic answers only the latter question; it is
// still used below, for exactly that coarser purpose, once the trailer
// versions above have already been split off.
var commitVersionIdentifiers = map[string]bool{"v2": true, "v3": true}

// ValidateSignable reports whether p is a proposal that may be signed: its
// envelope states every dimension, its binding names one exact pod
// artifact, and it fits the admission contract's limits
// (ValidateAdmissionLimits), so the server will not refuse it for size.
//
// This is the single source of truth described in this file's header
// comment. Do not inline any part of it into a verb: `check` must be able to
// promise that whatever it approves, `sign` accepts, and that promise is
// only as good as the two verbs calling the same function.
func ValidateSignable(p Proposal) error {
	if err := p.Envelope.ValidateAsCommission(); err != nil {
		return err
	}
	if err := p.Binding.Validate(); err != nil {
		return err
	}
	return ValidateAdmissionLimits(p)
}
