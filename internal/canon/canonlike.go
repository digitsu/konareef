// Copyright 2026 Jerry David Chan, Konareef.ai
// SPDX-License-Identifier: Apache-2.0

// canonlike.go — canonicalize AUTHOR input at the version a trusted
// REFERENCE document already carries.
//
// This is the one read-back emitter in canon. Its callers hold the
// author's pod.toml (e.g. extracted fresh from a content tarball, or
// read off local disk) alongside a SEPARATE, already-authenticated
// reference document that pins the version and, for v2, the commitment
// trailer. install.go's tarball-verification step is the motivating
// case — see its call site for the authentication story, which is what
// makes reusing the reference's trailer sound.
//
// A second entry point, Recanonicalize, answered the different question
// "were these ALREADY-canonical bytes produced faithfully", demanding
// byte-identical canonicalizer output plus the pod's file tree. It was
// deleted on 2026-09-21: Rulings 7 and 9 established that neither
// candidate call site holds both of those, so it never acquired a
// production caller. A site that genuinely holds stored canonical bytes
// AND their file tree would need it back.
package canon

import "bytes"

// CanonicalizeLike canonicalizes author (author-written pod.toml bytes)
// against dir, at the SAME konareef-toml version as reference, reusing
// reference's own trailer rather than recomputing a commitment.
//
// Dispatch is on reference's version magic, not author's:
//
//   - reference is v1 → CanonicalizeLike is Canonicalize(author, dir)
//     unchanged. There is no trailer to reuse.
//   - reference is v2 → the author body is canonicalized the same way
//     CanonicalizeV2 does (v1 rules over the author tree via
//     canonicalBody, plus `[_files]`), then the `[_commit]` trailer is
//     taken from reference: CommitTrailerBytes(trailer), where trailer
//     (fields_root plus the optional r_init_scheme marker) is parsed out
//     of reference with ParseCommitTrailer. No commitment is recomputed
//     here and no CommitParams are required. A reference whose trailer
//     is not in canonical key order re-emits in canonical order, so the
//     result does not hash to the reference's pod_hash and the caller's
//     hash comparison fails closed.
//   - reference is v3 → exactly as for v2, with the v3 magic line. The
//     trailer is reused, so the v3 declared_tools set (which includes the
//     brokered MCP tool ids) is not re-derived here either.
//   - reference carries no recognised konareef-toml version magic (v1,
//     v2 or v3) → a coded WRONG_VERSION *Error when it opens with the
//     exact `#!konareef-toml/` prefix (an unknown version), and a coded
//     MAGIC_NEAR_MISS *Error (CheckMagicLine) when its first line is some
//     other near miss of a magic line, or v1 followed by a lone CR and
//     more text. CanonicalizeLike never guesses a version for input it
//     cannot identify.
//
// Reusing reference's trailer instead of recomputing FieldsRoot is
// sound only because the CALLER has already authenticated reference
// before this is ever invoked — CanonicalizeLike itself performs no
// such check, and MUST NOT be treated as one. In install's case,
// reference is FetchedPod.ManifestCanonical: by the time
// verifyContentTarball runs, Verify has already confirmed (install.go)
// that SHA-256(ManifestCanonical) == PodHash and that the publisher's
// signature over ManifestCanonical is valid — so ManifestCanonical is
// the publisher's own attested document, and its committed
// fields_root is exactly as trustworthy as the rest of the manifest
// the publisher signed. CanonicalizeLike then checks that author (the
// tarball's pod.toml) reproduces the SAME author tree reference
// committed to: if the tarball content was tampered with, the
// resulting bytes carry reference's untouched trailer but a
// mismatched body/`[_files]` section, so they no longer hash to
// PodHash and the caller's existing hash comparison still catches the
// tamper (see canon_test.go /
// TestCanonicalizeLike_V2Reference_TamperedTreeDoesNotMatch).
//
// Because it recomputes no commitment, CanonicalizeLike needs no
// CommitParams and stays correct once memory-bearing pods (whose
// FieldsRoot needs a resolved r_init only the publisher can supply)
// are supported — the read-back side never needs to re-derive that
// value, only to reproduce the bytes that were already committed to.
func CanonicalizeLike(author []byte, dir string, reference []byte) ([]byte, error) {
	if hasV1Magic(reference) {
		// hasV1Magic also accepts `#!konareef-toml/v1` followed by a lone
		// CR and more text on the same LF line; that is a near miss
		// (KR-MAGIC).
		if err := CheckMagicLine(reference); err != nil {
			return nil, err
		}
		return Canonicalize(author, dir)
	}
	header := magicHeaderV2
	if hasV3Magic(reference) {
		header = magicHeaderV3
	}
	if !hasV2Magic(reference) && !hasV3Magic(reference) {
		version, hasMagic := VersionIdentifier(reference)
		if !hasMagic {
			// A near miss such as ` #!konareef-toml/v3` has no exact
			// prefix; name it rather than "no magic" (KR-MAGIC).
			if err := CheckMagicLine(reference); err != nil {
				return nil, err
			}
			return nil, newErr(ErrWrongVersion,
				"reference manifest carries no konareef-toml version magic; refusing to guess a version")
		}
		return nil, newErr(ErrWrongVersion,
			"reference manifest claims unsupported konareef-toml version "+version+"; refusing to guess")
	}

	trailer, err := ParseCommitTrailer(reference)
	if err != nil {
		return nil, err
	}
	body, _, err := canonicalBody(author, dir)
	if err != nil {
		return nil, err
	}
	var out bytes.Buffer
	out.WriteString(header)
	out.Write(body)
	out.Write(CommitTrailerBytes(trailer))
	return out.Bytes(), nil
}
