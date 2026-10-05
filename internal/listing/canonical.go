// Copyright 2026 Jerry David Chan, Konareef.ai
// SPDX-License-Identifier: Apache-2.0

// Package listing builds and submits marketplace listings — the mutable,
// publisher-signed overlay on a published pod. The canonical form here
// MUST stay byte-identical to reef-core's ReefCore.PodListings.Canonical
// (lib/pod/listings/canonical.ex): the publisher signs these bytes and
// the server re-derives them to verify.
//
// The shared golden string is pinned on both sides — here by
// TestCanonicalByteLayout, and in reef-core's canonical_test.exs by
// "produces the exact documented byte layout". The two tests are named
// differently; only the expected bytes are shared.
//
// The preimage is operation-domain-separated: its first line names the
// operation being authorised, so an upsert signature cannot be replayed
// as a delist. See Operation.
package listing

import (
	"fmt"
	"strconv"
	"strings"
)

// Operation names which listing mutation a signature authorises. It is
// the first line of the preimage, so an upsert signature and a delist
// signature over identical fields are different bytes.
//
// This exists because without it the two operations signed a
// byte-identical preimage: a captured PUT body replayed to DELETE
// verified perfectly and took the listing down, with no key compromise
// needed — an access log or a proxy was enough. Domain-separating the
// operations is what makes a signature mean "I authorise THIS action"
// rather than merely "I authorise these values".
//
// It is a defined type, not a bare string, so a caller cannot pass a
// typo'd operation and cannot omit the argument.
type Operation string

const (
	// OpUpsert authorises creating or updating a listing (PUT).
	OpUpsert Operation = "upsert"
	// OpDelist authorises taking a listing down (DELETE).
	OpDelist Operation = "delist"
)

// MaxRevision is the largest revision a listing signature may carry:
// 2^53-1, the biggest integer a JSON double represents exactly. It
// mirrors reef-core's Canonical.max_revision/0 and must not drift from
// it.
//
// It is not a storage bound — the column is a bigint. It exists so a
// revision cannot mean one number to a publisher's JSON client and
// another to the server.
const MaxRevision int64 = 9_007_199_254_740_991

// Fields is the signable subset of a listing. Status/signature are NOT
// here: status is operator-controlled server-side; the signature is the
// output of signing these fields. The operation is not here either — it
// is passed explicitly to Canonical so it can never be defaulted.
type Fields struct {
	// Revision is the publisher-chosen monotonic counter scoped to one
	// (handle, pod_name) row and SHARED by upsert and delist. reef-core
	// accepts a mutation only when the signed revision is strictly
	// greater than the revision stored on the row, so a signature
	// authorises one operation over one field tuple exactly once.
	//
	// It is a pointer so "unset" is distinguishable from the legitimate
	// value 0: a silent zero default would mint a signature the
	// publisher never chose the freshness of, and 0 is the one revision
	// guaranteed to lose to any stored row. Same reasoning as
	// pod.Model.Temperature. Canonical rejects nil rather than
	// substituting anything.
	Revision       *int64
	Handle         string
	PodName        string
	AuthorFeeSats  int
	ExecutionClass string
	Category       string
	Description    string
}

// Revision returns a pointer to n, for populating Fields.Revision.
// Callers need it because Go has no address-of for literals.
func Revision(n int64) *int64 { return &n }

// Validate reports whether f can be safely rendered to a canonical
// preimage. See checkNoControlChars for the rule and the reason.
//
// Callers do not normally need this: Canonical validates internally and
// refuses to emit bytes for invalid input. It is exported so a caller
// that wants to reject bad input early — before doing expensive work, or
// to report several problems at once — can do so.
func (f Fields) Validate() error {
	// Unset is an error, never a zero: the revision decides whether the
	// server accepts this mutation at all, so it must be a value the
	// publisher chose.
	switch {
	case f.Revision == nil:
		return fmt.Errorf(
			"listing revision is not set; it must be an integer in 0..%d, "+
				"strictly greater than the revision reef-core currently stores", MaxRevision)
	case *f.Revision < 0:
		return fmt.Errorf("listing revision must not be negative, got %d", *f.Revision)
	case *f.Revision > MaxRevision:
		return fmt.Errorf("listing revision must be at most %d, got %d", MaxRevision, *f.Revision)
	}
	for _, field := range []struct{ name, value string }{
		{"Handle", f.Handle},
		{"PodName", f.PodName},
		{"ExecutionClass", f.ExecutionClass},
		{"Category", f.Category},
		{"Description", f.Description},
	} {
		if err := checkNoControlChars(field.name, field.value); err != nil {
			return err
		}
	}
	return nil
}

// checkNoControlChars rejects any C0 control character (0x00-0x1F) or
// DEL (0x7F) in a field destined for the preimage.
//
// This is a signature-soundness requirement, not cosmetic validation.
// The preimage frames fields as "key\tvalue" joined by "\n". If a value
// could contain those delimiters, two DIFFERENT field-sets could render
// to IDENTICAL bytes — one signature would then authenticate both
// splits, e.g.
//
//	Category="research\ndisplay_description\tEVIL", Description="Good"
//	Category="research",  Description="EVIL\ndisplay_description\tGood"
//
// Rejecting at the boundary (rather than escaping) keeps the wire format
// unchanged and is provably unambiguous: with no delimiter able to occur
// inside a value, the field split is unique. The rule covers the whole
// C0 range plus DEL rather than just \t and \n, so \r can't be smuggled
// in either and no future field can reintroduce the hazard.
//
// Scanning bytes rather than runes is deliberate and does NOT reject
// non-ASCII: in UTF-8 a multi-byte rune is a lead byte (0xC2-0xF4) plus
// continuation bytes (0x80-0xBF), none of which fall in the rejected
// range. Real display metadata — accented Latin, CJK, emoji — passes
// through untouched.
func checkNoControlChars(name, value string) error {
	for i := 0; i < len(value); i++ {
		if c := value[i]; c < 0x20 || c == 0x7f {
			return fmt.Errorf(
				"listing field %s contains a disallowed control character 0x%02x at byte %d: "+
					"tabs, newlines and other control characters would make the signed "+
					"listing bytes ambiguous", name, c, i)
		}
	}
	return nil
}

// Canonical renders Fields to the deterministic signing preimage for a
// specific operation: fixed field order, one "key\tvalue" line per
// field, joined by "\n", no trailing newline. Integers are base-10 with
// no separators. The first two lines are always "op\t<operation>" and
// "revision\t<n>".
//
// The revision makes a signature single-use. Domain separation alone
// stops a PUT body being replayed as a DELETE, but leaves same-operation
// replay open: every body a publisher ever sent would stay a standing
// authorisation to re-apply those exact values — reverting a later price
// edit, or re-listing a pod that was deliberately delisted. Because the
// counter is shared across both operations, a delist consumes a revision
// and so becomes a real tombstone.
//
// Every field emits a line even when empty — the field set is fixed so
// reef-core can rebuild the exact preimage from a stored row. Changing
// the order, the key names, the separators, or the trailing-newline rule
// invalidates every signature already issued.
//
// op is a required argument with no default. Upsert and delist used to
// sign identical bytes, so a captured PUT body could be replayed to
// DELETE and would verify; forcing the caller to name the operation is
// what closes that. Passing the wrong one is a compile error rather
// than a silent authorisation of the wrong action.
//
// It returns an error, rather than validating in the caller, so that
// unvalidated bytes cannot be obtained at all: there is no code path
// that yields a preimage a publisher could sign without the delimiter
// check having run. AuthorFeeSats needs no check — strconv.Itoa cannot
// emit a delimiter.
func Canonical(f Fields, op Operation) ([]byte, error) {
	// Go permits Operation("anything"), so the closed set is enforced
	// here too: an unrecognised op must never reach the preimage.
	if op != OpUpsert && op != OpDelist {
		return nil, fmt.Errorf(
			"listing operation %q is not one of %q or %q", string(op), OpUpsert, OpDelist)
	}
	if err := f.Validate(); err != nil {
		return nil, err
	}
	lines := []string{
		"op\t" + string(op),
		"revision\t" + strconv.FormatInt(*f.Revision, 10),
		"handle\t" + f.Handle,
		"pod_name\t" + f.PodName,
		"author_fee_sats\t" + strconv.Itoa(f.AuthorFeeSats),
		"execution_class\t" + f.ExecutionClass,
		"category\t" + f.Category,
		"display_description\t" + f.Description,
	}
	return []byte(strings.Join(lines, "\n")), nil
}
