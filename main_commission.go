// Copyright 2026 Jerry David Chan, Konareef.ai
// SPDX-License-Identifier: Apache-2.0

// Commission subcommands: draft, check, sign, verify, show. The verbs that
// talk to reef-core (submit, key, revoke, receipt) are in
// main_commission_submit.go.
//
// `check` is advisory. It tells a buyer whether a pod fits their envelope
// before they sign; it enforces nothing, and a dishonest operator can
// ignore it. Enforcement is server-side: `commission submit` sends the
// signed artifact to reef-core, which admits or refuses it.
package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/BurntSushi/toml"
	"github.com/fxamacker/cbor/v2"

	"github.com/digitsu/konareef/internal/canon"
	"github.com/digitsu/konareef/internal/commission"
	"github.com/digitsu/konareef/internal/envelope"
	"github.com/digitsu/konareef/internal/identity"
	"github.com/digitsu/konareef/internal/install"
	"github.com/digitsu/konareef/internal/pod"
)

// confirmFlagCommission names the `commission sign` confirmation bypass.
// It is its own flag, deliberately distinct from confirmFlagPublish and
// confirmFlagSpend in main_confirm_gate.go: signing a commission is a third
// irreversible act, and one approval must never authorise a different one
// (see main_confirm_gate.go's header comment for the full reasoning).
const confirmFlagCommission = "confirm-commission"

// exitNotContained is the exit code for a proposal that fails containment.
// It is distinct from 1 (a pipeline failure), 2 (a usage error) and 3
// (exitNotConfirmed) so a script can tell a refusal from a failure.
const exitNotContained = 4

// hManifestHexLen is the length of Binding.HManifest ([32]byte) hex-encoded,
// matching internal/commission/rar.hManifestHexLen.
const hManifestHexLen = 64

// proposalFile is the on-disk TOML shape of a proposal.
//
// Models, Tools, Labels and CMaxSats are pointers, not plain values, for
// the same reason internal/commission/rar's detail type uses them (see its
// doc comment): the BurntSushi/toml encoder omits a nil pointer field
// entirely, but still emits a non-nil pointer's value even when that value
// is an empty slice or zero. A plain (non-pointer) field cannot make that
// distinction — BurntSushi/toml always writes it — so a dimension stated
// but deliberately empty (Tools: []string{}, ToolsSet: true, meaning "may
// call no tools") and a dimension never mentioned at all used to produce
// IDENTICAL TOML: no key either way. unmarshalProposal then read both back
// as omitted, silently discarding the buyer's restriction. See
// TestProposalRoundTripsThroughTOML_StatedEmptySurvives.
type proposalFile struct {
	PodRef     string    `toml:"pod_ref"`
	HManifest  string    `toml:"h_manifest"`
	FieldsRoot *string   `toml:"fields_root"`
	Prose      string    `toml:"prose"`
	Models     *[]string `toml:"models"`
	Tools      *[]string `toml:"tools"`
	Labels     *[]string `toml:"labels"`
	CMaxSats   *uint64   `toml:"c_max_sats"`
}

// statedSet returns a pointer to the normalised set for marshalProposal to
// emit, or nil if the dimension was never stated. A stated-but-empty set
// still returns a non-nil pointer to an empty (non-nil) slice, so it
// marshals as "tools = []" rather than being omitted — see proposalFile's
// doc comment. Mirrors internal/commission/rar.statedSet.
func statedSet(set bool, s []string) *[]string {
	if !set {
		return nil
	}
	out := envelope.Normalise(s)
	if out == nil {
		out = []string{}
	}
	return &out
}

// hexPtr hex-encodes an optional 32-byte commitment for TOML, preserving
// the nil/non-nil distinction as key-absent/key-present. Mirrors statedSet:
// the pointer is the presence carrier, because a fixed-width hex string
// cannot express "not pinned" and an empty string would round-trip as a
// pinned value of zero.
func hexPtr(v *[32]byte) *string {
	if v == nil {
		return nil
	}
	h := hex.EncodeToString(v[:])
	return &h
}

// marshalProposal encodes a proposal as TOML for a buyer to edit. A
// dimension whose presence flag is false is written with no key at all;
// one whose flag is true is always written, even when its value is empty
// or zero, so an edited-and-saved file preserves exactly what the buyer
// stated. Binding.HManifest is hex-encoded into h_manifest; it is not a
// presence-flagged dimension, so it is always written, even for a fresh
// draft whose binding is still the zero [32]byte.
func marshalProposal(p commission.Proposal) ([]byte, error) {
	f := proposalFile{
		PodRef:     p.Binding.PodRef,
		HManifest:  hex.EncodeToString(p.Binding.HManifest[:]),
		FieldsRoot: hexPtr(p.Binding.FieldsRoot),
		Prose:      p.Prose,
		Models:     statedSet(p.Envelope.ModelsSet, p.Envelope.Models),
		Tools:      statedSet(p.Envelope.ToolsSet, p.Envelope.Tools),
		Labels:     statedSet(p.Envelope.LabelsSet, p.Envelope.Labels),
	}
	if p.Envelope.CMaxSet {
		cMax := p.Envelope.CMax
		f.CMaxSats = &cMax
	}
	var buf bytes.Buffer
	err := toml.NewEncoder(&buf).Encode(f)
	return buf.Bytes(), err
}

// draftLabelsComment is written into a fresh draft immediately above the
// `labels` key. A buyer who reads the file has to be told why one dimension
// arrives empty when the other three arrive populated, or the seeded value
// looks like a bug rather than a decision.
//
// TOML comments are ignored by toml.Decode, so this survives an edit-and-save
// round trip and never reaches unmarshalProposal.
const draftLabelsComment = `# labels is the memory-scope dimension. Unlike models, tools and spend it
# has NO manifest-side source: the pod schema carries no provenance-label
# vocabulary to derive one from, so a draft cannot seed it from the pod.
# It is seeded empty, which attributes no label.
# Labels are attribution-only: your signed labels are bound in the
# commission, but no check enforces them and no proof covers them.
# Widening it is a deliberate act by you: list the provenance labels you
# intend to attribute. Deleting this key does not mean "anything"; it makes
# the proposal unsignable.
`

// annotateDraftLabels inserts draftLabelsComment above the `labels` key in
// encoded proposal TOML. It returns the input unchanged when there is no
// such key, so it can never corrupt a proposal it does not understand.
//
// The key is matched exactly, up to its `=`, rather than by prefix: a future
// `labels_denied` or similar must not collect this comment.
func annotateDraftLabels(tomlBytes []byte) []byte {
	lines := strings.Split(string(tomlBytes), "\n")
	for i, line := range lines {
		key, _, found := strings.Cut(line, "=")
		if !found || strings.TrimSpace(key) != "labels" {
			continue
		}
		out := make([]string, 0, len(lines)+1)
		out = append(out, lines[:i]...)
		out = append(out, draftLabelsComment+line)
		out = append(out, lines[i+1:]...)
		return []byte(strings.Join(out, "\n"))
	}
	return tomlBytes
}

// derefStrings returns the pointee of p, or nil if p is nil.
func derefStrings(p *[]string) []string {
	if p == nil {
		return nil
	}
	return *p
}

// derefUint64 returns the pointee of p, or 0 if p is nil.
func derefUint64(p *uint64) uint64 {
	if p == nil {
		return 0
	}
	return *p
}

// unmarshalProposal decodes an edited proposal file. Every dimension the
// file mentions is treated as explicitly stated; a dimension the file omits
// stays absent and will be refused at signing time. Presence is read via
// md.IsDefined against the decoded TOML keys, not by checking whether a
// pointer is nil, so a key written by an external tool with no comment in
// this package is still honoured correctly.
//
// h_manifest is treated differently from the four presence-flagged
// dimensions: an ABSENT h_manifest is accepted and decodes to the zero
// [32]byte (a fresh draft may not have a pod pinned yet), but a PRESENT
// value must decode to exactly 32 bytes (64 hex characters) or the whole
// proposal is rejected — matching internal/commission/rar.Parse's
// validation of the same field. HManifest is a commitment a signer relies
// on to detect a republished pod, so a truncated or malformed value must
// be refused rather than silently zeroed or truncated; silently zeroing it
// is indistinguishable from "no pin at all" to a caller, which is exactly
// the failure this guards against.
func unmarshalProposal(raw []byte) (commission.Proposal, error) {
	var f proposalFile
	md, err := toml.Decode(string(raw), &f)
	if err != nil {
		return commission.Proposal{}, err
	}
	var hManifest [32]byte
	if md.IsDefined("h_manifest") {
		if len(f.HManifest) != hManifestHexLen {
			return commission.Proposal{}, fmt.Errorf("h_manifest must be %d hex chars, got %d", hManifestHexLen, len(f.HManifest))
		}
		hm, err := hex.DecodeString(f.HManifest)
		if err != nil {
			return commission.Proposal{}, fmt.Errorf("h_manifest must be %d hex chars: %w", hManifestHexLen, err)
		}
		copy(hManifest[:], hm)
	}

	// fields_root uses key PRESENCE, not a sentinel value, to say whether a
	// circuit commitment is pinned — so an absent key stays nil and a
	// present one must decode to exactly 32 bytes. Zeroing a malformed
	// value would turn "pinned, but corrupt" into "not pinned", which
	// ValidateAgainstManifest treats as a legitimate v1 proposal. That is
	// the round-trip laundering this package has already had to fix in RAR
	// and twice in TOML; it is refused here instead.
	var fieldsRoot *[32]byte
	if md.IsDefined("fields_root") {
		if f.FieldsRoot == nil || len(*f.FieldsRoot) != hManifestHexLen {
			got := 0
			if f.FieldsRoot != nil {
				got = len(*f.FieldsRoot)
			}
			return commission.Proposal{}, fmt.Errorf("fields_root must be %d hex chars, got %d", hManifestHexLen, got)
		}
		fr, err := hex.DecodeString(*f.FieldsRoot)
		if err != nil {
			return commission.Proposal{}, fmt.Errorf("fields_root must be %d hex chars: %w", hManifestHexLen, err)
		}
		var v [32]byte
		copy(v[:], fr)
		fieldsRoot = &v
	}

	e := envelope.Envelope{
		Models: derefStrings(f.Models), ModelsSet: md.IsDefined("models"),
		Tools: derefStrings(f.Tools), ToolsSet: md.IsDefined("tools"),
		Labels: derefStrings(f.Labels), LabelsSet: md.IsDefined("labels"),
		CMax: derefUint64(f.CMaxSats), CMaxSet: md.IsDefined("c_max_sats"),
	}
	return commission.Proposal{
		Envelope: e,
		Binding:  commission.Binding{PodRef: f.PodRef, HManifest: hManifest, FieldsRoot: fieldsRoot},
		Prose:    f.Prose,
	}, nil
}

// memoryScopeCaveat is the disclosure every verb that reports containment
// must print. commission.FromSpec never populates Labels, so the labels
// dimension is structurally vacuous in every containment check: it can
// never fail, and a report that stays silent about it invites the reader to
// believe memory scope was checked. Sharing one constant is what keeps the
// disclosure from drifting between `check` and `verify`, which is exactly
// how it drifted before.
//
// Labels are attribution-only (DATA-00, owner decision 2026-10-08): the
// commission binds them and nothing enforces them.
const memoryScopeCaveat = "  memory scope: not checked — labels are attribution-only: signed in the commission, never enforced\n"

// formatContainmentReport renders a containment result for a human.
//
// It prints every failure in full. That is safe HERE because the caller is
// buyer-side and local, comparing the buyer's own commission against an
// already-public manifest — not because detail is free. A server-side
// caller must apply a disclosure policy before showing this.
func formatContainmentReport(res envelope.Result) string {
	var b strings.Builder
	if res.OK {
		b.WriteString("contained: the pod fits inside your commission\n")
	} else {
		b.WriteString("NOT contained:\n")
		for _, f := range res.Failures {
			fmt.Fprintf(&b, "  %s: %s\n", f.Dimension, f.Detail)
		}
	}
	b.WriteString(memoryScopeCaveat)
	return b.String()
}

// resolvePodSpecManifest returns the canonical manifest bytes and the
// parsed pod.Spec for handle/podName/version.
//
// When podDir is non-empty it reads and canonicalizes <podDir>/pod.toml
// locally — the exact canon.Canonicalize(raw, dir) step `konareef pod
// publish` runs before signing — so `draft` and `check` are testable
// without a running reef-core. Otherwise it fetches the published manifest
// from resolvedServer via install.Fetch, mirroring `konareef install`.
//
// Either path returns the same two things a caller needs: the exact bytes
// to hash into Binding.HManifest, and the Spec to derive an envelope from
// via commission.FromSpec.
//
// This local-podDir path is deliberately pinned to v1 (canon.Canonicalize),
// never CanonicalizeV2 or CanonicalizeLike, and stays that way even after
// konareef-toml/v2 ships elsewhere: a commission drafted from a LOCAL pod
// directory cannot know whether that pod will later be published `--zk` —
// that is a publish-time choice, not something pod.toml declares — and the
// spec already states Binding.FieldsRoot is nil for a non-ZK pod, which is
// exactly what a v1-canonicalized draft produces. A buyer who wants a ZK
// commission (one whose Binding.FieldsRoot is populated) should draft
// against the PUBLISHED manifest instead — the other branch below, via
// install.Fetch — which carries its own `[_commit]` trailer already
// committed by the publisher.
func resolvePodSpecManifest(podDir, resolvedServer, handle, podName, version string) ([]byte, pod.Spec, error) {
	if podDir != "" {
		raw, err := os.ReadFile(filepath.Join(podDir, "pod.toml"))
		if err != nil {
			return nil, pod.Spec{}, fmt.Errorf("read local pod.toml: %w", err)
		}
		canonical, err := canon.Canonicalize(raw, podDir)
		if err != nil {
			return nil, pod.Spec{}, fmt.Errorf("canonicalize local pod.toml: %w", err)
		}
		spec, err := pod.Parse(canonical)
		if err != nil {
			return nil, pod.Spec{}, fmt.Errorf("parse local pod.toml: %w", err)
		}
		return canonical, spec, nil
	}

	fetched, err := install.Fetch(resolvedServer, handle, podName, version)
	if err != nil {
		return nil, pod.Spec{}, err
	}
	spec, err := pod.Parse(fetched.ManifestCanonical)
	if err != nil {
		return nil, pod.Spec{}, fmt.Errorf("parse fetched manifest: %w", err)
	}
	return fetched.ManifestCanonical, spec, nil
}

// renderForSigning returns what the buyer sees before signing. The exact
// canonical bytes are embedded verbatim, because the signed object must be
// the displayed object (spec section 5.3). Re-rendering or prettifying the
// parameters here would void that property.
func renderForSigning(p commission.Proposal) ([]byte, error) {
	canonical, err := p.Canonical()
	if err != nil {
		return nil, err
	}
	var b bytes.Buffer
	fmt.Fprintf(&b, "You are about to sign this commission.\n\n")
	fmt.Fprintf(&b, "  pod:    %s\n", p.Binding.PodRef)
	fmt.Fprintf(&b, "  models: %v\n", envelope.Normalise(p.Envelope.Models))
	fmt.Fprintf(&b, "  tools:  %v\n", envelope.Normalise(p.Envelope.Tools))
	fmt.Fprintf(&b, "  labels: %v\n", envelope.Normalise(p.Envelope.Labels))
	fmt.Fprintf(&b, "  spend:  %d sats\n\n", p.Envelope.CMax)
	fmt.Fprintf(&b, "  %s\n\n", p.Prose)
	fmt.Fprintf(&b, "Signed bytes (canonical, this is what your key attests):\n")
	b.Write(canonical)
	b.WriteString("\n")
	return b.Bytes(), nil
}

// confirmSigning fails closed. Signing binds the buyer to an envelope, so
// with no terminal to ask and no flag, it refuses rather than defaulting to
// yes — the same posture main_confirm_gate.go takes for publish and spend.
//
// A separate flag from --confirm-publish and --confirm-spend is deliberate:
// one approval must never authorise a different irreversible act.
func confirmSigning(p commission.Proposal, confirmFlag, isTerminal bool) error {
	if confirmFlag {
		return nil
	}
	if !isTerminal {
		return fmt.Errorf("refusing to sign without confirmation: pass --confirm-commission, or run with a terminal")
	}
	shown, err := renderForSigning(p)
	if err != nil {
		return err
	}
	os.Stdout.Write(shown)
	fmt.Print("Sign this commission? [y/N] ")
	var answer string
	_, _ = fmt.Scanln(&answer)
	if a := strings.ToLower(strings.TrimSpace(answer)); a != "y" && a != "yes" {
		return fmt.Errorf("aborted: commission not signed")
	}
	return nil
}

// commissionArtifact is the on-disk CBOR shape of a signed commission,
// written by `sign` and read back by `verify` and `show`. It carries
// exactly the three parts commission.Reconstruct needs: the proposal that
// was signed, the signer's public key, and the signature itself. Presence
// flags round-trip inside Proposal.Envelope like every other field here,
// and are not special-cased the way proposalFile's pointer fields are.
//
// That is safe only because of what happens on the way back IN. The flags
// are outside the signed canonical form (see
// internal/commission/object.go's canonicalProposal), so nothing stops
// anyone editing them in a stored artifact without breaking the signature.
// This type therefore carries no authenticated presence information at all,
// and "commission.Sign already refused to produce it unless every dimension
// was stated" — the reasoning this comment used to give — is not a property
// of the BYTES on disk. loadAndVerifyCommission re-runs
// commission.ValidateSignable on the decoded proposal for exactly that
// reason, and `show` reports the same failure; see
// TestLoadAndVerifyCommission_RejectsPresenceFlagTamper.
type commissionArtifact struct {
	Proposal  commission.Proposal `cbor:"1,keyasint"`
	PubKeyHex string              `cbor:"2,keyasint"`
	Sig       []byte              `cbor:"3,keyasint"`
}

// marshalCommission encodes a signed commission as CBOR for `sign` to
// write to disk. This is a storage encoding, not the signed form — it is
// never hashed or verified against anything, so it uses ordinary (not
// canonical/deterministic) CBOR encoding options.
func marshalCommission(c commission.Commission) ([]byte, error) {
	return cbor.Marshal(commissionArtifact{
		Proposal:  c.Proposal(),
		PubKeyHex: c.PubKeyHex,
		Sig:       c.Sig,
	})
}

// unmarshalCommission decodes a commission artifact written by
// marshalCommission. The returned Commission is UNVERIFIED — decoding
// bytes off disk proves nothing about their authenticity — so every caller
// MUST call Verify or VerifyAgainstManifest on the result before trusting
// it. See commission.Reconstruct's doc comment for why this is safe.
func unmarshalCommission(raw []byte) (commission.Commission, error) {
	var a commissionArtifact
	if err := cbor.Unmarshal(raw, &a); err != nil {
		return commission.Commission{}, err
	}
	return commission.Reconstruct(a.Proposal, a.PubKeyHex, a.Sig), nil
}

// loadAndVerifyCommission reads a commission artifact from path, decodes
// it, verifies its signature, and re-applies the semantic checks `sign`
// applied, before returning. This is the SAFE default for any verb that
// needs a loaded commission: it cannot return a Commission whose signature
// hasn't already checked out AND which isn't a valid commission. `verify`
// uses this.
//
// The commission.ValidateSignable call is not redundant with Verify. The
// signed canonical form deliberately excludes the four presence flags (see
// internal/commission/object.go's canonicalProposal), so those flags are
// UNAUTHENTICATED artifact state: flipping LabelsSet to false in a stored
// CBOR artifact leaves the signature checking out perfectly, while turning
// the decoded proposal into one `sign` would have refused. Without this
// call, `verify` would report such an artifact as fully verified. Applying
// the same predicate the signing path applies is what closes that gap —
// see TestLoadAndVerifyCommission_RejectsPresenceFlagTamper.
//
// `show` deliberately does NOT use this — see runCommissionShowCore's doc
// comment for why a caller would ever want the raw, unverified loader
// (unmarshalCommission) instead. A future verb should reach for this
// helper by default and justify, in a comment, any reason to bypass it —
// the same way runCommissionShowCore justifies its exception here.
func loadAndVerifyCommission(path string) (commission.Commission, error) {
	c, overLimit, err := loadAndVerifyCommissionForReport(path)
	if err != nil {
		return commission.Commission{}, err
	}
	if overLimit != nil {
		return commission.Commission{}, fmt.Errorf("signature checks out but the artifact is not a valid commission: %w", overLimit)
	}
	return c, nil
}

// loadAndVerifyCommissionForReport is loadAndVerifyCommission for the verbs
// that only report on an artifact (`verify`). It applies every check, but
// returns an artifact that fails ONLY the admission contract's size limits
// with that failure as a separate warning (overLimit), instead of refusing
// it: such an artifact is validly signed and valid, and only the server
// refuses it. Every other failure is err, exactly as in
// loadAndVerifyCommission.
//
// Output: the commission, the over-limit warning or nil, and an error.
func loadAndVerifyCommissionForReport(path string) (c commission.Commission, overLimit error, err error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return commission.Commission{}, nil, err
	}
	c, err = unmarshalCommission(raw)
	if err != nil {
		return commission.Commission{}, nil, err
	}
	if err := c.Verify(); err != nil {
		return commission.Commission{}, nil, err
	}
	if err := commission.ValidateSignable(c.Proposal()); err != nil {
		if errors.Is(err, commission.ErrOverAdmissionLimit) {
			return c, err, nil
		}
		return commission.Commission{}, nil, fmt.Errorf("signature checks out but the artifact is not a valid commission: %w", err)
	}
	return c, nil, nil
}

// overLimitWarning is what `verify` and `show` print for an artifact that
// is valid but over the admission contract's size limits.
func overLimitWarning(err error) string {
	return fmt.Sprintf("WARNING: %v — reef-core will refuse to admit this commission, and `commission submit` will not send it", err)
}

// defaultCommissionOutPath derives `sign`'s default output path from the
// proposal path it read: a ".toml" suffix is swapped for ".cbor"; anything
// else just gets ".cbor" appended. Used when `sign` is not given -o.
func defaultCommissionOutPath(proposalPath string) string {
	if ext := filepath.Ext(proposalPath); ext != "" {
		return strings.TrimSuffix(proposalPath, ext) + ".cbor"
	}
	return proposalPath + ".cbor"
}

// runCommission dispatches the commission subcommands.
func runCommission(args []string) {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "usage: konareef commission <draft|check|sign|verify|show|submit|key|revoke|receipt|replay> ...")
		os.Exit(2)
	}
	switch args[0] {
	case "draft":
		runCommissionDraft(args[1:])
	case "check":
		runCommissionCheck(args[1:])
	case "sign":
		runCommissionSign(args[1:])
	case "verify":
		runCommissionVerify(args[1:])
	case "show":
		runCommissionShow(args[1:])
	case "submit":
		runCommissionSubmit(args[1:])
	case "key":
		runCommissionKey(args[1:])
	case "revoke":
		runCommissionRevoke(args[1:])
	case "receipt":
		runCommissionReceipt(args[1:])
	case "replay":
		runCommissionReplay(args[1:])
	default:
		fmt.Fprintf(os.Stderr, "unknown commission subcommand %q\n", args[0])
		os.Exit(2)
	}
}

// runCommissionDraft implements `commission draft <handle>/<pod>@<version>`.
// It fetches the pod's published manifest (or, with --pod-dir, canonicalizes
// a local pod directory for offline testing), derives the envelope the
// manifest declares, and writes a proposal seeded at exactly that envelope
// — so every edit a buyer makes from here on is a narrowing, never a
// widening past what the pod actually declares.
func runCommissionDraft(args []string) {
	fs := flag.NewFlagSet("commission draft", flag.ExitOnError)
	server := fs.String("server", "", "reef-core URL (default: $KONAREEF_SERVER or http://localhost:4000)")
	podDir := fs.String("pod-dir", "", "read and canonicalize a local pod directory's pod.toml instead of fetching from a server (offline testing)")
	fs.Parse(reorderFlagsFirst(args))
	if fs.NArg() < 1 {
		fmt.Fprintln(os.Stderr, "usage: konareef commission draft <handle>/<pod-name>@<version> [--server URL] [--pod-dir DIR]")
		os.Exit(2)
	}

	handle, podName, version, err := parsePodSpec(fs.Arg(0))
	if err != nil {
		fmt.Fprintln(os.Stderr, "commission draft:", err)
		os.Exit(2)
	}

	var resolvedServer string
	if *podDir == "" {
		resolvedServer, err = resolveServerURL(*server)
		if err != nil {
			fmt.Fprintln(os.Stderr, "commission draft:", err)
			os.Exit(2)
		}
	}

	manifestBytes, spec, err := resolvePodSpecManifest(*podDir, resolvedServer, handle, podName, version)
	if err != nil {
		fmt.Fprintln(os.Stderr, "commission draft:", err)
		os.Exit(1)
	}
	// IB-00 D16: a pod whose head carries the sealed-grants marker is not
	// commissionable; reef-core refuses it with the same code.
	if pod.HasSealedGrantsMarker(spec) {
		fmt.Fprintln(os.Stderr, "commission draft: commission_sealed_grants_unsupported: this closed pod carries sealed grants, and commissions for such pods are not supported (IB-00 D16)")
		os.Exit(1)
	}

	// Gate the manifest version and its commitment first, with the rules
	// `check` uses: an unsupported version is reported as
	// ErrManifestVersionUnsupported rather than as a declared_tools
	// derivation error, and a trailer the content does not reproduce is
	// refused rather than drafted and then refused by `check`.
	if err := commission.CheckManifestCommitment(manifestBytes); err != nil {
		fmt.Fprintln(os.Stderr, "commission draft:", err)
		os.Exit(1)
	}

	e, err := commission.FromManifest(manifestBytes, spec)
	if err != nil {
		fmt.Fprintln(os.Stderr, "commission draft:", err)
		os.Exit(1)
	}

	// FromSpec leaves the memory-scope dimension unstated, correctly: there
	// is no provenance-label vocabulary in the pod schema to derive one from
	// (see its doc comment). But an unstated dimension is unsignable, so a
	// draft that simply omitted the key would emit a proposal `check`
	// approves and `sign` refuses, with nothing telling the buyer which of
	// four keys to add. Seed it stated-but-empty instead: empty permits
	// nothing, which is the fail-closed reading, and containment against a
	// manifest that declares no labels still passes. §4.5 is preserved —
	// the buyer still makes the statement, they are just shown where.
	// annotateDraftLabels writes the explanation into the emitted file.
	e.Labels, e.LabelsSet = []string{}, true

	// Pin the ref to what the manifest itself declares (handle plus the
	// manifest's own name/version), not the possibly-partial spec the
	// caller typed — so a draft against "dave/mybot" (no version) still
	// pins the resolved version, exactly like Binding.HManifest pins the
	// resolved bytes.
	podRef := fmt.Sprintf("%s/%s@%s", handle, spec.Pod.Name, spec.Pod.Version)

	// Pin the circuit commitment too, when the pod publishes one. This is
	// what lets a later proof be tied to THIS commission rather than merely
	// to a manifest someone says produced it. commission.ManifestFieldsRoot
	// is the same rule the checker applies, so a draft cannot pin something
	// `check` would then refuse. It returns nil for a manifest that is not
	// konareef-toml/v2 or v3 (a v1 or author manifest), and an ERROR for one
	// that claims v2 or v3 and will not parse, which must not be quietly
	// drafted as unpinned.
	pinnedFieldsRoot, err := commission.ManifestFieldsRoot(manifestBytes)
	if err != nil {
		fmt.Fprintln(os.Stderr, "commission draft:", err)
		os.Exit(1)
	}

	p := commission.Proposal{
		Envelope: e,
		Binding:  commission.Binding{PodRef: podRef, HManifest: sha256.Sum256(manifestBytes), FieldsRoot: pinnedFieldsRoot},
	}

	out, err := marshalProposal(p)
	if err != nil {
		fmt.Fprintln(os.Stderr, "commission draft:", err)
		os.Exit(1)
	}
	os.Stdout.Write(annotateDraftLabels(out))
}

// runCommissionCheck implements `commission check <proposal.toml>`. It is
// advisory only (see this file's header comment): it re-fetches the pod's
// manifest, derives what it declares, and reports whether the proposal's
// envelope contains it — but it enforces nothing.
//
// Advisory about containment is not the same as silent about validity. It
// first refuses any proposal `sign` would refuse — through the same
// predicate, commission.ValidateSignable — so a pass here is a truthful
// signal that signing will work.
//
// It then checks one thing `sign` structurally cannot: that the proposal's
// h_manifest is still the hash of the artifact its pod_ref resolves to.
// `sign` never fetches a manifest, so `check` is the only verb positioned
// to catch a pin gone stale under a republished pod.
func runCommissionCheck(args []string) {
	fs := flag.NewFlagSet("commission check", flag.ExitOnError)
	server := fs.String("server", "", "reef-core URL (default: $KONAREEF_SERVER or http://localhost:4000)")
	podDir := fs.String("pod-dir", "", "read and canonicalize a local pod directory's pod.toml instead of fetching from a server (offline testing)")
	fs.Parse(reorderFlagsFirst(args))
	if fs.NArg() < 1 {
		fmt.Fprintln(os.Stderr, "usage: konareef commission check <proposal.toml> [--server URL] [--pod-dir DIR]")
		os.Exit(2)
	}

	raw, err := os.ReadFile(fs.Arg(0))
	if err != nil {
		fmt.Fprintln(os.Stderr, "commission check:", err)
		os.Exit(1)
	}
	p, err := unmarshalProposal(raw)
	if err != nil {
		fmt.Fprintln(os.Stderr, "commission check:", err)
		os.Exit(1)
	}

	// Refuse anything `sign` would refuse before saying anything about
	// containment, through the SAME predicate `sign` uses — see
	// internal/commission/signable.go's header comment. Containment ignores
	// the presence flags and knows nothing about the binding, so an envelope
	// missing a dimension, or a proposal pinning no manifest, can still be
	// "contained"; reporting that is a green light for a proposal `sign`
	// will reject. Calling commission.ValidateSignable rather than
	// restating its rules is what makes "whatever `check` approves, `sign`
	// must accept" a structural fact instead of a promise two verbs have
	// twice failed to keep.
	if err := commission.ValidateSignable(p); err != nil {
		fmt.Fprintln(os.Stderr, "commission check:", err)
		fmt.Fprintln(os.Stderr, "  (a proposal must state all four of models, tools, labels, c_max_sats —")
		fmt.Fprintln(os.Stderr, "   an empty value such as `labels = []` states the dimension and attributes no label —")
		fmt.Fprintln(os.Stderr, "   and must pin one exact artifact via pod_ref = \"<handle>/<pod>@<version>\" and h_manifest)")
		os.Exit(1)
	}

	// ValidateSignable already proved the ref parses; this only takes it
	// apart. Using commission.ParsePodRef rather than parsePodSpec is
	// deliberate: parsePodSpec accepts an unversioned ref (`install` reads
	// that as "latest"), which a commission must not.
	handle, podName, version, err := commission.ParsePodRef(p.Binding.PodRef)
	if err != nil {
		fmt.Fprintln(os.Stderr, "commission check: proposal's pod_ref:", err)
		os.Exit(1)
	}

	var resolvedServer string
	if *podDir == "" {
		resolvedServer, err = resolveServerURL(*server)
		if err != nil {
			fmt.Fprintln(os.Stderr, "commission check:", err)
			os.Exit(2)
		}
	}

	manifestBytes, spec, err := resolvePodSpecManifest(*podDir, resolvedServer, handle, podName, version)
	if err != nil {
		fmt.Fprintln(os.Stderr, "commission check:", err)
		os.Exit(1)
	}
	// IB-00 D16: a pod whose head carries the sealed-grants marker is not
	// commissionable; reef-core refuses it with the same code.
	if pod.HasSealedGrantsMarker(spec) {
		fmt.Fprintln(os.Stderr, "commission check: commission_sealed_grants_unsupported: this closed pod carries sealed grants, and commissions for such pods are not supported (IB-00 D16)")
		os.Exit(1)
	}

	// The proposal's pin must still be the artifact that ref resolves to.
	// resolvePodSpecManifest returns CANONICAL bytes and `draft` pins
	// sha256 of exactly those, so hashing them here compares like with
	// like; hashing the author's raw pod.toml instead would never match.
	//
	// A mismatch means the pod was republished, or the proposal was rebound
	// by hand, since the draft was taken. Reporting containment against the
	// new artifact while the buyer would sign a pin to the old one is the
	// stale-approval case: what `check` measured is not what `sign` attests.
	//
	// Both this pin and the circuit commitment are checked by the SAME
	// function `sign` and `verify` use, so `check` cannot approve a binding
	// they would refuse. The diagnostics below explain each refusal; the
	// decision itself is not restated here.
	if err := p.Binding.ValidateAgainstManifest(manifestBytes); err != nil {
		got := sha256.Sum256(manifestBytes)
		fmt.Fprintln(os.Stderr, "commission check:", err)
		switch {
		case errors.Is(err, commission.ErrManifestHashMismatch):
			fmt.Fprintf(os.Stderr, "  proposal pins: %s\n", hex.EncodeToString(p.Binding.HManifest[:]))
			fmt.Fprintf(os.Stderr, "  %s is now: %s\n", p.Binding.PodRef, hex.EncodeToString(got[:]))
			fmt.Fprintln(os.Stderr, "  (the pod was republished, or the proposal was rebound — re-run `commission draft`)")
		case errors.Is(err, commission.ErrCircuitCommitmentUnpinned):
			fmt.Fprintln(os.Stderr, "  this pod publishes a fields_root; a proposal that pins none cannot tie a proof to these constraints")
			fmt.Fprintln(os.Stderr, "  (re-run `commission draft` — it pins whatever the manifest commits)")
		case errors.Is(err, commission.ErrCircuitCommitmentUnexpected):
			fmt.Fprintln(os.Stderr, "  this pod publishes no fields_root, so there is nothing for the pinned value to match")
		case errors.Is(err, commission.ErrFieldsRootMismatch):
			fmt.Fprintln(os.Stderr, "  the pinned circuit commitment is not the one this manifest publishes")
			fmt.Fprintln(os.Stderr, "  (re-run `commission draft`)")
		}
		os.Exit(1)
	}

	declared, err := commission.FromManifest(manifestBytes, spec)
	if err != nil {
		fmt.Fprintln(os.Stderr, "commission check:", err)
		os.Exit(1)
	}

	res := p.Envelope.Contains(declared)
	fmt.Print(formatContainmentReport(res))
	if !res.OK {
		os.Exit(exitNotContained)
	}
}

// runCommissionSign implements `commission sign <proposal.toml>`. It fails
// closed behind --confirm-commission (main_confirm_gate.go's pattern,
// applied with its own flag — see confirmSigning's doc comment), then
// signs with the local publisher identity and writes the CBOR artifact.
func runCommissionSign(args []string) {
	fs := flag.NewFlagSet("commission sign", flag.ExitOnError)
	confirmFlag := fs.Bool(confirmFlagCommission, false,
		"the buyer has confirmed this signature (skips the interactive prompt)")
	out := fs.String("o", "", "write the signed commission artifact here (default: <proposal>.cbor)")
	fs.Parse(reorderFlagsFirst(args))
	if fs.NArg() < 1 {
		fmt.Fprintln(os.Stderr, "usage: konareef commission sign <proposal.toml> [--confirm-commission] [-o commission.cbor]")
		os.Exit(2)
	}
	proposalPath := fs.Arg(0)

	raw, err := os.ReadFile(proposalPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "commission sign:", err)
		os.Exit(1)
	}
	p, err := unmarshalProposal(raw)
	if err != nil {
		fmt.Fprintln(os.Stderr, "commission sign:", err)
		os.Exit(1)
	}

	if err := confirmSigning(p, *confirmFlag, stdinIsTerminal()); err != nil {
		fmt.Fprintln(os.Stderr, "commission sign:", err)
		os.Exit(exitNotConfirmed)
	}

	home, err := os.UserHomeDir()
	if err != nil {
		fmt.Fprintln(os.Stderr, "commission sign: locate home directory:", err)
		os.Exit(1)
	}
	id, err := identity.Load(home)
	if err != nil {
		fmt.Fprintln(os.Stderr, "commission sign:", err)
		fmt.Fprintln(os.Stderr, "  (run `konareef pod identity create --handle <h>` first)")
		os.Exit(1)
	}

	c, err := commission.Sign(p, id)
	if err != nil {
		fmt.Fprintln(os.Stderr, "commission sign:", err)
		os.Exit(1)
	}

	artifact, err := marshalCommission(c)
	if err != nil {
		fmt.Fprintln(os.Stderr, "commission sign:", err)
		os.Exit(1)
	}

	outPath := *out
	if outPath == "" {
		outPath = defaultCommissionOutPath(proposalPath)
	}
	if err := os.WriteFile(outPath, artifact, 0o644); err != nil {
		fmt.Fprintln(os.Stderr, "commission sign:", err)
		os.Exit(1)
	}
	fmt.Printf("✓ Signed commission written to %s\n", outPath)
}

// readManifestForVerify returns the bytes to hash against a commission's
// pinned h_manifest.
//
// `draft` pins sha256(canon.Canonicalize(raw, podDir)) for a v1 pod, or
// sha256 of the konareef-toml/v2 output for a `--zk` one, so `verify` must
// arrive at the same canonical form or no file a buyer actually holds could
// ever match — handing `verify` the very pod.toml `draft` was run against
// used to fail. An author-written pod.toml is therefore canonicalized here
// against its own directory, exactly as `draft --pod-dir` does. A file that
// is already canonicalizer output (an install cache's manifest.canon, or a
// server-fetched manifest) is returned verbatim, because Canonicalize is not
// idempotent — see canon.HasVersionMagic.
//
// "Verbatim" applies only to a version this binary can actually read, which
// is gated by canon.HasSupportedVersionMagic (v1, v2 and v3, per konareef-toml/v2
// spec R-V2.11). canon.HasVersionMagic answers "have these bytes already
// been canonicalized" and says yes to any `#!konareef-toml/vN`, so using it
// alone would let a `v999` manifest through unexamined and let `verify`
// bless a commission against bytes it cannot validate — a fail-open across
// exactly the version boundary a future version would introduce. Nothing in
// this repository produces a manifest past v3, so the honest answer to one
// is refusal, not a best-effort hash.
//
// This branch deliberately does NOT re-derive the bytes before hashing
// them (a fix-round-2 correction — an earlier version of this function
// re-canonicalized first, and that was wrong). Re-deriving canonical bytes
// means recomputing the `[_files]` section, which needs the pod's real file
// tree; this call site has no such tree — `path` is just wherever the
// caller pointed `--manifest`, with no guarantee anything of the original
// pod's other files sits alongside it. A pod that legitimately committed to
// a non-empty `[_files]` section (i.e. most real pods) can never reproduce
// here without that tree, so the check would fail closed on perfectly valid
// input — a regression, not a safety improvement. Reproduction against the
// real file tree is already done elsewhere, by the sites that actually hold
// that tree: publish.Prepare (at publish time) and install's
// verifyContentTarball (which extracts the tarball into its own tmpDir
// before checking). This site's job is narrower: read already-canonical
// bytes so their hash can be pinned into Binding.HManifest; authenticity of
// those bytes comes from the h_manifest/signature comparisons elsewhere in
// the commission flow, not from a reproduction check here.
//
// A file whose first line is a near miss of a magic line
// (canon.CheckMagicLine) is refused with MAGIC_NEAR_MISS, unless it opens
// with the exact `#!konareef-toml/` prefix of a version this build does
// not read, which keeps its "unsupported version" refusal.
//
// This is the reasoning (Ruling 9) that, together with Ruling 7, left
// canon.Recanonicalize with no production caller at all. It was deleted on
// 2026-09-21.
func readManifestForVerify(path string) ([]byte, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if canon.HasVersionMagic(raw) {
		if !canon.HasSupportedVersionMagic(raw) {
			version, _ := canon.VersionIdentifier(raw)
			return nil, fmt.Errorf("%s: unsupported canonical manifest version %q; this build reads konareef-toml/v1, v2 and v3 only", path, version)
		}
		// HasSupportedVersionMagic accepts `#!konareef-toml/v1` followed by
		// a lone CR and more text on the same line; that is a near miss
		// (KR-MAGIC).
		if err := canon.CheckMagicLine(raw); err != nil {
			return nil, fmt.Errorf("%s: %w", path, err)
		}
		return raw, nil
	}
	// No exact `#!konareef-toml/` prefix: a near miss such as
	// ` #!konareef-toml/v3` is refused here rather than read as author
	// input (KR-MAGIC). Canonicalize would refuse it too; this names the
	// file.
	if err := canon.CheckMagicLine(raw); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	canonical, err := canon.Canonicalize(raw, filepath.Dir(path))
	if err != nil {
		return nil, fmt.Errorf("canonicalize %s: %w", path, err)
	}
	return canonical, nil
}

// runCommissionVerify implements `commission verify <commission.cbor>
// [--manifest <path>]`. With no --manifest it is a fully offline check of
// the artifact's own integrity and signature. With --manifest it
// additionally checks that the supplied manifest is the pinned artifact
// and that its declared envelope is contained in the commission.
func runCommissionVerify(args []string) {
	fs := flag.NewFlagSet("commission verify", flag.ExitOnError)
	manifestPath := fs.String("manifest", "", "path to the manifest to check the commission against — either the pod.toml a draft was taken from (canonicalized here, against its own directory) or already-canonical manifest bytes; when given, also checks the manifest binding and containment")
	fs.Parse(reorderFlagsFirst(args))
	if fs.NArg() < 1 {
		fmt.Fprintln(os.Stderr, "usage: konareef commission verify <commission.cbor> [--manifest <path>]")
		os.Exit(2)
	}

	// loadAndVerifyCommission is the safe default loader: it never returns
	// a Commission whose signature hasn't already checked out, so a
	// mistake here (e.g. dropping this call in a future edit) fails
	// loudly rather than silently trusting an unverified artifact.
	c, overLimit, err := loadAndVerifyCommissionForReport(fs.Arg(0))
	if err != nil {
		fmt.Fprintln(os.Stderr, "commission verify: FAILED:", err)
		os.Exit(1)
	}
	if overLimit != nil {
		fmt.Fprintln(os.Stderr, "commission verify:", overLimitWarning(overLimit))
	}

	if *manifestPath == "" {
		fmt.Println("✓ commission signature and integrity verified")
		return
	}

	manifestBytes, err := readManifestForVerify(*manifestPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "commission verify:", err)
		os.Exit(1)
	}
	spec, err := pod.Parse(manifestBytes)
	if err != nil {
		fmt.Fprintln(os.Stderr, "commission verify: parse manifest:", err)
		os.Exit(1)
	}
	declared, err := commission.FromManifest(manifestBytes, spec)
	if err != nil {
		fmt.Fprintln(os.Stderr, "commission verify:", err)
		os.Exit(1)
	}
	if err := c.VerifyAgainstManifest(manifestBytes, declared); err != nil {
		fmt.Fprintln(os.Stderr, "commission verify: FAILED:", err)
		os.Exit(1)
	}
	// The same caveat `check` prints, for the same reason and from the same
	// constant: containment reached this point through the same vacuous
	// labels comparison, so an unqualified "containment verified" would
	// imply a memory-scope check that did not happen.
	fmt.Println("✓ commission signature, manifest binding, and containment verified (models, tools, spend)")
	fmt.Print(memoryScopeCaveat)
}

// runCommissionShowCore is `show`'s testable body: it writes every line of
// output to stdout/stderr and returns an exit code, instead of calling
// os.Exit directly, so a test can assert on the exact text without forking
// a process. runCommissionShow below is the thin os.Exit wrapper around it
// (the same split main_test.go's runPodInitCore already uses).
//
// show is the ONE deliberate exception to "load via loadAndVerifyCommission
// by default": it reads the artifact with the raw, unverified
// unmarshalCommission, not loadAndVerifyCommission. That is intentional —
// being able to inspect a broken, forged, or corrupted artifact is a
// legitimate thing to want ("what does this claim to say"), and refusing
// outright would make show useless for exactly the case where a human most
// needs to see what an artifact contains.
//
// What show must never do is present that content as though it were
// attested. So it calls Verify itself, prints the result as the FIRST line
// of output before anything else, and labels every line that would
// otherwise imply authenticity — the signer line and the prose — whenever
// verification failed. A caller reading only the last line still sees the
// truth, but so does a caller reading only the first.
//
// A valid signature is necessary but NOT sufficient for that first line to
// read VERIFIED. The signed canonical form excludes the presence flags and
// says nothing about the shape of pod_ref, so an artifact can carry a
// perfectly good signature and still be one `sign` would have refused. show
// therefore also applies commission.ValidateSignable and, when that fails,
// reports the artifact as invalid rather than verified — while still
// printing its contents, which is what show is for. The two failures are
// reported separately because they are different facts: a bad signature
// means nobody attested these bytes, while a failed semantic check means
// somebody did attest them and they are still not a usable commission.
func runCommissionShowCore(stdout, stderr io.Writer, path string) int {
	raw, err := os.ReadFile(path)
	if err != nil {
		fmt.Fprintln(stderr, "commission show:", err)
		return 1
	}
	c, err := unmarshalCommission(raw)
	if err != nil {
		fmt.Fprintln(stderr, "commission show:", err)
		return 1
	}

	verifyErr := c.Verify()
	semanticErr := commission.ValidateSignable(c.Proposal())
	// Over the size limits only: the artifact is valid, so it is shown as
	// VERIFIED with a warning that the server will refuse it.
	var overLimit error
	if errors.Is(semanticErr, commission.ErrOverAdmissionLimit) {
		overLimit, semanticErr = semanticErr, nil
	}
	switch {
	case verifyErr != nil:
		fmt.Fprintf(stdout, "signature:  INVALID — %v\n", verifyErr)
	case semanticErr != nil:
		fmt.Fprintf(stdout, "signature:  NOT A VALID COMMISSION — signed, but %v\n", semanticErr)
	default:
		fmt.Fprintln(stdout, "signature:  VERIFIED")
	}
	if verifyErr == nil && overLimit != nil {
		fmt.Fprintln(stdout, overLimitWarning(overLimit))
	}

	p := c.Proposal()
	fmt.Fprintf(stdout, "pod:        %s\n", p.Binding.PodRef)
	fmt.Fprintf(stdout, "h_manifest: %s\n", hex.EncodeToString(p.Binding.HManifest[:]))
	// State the circuit-commitment fact plainly in both directions. A buyer
	// reading this is deciding how much a later proof will be worth, and an
	// unpinned commission is one a proof cannot be tied to by anything
	// stronger than trust in whoever derived the manifest's fields. Saying
	// nothing here would let the silence read as "fine".
	if fr := p.Binding.FieldsRoot; fr != nil {
		fmt.Fprintf(stdout, "fields_root: %s (circuit commitment pinned)\n", hex.EncodeToString(fr[:]))
	} else {
		fmt.Fprintf(stdout, "fields_root: not pinned — this pod publishes no circuit commitment,\n")
		fmt.Fprintf(stdout, "             so a proof cannot be tied to this commission\n")
	}
	if verifyErr == nil {
		fmt.Fprintf(stdout, "signer:     %s\n", c.PubKeyHex)
	} else {
		fmt.Fprintf(stdout, "signer:     %s (UNVERIFIED)\n", c.PubKeyHex)
	}
	fmt.Fprintf(stdout, "models:     %v\n", envelope.Normalise(p.Envelope.Models))
	fmt.Fprintf(stdout, "tools:      %v\n", envelope.Normalise(p.Envelope.Tools))
	fmt.Fprintf(stdout, "labels:     %v\n", envelope.Normalise(p.Envelope.Labels))
	fmt.Fprintf(stdout, "spend:      %d sats\n\n", p.Envelope.CMax)
	switch {
	case verifyErr != nil:
		fmt.Fprintln(stdout, "UNVERIFIED — signature did not check out; the prose below is NOT attested:")
	case semanticErr != nil:
		// The prose IS attested here — the signature covers it — so this
		// warning must not claim otherwise. What is wrong is the artifact:
		// it fails a check `sign` applies, so nothing may act on it.
		fmt.Fprintf(stdout, "NOT A VALID COMMISSION — the signature covers the prose below, but this artifact fails a check `sign` applies (%v); do not act on it:\n", semanticErr)
	}
	fmt.Fprintln(stdout, p.Prose)

	if verifyErr != nil || semanticErr != nil {
		return 1
	}
	return 0
}

// runCommissionShow implements `commission show <commission.cbor>`. It
// prints the signed prose and parameters — the whole point being that a
// reader can see both together, since Sign binds them into one hash (spec
// §5.3) — labelled by whether the signature actually checked out; see
// runCommissionShowCore's doc comment.
func runCommissionShow(args []string) {
	fs := flag.NewFlagSet("commission show", flag.ExitOnError)
	fs.Parse(args)
	if fs.NArg() < 1 {
		fmt.Fprintln(os.Stderr, "usage: konareef commission show <commission.cbor>")
		os.Exit(2)
	}
	os.Exit(runCommissionShowCore(os.Stdout, os.Stderr, fs.Arg(0)))
}
