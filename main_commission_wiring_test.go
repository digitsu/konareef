// Copyright 2026 Jerry David Chan, Konareef.ai
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/fxamacker/cbor/v2"

	"github.com/digitsu/konareef/internal/commission"
	"github.com/digitsu/konareef/internal/envelope"
	"github.com/digitsu/konareef/internal/identity"
)

func completeProposal() commission.Proposal {
	return commission.Proposal{
		Envelope: envelope.Envelope{
			Models: []string{"anthropic/claude-sonnet-5"}, ModelsSet: true,
			Tools: []string{"fs_read"}, ToolsSet: true,
			Labels: []string{"public"}, LabelsSet: true,
			CMax: 4200, CMaxSet: true,
		},
		Binding: commission.Binding{PodRef: "dave/mybot@0.1.0", HManifest: [32]byte{1}},
		Prose:   "Summarise the weekly reports.",
	}
}

// Display fidelity: what the buyer is shown must be byte-identical to what
// is hashed and signed.
func TestRenderForSigning_ShowsTheExactSignedBytes(t *testing.T) {
	p := completeProposal()
	shown, err := renderForSigning(p)
	if err != nil {
		t.Fatal(err)
	}
	canonical, err := p.Canonical()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(shown, canonical) {
		t.Fatal("the bytes shown to the buyer must contain the exact canonical bytes signed")
	}
}

func TestSignRefusesWithoutConfirmation(t *testing.T) {
	err := confirmSigning(completeProposal(), false, false)
	if err == nil {
		t.Fatal("sign must fail closed with no terminal and no confirmation flag")
	}
	if !strings.Contains(err.Error(), "--confirm-commission") {
		t.Fatalf("the refusal must name the flag that authorises it, got %q", err)
	}
}

func TestSignProceedsWithConfirmation(t *testing.T) {
	if err := confirmSigning(completeProposal(), true, false); err != nil {
		t.Fatalf("explicit confirmation must proceed, got %v", err)
	}
}

// samplePodTOML is a minimal, valid pod.toml this test suite canonicalizes
// with a local --pod-dir, so draft/check/sign/verify/show are all
// exercisable offline, without a running reef-core.
const samplePodTOML = `pod_spec_version = "0.1"

[pod]
name = "mybot"
version = "0.1.0"

[runtime]
kind = "claude-code"

[model]
provider = "anthropic"
name = "claude-sonnet-5"

[directive]
task = "Summarise the weekly reports."

[[context.tools]]
source = "fs_read"

[budget]
max_sats = 4200
`

// writeSamplePodDir writes samplePodTOML to a fresh temp directory and
// returns the directory path, for use with the commission commands'
// --pod-dir offline path.
func writeSamplePodDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "pod.toml"), []byte(samplePodTOML), 0o644); err != nil {
		t.Fatal(err)
	}
	return dir
}

// TestResolvePodSpecManifest_LocalPodDir checks the offline manifest path:
// given a local pod directory, it canonicalizes pod.toml and parses a Spec
// whose declared envelope matches what's in samplePodTOML.
func TestResolvePodSpecManifest_LocalPodDir(t *testing.T) {
	dir := writeSamplePodDir(t)
	manifestBytes, spec, err := resolvePodSpecManifest(dir, "", "dave", "mybot", "0.1.0")
	if err != nil {
		t.Fatal(err)
	}
	if len(manifestBytes) == 0 {
		t.Fatal("expected non-empty canonical manifest bytes")
	}
	e, err := commission.FromSpec(spec)
	if err != nil {
		t.Fatal(err)
	}
	if !e.ModelsSet || !e.ToolsSet || !e.CMaxSet {
		t.Fatalf("derived envelope should have every derived dimension set, got %+v", e)
	}
	if len(e.Tools) != 1 || e.Tools[0] != "fs_read" {
		t.Fatalf("expected tools=[fs_read], got %v", e.Tools)
	}
	if e.CMax != 4200 {
		t.Fatalf("expected c_max=4200, got %d", e.CMax)
	}
}

// TestCommissionDraftCheckSignVerifyShow_EndToEnd_LocalPodDir exercises the
// full five-verb lifecycle against a local pod directory (no server), which
// is how this test suite covers Step 5 of the task-9 brief offline.
func TestCommissionDraftCheckSignVerifyShow_EndToEnd_LocalPodDir(t *testing.T) {
	dir := writeSamplePodDir(t)
	manifestBytes, spec, err := resolvePodSpecManifest(dir, "", "dave", "mybot", "0.1.0")
	if err != nil {
		t.Fatal(err)
	}
	declared, err := commission.FromSpec(spec)
	if err != nil {
		t.Fatal(err)
	}

	// draft: seed a proposal at the manifest's own envelope.
	p := commission.Proposal{
		Envelope: declared,
		Binding: commission.Binding{
			PodRef:    "dave/mybot@0.1.0",
			HManifest: sha256.Sum256(manifestBytes),
		},
		Prose: "Summarise the weekly reports.",
	}

	// check: a proposal seeded at the manifest's own envelope must contain it.
	if res := p.Envelope.Contains(declared); !res.OK {
		t.Fatalf("a proposal seeded from the manifest's own envelope must contain it: %+v", res.Failures)
	}

	// Narrowing a dimension below what the manifest declares must fail
	// containment — this is the check verb's negative case (spec §6,
	// exitNotContained).
	narrowed := p
	narrowed.Envelope.Tools, narrowed.Envelope.ToolsSet = []string{}, true
	if res := narrowed.Envelope.Contains(declared); res.OK {
		t.Fatal("narrowing tools to empty must break containment when the manifest declares a tool")
	}

	// FromSpec deliberately leaves the memory-scope (Labels) dimension
	// unstated — it isn't derivable from a manifest, see FromSpec's doc
	// comment — and commission.Sign refuses any omitted dimension. This
	// line stands in for what runCommissionDraft does for a real buyer:
	// seed the dimension stated-but-empty so the proposal is signable.
	//
	// This test builds its proposal in-process, so the line has to be
	// here. That is also its limit, and it is why it could not catch the
	// CLI shipping a draft with no labels key at all:
	// main_commission_cli_test.go drives the binary and repairs nothing.
	p.Envelope.Labels, p.Envelope.LabelsSet = []string{}, true

	// sign: requires --confirm-commission (or a terminal), then produces a
	// Commission whose canonical bytes embed exactly what was shown.
	if err := confirmSigning(p, true, false); err != nil {
		t.Fatal(err)
	}
	id, err := identity.Generate("dave")
	if err != nil {
		t.Fatal(err)
	}
	c, err := commission.Sign(p, id)
	if err != nil {
		t.Fatal(err)
	}

	// The artifact round trip: marshalCommission -> unmarshalCommission
	// must preserve everything Verify needs.
	artifact, err := marshalCommission(c)
	if err != nil {
		t.Fatal(err)
	}
	reloaded, err := unmarshalCommission(artifact)
	if err != nil {
		t.Fatal(err)
	}

	// verify (no manifest): offline signature + integrity check.
	if err := reloaded.Verify(); err != nil {
		t.Fatalf("reloaded commission must verify, got %v", err)
	}

	// verify (with manifest): binding + containment check.
	if err := reloaded.VerifyAgainstManifest(manifestBytes, declared); err != nil {
		t.Fatalf("reloaded commission must verify against its pinned manifest, got %v", err)
	}

	// A tampered manifest must fail VerifyAgainstManifest's hash check.
	tampered := append(append([]byte(nil), manifestBytes...), '\n')
	if err := reloaded.VerifyAgainstManifest(tampered, declared); err == nil {
		t.Fatal("verify against a different manifest must fail")
	}

	// show: prose and parameters must be recoverable from the artifact.
	shown := reloaded.Proposal()
	if shown.Prose != p.Prose {
		t.Fatalf("show must recover the signed prose: got %q want %q", shown.Prose, p.Prose)
	}
	if shown.Binding.PodRef != p.Binding.PodRef {
		t.Fatalf("show must recover the signed pod_ref: got %q want %q", shown.Binding.PodRef, p.Binding.PodRef)
	}
}

// TestDefaultCommissionOutPath checks the .toml -> .cbor default naming
// `sign` uses when -o is not given.
func TestDefaultCommissionOutPath(t *testing.T) {
	cases := map[string]string{
		"/tmp/proposal.toml": "/tmp/proposal.cbor",
		"/tmp/proposal":      "/tmp/proposal.cbor",
	}
	for in, want := range cases {
		if got := defaultCommissionOutPath(in); got != want {
			t.Errorf("defaultCommissionOutPath(%q) = %q, want %q", in, got, want)
		}
	}
}

// signedFixtureArtifact builds a valid, signed commission CBOR artifact —
// just Sign + marshalCommission, not the full draft/check flow — for tests
// that only need genuine bytes to load and, in some cases, tamper with.
func signedFixtureArtifact(t *testing.T) []byte {
	t.Helper()
	dir := writeSamplePodDir(t)
	manifestBytes, spec, err := resolvePodSpecManifest(dir, "", "dave", "mybot", "0.1.0")
	if err != nil {
		t.Fatal(err)
	}
	declared, err := commission.FromSpec(spec)
	if err != nil {
		t.Fatal(err)
	}
	// FromSpec leaves memory-scope (Labels) unstated; commission.Sign
	// refuses any omitted dimension, so a real buyer states it explicitly.
	declared.Labels, declared.LabelsSet = []string{}, true

	p := commission.Proposal{
		Envelope: declared,
		Binding: commission.Binding{
			PodRef:    "dave/mybot@0.1.0",
			HManifest: sha256.Sum256(manifestBytes),
		},
		Prose: "Summarise the weekly reports.",
	}
	id, err := identity.Generate("dave")
	if err != nil {
		t.Fatal(err)
	}
	c, err := commission.Sign(p, id)
	if err != nil {
		t.Fatal(err)
	}
	artifact, err := marshalCommission(c)
	if err != nil {
		t.Fatal(err)
	}
	return artifact
}

// tamperedArtifact returns a copy of a genuine artifact with one byte near
// the tail flipped — enough to invalidate the ECDSA signature over it
// without corrupting the CBOR framing (confirmed manually: the artifact
// still decodes; only Verify fails).
func tamperedArtifact(artifact []byte) []byte {
	tampered := append([]byte(nil), artifact...)
	tampered[len(tampered)-5] ^= 0xFF
	return tampered
}

// TestRunCommissionShowCore_TamperedArtifact_ReportsInvalidAndDoesNotAttributeProse
// is fix-round-1's discriminating test: `show` must never print a bare,
// unlabelled `signer:` line — attributing prose and identity to a key that
// never actually signed these bytes — for an artifact whose signature does
// not check out. Before this fix, runCommissionShow called
// unmarshalCommission and printed straight through with no Verify call at
// all; this test fails against that code (see task-9-report.md's
// fix-round-1 section for the before/after proof).
func TestRunCommissionShowCore_TamperedArtifact_ReportsInvalidAndDoesNotAttributeProse(t *testing.T) {
	artifact := signedFixtureArtifact(t)
	dir := t.TempDir()
	path := filepath.Join(dir, "tampered.cbor")
	if err := os.WriteFile(path, tamperedArtifact(artifact), 0o644); err != nil {
		t.Fatal(err)
	}

	var stdout, stderr bytes.Buffer
	code := runCommissionShowCore(&stdout, &stderr, path)
	if code == 0 {
		t.Fatalf("show on a tampered artifact must exit non-zero, stdout:\n%s", stdout.String())
	}
	out := stdout.String()

	firstLine := strings.SplitN(out, "\n", 2)[0]
	if !strings.Contains(firstLine, "signature:") || !strings.Contains(firstLine, "INVALID") {
		t.Fatalf("the signature status must be the FIRST line of output, got first line %q\nfull output:\n%s", firstLine, out)
	}

	// The exact bug this fix closes: an unlabelled "signer:" line
	// attributes the artifact to that pubkey even when the signature
	// never checked out. Every such line must carry the label.
	for _, line := range strings.Split(out, "\n") {
		if strings.HasPrefix(line, "signer:") && !strings.Contains(line, "UNVERIFIED") {
			t.Fatalf("signer line must be labelled UNVERIFIED when the signature is invalid, got %q\nfull output:\n%s", line, out)
		}
	}
	if !strings.Contains(out, "UNVERIFIED") {
		t.Fatalf("show must warn that the prose is unattested when verification fails, got:\n%s", out)
	}
}

// TestRunCommissionShowCore_GoodArtifact_ReportsVerified is the positive
// twin of the test above: a genuine artifact must be labelled VERIFIED,
// with no UNVERIFIED marker anywhere in the output.
func TestRunCommissionShowCore_GoodArtifact_ReportsVerified(t *testing.T) {
	artifact := signedFixtureArtifact(t)
	dir := t.TempDir()
	path := filepath.Join(dir, "commission.cbor")
	if err := os.WriteFile(path, artifact, 0o644); err != nil {
		t.Fatal(err)
	}

	var stdout, stderr bytes.Buffer
	code := runCommissionShowCore(&stdout, &stderr, path)
	if code != 0 {
		t.Fatalf("show on a genuine artifact must exit 0, got %d, stderr: %s", code, stderr.String())
	}
	out := stdout.String()
	if !strings.Contains(out, "signature:  VERIFIED") {
		t.Fatalf("show must report VERIFIED for a genuine artifact, got:\n%s", out)
	}
	if strings.Contains(out, "UNVERIFIED") {
		t.Fatalf("a genuine artifact's output must carry no UNVERIFIED label, got:\n%s", out)
	}
}

// signedArtifactBypassingSign builds a GENUINELY signed commission artifact
// from a proposal commission.Sign itself would refuse.
//
// This is not a way around Sign's contract; it is the only way to test what
// happens when that contract is not the last line of defence. Sign is one
// implementation's gate. An artifact reaching `verify` or `show` may have
// been produced by another tool, an older build, or a hand-rolled signer —
// all of which hold a private key and can sign whatever proposal they like.
// So the artifacts here are exactly what such a producer emits: a real
// secp256k1 signature over a real canonical form, carrying a proposal this
// build would never have signed. identity.Sign SHA-256s its argument, so
// signing the canonical bytes is a signature over exactly h_commission,
// which is what Verify checks.
//
// The Verify assertion inside is load-bearing: if the artifact did not
// verify, every test built on it would pass for the wrong reason.
func signedArtifactBypassingSign(t *testing.T, p commission.Proposal) []byte {
	t.Helper()
	id, err := identity.Generate("dave")
	if err != nil {
		t.Fatal(err)
	}
	canonical, err := p.Canonical()
	if err != nil {
		t.Fatal(err)
	}
	sig, err := id.Sign(canonical)
	if err != nil {
		t.Fatal(err)
	}
	c := commission.Reconstruct(p, id.PublicKeyHex, sig)
	if err := c.Verify(); err != nil {
		t.Fatalf("this artifact must carry a real signature, or the test proves nothing: %v", err)
	}
	artifact, err := marshalCommission(c)
	if err != nil {
		t.Fatal(err)
	}
	return artifact
}

// clearLabelsSetInArtifact decodes a signed artifact, flips LabelsSet to
// false, and re-encodes it — the presence-flag tamper from blocker 4.
//
// No re-signing is involved, and none is needed: the presence flags are
// excluded from the signed canonical form by design (see
// internal/commission/object.go's canonicalProposal), so this edit leaves
// h_commission and the signature untouched. That is the whole point. The
// signature is not evidence about these four bits, and the callers below
// assert exactly that — the tampered artifact still VERIFIES, and must
// still be refused.
func clearLabelsSetInArtifact(t *testing.T, artifact []byte) []byte {
	t.Helper()
	var a commissionArtifact
	if err := cbor.Unmarshal(artifact, &a); err != nil {
		t.Fatal(err)
	}
	if !a.Proposal.Envelope.LabelsSet {
		t.Fatal("the source artifact must have LabelsSet true, or this tamper changes nothing")
	}
	a.Proposal.Envelope.LabelsSet = false
	tampered, err := cbor.Marshal(a)
	if err != nil {
		t.Fatal(err)
	}
	return tampered
}

// writeArtifact writes bytes to a fresh temp file and returns its path.
func writeArtifact(t *testing.T, name string, artifact []byte) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, artifact, 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

// TestPresenceFlagTamperLeavesTheSignatureIntact is the premise every test
// below depends on, asserted on its own so a failure names the right cause.
// If the canonical form ever starts covering the presence flags, this test
// fails FIRST and tells the reader the threat model changed, rather than
// letting the tamper tests pass for a reason they do not describe.
func TestPresenceFlagTamperLeavesTheSignatureIntact(t *testing.T) {
	tampered := clearLabelsSetInArtifact(t, signedFixtureArtifact(t))
	c, err := unmarshalCommission(tampered)
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Verify(); err != nil {
		t.Fatalf("flipping a presence flag must NOT break the signature (that is why load must re-validate), got %v", err)
	}
	if c.Proposal().Envelope.LabelsSet {
		t.Fatal("the tamper did not survive the CBOR round trip")
	}
}

// TestLoadAndVerifyCommission_RejectsPresenceFlagTamper is blocker 4's
// regression. The artifact's signature checks out (proved above), so
// Verify alone reports it as genuine — but its decoded envelope no longer
// states the memory-scope dimension, which is a commission `sign` would
// have refused to produce. The safe-default loader must refuse it too,
// rather than handing `verify` something it will call fully verified.
func TestLoadAndVerifyCommission_RejectsPresenceFlagTamper(t *testing.T) {
	path := writeArtifact(t, "flagtamper.cbor", clearLabelsSetInArtifact(t, signedFixtureArtifact(t)))
	_, err := loadAndVerifyCommission(path)
	if err == nil {
		t.Fatal("loadAndVerifyCommission accepted an artifact whose presence flags were edited after signing")
	}
	if !errors.Is(err, envelope.ErrDimensionAbsent) {
		t.Fatalf("the refusal must name the omitted dimension, got %v", err)
	}
}

// TestRunCommissionShowCore_PresenceFlagTamper_DoesNotReportVerified is the
// `show` half. show deliberately still prints a broken artifact's contents,
// so the requirement is not that it refuses to speak — it is that it never
// calls this artifact VERIFIED, and exits non-zero.
func TestRunCommissionShowCore_PresenceFlagTamper_DoesNotReportVerified(t *testing.T) {
	path := writeArtifact(t, "flagtamper.cbor", clearLabelsSetInArtifact(t, signedFixtureArtifact(t)))

	var stdout, stderr bytes.Buffer
	code := runCommissionShowCore(&stdout, &stderr, path)
	out := stdout.String()
	if code == 0 {
		t.Fatalf("show on a post-signing tamper must exit non-zero, stdout:\n%s", out)
	}
	if strings.Contains(out, "signature:  VERIFIED") {
		t.Fatalf("show labelled a semantically invalid artifact VERIFIED:\n%s", out)
	}
	if !strings.Contains(out, "NOT A VALID COMMISSION") {
		t.Fatalf("show must say why the artifact is unusable:\n%s", out)
	}
}

// malformedRefProposal returns a genuinely signable-looking proposal whose
// pod_ref is not <handle>/<pod>@<version>: the ref is unversioned, so it
// names whatever the registry serves today rather than one exact artifact.
func malformedRefProposal() commission.Proposal {
	p := completeProposal()
	p.Binding.PodRef = "dave/mybot"
	return p
}

// TestLoadAndVerifyCommission_RejectsMalformedPodRef is blocker 3's
// verify-side regression: a signed artifact whose durable pod reference
// violates the documented binding shape must not be reported as cleanly
// verified just because the signature is real.
func TestLoadAndVerifyCommission_RejectsMalformedPodRef(t *testing.T) {
	path := writeArtifact(t, "badref.cbor", signedArtifactBypassingSign(t, malformedRefProposal()))
	_, err := loadAndVerifyCommission(path)
	if err == nil {
		t.Fatal("loadAndVerifyCommission accepted a signed artifact with a malformed pod_ref")
	}
	if !errors.Is(err, commission.ErrPodRefMalformed) {
		t.Fatalf("the refusal must name the pod_ref as the problem, got %v", err)
	}
}

// TestRunCommissionShowCore_MalformedPodRef_DoesNotReportVerified is the
// `show` half of the same blocker.
func TestRunCommissionShowCore_MalformedPodRef_DoesNotReportVerified(t *testing.T) {
	path := writeArtifact(t, "badref.cbor", signedArtifactBypassingSign(t, malformedRefProposal()))

	var stdout, stderr bytes.Buffer
	code := runCommissionShowCore(&stdout, &stderr, path)
	out := stdout.String()
	if code == 0 {
		t.Fatalf("show on an artifact with a malformed pod_ref must exit non-zero, stdout:\n%s", out)
	}
	if strings.Contains(out, "signature:  VERIFIED") {
		t.Fatalf("show labelled an artifact with a malformed pod_ref VERIFIED:\n%s", out)
	}
}

// TestLoadAndVerifyCommission checks the safe-default loader directly:
// success for a genuine artifact, an error for a tampered one.
func TestLoadAndVerifyCommission(t *testing.T) {
	artifact := signedFixtureArtifact(t)
	dir := t.TempDir()

	goodPath := filepath.Join(dir, "commission.cbor")
	if err := os.WriteFile(goodPath, artifact, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := loadAndVerifyCommission(goodPath); err != nil {
		t.Fatalf("loadAndVerifyCommission must succeed for a genuine artifact, got %v", err)
	}

	badPath := filepath.Join(dir, "tampered.cbor")
	if err := os.WriteFile(badPath, tamperedArtifact(artifact), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := loadAndVerifyCommission(badPath); err == nil {
		t.Fatal("loadAndVerifyCommission must return an error for a tampered artifact")
	}
}
