// Copyright 2026 Jerry David Chan, Konareef.ai
// SPDX-License-Identifier: Apache-2.0

// Binary-level tests for the five commission verbs.
//
// These exist because every other commission test calls library functions
// directly, and that is how the flow shipped broken: `draft` emitted a
// proposal `check` approved and `sign` refused, and no in-process test could
// see it, because each in-process test constructed the proposal it wanted
// instead of using the one `draft` actually writes.
//
// So the rule for this file is that nothing in it may construct a
// commission.Proposal, call marshalProposal, or reach past the binary in any
// other way. Every step consumes the previous step's real output, through a
// real file, through real flag parsing, and asserts the real exit code.
// A test here can only pass if a buyer at a shell could do the same thing.
package main

import (
	"bytes"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// commissionCLIResult is one binary invocation's outcome. Stdout and stderr
// are kept apart because `draft` writes the proposal to stdout: a test that
// merged the two would happily save a TOML file with a diagnostic in it.
type commissionCLIResult struct {
	stdout string
	stderr string
	code   int
}

// combined returns both streams, for assertions that only care that some
// text was printed somewhere.
func (r commissionCLIResult) combined() string { return r.stdout + r.stderr }

// runCommissionCLI runs the built binary with args and home as $HOME, and
// returns its two output streams and its exit code. It fails the test only
// if the process could not be run at all; a non-zero exit is data, since
// most of what these tests assert is exactly which code came back.
func runCommissionCLI(t *testing.T, bin, home string, args ...string) commissionCLIResult {
	t.Helper()
	cmd := exec.Command(bin, args...)
	// $HOME points identity.Load at a throwaway key, so these tests never
	// read or write the developer's real ~/.konareef/identity.json.
	env := make([]string, 0, len(os.Environ())+1)
	for _, kv := range os.Environ() {
		if strings.HasPrefix(kv, "HOME=") {
			continue
		}
		env = append(env, kv)
	}
	cmd.Env = append(env, "HOME="+home)

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()

	res := commissionCLIResult{stdout: stdout.String(), stderr: stderr.String()}
	if err == nil {
		return res
	}
	var exitErr *exec.ExitError
	if !errors.As(err, &exitErr) {
		t.Fatalf("running %v: %v\nstdout:\n%s\nstderr:\n%s", args, err, res.stdout, res.stderr)
	}
	res.code = exitErr.ExitCode()
	return res
}

// commissionCLIHome creates a temp $HOME holding a real publisher identity,
// created through the binary's own `pod identity create` rather than by
// calling internal/identity, so the test depends on nothing the CLI does not
// itself expose.
func commissionCLIHome(t *testing.T, bin string) string {
	t.Helper()
	home := t.TempDir()
	res := runCommissionCLI(t, bin, home, "pod", "identity", "create", "--handle", "dave")
	if res.code != 0 {
		t.Fatalf("could not create a test identity: exit %d\n%s", res.code, res.combined())
	}
	return home
}

// TestCommissionCLI_FullFlow drives the entire documented five-verb flow at
// the binary boundary: draft → edit → narrow → check → widen back → check →
// sign → verify → verify --manifest → show. This is spec §12 criterion 3
// ("a buyer can draft, narrow, check, sign, and offline-verify a commission
// against a published pod using only the five verbs of §6") stated as a
// test, and it is the guard that makes the draft/check/sign dead-end
// impossible to reintroduce: it never repairs a proposal by hand, so any
// verb that emits something the next verb rejects fails it.
func TestCommissionCLI_FullFlow(t *testing.T) {
	bin := buildGateCLI(t)
	home := commissionCLIHome(t, bin)
	podDir := writeSamplePodDir(t)
	work := t.TempDir()
	proposalPath := filepath.Join(work, "proposal.toml")
	commissionPath := filepath.Join(work, "commission.cbor")

	// draft — flags AFTER the positional argument, which is how the help
	// text reads and what reorderFlagsFirst exists to accept.
	draft := runCommissionCLI(t, bin, home, "commission", "draft", "dave/mybot@0.1.0", "--pod-dir", podDir)
	if draft.code != 0 {
		t.Fatalf("draft: exit %d, want 0\n%s", draft.code, draft.combined())
	}
	proposal := draft.stdout
	if !strings.Contains(proposal, "labels") {
		t.Fatalf("draft must emit a labels key, or the proposal it writes cannot be signed:\n%s", proposal)
	}
	if !strings.Contains(proposal, "h_manifest =") {
		t.Fatalf("draft must pin h_manifest:\n%s", proposal)
	}

	// edit — the buyer states their prose. `draft` seeds it empty.
	edited := strings.Replace(proposal, `prose = ""`, `prose = "Summarise the weekly reports."`, 1)
	if edited == proposal {
		t.Fatalf("expected an empty prose key to edit, got:\n%s", proposal)
	}
	if err := os.WriteFile(proposalPath, []byte(edited), 0o644); err != nil {
		t.Fatal(err)
	}

	// narrow — cutting the one tool the manifest declares must break
	// containment and exit exitNotContained, not 0 and not 1.
	narrowed := strings.Replace(edited, `tools = ["fs_read"]`, `tools = []`, 1)
	if narrowed == edited {
		t.Fatalf("expected a tools key to narrow, got:\n%s", edited)
	}
	narrowedPath := filepath.Join(work, "narrowed.toml")
	if err := os.WriteFile(narrowedPath, []byte(narrowed), 0o644); err != nil {
		t.Fatal(err)
	}
	narrowCheck := runCommissionCLI(t, bin, home, "commission", "check", narrowedPath, "--pod-dir", podDir)
	if narrowCheck.code != exitNotContained {
		t.Fatalf("check on an over-narrowed proposal: exit %d, want %d\n%s",
			narrowCheck.code, exitNotContained, narrowCheck.combined())
	}
	if !strings.Contains(narrowCheck.stdout, "NOT contained") {
		t.Fatalf("check must say which way it failed:\n%s", narrowCheck.combined())
	}

	// check — the edited (un-narrowed) proposal must pass.
	check := runCommissionCLI(t, bin, home, "commission", "check", proposalPath, "--pod-dir", podDir)
	if check.code != 0 {
		t.Fatalf("check: exit %d, want 0\n%s", check.code, check.combined())
	}
	if !strings.Contains(check.stdout, "contained") {
		t.Fatalf("check must report containment:\n%s", check.combined())
	}

	// sign — what check just approved must be signable. This assertion is
	// the whole point of the file.
	sign := runCommissionCLI(t, bin, home, "commission", "sign", proposalPath,
		"--confirm-commission", "-o", commissionPath)
	if sign.code != 0 {
		t.Fatalf("sign refused a proposal check had just approved: exit %d, want 0\n%s",
			sign.code, sign.combined())
	}
	if _, err := os.Stat(commissionPath); err != nil {
		t.Fatalf("sign reported success but wrote no artifact: %v", err)
	}

	// verify — offline, no manifest.
	verify := runCommissionCLI(t, bin, home, "commission", "verify", commissionPath)
	if verify.code != 0 {
		t.Fatalf("verify: exit %d, want 0\n%s", verify.code, verify.combined())
	}

	// verify --manifest, handed the SAME pod.toml the draft was taken from.
	// `draft` pins canonicalized bytes, so this only passes if `verify`
	// canonicalizes the file the same way instead of hashing it verbatim.
	verifyManifest := runCommissionCLI(t, bin, home, "commission", "verify", commissionPath,
		"--manifest", filepath.Join(podDir, "pod.toml"))
	if verifyManifest.code != 0 {
		t.Fatalf("verify --manifest, given the pod.toml draft used: exit %d, want 0\n%s",
			verifyManifest.code, verifyManifest.combined())
	}
	if !strings.Contains(verifyManifest.stdout, "memory scope: not checked") {
		t.Fatalf("verify --manifest must carry the same memory-scope caveat check gives:\n%s",
			verifyManifest.combined())
	}

	// show — the signed prose and parameters come back, labelled VERIFIED.
	show := runCommissionCLI(t, bin, home, "commission", "show", commissionPath)
	if show.code != 0 {
		t.Fatalf("show: exit %d, want 0\n%s", show.code, show.combined())
	}
	for _, want := range []string{
		"signature:  VERIFIED",
		"dave/mybot@0.1.0",
		"Summarise the weekly reports.",
	} {
		if !strings.Contains(show.stdout, want) {
			t.Fatalf("show output missing %q:\n%s", want, show.stdout)
		}
	}
}

// TestCommissionCLI_DraftOutputIsSignableUnedited is the H1 regression guard
// in its sharpest form. `check` and `sign` both refuse a proposal that omits
// a dimension, and the memory-scope dimension has no manifest-side source,
// so `draft` must state it itself. A buyer must be able to sign what `draft`
// wrote without knowing which key the tool left out.
func TestCommissionCLI_DraftOutputIsSignableUnedited(t *testing.T) {
	bin := buildGateCLI(t)
	home := commissionCLIHome(t, bin)
	podDir := writeSamplePodDir(t)
	work := t.TempDir()
	proposalPath := filepath.Join(work, "proposal.toml")

	draft := runCommissionCLI(t, bin, home, "commission", "draft", "dave/mybot@0.1.0", "--pod-dir", podDir)
	if draft.code != 0 {
		t.Fatalf("draft: exit %d\n%s", draft.code, draft.combined())
	}
	// Seeded empty, not seeded permissive: empty permits nothing.
	if !strings.Contains(draft.stdout, "labels = []") {
		t.Fatalf("draft must seed labels empty (permitting nothing):\n%s", draft.stdout)
	}
	// And the file must say why, or the empty value reads as a bug.
	if !strings.Contains(draft.stdout, "memory-scope dimension") {
		t.Fatalf("draft must explain the seeded labels key in the file it writes:\n%s", draft.stdout)
	}

	if err := os.WriteFile(proposalPath, []byte(draft.stdout), 0o644); err != nil {
		t.Fatal(err)
	}
	sign := runCommissionCLI(t, bin, home, "commission", "sign", proposalPath, "--confirm-commission")
	if sign.code != 0 {
		t.Fatalf("draft's own output was not signable: exit %d, want 0\n%s", sign.code, sign.combined())
	}
	// The default output path is the proposal's, with .toml swapped for .cbor.
	if _, err := os.Stat(filepath.Join(work, "proposal.cbor")); err != nil {
		t.Fatalf("sign's default output path did not appear: %v", err)
	}
}

// TestCommissionCLI_CheckAndSignAgreeOnValidity is the other half of the H1
// fix. The defect was not only that draft omitted a key; it was that two
// verbs disagreed about whether the result was valid, so `check` handed the
// buyer a green light on something `sign` would reject. Whatever `sign`
// refuses for an incomplete envelope, `check` must refuse too, with the same
// error, before it says anything about containment.
func TestCommissionCLI_CheckAndSignAgreeOnValidity(t *testing.T) {
	bin := buildGateCLI(t)
	home := commissionCLIHome(t, bin)
	podDir := writeSamplePodDir(t)
	work := t.TempDir()

	// A proposal that would pass containment but omits the labels key.
	incomplete := `pod_ref = "dave/mybot@0.1.0"
h_manifest = "ffe0a7f6b43321598a01dcde46fe18c515f3310898ab31f231175252c076411c"
prose = "Summarise the weekly reports."
models = ["claude-sonnet-5"]
tools = ["fs_read"]
c_max_sats = 4200
`
	path := filepath.Join(work, "incomplete.toml")
	if err := os.WriteFile(path, []byte(incomplete), 0o644); err != nil {
		t.Fatal(err)
	}

	check := runCommissionCLI(t, bin, home, "commission", "check", path, "--pod-dir", podDir)
	sign := runCommissionCLI(t, bin, home, "commission", "sign", path, "--confirm-commission",
		"-o", filepath.Join(work, "out.cbor"))

	if sign.code == 0 {
		t.Fatalf("sign accepted a proposal that omits a dimension:\n%s", sign.combined())
	}
	if check.code == 0 {
		t.Fatalf("check approved a proposal sign refuses; the two verbs must agree:\n%s", check.combined())
	}
	const sentinel = "commission omits a constraint dimension"
	if !strings.Contains(check.combined(), sentinel) {
		t.Fatalf("check's refusal must carry the same error sign gives (%q):\n%s", sentinel, check.combined())
	}
	if !strings.Contains(sign.combined(), sentinel) {
		t.Fatalf("sign's refusal changed; this test compares the two:\n%s", sign.combined())
	}
	if strings.Contains(check.stdout, "contained") {
		t.Fatalf("check must not report containment on a proposal it is refusing:\n%s", check.stdout)
	}
}

// TestCommissionCLI_CheckAndSignAgreeOnAnUnpinnedProposal is blocker 2's
// regression, and it is deliberately the SAME shape as
// TestCommissionCLI_CheckAndSignAgreeOnValidity above, one field over.
//
// That repetition is the finding. The first version of this branch let
// `check` approve a proposal missing `labels` that `sign` refused; the fix
// made `check` validate the envelope. `sign` then gained a second refusal —
// a zero h_manifest — and the same gap reopened immediately on a different
// field, because the two verbs were still keeping two lists. The fix this
// time is structural: both call commission.ValidateSignable, so a rule
// added there reaches both at once. This test is what fails if anyone
// re-inlines a rule into one verb.
func TestCommissionCLI_CheckAndSignAgreeOnAnUnpinnedProposal(t *testing.T) {
	bin := buildGateCLI(t)
	home := commissionCLIHome(t, bin)
	podDir := writeSamplePodDir(t)
	work := t.TempDir()

	// Every dimension stated, containment would pass — but no h_manifest
	// key at all, so the proposal pins no artifact.
	unpinned := `pod_ref = "dave/mybot@0.1.0"
prose = "Summarise the weekly reports."
models = ["claude-sonnet-5"]
tools = ["fs_read"]
labels = []
c_max_sats = 4200
`
	path := filepath.Join(work, "unpinned.toml")
	if err := os.WriteFile(path, []byte(unpinned), 0o644); err != nil {
		t.Fatal(err)
	}

	check := runCommissionCLI(t, bin, home, "commission", "check", path, "--pod-dir", podDir)
	sign := runCommissionCLI(t, bin, home, "commission", "sign", path, "--confirm-commission",
		"-o", filepath.Join(work, "out.cbor"))

	if sign.code == 0 {
		t.Fatalf("sign accepted a proposal that pins no manifest:\n%s", sign.combined())
	}
	if check.code == 0 {
		t.Fatalf("check approved an unpinned proposal sign refuses; the two verbs must agree:\n%s", check.combined())
	}
	const sentinel = "pins no manifest"
	if !strings.Contains(check.combined(), sentinel) {
		t.Fatalf("check's refusal must carry the same error sign gives (%q):\n%s", sentinel, check.combined())
	}
	if !strings.Contains(sign.combined(), sentinel) {
		t.Fatalf("sign's refusal changed; this test compares the two:\n%s", sign.combined())
	}
	if strings.Contains(check.stdout, "contained") {
		t.Fatalf("check must not report containment on a proposal it is refusing:\n%s", check.stdout)
	}
}

// TestCommissionCLI_CheckRefusesAStalePin covers the other half of blocker
// 2: a proposal whose h_manifest is well-formed and non-zero, but is not
// the hash of the artifact its pod_ref now resolves to.
//
// `sign` cannot catch this — it never fetches a manifest — so `check` is
// the only verb positioned to. A green containment report here would be
// measured against the CURRENT pod while the buyer signs a pin to a
// different one, which is a stale approval, not an advisory pass.
func TestCommissionCLI_CheckRefusesAStalePin(t *testing.T) {
	bin := buildGateCLI(t)
	home := commissionCLIHome(t, bin)
	podDir := writeSamplePodDir(t)
	work := t.TempDir()
	proposalPath := filepath.Join(work, "proposal.toml")

	draft := runCommissionCLI(t, bin, home, "commission", "draft", "dave/mybot@0.1.0", "--pod-dir", podDir)
	if draft.code != 0 {
		t.Fatalf("draft: exit %d\n%s", draft.code, draft.combined())
	}

	// Repoint the pin at a different, still well-formed hash — what a
	// republished pod or a hand-rebound proposal looks like from here. The
	// file stays valid in every other respect, so the pin is the ONLY thing
	// `check` can be refusing it for.
	stale := setHManifest(t, draft.stdout, strings.Repeat("ab", 32))
	if stale == draft.stdout {
		t.Fatalf("expected to alter the pinned h_manifest:\n%s", draft.stdout)
	}
	if err := os.WriteFile(proposalPath, []byte(stale), 0o644); err != nil {
		t.Fatal(err)
	}

	check := runCommissionCLI(t, bin, home, "commission", "check", proposalPath, "--pod-dir", podDir)
	if check.code == 0 {
		t.Fatalf("check approved a proposal pinned to a different artifact:\n%s", check.combined())
	}
	if !strings.Contains(check.combined(), "h_manifest") {
		t.Fatalf("check must say the pin is the problem:\n%s", check.combined())
	}
	if strings.Contains(check.stdout, "contained") {
		t.Fatalf("check must not report containment on a stale pin:\n%s", check.stdout)
	}
}

// setHManifest replaces the h_manifest value in proposal TOML, leaving
// every other key exactly as the binary wrote it. want must be 64 hex
// characters, or the resulting file would be rejected for being malformed
// rather than for pinning the wrong artifact — a different test.
func setHManifest(t *testing.T, tomlText, want string) string {
	t.Helper()
	if len(want) != hManifestHexLen {
		t.Fatalf("replacement h_manifest is %d chars, want %d", len(want), hManifestHexLen)
	}
	const key = `h_manifest = "`
	start := strings.Index(tomlText, key)
	if start < 0 {
		t.Fatalf("no h_manifest key in:\n%s", tomlText)
	}
	valueStart := start + len(key)
	end := strings.Index(tomlText[valueStart:], `"`)
	if end < 0 {
		t.Fatalf("unterminated h_manifest value in:\n%s", tomlText)
	}
	return tomlText[:valueStart] + want + tomlText[valueStart+end:]
}

// TestCommissionCLI_SignRefusesMalformedPodRef is blocker 3 at the shell.
// A commission's binding is `<handle>/<pod>@<version>` plus h_manifest
// (spec §6.4). `sign` used to copy pod_ref through unparsed, so a ref that
// no resolver could resolve — or one naming "latest" rather than an exact
// version — could become a signed artifact that `verify` later called
// clean.
func TestCommissionCLI_SignRefusesMalformedPodRef(t *testing.T) {
	bin := buildGateCLI(t)
	home := commissionCLIHome(t, bin)
	work := t.TempDir()

	cases := map[string]string{
		"unversioned": "dave/mybot",
		"no handle":   "mybot@0.1.0",
		"empty":       "",
	}
	for name, ref := range cases {
		t.Run(name, func(t *testing.T) {
			proposal := `pod_ref = "` + ref + `"
h_manifest = "ffe0a7f6b43321598a01dcde46fe18c515f3310898ab31f231175252c076411c"
prose = "Summarise the weekly reports."
models = ["claude-sonnet-5"]
tools = ["fs_read"]
labels = []
c_max_sats = 4200
`
			path := filepath.Join(work, name+".toml")
			if err := os.WriteFile(path, []byte(proposal), 0o644); err != nil {
				t.Fatal(err)
			}
			outPath := filepath.Join(work, name+".cbor")

			sign := runCommissionCLI(t, bin, home, "commission", "sign", path, "--confirm-commission", "-o", outPath)
			if sign.code == 0 {
				t.Fatalf("sign produced a commission with pod_ref %q:\n%s", ref, sign.combined())
			}
			if !strings.Contains(sign.combined(), "pod_ref") {
				t.Fatalf("the refusal must say pod_ref is the problem:\n%s", sign.combined())
			}
			if _, err := os.Stat(outPath); err == nil {
				t.Fatal("sign refused but still wrote an artifact")
			}
		})
	}
}

// TestCommissionCLI_SignRefusesUnpinnedProposal drives the h_manifest
// presence boundary from the shell. A proposal file with no h_manifest key
// at all decodes to the zero pin — legitimate for a draft in progress, never
// legitimate to sign, because spec §6.4's drift detection has nothing to
// compare against and every later verb would still print success.
func TestCommissionCLI_SignRefusesUnpinnedProposal(t *testing.T) {
	bin := buildGateCLI(t)
	home := commissionCLIHome(t, bin)
	work := t.TempDir()

	unpinned := `pod_ref = "dave/mybot@0.1.0"
prose = "Summarise the weekly reports."
models = ["claude-sonnet-5"]
tools = ["fs_read"]
labels = ["public"]
c_max_sats = 4200
`
	path := filepath.Join(work, "unpinned.toml")
	if err := os.WriteFile(path, []byte(unpinned), 0o644); err != nil {
		t.Fatal(err)
	}
	outPath := filepath.Join(work, "unpinned.cbor")

	sign := runCommissionCLI(t, bin, home, "commission", "sign", path, "--confirm-commission", "-o", outPath)
	if sign.code == 0 {
		t.Fatalf("sign produced a commission bound to nothing:\n%s", sign.combined())
	}
	if !strings.Contains(sign.combined(), "pins no manifest") {
		t.Fatalf("the refusal must say the binding is the problem:\n%s", sign.combined())
	}
	if _, err := os.Stat(outPath); err == nil {
		t.Fatal("sign refused but still wrote an artifact")
	}
}

// TestCommissionCLI_SignFailsClosedWithoutConfirmation checks that the
// confirmation gate is actually wired into the verb, not merely into
// confirmSigning. With no terminal and no flag the process must exit
// exitNotConfirmed and write nothing.
func TestCommissionCLI_SignFailsClosedWithoutConfirmation(t *testing.T) {
	bin := buildGateCLI(t)
	home := commissionCLIHome(t, bin)
	podDir := writeSamplePodDir(t)
	work := t.TempDir()
	proposalPath := filepath.Join(work, "proposal.toml")

	draft := runCommissionCLI(t, bin, home, "commission", "draft", "dave/mybot@0.1.0", "--pod-dir", podDir)
	if draft.code != 0 {
		t.Fatalf("draft: exit %d\n%s", draft.code, draft.combined())
	}
	if err := os.WriteFile(proposalPath, []byte(draft.stdout), 0o644); err != nil {
		t.Fatal(err)
	}

	outPath := filepath.Join(work, "unconfirmed.cbor")
	sign := runCommissionCLI(t, bin, home, "commission", "sign", proposalPath, "-o", outPath)
	if sign.code != exitNotConfirmed {
		t.Fatalf("sign without confirmation: exit %d, want %d\n%s",
			sign.code, exitNotConfirmed, sign.combined())
	}
	if !strings.Contains(sign.combined(), "--"+confirmFlagCommission) {
		t.Fatalf("the refusal must name the flag that authorises it:\n%s", sign.combined())
	}
	if _, err := os.Stat(outPath); err == nil {
		t.Fatal("sign refused but still wrote an artifact")
	}
}

// TestCommissionCLI_Dispatch covers runCommission's own switch and each
// verb's usage path — the argument handling every other test walks straight
// past because it always passes correct arguments.
func TestCommissionCLI_Dispatch(t *testing.T) {
	bin := buildGateCLI(t)
	home := commissionCLIHome(t, bin)

	cases := []struct {
		name string
		args []string
		want string
	}{
		{"no subcommand", []string{"commission"}, "usage: konareef commission"},
		{"unknown subcommand", []string{"commission", "narrow"}, `unknown commission subcommand "narrow"`},
		{"draft with no pod ref", []string{"commission", "draft"}, "usage: konareef commission draft"},
		{"check with no proposal", []string{"commission", "check"}, "usage: konareef commission check"},
		{"sign with no proposal", []string{"commission", "sign"}, "usage: konareef commission sign"},
		{"verify with no artifact", []string{"commission", "verify"}, "usage: konareef commission verify"},
		{"show with no artifact", []string{"commission", "show"}, "usage: konareef commission show"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			res := runCommissionCLI(t, bin, home, tc.args...)
			if res.code != 2 {
				t.Fatalf("exit %d, want 2 (usage error)\n%s", res.code, res.combined())
			}
			if !strings.Contains(res.combined(), tc.want) {
				t.Fatalf("expected %q in the output:\n%s", tc.want, res.combined())
			}
		})
	}
}

// TestCommissionCLI_ShowRefusesAGarbageArtifact keeps `show`'s error path
// honest: it must exit non-zero on bytes that are not a commission at all,
// rather than printing an empty, official-looking record.
func TestCommissionCLI_ShowRefusesAGarbageArtifact(t *testing.T) {
	bin := buildGateCLI(t)
	home := commissionCLIHome(t, bin)
	work := t.TempDir()
	path := filepath.Join(work, "garbage.cbor")
	if err := os.WriteFile(path, []byte("this is not CBOR"), 0o644); err != nil {
		t.Fatal(err)
	}

	show := runCommissionCLI(t, bin, home, "commission", "show", path)
	if show.code == 0 {
		t.Fatalf("show accepted bytes that are not a commission:\n%s", show.combined())
	}
	if strings.Contains(show.stdout, "VERIFIED") {
		t.Fatalf("show must never print VERIFIED for an artifact it could not decode:\n%s", show.stdout)
	}
}
