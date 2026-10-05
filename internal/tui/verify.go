// Copyright 2026 Jerry David Chan, Konareef.ai
// SPDX-License-Identifier: Apache-2.0

// internal/tui/verify.go
//
// VerifyModel is a standalone Bubble Tea screen for the dedicated
// `konareef verify <path> --tui` mode (Track A.1 of the TUI ZK-surfacing
// work-map). Unlike the live-monitor App, it is fully offline: it loads a
// konareef-bundle from a path or URL, runs the existing verify pipeline,
// and renders the structured outcome (pass/fail, per-check verdicts,
// divergences) with scrolling and re-verify.
//
// Format dispatch mirrors verify.VerifyV2's first-byte ladder:
//   - '{' (0x7B)      → konareef-bundle/v1 JSON  → verify.Verify[Strict]
//   - 0xA0..0xBB      → konareef-bundle/v2 CBOR   → verify.VerifyV2
//   - anything else   → malformed; VerifyV2 emits the divergence
//
// The presentation layer is split into pure functions (outcomeFromV1,
// outcomeFromV2, verifyOutcome.styledLines) so the mapping logic is unit-
// tested without driving the Bubble Tea event loop.

package tui

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/fxamacker/cbor/v2"

	"github.com/digitsu/konareef/internal/verify"
)

// checkState is the verdict for a single named verification check.
type checkState int

const (
	checkPass checkState = iota // the check ran and passed
	checkFail                   // the check ran and failed
	checkInfo                   // informational (e.g. fail-closed / legacy), not a hard fail
	checkNA                     // not applicable to this bundle version
)

// glyph returns the status glyph rendered for a check state.
func (s checkState) glyph() string {
	switch s {
	case checkPass:
		return "✅"
	case checkFail:
		return "❌"
	case checkInfo:
		return "⚠"
	default:
		return "—"
	}
}

// checkLine is one named check row in the verify view.
type checkLine struct {
	Label  string     // human label, e.g. "SNARK proof"
	State  checkState // pass / fail / info / na
	Detail string     // optional trailing detail, e.g. "valid", identity status
}

// verifyOutcome is the format-agnostic display model produced from either
// a v1 verify.Result or a v2 verify.ResultV2. It carries only plain data
// so it can be asserted on directly in tests.
type verifyOutcome struct {
	Source      string                 // path or URL the bundle was loaded from
	Version     string                 // bundle version string ("konareef-bundle/v1" | ".../v2")
	IsV2        bool                   // true for the CBOR v2 path
	OK          bool                   // overall pass/fail
	ChainLength int                    // number of chain links verified
	CircuitID   string                 // v2 only — circuit the proof targets
	Disclosure  string                 // v2 only — "C" or "D"
	Attestation string                 // v1 only — raw AttestationStatus
	Custody     verify.BrokerAssurance // MCP broker assurance of the custody record
	Checks      []checkLine            // per-check verdicts (granularity varies by version)
	Divergences []string               // human-readable failure messages
}

// boolState maps a verdict bool to pass/fail.
func boolState(ok bool) checkState {
	if ok {
		return checkPass
	}
	return checkFail
}

// boolText returns one of two strings based on a verdict bool.
func boolText(ok bool, yes, no string) string {
	if ok {
		return yes
	}
	return no
}

// outcomeFromV1 maps a legacy v1 verify.Result (+ its Bundle, for the
// version string) into a verifyOutcome.
func outcomeFromV1(src string, b *verify.Bundle, r *verify.Result) verifyOutcome {
	o := verifyOutcome{
		Source:      src,
		Version:     orDefault(b.Version, "konareef-bundle/v1"),
		IsV2:        false,
		OK:          r.OK,
		ChainLength: r.ChainLength,
		Attestation: r.AttestationStatus,
		Divergences: append([]string(nil), r.Divergences...),
	}
	switch r.AttestationStatus {
	case "attested":
		o.Checks = append(o.Checks, checkLine{"publisher attestation", checkPass, "attested"})
	case "legacy_unsigned":
		o.Checks = append(o.Checks, checkLine{"publisher attestation", checkInfo, "legacy unsigned (--strict to require)"})
	}
	o.Custody = r.Custody.Assurance
	o.Checks = append(o.Checks, custodyCheck(r.Custody))
	return o
}

// custodyCheckLabel is the row label of the broker assurance check. It
// says "server custody" so the row is never read as circuit coverage.
const custodyCheckLabel = "MCP broker (server custody)"

// custodyCheck maps a custody assessment to a check row. Only a fully
// verified contained record is a pass. A refused record is a fail. Every
// other level is informational: it is not a failure, and it is not a
// broker guarantee.
//
// Input: a, the assessment from verify.Result or verify.ResultV2.
// Output: the check row, whose Detail is the assessment's display label.
func custodyCheck(a verify.CustodyAssessment) checkLine {
	state := checkInfo
	switch a.Assurance {
	case verify.BrokerAssuranceContained:
		state = checkPass
	case verify.BrokerAssuranceRefused:
		state = checkFail
	}
	return checkLine{custodyCheckLabel, state, a.Label()}
}

// outcomeFromV2 maps a v2 verify.ResultV2 into a verifyOutcome. The
// version/circuit/disclosure header fields are sourced from a best-effort
// CBOR header decode (the ResultV2 itself does not carry them). When the
// SNARK verifier is not wired (production fail-closed default), the proof
// check is rendered as informational rather than a hard failure so the
// view does not misrepresent an un-provisioned verifier as a tamper.
func outcomeFromV2(src, version, circuitID, disclosure string, r *verify.ResultV2) verifyOutcome {
	o := verifyOutcome{
		Source:      src,
		Version:     orDefault(version, "konareef-bundle/v2"),
		IsV2:        true,
		OK:          r.OK,
		ChainLength: r.ChainLength,
		CircuitID:   circuitID,
		Disclosure:  disclosure,
	}
	for _, d := range r.Divergences {
		o.Divergences = append(o.Divergences, d.Msg)
	}

	v := r.V2Verdict
	if v == nil {
		// Decode failed before the verdict was built; divergences carry
		// the reason. Nothing more to map.
		return o
	}

	if snarkNotConfigured(r) {
		o.Checks = append(o.Checks, checkLine{"SNARK proof", checkInfo, "verifier not configured (fail-closed)"})
	} else {
		o.Checks = append(o.Checks, checkLine{"SNARK proof", boolState(v.ProofValid), boolText(v.ProofValid, "valid", "invalid")})
	}

	discLabel := "disclosure"
	if disclosure != "" {
		discLabel = fmt.Sprintf("disclosure (Type %s)", disclosure)
	}
	o.Checks = append(o.Checks, checkLine{discLabel, boolState(v.DisclosureValid), ""})
	o.Checks = append(o.Checks, checkLine{"commitments", boolState(v.CommitmentsValid), ""})

	chainLabel := "chain policy"
	if v.ChainPolicyMode != "" {
		chainLabel = fmt.Sprintf("chain policy (%s)", v.ChainPolicyMode)
	}
	o.Checks = append(o.Checks, checkLine{chainLabel, boolState(v.ChainPolicyValid), chainDetail(v)})

	// Publisher attestation (P1.4 landed): the out-of-circuit ECDSA check
	// over h_manifest now runs for real, so an envelope-bearing bundle is
	// either self_signed (valid) or signature_invalid (proven bad). There
	// is no longer a "pending" soft state — render the verdict directly.
	o.Checks = append(o.Checks, checkLine{"publisher attestation", boolState(v.SignatureValid), string(v.PublisherIdentityStatus)})
	o.Custody = r.Custody.Assurance
	o.Checks = append(o.Checks, custodyCheck(r.Custody))
	return o
}

// chainDetail returns the trailing detail for the chain-policy line. The
// line says whether the chain head is anchored (anchorDetail) and never
// reads as a tamper-evident chain unless the anchor verified. A chain
// that starts mid-chain is reported as truncated (R2b D2).
//
// Input: the v2 structured verdict.
// Output: the detail text.
func chainDetail(v *verify.Verdict) string {
	detail := anchorDetail(v)
	if v.ChainTruncated {
		detail = "truncated chain · " + detail
	}
	return detail
}

// anchorDetail describes the chain-head anchor in plain words
// (reef-core#76). Only a verified anchor says "anchored"; every other
// status names why the head is not anchored.
//
// Input: the v2 structured verdict. Output: the text.
func anchorDetail(v *verify.Verdict) string {
	a := v.ChainHeadAnchor
	if a == nil {
		return "head not anchored"
	}
	floor := ""
	if a.FloorOverridden {
		floor = " · lowered difficulty floor"
	}
	if v.ChainHeadAnchored && a.Status == verify.AnchorVerified {
		return fmt.Sprintf("head anchored at block %d (%d conf) · node %s%s",
			a.BlockHeight, a.Confirmations, shortKey(a.AttributedTo), floor)
	}
	switch a.Status {
	case verify.AnchorVerified:
		return "head anchor checks out, but the bundle failed" + floor
	case verify.AnchorHeadersUnavailable:
		return "head anchor not checked: no block headers"
	case verify.AnchorInsufficientDepth:
		return fmt.Sprintf("head anchor unconfirmed (%d conf)", a.Confirmations)
	case verify.AnchorUnattributed:
		return "head anchor not from a trusted node"
	case verify.AnchorInvalid:
		return "head anchor invalid"
	default:
		return "head not anchored"
	}
}

// shortKey abbreviates a hex key to its first 12 characters.
func shortKey(k string) string {
	if len(k) > 12 {
		return k[:12] + "…"
	}
	return k
}

// snarkNotConfigured reports whether the v2 result failed solely because
// no Spartan verifier was wired (the production fail-closed default).
func snarkNotConfigured(r *verify.ResultV2) bool {
	for _, d := range r.Divergences {
		if errors.Is(d.Err, verify.ErrSnarkVerifierNotConfigured) {
			return true
		}
	}
	return false
}

// orDefault returns s, or def when s is empty.
func orDefault(s, def string) string {
	if s == "" {
		return def
	}
	return s
}

// ── presentation ────────────────────────────────────────────────────

// styledLine pairs rendered text with the lipgloss style applied in the
// styled View(). The plain .text is what unit tests assert against.
type styledLine struct {
	text  string
	style lipgloss.Style
}

// styledLines builds the full ordered line list for the outcome. Layout
// is shared between the styled View() and the plain-text test helper.
func (o verifyOutcome) styledLines() []styledLine {
	var ls []styledLine
	add := func(text string, style lipgloss.Style) { ls = append(ls, styledLine{text, style}) }

	add("konareef verify", TitleStyle)

	header := fmt.Sprintf("bundle: %s   %s", o.Source, shortVersion(o.Version))
	if o.CircuitID != "" {
		header += "   circuit: " + o.CircuitID
	}
	add(header, SubtitleStyle)
	if o.Disclosure != "" {
		add("disclosure: "+o.Disclosure, SubtitleStyle)
	}
	add("", HelpStyle)

	if o.OK {
		add(fmt.Sprintf("✅ PASS   chain length: %d", o.ChainLength), RunningDotStyle)
	} else {
		add(fmt.Sprintf("❌ FAIL   chain length: %d", o.ChainLength), ErrorStyle)
	}

	if len(o.Checks) > 0 {
		add("", HelpStyle)
		for _, c := range o.Checks {
			add(formatCheck(c), checkStyle(c.State))
		}
	}

	add("", HelpStyle)
	add(fmt.Sprintf("Divergences (%d)", len(o.Divergences)), SubtitleStyle)
	for _, d := range o.Divergences {
		add("  • "+d, ErrorStyle)
	}
	return ls
}

// formatCheck renders one check row as "  label .... ✅ detail" with the
// label dot-padded to a fixed column so the glyphs align.
func formatCheck(c checkLine) string {
	const col = 26
	label := c.Label
	dots := col - len(label)
	if dots < 1 {
		dots = 1
	}
	line := fmt.Sprintf("  %s %s %s", label, strings.Repeat(".", dots), c.State.glyph())
	if c.Detail != "" {
		line += " " + c.Detail
	}
	return strings.TrimRight(line, " ")
}

// checkStyle maps a check state to its lipgloss style.
func checkStyle(s checkState) lipgloss.Style {
	switch s {
	case checkPass:
		return RunningDotStyle
	case checkFail:
		return ErrorStyle
	case checkInfo:
		return FlashStyle
	default:
		return HelpStyle
	}
}

// shortVersion compresses a full bundle version string to a compact tag.
func shortVersion(v string) string {
	switch {
	case strings.HasSuffix(v, "/v2") || strings.Contains(v, "v2"):
		return "v2"
	case strings.HasSuffix(v, "/v1") || strings.Contains(v, "v1"):
		return "v1"
	default:
		return v
	}
}

// plainVerifyLines returns the unstyled text of each line — the unit-test
// surface for the layout produced by styledLines.
func plainVerifyLines(o verifyOutcome) []string {
	sl := o.styledLines()
	out := make([]string, len(sl))
	for i, l := range sl {
		out[i] = l.text
	}
	return out
}

// ── loading / dispatch ──────────────────────────────────────────────

// computeOutcome reads the bundle at src, dispatches on the first byte to
// the v1 or v2 verifier, and returns the display outcome. strict applies
// only to the v1 path (--strict publisher-attestation requirement).
//
// disclosurePolicy ("", "C", or "D"; case-insensitive) is the optional
// verify-side assertion from `--disclosure-policy`. When non-empty it is
// enforced AFTER load and BEFORE verification — mirroring the headless
// `konareef verify` semantics (main.go) — so the `--tui` path cannot
// bypass a Type C/D mismatch. A violation is returned as a hard error
// (rendered as a fail-closed load error), never silently rendered.
func computeOutcome(src string, strict bool, disclosurePolicy string) (verifyOutcome, error) {
	return computeOutcomeWithAnchor(src, strict, disclosurePolicy, verify.AnchorConfig{})
}

// computeOutcomeWithAnchor is computeOutcome with extra chain-head anchor
// configuration (header source, confirmation minimum, trusted node keys)
// merged over the environment's for the v2 path (reef-core#76).
func computeOutcomeWithAnchor(src string, strict bool, disclosurePolicy string, anchor verify.AnchorConfig) (verifyOutcome, error) {
	raw, err := readBundleBytes(src)
	if err != nil {
		return verifyOutcome{}, err
	}
	if len(raw) == 0 {
		return verifyOutcome{}, fmt.Errorf("empty bundle: %s", src)
	}

	// Normalise the asserted policy exactly as the CLI does (ToUpper);
	// empty is a no-op inside AssertDisclosurePolicy.
	want := strings.ToUpper(disclosurePolicy)

	if raw[0] == '{' {
		var b verify.Bundle
		if err := json.Unmarshal(raw, &b); err != nil {
			return verifyOutcome{}, fmt.Errorf("parse v1 bundle: %w", err)
		}
		// Mirror verify.Load's version gate (load.go) so the --tui JSON
		// path has the same fail-closed format contract as headless
		// `konareef verify`: an unsupported version (e.g. a future
		// konareef-bundle/v999) is rejected here, not fed into the v1
		// verifier/presentation path.
		if b.Version != verify.BundleVersion {
			return verifyOutcome{}, fmt.Errorf(
				"unsupported bundle version %q (this verifier handles %q only)",
				b.Version, verify.BundleVersion)
		}
		if err := verify.AssertDisclosurePolicy(&b, want); err != nil {
			return verifyOutcome{}, err
		}
		var r *verify.Result
		if strict {
			r = verify.VerifyStrict(&b)
		} else {
			r = verify.Verify(&b)
		}
		return outcomeFromV1(src, &b, r), nil
	}

	// v2 CBOR (or malformed) — VerifyV2 owns the first-byte dispatch and
	// emits a divergence for anything it cannot decode. The header decode
	// is best-effort and feeds both the display fields and the disclosure
	// assertion (v2 carries `disclosure` in the CBOR header, not in a
	// verify.Bundle, so assert against a minimal carrier for identical
	// ERR_DISCLOSURE_POLICY_VIOLATION semantics).
	var hdr struct {
		Version    string `cbor:"version"`
		CircuitID  string `cbor:"circuit_id"`
		Disclosure string `cbor:"disclosure"`
	}
	_ = cbor.Unmarshal(raw, &hdr)
	if err := verify.AssertDisclosurePolicy(&verify.Bundle{Disclosure: hdr.Disclosure}, want); err != nil {
		return verifyOutcome{}, err
	}
	// Live verify path. VerifyV2Production decodes the bundle and, when
	// KONAREEF_VERIFY_BIN is set, injects the real Rust Spartan verifier
	// subprocess (reading the bundle's 704-byte z0); when unset it stays
	// fail-closed (failClosedVerifier) so production cannot PASS a v2
	// bundle without a real verifier. The test-only accepting stub is
	// never used on this path.
	r := verify.VerifyV2ProductionWithAnchor(raw, false, anchor)
	return outcomeFromV2(src, hdr.Version, hdr.CircuitID, hdr.Disclosure, r), nil
}

// readBundleBytes reads the raw bundle bytes from a local path or an
// http(s) URL, mirroring the source handling of `konareef verify`.
func readBundleBytes(src string) ([]byte, error) {
	if strings.HasPrefix(src, "http://") || strings.HasPrefix(src, "https://") {
		resp, err := http.Get(src)
		if err != nil {
			return nil, err
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			return nil, fmt.Errorf("fetch %s: status %d", src, resp.StatusCode)
		}
		return io.ReadAll(resp.Body)
	}
	return os.ReadFile(src)
}

// ── Bubble Tea model ────────────────────────────────────────────────

// VerifyModel is the standalone verify screen.
type VerifyModel struct {
	src              string
	strict           bool
	disclosurePolicy string // "", "C", or "D" — re-applied on re-verify
	anchor           verify.AnchorConfig
	outcome          verifyOutcome
	loadErr          error
	width            int
	height           int
	scroll           int // first visible line index
}

// newVerifyModel constructs the model around an already-computed outcome.
func newVerifyModel(src string, strict bool, disclosurePolicy string, o verifyOutcome) VerifyModel {
	return VerifyModel{src: src, strict: strict, disclosurePolicy: disclosurePolicy, outcome: o}
}

// Init implements tea.Model. No async work on start — the outcome is
// computed before the program runs.
func (m VerifyModel) Init() tea.Cmd { return nil }

// Update handles window sizing, quit, scroll, and re-verify.
func (m VerifyModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
		return m, nil

	case tea.KeyMsg:
		switch msg.String() {
		case "q", "ctrl+c":
			return m, tea.Quit
		case "r":
			// Re-read from disk and re-verify. The read is local and
			// fast, so it runs inline rather than as a tea.Cmd.
			o, err := computeOutcomeWithAnchor(m.src, m.strict, m.disclosurePolicy, m.anchor)
			m.outcome, m.loadErr = o, err
			m.scroll = 0
			return m, nil
		case "up", "k":
			if m.scroll > 0 {
				m.scroll--
			}
		case "down", "j":
			if m.scroll < m.maxScroll() {
				m.scroll++
			}
		case "g":
			m.scroll = 0
		case "G":
			m.scroll = m.maxScroll()
		}
	}
	return m, nil
}

// visibleLines is how many body lines fit given the current height.
func (m VerifyModel) visibleLines() int {
	avail := m.height - 4 // box border + footer
	if avail < 3 {
		avail = 3
	}
	return avail
}

// maxScroll is the largest valid scroll offset.
func (m VerifyModel) maxScroll() int {
	total := len(m.outcome.styledLines())
	max := total - m.visibleLines()
	if max < 0 {
		return 0
	}
	return max
}

// View renders the verify screen with a scroll window and a key-hint
// footer.
func (m VerifyModel) View() string {
	if m.loadErr != nil {
		body := ErrorStyle.Render(fmt.Sprintf("⚠ %v", m.loadErr))
		inner := lipgloss.JoinVertical(lipgloss.Left, body, "", HelpStyle.Render("r retry · q quit"))
		return renderPanel(inner, m.width-8)
	}

	all := m.outcome.styledLines()
	vis := m.visibleLines()
	start := m.scroll
	if start > len(all) {
		start = len(all)
	}
	end := start + vis
	if end > len(all) {
		end = len(all)
	}

	rows := make([]string, 0, vis+2)
	for _, l := range all[start:end] {
		rows = append(rows, l.style.Render(l.text))
	}
	if start > 0 {
		rows = append([]string{HelpStyle.Render("↑ more")}, rows...)
	}
	if end < len(all) {
		rows = append(rows, HelpStyle.Render("↓ more"))
	}

	footer := HelpStyle.Render("q quit · r re-verify · ↑/↓ scroll · g top · G bottom")
	body := lipgloss.JoinVertical(lipgloss.Left, append(rows, "", footer)...)
	return renderPanel(body, m.width-8)
}

// verifyExitErr maps a verify outcome to the process-exit contract shared
// with headless `konareef verify` (main.go): a non-nil error (→ exit 1)
// on a load/parse/version/disclosure failure or any verification
// divergence; nil (→ exit 0) only on a clean pass. It is a pure function
// so the non-interactive decision surface is unit-tested without driving
// the Bubble Tea loop.
func verifyExitErr(o verifyOutcome, loadErr error) error {
	if loadErr != nil {
		return loadErr
	}
	if !o.OK {
		return fmt.Errorf("verification failed: %d divergence(s)", len(o.Divergences))
	}
	return nil
}

// RunVerify computes the verify outcome for src and runs the standalone
// verify TUI. strict applies the v1 --strict attestation requirement;
// disclosurePolicy ("", "C", or "D") applies the --disclosure-policy
// assertion before rendering (fail-closed on mismatch). It is the entry
// point wired into `konareef verify --tui`.
//
// RunVerify preserves the headless verify exit contract: it returns a
// non-nil error (so `runVerify` exits 1) when the FINAL model state — the
// outcome as last re-verified by the user — has a load error or any
// divergence. A TUI runtime error takes precedence over the verdict.
func RunVerify(src string, strict bool, disclosurePolicy string) error {
	return RunVerifyWithAnchor(src, strict, disclosurePolicy, verify.AnchorConfig{})
}

// RunVerifyWithAnchor is RunVerify with extra chain-head anchor
// configuration from CLI flags (reef-core#76). Re-verify keeps using it.
func RunVerifyWithAnchor(src string, strict bool, disclosurePolicy string, anchor verify.AnchorConfig) error {
	o, err := computeOutcomeWithAnchor(src, strict, disclosurePolicy, anchor)
	m := newVerifyModel(src, strict, disclosurePolicy, o)
	m.anchor = anchor
	m.loadErr = err
	finalModel, runErr := tea.NewProgram(m, tea.WithAltScreen()).Run()
	if runErr != nil {
		return runErr
	}
	if fm, ok := finalModel.(VerifyModel); ok {
		return verifyExitErr(fm.outcome, fm.loadErr)
	}
	return verifyExitErr(o, err)
}
