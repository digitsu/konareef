// Copyright 2026 Jerry David Chan, Konareef.ai
// SPDX-License-Identifier: Apache-2.0

// report.go — the replay verdict, the per-dimension assurance statements,
// and their text and JSON renderings.
//
// The dimension statuses are exactly verified, unverified and
// not_applicable. Each dimension also lists its basis in the contract §14.2
// vocabulary (buyer_attested, admission_checked,
// admission_checked_declared_only, circuit_verified, not_evaluated) plus
// server_asserted and not_buyer_signed, and a reason. No verdict, headline
// or dimension says that the commission was fulfilled: the evidence
// formats cannot show it (§14.4).

package replay

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/digitsu/konareef/internal/api"
)

// Status is the assurance status of one dimension.
type Status string

// The dimension statuses.
const (
	StatusVerified      Status = "verified"
	StatusUnverified    Status = "unverified"
	StatusNotApplicable Status = "not_applicable"
)

// Verdict is the overall replay result.
type Verdict string

// The verdicts, from weakest to strongest evidence.
const (
	// VerdictContradicted: at least one check failed.
	VerdictContradicted Verdict = "contradicted"
	// VerdictIncomplete: required evidence is missing or unreadable, and
	// nothing failed.
	VerdictIncomplete Verdict = "incomplete"
	// VerdictNotLaunched: the admission replays, and the receipt says the
	// commission was consumed without a run.
	VerdictNotLaunched Verdict = "admission_replayed_not_launched"
	// VerdictAdmissionReplayed: the admission replays; no proof supports
	// the run.
	VerdictAdmissionReplayed Verdict = "admission_replayed"
	// VerdictProofVerified: the admission replays, and a verified proof
	// covers the recorded steps of a run of this exact manifest.
	VerdictProofVerified Verdict = "admission_replayed_proof_verified"
)

// headlines are the display strings of the verdicts. Each one states its
// own limit, so no verdict can be read as proof of fulfilment.
var headlines = map[Verdict]string{
	VerdictContradicted: "CONTRADICTED: the evidence does not agree. Do not rely on this commission-to-run record.",
	VerdictIncomplete:   "INCOMPLETE: some evidence is missing or unreadable. Only the dimensions marked verified hold.",
	VerdictNotLaunched:  "ADMISSION REPLAYED, NO RUN: the admission checks reproduce offline, and the receipt says the commission was consumed without launching a run.",
	VerdictAdmissionReplayed: "ADMISSION REPLAYED: the admission checks reproduce offline. The run-to-commission link is server-asserted, " +
		"and nothing about the run's actions is proven.",
	VerdictProofVerified: "ADMISSION REPLAYED, PROOF VERIFIED: the admission checks reproduce offline, and a verified proof covers the recorded " +
		"steps of a run of this exact manifest. The proof is not bound to this receipt's run, and the run-to-commission link is server-asserted.",
}

// Headline returns the display string of a verdict.
//
// Input: the verdict. Output: its headline, or a CONTRADICTED line for an
// unknown value (an unknown verdict is never displayed as a success).
func Headline(v Verdict) string {
	if h, ok := headlines[v]; ok {
		return h
	}
	return fmt.Sprintf("CONTRADICTED: unknown verdict %q.", string(v))
}

// ExitCode maps a verdict to the `commission replay` exit code: 0 for a
// consistent record of a started run, 5 for a consistent record of a
// consumed commission with no run, 3 for incomplete evidence and 4 for a
// contradiction.
func ExitCode(v Verdict) int {
	switch v {
	case VerdictAdmissionReplayed, VerdictProofVerified:
		return 0
	case VerdictNotLaunched:
		return 5
	case VerdictIncomplete:
		return 3
	default:
		return 4
	}
}

// limits are printed with every report, whatever the verdict.
var limits = []string{
	"No result of this command means that the commission was fulfilled. The join between the commission and the run rests on an unsigned receipt (authenticity api_session_only, contract D13 = a).",
	"Tools are a checked declaration: the runtime also exposes builtin and plugin tools. A proof covers recorded calls only, and recording completeness is not proven.",
	"Labels are not evaluated: the manifest has no label vocabulary (DATA-00). The buyer's labels are signed, not enforced.",
	"The ZK fee in spend_total is the server's value; it cannot be recomputed offline.",
	"Signer authorization (the key registered to the buyer's account), revocation and single use are server state; the replay checks only that the receipt names this signer.",
	"Nothing here speaks to output quality, to the harm of an allowed action, or to data the run reached through inputs, tools or network.",
}

// Dimension is the assurance statement for one dimension.
type Dimension struct {
	// Name is the dimension, for example "models".
	Name string `json:"name"`
	// Status is verified, unverified or not_applicable.
	Status Status `json:"status"`
	// Basis lists what supports the statement, in the §14.2 vocabulary.
	Basis []string `json:"basis"`
	// Reason says what is established and what is not.
	Reason string `json:"reason"`
}

// Report is the replay result.
type Report struct {
	// Format is ReportFormat.
	Format string `json:"format"`
	// Verdict is the overall result and Headline its display string.
	Verdict  Verdict `json:"verdict"`
	Headline string  `json:"headline"`
	// HCommission is SHA-256 of the canonical commission bytes, hex, when
	// the commission verified; ReceiptID is the receipt's id, when read.
	HCommission string `json:"h_commission,omitempty"`
	ReceiptID   string `json:"receipt_id,omitempty"`
	// Dimensions are in a fixed order.
	Dimensions []Dimension `json:"dimensions"`
	// Checks are every check, in the order they ran.
	Checks []Check `json:"checks"`
	// Limits are the statements printed with every report.
	Limits []string `json:"limits"`
}

// requiredPrefixes are the check groups whose missing evidence makes the
// verdict incomplete. The proof is optional.
var requiredPrefixes = []string{"commission.", "receipt.", "manifest.", "derivation.", "containment.", "effective."}

// verdict computes the overall verdict from the checks.
func (r *replayer) verdict() Verdict {
	incomplete := false
	for _, c := range r.checks {
		if c.Outcome == CheckFail {
			return VerdictContradicted
		}
		if c.Outcome == CheckMissing {
			for _, p := range requiredPrefixes {
				if strings.HasPrefix(c.ID, p) {
					incomplete = true
				}
			}
		}
	}
	switch {
	case incomplete:
		return VerdictIncomplete
	case !r.runStarted:
		return VerdictNotLaunched
	case r.proofVerified:
		return VerdictProofVerified
	default:
		return VerdictAdmissionReplayed
	}
}

// firstNotPassing returns the first of the checks that did not pass, as
// "id: reason", or "" when all passed. Not-applicable checks count as
// passing here.
func (r *replayer) firstNotPassing(ids ...string) string {
	for _, id := range ids {
		for _, c := range r.checks {
			if c.ID == id && c.Outcome != CheckPass && c.Outcome != CheckNotApplicable {
				prefix := "unverified"
				if c.Outcome == CheckFail {
					prefix = "contradicted"
				}
				return fmt.Sprintf("%s by %s: %s", prefix, c.ID, c.Reason)
			}
		}
		if r.outcome(id) == "" {
			return fmt.Sprintf("unverified: %s did not run", id)
		}
	}
	return ""
}

// The check groups each dimension rests on.
var (
	signatureChecks = []string{"commission.present", "commission.signature", "commission.valid"}
	receiptChecks   = []string{"receipt.present", "receipt.contract", "receipt.authenticity", "receipt.inputs",
		"receipt.run_state", "receipt.h_commission", "receipt.signer", "receipt.pod_ref", "receipt.pod_hash"}
	manifestChecks   = []string{"manifest.present", "manifest.hash", "manifest.version", "manifest.commitment"}
	derivationChecks = []string{"derivation.manifest", "derivation.receipt_derived", "derivation.fields_root",
		"derivation.memory_class", "derivation.fees", "receipt.dimensions"}
)

// dimension builds one dimension: verified with the given basis and reason
// when every listed check passed, otherwise unverified with the first
// check that did not pass as the reason.
func (r *replayer) dimension(name string, basis []string, reason string, checks ...string) Dimension {
	if why := r.firstNotPassing(checks...); why != "" {
		return Dimension{Name: name, Status: StatusUnverified, Reason: why}
	}
	return Dimension{Name: name, Status: StatusVerified, Basis: basis, Reason: reason}
}

// dimensions builds the dimension list in its fixed order.
func (r *replayer) dimensions() []Dimension {
	var dims []Dimension

	sig := r.dimension("signature", []string{"buyer_attested"},
		"the buyer's key signed these canonical bytes, and they form a valid commission", signatureChecks...)
	dims = append(dims, sig)

	// The run binding is never verified: no signature or proof binds
	// h_commission to a run.
	run := Dimension{Name: "run_binding", Status: StatusUnverified, Basis: []string{"server_asserted"}}
	switch why := r.firstNotPassing(concat(signatureChecks, receiptChecks)...); {
	case why != "":
		run.Reason = why
	case !r.runStarted:
		run.Status, run.Basis = StatusNotApplicable, nil
		run.Reason = "the receipt says the commission was consumed and no run was launched"
	default:
		run.Reason = "server-asserted: the receipt names this commission, signer and pod, but it is not signed; " +
			"no signature or proof binds h_commission to the run"
	}
	dims = append(dims, run)

	admission := concat(signatureChecks, receiptChecks, manifestChecks, derivationChecks)
	dims = append(dims, r.dimension("manifest_binding", []string{"admission_checked"},
		"SHA-256(manifest) = signed h_manifest = receipt pod_hash; the pinned fields_root is the trailer, and the declared fields reproduce it",
		concat(signatureChecks, manifestChecks, []string{"receipt.pod_hash"})...))

	proofNote := ""
	proofBasis := []string{}
	if r.proofVerified {
		proofBasis = []string{"circuit_verified"}
		proofNote = " A verified proof shows the recorded steps of a run of this manifest inside the committed set; that run is not bound to this receipt."
	}
	dims = append(dims, r.dimension("models",
		append([]string{"buyer_attested", "admission_checked"}, proofBasis...),
		"the manifest's declared model, derived offline, is inside the commission and equals the receipt's derived model."+proofNote,
		concat(admission, []string{"containment.models"})...))
	dims = append(dims, r.dimension("tools",
		append([]string{"buyer_attested", "admission_checked_declared_only"}, proofBasis...),
		"the manifest's declared tools (S1), derived offline, are inside the commission; no runtime restricts calls to them."+proofNote,
		concat(admission, []string{"containment.tools"})...))
	dims = append(dims, r.dimension("spend",
		append([]string{"buyer_attested", "admission_checked", "server_asserted"}, proofBasis...),
		"the declared compute cap, and the cap plus author fee plus the ZK fee from the receipt (server-asserted), are at most the commission's cap; runtime enforcement is server-asserted."+proofNote,
		concat(admission, []string{"containment.spend", "containment.spend_total"})...))

	dims = append(dims, Dimension{Name: "labels", Status: StatusUnverified, Basis: []string{"buyer_attested", "not_evaluated"},
		Reason: "not evaluated: the manifest has no label vocabulary (DATA-00); the signed labels are not enforced"})

	memoryReason := "the trailer commits the empty memory root (E20), and the manifest declares no initial memory"
	if r.derived != nil && r.derived.class == memoryClassLegacy {
		memoryReason = "the manifest declares no initial memory; the trailer commits the legacy zero root, which is not proof-eligible"
	}
	dims = append(dims, r.dimension("memory", []string{"admission_checked"}, memoryReason, admission...))

	eff := Dimension{Name: "effective_runtime", Status: StatusUnverified, Basis: []string{"server_asserted"}}
	switch why := r.firstNotPassing(concat(admission, []string{"effective.model", "effective.budget"})...); {
	case r.receipt != nil && !r.runStarted:
		eff.Status, eff.Basis = StatusNotApplicable, nil
		eff.Reason = "no run was launched"
	case why != "":
		eff.Reason = why
	default:
		eff.Reason = fmt.Sprintf("server-asserted: the receipt says the runtime used model %s with budget %d sats; these are the declared values, inside the commission",
			r.receipt.Effective.ModelID, r.receipt.Effective.BudgetSats)
	}
	dims = append(dims, eff)

	proof := Dimension{Name: "proof", Status: StatusUnverified}
	switch {
	case r.proofVerified:
		proof.Status, proof.Basis = StatusVerified, []string{"circuit_verified"}
		proof.Reason = "the proof verifies, is Type-C, discloses the pinned manifest, and its genesis fields_root is the trailer; it names no run or commission"
	case r.receipt != nil && !r.runStarted:
		proof.Status = StatusNotApplicable
		proof.Reason = "no run was launched"
	case r.ev.Proof == nil:
		proof.Reason = problem(r.ev.ProofProblem, "no proof bundle was supplied; nothing about the run's actions is proven")
	default:
		proof.Reason = r.firstNotPassing("proof.snark", "proof.disclosure", "proof.manifest", "proof.fields_root", "proof.memory_eligible")
	}
	dims = append(dims, proof)

	dims = append(dims, Dimension{Name: "inputs", Status: StatusUnverified, Basis: []string{"not_buyer_signed"},
		Reason: "the run inputs are not covered by the commission signature (contract §7.4)"})
	return dims
}

// concat concatenates string lists.
func concat(lists ...[]string) []string {
	var out []string
	for _, l := range lists {
		out = append(out, l...)
	}
	return out
}

// report assembles the report.
func (r *replayer) report() *Report {
	v := r.verdict()
	rep := &Report{
		Format:     ReportFormat,
		Verdict:    v,
		Headline:   Headline(v),
		Dimensions: r.dimensions(),
		Checks:     r.checks,
		Limits:     limits,
	}
	if r.commissionOK {
		rep.HCommission = fmt.Sprintf("%x", r.hCommission)
	}
	if r.receipt != nil {
		rep.ReceiptID = r.receipt.ReceiptID
	}
	return rep.terminalSafe()
}

// terminalSafe returns a copy of the report with every string passed
// through api.TerminalSafe. Receipt, manifest and proof values reach the
// reasons, so both renderings print only escaped text. In the JSON report
// the values are therefore the escaped text (for example `\x1b`), not the
// original bytes: the report describes evidence, it does not carry it.
func (rep *Report) terminalSafe() *Report {
	safe := api.TerminalSafe
	out := *rep
	out.Headline = safe(rep.Headline)
	out.HCommission = safe(rep.HCommission)
	out.ReceiptID = safe(rep.ReceiptID)
	out.Dimensions = make([]Dimension, len(rep.Dimensions))
	for i, d := range rep.Dimensions {
		d.Reason = safe(d.Reason)
		basis := make([]string, len(d.Basis))
		for j, b := range d.Basis {
			basis[j] = safe(b)
		}
		d.Basis = basis
		out.Dimensions[i] = d
	}
	out.Checks = make([]Check, len(rep.Checks))
	for i, c := range rep.Checks {
		out.Checks[i] = Check{ID: safe(c.ID), Outcome: c.Outcome, Reason: safe(c.Reason)}
	}
	out.Limits = make([]string, len(rep.Limits))
	for i, l := range rep.Limits {
		out.Limits[i] = safe(l)
	}
	return &out
}

// RenderText prints the report for a person: the headline, one line per
// dimension, the checks that did not pass, and the limits.
//
// Inputs: the writer, the report and whether to list every check.
// Output: none. Every string is escaped with api.TerminalSafe, again, so a
// report built by hand is safe to print too.
func RenderText(w io.Writer, rep *Report, allChecks bool) {
	rep = rep.terminalSafe()
	fmt.Fprintln(w, "Commission replay")
	fmt.Fprintf(w, "verdict:   %s\n", rep.Verdict)
	fmt.Fprintf(w, "           %s\n", rep.Headline)
	if rep.HCommission != "" {
		fmt.Fprintf(w, "commission: %s\n", rep.HCommission)
	}
	if rep.ReceiptID != "" {
		fmt.Fprintf(w, "receipt:    %s\n", rep.ReceiptID)
	}
	fmt.Fprintln(w, "\nDimensions")
	for _, d := range rep.Dimensions {
		basis := "-"
		if len(d.Basis) > 0 {
			basis = strings.Join(d.Basis, ", ")
		}
		fmt.Fprintf(w, "  %-18s %-14s [%s]\n", d.Name, d.Status, basis)
		fmt.Fprintf(w, "  %-18s %s\n", "", d.Reason)
	}
	fmt.Fprintln(w, "\nChecks")
	shown := 0
	for _, c := range rep.Checks {
		if !allChecks && (c.Outcome == CheckPass || c.Outcome == CheckNotApplicable) {
			continue
		}
		shown++
		fmt.Fprintf(w, "  %-15s %-28s %s\n", c.Outcome, c.ID, c.Reason)
	}
	if shown == 0 {
		fmt.Fprintf(w, "  all %d checks passed or do not apply (--all-checks lists them)\n", len(rep.Checks))
	}
	fmt.Fprintln(w, "\nLimits")
	for _, l := range rep.Limits {
		fmt.Fprintf(w, "  - %s\n", l)
	}
}

// RenderJSON writes the report as indented JSON, for scripts.
//
// Inputs: the writer and the report. Output: a write or encode error.
func RenderJSON(w io.Writer, rep *Report) error {
	out, err := json.MarshalIndent(rep.terminalSafe(), "", "  ")
	if err != nil {
		return err
	}
	_, err = w.Write(append(api.TerminalSafeJSON(out), '\n'))
	return err
}
