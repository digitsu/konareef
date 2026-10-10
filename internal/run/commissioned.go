// Copyright 2026 Jerry David Chan, Konareef.ai
// SPDX-License-Identifier: Apache-2.0

// commissioned.go — run a pod under a buyer-signed commission
// (docs/design/commission-admission-contract.md, IB-06).
//
// The flow is:
//
//  1. The caller loads the signed commission.cbor with the verifying loader
//     (signature and ValidateSignable). An unsigned proposal has no path
//     into this file: every entry point takes a commission.Commission.
//  2. CheckLocally compares the commission with the pod's public manifest.
//     It is a convenience only. A local refusal stops before any request;
//     a local check that cannot run is reported and does not stop the
//     submission, because the server checks again.
//  3. SubmitCommissioned posts the exact signed bytes to
//     POST /api/commissioned-runs, and nowhere else. It retries only the
//     SAME request, and only when retrying is safe: after a transport
//     failure (the server answers a repeat with the same run) and after a
//     409 commission_admission_in_progress. It checks the receipt against
//     the commission before it reports admission.
//  4. RunCommissioned then waits for the run and downloads its
//     deliverables, as `pod run` does.
//
// Nothing here ever builds a /api/pods/spawn or /api/agents request. A
// refused, unsupported or failed submission ends the command; the run is
// never retried without the commission (§15).

package run

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/digitsu/konareef/internal/api"
	"github.com/digitsu/konareef/internal/commission"
	"github.com/digitsu/konareef/internal/envelope"
	"github.com/digitsu/konareef/internal/pod"
)

// DefaultSubmitAttempts is how many times SubmitCommissioned sends the
// same request when the earlier attempt failed in a retry-safe way.
const DefaultSubmitAttempts = 4

// DefaultSubmitRetryDelay is the wait before the first retry; each later
// retry waits twice as long as the one before.
const DefaultSubmitRetryDelay = 2 * time.Second

// ErrReceiptMismatch means the server admitted a run whose receipt does not
// describe the submitted commission. The run may be running; the command
// reports this and fails instead of reporting an admission.
var ErrReceiptMismatch = errors.New("the server's receipt does not match the submitted commission")

// ErrLaunchFailed means the server admitted the commission and consumed it,
// but the runtime launch failed (receipt run_state "launch_failed",
// contract §7.3). There is no run to wait for. A new run needs a new
// signed commission.
var ErrLaunchFailed = errors.New("the commission was consumed but its run failed to launch; sign a new commission to try again")

// ErrSubmitCancelled means the caller cancelled the submission. The
// request may already have been admitted; submitting the same commission
// with the same inputs again returns the same run.
var ErrSubmitCancelled = errors.New("commissioned-run submission cancelled")

// CommissionedConfig configures one commissioned run.
type CommissionedConfig struct {
	// BaseURL is the reef-core URL.
	BaseURL string
	// SessionToken authenticates the buyer account.
	SessionToken string
	// Commission is the signed commission, already verified by the caller.
	Commission commission.Commission
	// Inputs are the run's inputs. They are not signed (§7.4).
	Inputs map[string]string
	// OutDir is where deliverables are downloaded.
	OutDir string
	// Timeout and PollInterval control the wait for the run to finish.
	Timeout      time.Duration
	PollInterval time.Duration
	// MaxAttempts and RetryDelay control SubmitCommissioned's retries;
	// zero means DefaultSubmitAttempts and DefaultSubmitRetryDelay.
	MaxAttempts int
	RetryDelay  time.Duration
	// HTTPClient, when set, replaces the API client's HTTP client.
	HTTPClient *http.Client
	// Out receives progress and status lines; nil means io.Discard.
	Out io.Writer
}

// SubmitOutcome is what SubmitCommissioned learned.
type SubmitOutcome struct {
	// Response is the server's spawn fields and receipt.
	Response *api.CommissionedRunResponse
	// Replayed is true when the server answered 200: this account had
	// already started a run with this commission and these inputs.
	Replayed bool
	// HCommission is SHA-256 of the canonical bytes, hex.
	HCommission string
	// RequestDigest is SHA-256(JCS(inputs)), hex: the value the server
	// uses to tell a retry from a changed request.
	RequestDigest string
	// Attempts is how many requests were sent.
	Attempts int
}

// LocalCheckState is the outcome of CheckLocally.
type LocalCheckState string

// The local check outcomes.
const (
	// LocalContained: the manifest is the pinned artifact and its declared
	// envelope is inside the commission.
	LocalContained LocalCheckState = "contained"
	// LocalNotContained: the manifest declares more than the commission
	// permits.
	LocalNotContained LocalCheckState = "not_contained"
	// LocalRefused: the manifest is not the pinned artifact, or the server
	// refuses this kind of pod (sealed grants), or it cannot be derived.
	LocalRefused LocalCheckState = "refused"
	// LocalNotChecked: the manifest could not be fetched.
	LocalNotChecked LocalCheckState = "not_checked"
)

// LocalCheck is the advisory local containment result.
type LocalCheck struct {
	State  LocalCheckState
	Detail string
}

// Blocks reports whether the local result must stop the submission: the
// server would refuse it, so nothing is sent.
func (l LocalCheck) Blocks() bool { return l.State == LocalNotContained || l.State == LocalRefused }

// ManifestFetcher returns the canonical manifest bytes of a published pod.
type ManifestFetcher func(handle, podName, version string) ([]byte, error)

// CheckLocally compares a signed commission with its pod's public manifest.
//
// Inputs: the commission and a fetcher for the manifest its pod_ref names.
// Output: the local result. It applies the same functions `commission
// check` applies (Binding.ValidateAgainstManifest, FromManifest,
// Envelope.Contains) plus the sealed-grants refusal (D16). It is advisory:
// the server derives the envelope itself and is the only enforcement.
func CheckLocally(c commission.Commission, fetch ManifestFetcher) LocalCheck {
	p := c.Proposal()
	handle, podName, version, err := commission.ParsePodRef(p.Binding.PodRef)
	if err != nil {
		return LocalCheck{LocalRefused, err.Error()}
	}
	manifest, err := fetch(handle, podName, version)
	if err != nil {
		return LocalCheck{LocalNotChecked, fmt.Sprintf("could not fetch the manifest: %v", err)}
	}
	if err := p.Binding.ValidateAgainstManifest(manifest); err != nil {
		return LocalCheck{LocalRefused, fmt.Sprintf("the manifest does not match the signed binding: %v", err)}
	}
	spec, err := pod.Parse(manifest)
	if err != nil {
		return LocalCheck{LocalRefused, fmt.Sprintf("parse manifest: %v", err)}
	}
	if pod.HasSealedGrantsMarker(spec) {
		return LocalCheck{LocalRefused, "commission_sealed_grants_unsupported: this closed pod carries sealed grants, and commissions for such pods are not supported (IB-00 D16)"}
	}
	declared, err := commission.FromManifest(manifest, spec)
	if err != nil {
		return LocalCheck{LocalRefused, fmt.Sprintf("derive the manifest envelope: %v", err)}
	}
	if res := p.Envelope.Contains(declared); !res.OK {
		var parts []string
		for _, f := range res.Failures {
			parts = append(parts, fmt.Sprintf("%s: %s", f.Dimension, f.Detail))
		}
		return LocalCheck{LocalNotContained, strings.Join(parts, "; ")}
	}
	return LocalCheck{LocalContained, "models, tools and spend fit; labels are not checked"}
}

// SubmitCommissioned sends the signed commission to
// POST /api/commissioned-runs and returns the admitted run.
//
// Inputs: a context (cancel it to stop; see ErrSubmitCancelled) and the
// config. Output: the outcome, or an error:
//   - an error wrapping commission.ErrWireEncode or ErrInputsNotUTF8: no
//     request was sent;
//   - *api.ServerError: the server refused; Kind is its code, unchanged;
//   - api.ErrCommissionRouteMissing: the server predates the contract;
//   - *api.TransportError: no usable answer after the last attempt;
//   - ErrSubmitCancelled;
//   - ErrReceiptMismatch, with the outcome: a run was admitted, but its
//     receipt does not describe this commission;
//   - ErrLaunchFailed, with the outcome: the commission was consumed and
//     no run exists.
//
// Every attempt sends the same body. Only a transport failure and a 409
// commission_admission_in_progress are retried; the server answers a
// repeat of an admitted request with the same run (§7.3), so a retry can
// never start a second run.
func SubmitCommissioned(ctx context.Context, cfg CommissionedConfig) (*SubmitOutcome, error) {
	if cfg.SessionToken == "" {
		return nil, fmt.Errorf("session token required (pass --token or KONAREEF_TOKEN env)")
	}
	wire, err := commission.EncodeWireV1(cfg.Commission)
	if err != nil {
		return nil, err
	}
	hCommission, err := cfg.Commission.HCommissionHex()
	if err != nil {
		return nil, err
	}
	digest, err := commission.RequestDigest(cfg.Inputs)
	if err != nil {
		return nil, err
	}
	var inputs map[string]string
	if len(cfg.Inputs) > 0 {
		inputs = cfg.Inputs
	}
	req := api.CommissionedRunRequest{
		Contract:      commission.AdmissionContractV1,
		AssuranceMode: commission.AssuranceModeLimitedV1,
		Commission:    base64.StdEncoding.EncodeToString(wire),
		Inputs:        inputs,
	}

	client := api.NewClient(cfg.BaseURL).WithToken(cfg.SessionToken)
	if cfg.HTTPClient != nil {
		client.HTTPClient = cfg.HTTPClient
	}
	attempts := cfg.MaxAttempts
	if attempts <= 0 {
		attempts = DefaultSubmitAttempts
	}
	delay := cfg.RetryDelay
	if delay <= 0 {
		delay = DefaultSubmitRetryDelay
	}
	out := cfg.Out
	if out == nil {
		out = io.Discard
	}

	outcome := &SubmitOutcome{HCommission: hCommission, RequestDigest: hex.EncodeToString(digest[:])}
	for attempt := 1; ; attempt++ {
		outcome.Attempts = attempt
		resp, replayed, err := client.SubmitCommissionedRun(ctx, req)
		if err == nil {
			outcome.Response, outcome.Replayed = resp, replayed
			break
		}
		if ctx.Err() != nil {
			return nil, fmt.Errorf("%w: %w", ErrSubmitCancelled, ctx.Err())
		}
		if attempt >= attempts || !retrySafe(err) {
			return nil, err
		}
		fmt.Fprintf(out, "  attempt %d: %s; sending the same request again in %s\n", attempt, api.TerminalSafe(err.Error()), delay)
		select {
		case <-ctx.Done():
			return nil, fmt.Errorf("%w: %w", ErrSubmitCancelled, ctx.Err())
		case <-time.After(delay):
		}
		delay *= 2
	}

	if err := checkReceipt(cfg.Commission, hCommission, outcome.Response.Receipt); err != nil {
		return outcome, err
	}
	return outcome, nil
}

// retrySafe reports whether a failed submission may be sent again
// unchanged: after a transport failure (the request may or may not have
// arrived), after a concurrent duplicate that is still being admitted, and
// after commission_claim_lost (the server released the claim and asks for
// a retry). Every other answer is final, including a 4xx without a code
// (*api.HTTPRefusal).
//
// Input: the error from Client.SubmitCommissionedRun. Output: true when a
// retry is safe.
func retrySafe(err error) bool {
	var transport *api.TransportError
	if errors.As(err, &transport) {
		return true
	}
	var serverErr *api.ServerError
	return errors.As(err, &serverErr) &&
		(serverErr.Kind == "commission_admission_in_progress" || serverErr.Kind == "commission_claim_lost")
}

// checkReceipt compares a receipt with the commission it should describe.
// It checks the facts the buyer can check without the server: the identity
// of the commission, the contract and mode, the pinned pod and commitment,
// and that the derived and effective values are inside the commission.
// IB-07 (offline replay) checks the full derivation.
//
// Inputs: the commission, its h_commission hex and the receipt. Output:
// nil; ErrLaunchFailed for a consistent receipt whose run did not launch;
// or an error wrapping ErrReceiptMismatch that names the field.
func checkReceipt(c commission.Commission, hCommission string, r *api.CommissionReceipt) error {
	p := c.Proposal()
	mismatch := func(field, got, want string) error {
		return fmt.Errorf("%w: %s is %q, want %q", ErrReceiptMismatch, field, got, want)
	}
	switch {
	case r == nil:
		return fmt.Errorf("%w: no receipt", ErrReceiptMismatch)
	case r.HCommission != hCommission:
		return mismatch("h_commission", r.HCommission, hCommission)
	case r.Contract != commission.AdmissionContractV1:
		return mismatch("contract", r.Contract, commission.AdmissionContractV1)
	case r.AssuranceMode != commission.AssuranceModeLimitedV1:
		return mismatch("assurance_mode", r.AssuranceMode, commission.AssuranceModeLimitedV1)
	case r.PodRef != p.Binding.PodRef:
		return mismatch("pod_ref", r.PodRef, p.Binding.PodRef)
	case r.PodHash != hex.EncodeToString(p.Binding.HManifest[:]):
		return mismatch("pod_hash", r.PodHash, hex.EncodeToString(p.Binding.HManifest[:]))
	case !strings.EqualFold(r.SignerPubkey, c.PubKeyHex):
		return mismatch("signer_pubkey", r.SignerPubkey, c.PubKeyHex)
	}
	switch {
	case r.Authenticity != "api_session_only":
		return mismatch("authenticity", r.Authenticity, "api_session_only")
	case r.Inputs != "not_buyer_signed":
		return mismatch("inputs", r.Inputs, "not_buyer_signed")
	case r.MemoryClass != "rinit_v1" && r.MemoryClass != "legacy_zero":
		return mismatch("memory_class", r.MemoryClass, "rinit_v1 or legacy_zero")
	case r.Dimensions["labels"] != "not_evaluated":
		// The limited mode never evaluates labels (§10); a receipt that
		// claims otherwise overstates what was checked.
		return mismatch("dimensions.labels", r.Dimensions["labels"], "not_evaluated")
	case r.Effective.ModelID == "":
		return fmt.Errorf("%w: the receipt names no effective model", ErrReceiptMismatch)
	}
	if r.Fees.BoundedByCommission {
		total := r.Derived.CMaxSats + r.Fees.AuthorFeeSats
		overflow := total < r.Derived.CMaxSats
		total2 := total + r.Fees.ZKFeeSats
		overflow = overflow || total2 < total
		if overflow || total2 > p.Envelope.CMax {
			return fmt.Errorf("%w: compute cap %d plus fees %d+%d is over the commission cap %d, but the receipt says the fees are bounded",
				ErrReceiptMismatch, r.Derived.CMaxSats, r.Fees.AuthorFeeSats, r.Fees.ZKFeeSats, p.Envelope.CMax)
		}
	}
	if p.Binding.FieldsRoot != nil && r.FieldsRoot != hex.EncodeToString(p.Binding.FieldsRoot[:]) {
		return mismatch("fields_root", r.FieldsRoot, hex.EncodeToString(p.Binding.FieldsRoot[:]))
	}
	permitted := envelope.Normalise(p.Envelope.Models)
	if !slices.Contains(permitted, r.Effective.ModelID) {
		return fmt.Errorf("%w: effective model %q is not in the commission", ErrReceiptMismatch, r.Effective.ModelID)
	}
	for _, m := range r.Derived.Models {
		if !slices.Contains(permitted, m) {
			return fmt.Errorf("%w: derived model %q is not in the commission", ErrReceiptMismatch, m)
		}
	}
	tools := envelope.Normalise(p.Envelope.Tools)
	for _, tool := range r.Derived.Tools {
		if !slices.Contains(tools, tool) {
			return fmt.Errorf("%w: derived tool %q is not in the commission", ErrReceiptMismatch, tool)
		}
	}
	if r.Derived.CMaxSats > p.Envelope.CMax || r.Effective.BudgetSats > p.Envelope.CMax {
		return fmt.Errorf("%w: derived cap %d or effective budget %d is over the commission cap %d",
			ErrReceiptMismatch, r.Derived.CMaxSats, r.Effective.BudgetSats, p.Envelope.CMax)
	}
	switch r.RunState {
	case "started":
		return nil
	case "launch_failed":
		return ErrLaunchFailed
	default:
		return mismatch("run_state", r.RunState, "started")
	}
}

// RunCommissioned submits the commission, prints the admission status, and
// then waits for the run and downloads its deliverables.
//
// Inputs: a context, the config, and the local check result (printed in
// the status; the caller has already stopped on a blocking one). Output:
// the submit outcome (nil when nothing was admitted) and an error. After
// admission, a failure while waiting or downloading is returned with the
// outcome, so the caller can still name the admitted run.
func RunCommissioned(ctx context.Context, cfg CommissionedConfig, local LocalCheck) (*SubmitOutcome, error) {
	out := cfg.Out
	if out == nil {
		out = io.Discard
	}
	status := CommissionStatus{PubKeyHex: cfg.Commission.PubKeyHex, Local: local}
	outcome, err := SubmitCommissioned(ctx, cfg)
	status.Outcome = outcome
	status.SubmitErr = err
	if err != nil {
		RenderCommissionStatus(out, status)
		return outcome, err
	}

	status.Executed = fmt.Sprintf("started: agent_id=%s pod_id=%s", outcome.Response.AgentID, outcome.Response.PodID)
	RenderCommissionStatus(out, status)

	client := api.NewClient(cfg.BaseURL).WithToken(cfg.SessionToken)
	if cfg.HTTPClient != nil {
		client.HTTPClient = cfg.HTTPClient
	}
	collectCfg := Config{BaseURL: cfg.BaseURL, OutDir: cfg.OutDir, Timeout: cfg.Timeout, PollInterval: cfg.PollInterval}
	if err := collectRun(ctx, client, outcome.Response.AgentID, collectCfg); err != nil {
		return outcome, fmt.Errorf("the commissioned run was admitted (receipt %s), but: %w", outcome.Response.Receipt.ReceiptID, err)
	}
	fmt.Fprintln(out, "executed:          finished; the custody proof is listed above")
	fmt.Fprintln(out, "proof verified:    no — this command does not verify the proof; run `konareef verify` on the bundle")
	return outcome, nil
}

// CommissionStatus is what RenderCommissionStatus prints: five separate
// facts that must not be read as one (IB-06 step 4).
type CommissionStatus struct {
	// PubKeyHex is the signer key, whose signature was verified locally.
	PubKeyHex string
	// Local is the advisory local containment result.
	Local LocalCheck
	// Outcome and SubmitErr are the server's answer.
	Outcome   *SubmitOutcome
	SubmitErr error
	// Executed describes the run, when one started.
	Executed string
}

// RenderCommissionStatus prints the status of a commissioned run as five
// separate lines: signature valid, locally contained, server admitted,
// executed, proof verified. A passing local check is never shown as
// server enforcement, and a receipt is never shown as a proof. Every
// string that came from the server or a manifest is escaped with
// api.TerminalSafe, so it cannot move the cursor or recolour the terminal.
//
// Inputs: the writer and the status. Output: none.
func RenderCommissionStatus(w io.Writer, s CommissionStatus) {
	safe := api.TerminalSafe
	fmt.Fprintln(w, "Commissioned run status")
	fmt.Fprintf(w, "signature valid:   yes, checked locally (signer %s)\n", safe(s.PubKeyHex))
	fmt.Fprintf(w, "locally contained: %s — %s (advisory; the server checks again)\n", s.Local.State, safe(s.Local.Detail))
	hasResponse := s.Outcome != nil && s.Outcome.Response != nil
	switch {
	case s.SubmitErr != nil && hasResponse && errors.Is(s.SubmitErr, ErrLaunchFailed):
		fmt.Fprintf(w, "server admitted:   yes, but the commission is consumed and its run failed to launch (receipt_id=%s)\n", safe(receiptID(s.Outcome.Response)))
	case s.SubmitErr != nil && hasResponse:
		fmt.Fprintf(w, "server admitted:   UNTRUSTED — %s\n", safe(s.SubmitErr.Error()))
		fmt.Fprintf(w, "                   agent_id=%s receipt_id=%s\n", safe(s.Outcome.Response.AgentID), safe(receiptID(s.Outcome.Response)))
	case s.SubmitErr != nil:
		fmt.Fprintf(w, "server admitted:   no — %s\n", safe(s.SubmitErr.Error()))
	default:
		o := s.Outcome
		r := o.Response.Receipt
		how := "yes, new run"
		if o.Replayed {
			how = "yes, an earlier run of this same request (replay; no second run)"
		}
		fmt.Fprintf(w, "server admitted:   %s\n", how)
		fmt.Fprintf(w, "  receipt_id:      %s (authenticity: %s)\n", safe(r.ReceiptID), safe(r.Authenticity))
		fmt.Fprintf(w, "  h_commission:    %s\n", o.HCommission)
		fmt.Fprintf(w, "  request_digest:  %s (inputs: %s)\n", o.RequestDigest, safe(r.Inputs))
		fmt.Fprintf(w, "  pod:             %s pod_hash=%s\n", safe(r.PodRef), safe(r.PodHash))
		fmt.Fprintf(w, "  memory_class:    %s\n", safe(r.MemoryClass))
		fmt.Fprintf(w, "  derived:         models=%q tools=%q c_max_sats=%d\n", r.Derived.Models, r.Derived.Tools, r.Derived.CMaxSats)
		fmt.Fprintf(w, "  effective:       model=%s budget_sats=%d\n", safe(r.Effective.ModelID), r.Effective.BudgetSats)
		fmt.Fprintf(w, "  fees:            author=%d zk=%d bounded_by_commission=%t\n", r.Fees.AuthorFeeSats, r.Fees.ZKFeeSats, r.Fees.BoundedByCommission)
		for _, dim := range sortedKeys(r.Dimensions) {
			fmt.Fprintf(w, "  %-16s %s\n", safe(dim)+":", safe(r.Dimensions[dim]))
		}
	}
	if s.Executed != "" {
		fmt.Fprintf(w, "executed:          %s\n", safe(s.Executed))
	} else {
		fmt.Fprintln(w, "executed:          no")
	}
	fmt.Fprintln(w, "proof verified:    no")
}

// receiptID returns the receipt id of a response, or "(none)".
func receiptID(r *api.CommissionedRunResponse) string {
	if r == nil || r.Receipt == nil {
		return "(none)"
	}
	return r.Receipt.ReceiptID
}

// sortedKeys returns the keys of m in order, for stable output.
func sortedKeys(m map[string]string) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	return keys
}
