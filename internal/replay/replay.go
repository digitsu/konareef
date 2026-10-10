// Copyright 2026 Jerry David Chan, Konareef.ai
// SPDX-License-Identifier: Apache-2.0

// Package replay checks the evidence of one commissioned run offline and
// reports, dimension by dimension, what that evidence proves
// (docs/design/commission-admission-contract.md §14.4, IB-07).
//
// The inputs are the buyer's own signed commission, the admission receipt
// reef-core returned (POST /api/commissioned-runs or
// GET /api/commissioned-runs/:receipt_id), the public manifest bytes, and
// optionally a konareef-bundle/v2 proof. Replay repeats the admission
// checks locally:
//
//  1. the commission signature and ValidateSignable;
//  2. the receipt names this commission, signer, pod_ref and pod_hash;
//  3. SHA-256(manifest) == h_manifest == receipt pod_hash, and the pinned
//     fields_root equals the trailer that the manifest's own declared
//     fields reproduce;
//  4. the §9 derivation (models, S1 tools, c_max, author fee) and the
//     memory classification give the receipt's derived, fields_root and
//     memory_class values;
//  5. containment, including spend_total (owner decision D17 = b);
//  6. the receipt's effective values are inside the commission;
//  7. with a proof: the proof verifies, is Type-C, is over these manifest
//     bytes, and its genesis fields_root equals the trailer.
//
// Every check has an outcome (pass, fail, missing, not_applicable) and a
// reason. Dimensions are derived from the checks and say verified,
// unverified or not_applicable, with the basis (the §14.2 vocabulary) and
// the reason. A failed check makes the verdict "contradicted"; missing
// required evidence makes it "incomplete". Nothing here panics on bad
// input, and nothing upgrades a server assertion into a proof: the join
// "this run was admitted under this commission" rests on an unsigned
// receipt and is always reported as server-asserted (§21 D13 = a).
//
// The report never contains the commission prose.
package replay

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"slices"
	"strings"

	"github.com/BurntSushi/toml"
	"golang.org/x/text/unicode/norm"

	"github.com/digitsu/konareef/internal/api"
	"github.com/digitsu/konareef/internal/canon"
	"github.com/digitsu/konareef/internal/commission"
	"github.com/digitsu/konareef/internal/envelope"
	"github.com/digitsu/konareef/internal/identity"
	"github.com/digitsu/konareef/internal/pod"
	"github.com/digitsu/konareef/internal/verify"
)

// ReportFormat identifies the machine-readable report shape.
const ReportFormat = "konareef-commission-replay/v1"

// The receipt constants of the limited mode (contract §14.1, reef-core
// Claims.receipt/1 and Verifier admission/8).
const (
	receiptAuthenticity = "api_session_only"
	receiptInputs       = "not_buyer_signed"
	memoryClassRInitV1  = "rinit_v1"
	memoryClassLegacy   = "legacy_zero"
	memoryClaimRInitV1  = "declares_no_initial_memory_and_commits_empty_root"
	memoryClaimLegacy   = "declares_no_initial_memory_legacy_zero_root_not_proof_eligible"
	runStateStarted     = "started"
	runStateLaunchFail  = "launch_failed"
	maxCommittedTools   = 32
	toolWildcardChars   = "*?[]{}"
)

// canonicalTrailer is the exact [_commit] trailer the canonicalizer emits
// and reef-core P1e accepts (ManifestDerivation.trailer_fields_root/1): no
// extra whitespace, no r_init_scheme key, one final LF. canon's own trailer
// parser is more lenient, so the replay applies the server's form.
var canonicalTrailer = regexp.MustCompile(`\n\[_commit\]\nfields_root = "poseidon:[0-9a-f]{64}"\n\z`)

// receiptKey is the key form every reef-core receipt and response uses.
var receiptKey = regexp.MustCompile(`^[a-z0-9_]+$`)

// CheckOutcome is the result of one check.
type CheckOutcome string

// The check outcomes.
const (
	// CheckPass: the check ran and the evidence agrees.
	CheckPass CheckOutcome = "pass"
	// CheckFail: the check ran and the evidence disagrees (tampered,
	// swapped or mismatched evidence). Any failure makes the verdict
	// "contradicted".
	CheckFail CheckOutcome = "fail"
	// CheckMissing: the check could not run, because evidence is missing,
	// unreadable, or depends on a failed check.
	CheckMissing CheckOutcome = "missing"
	// CheckNotApplicable: the check does not apply to this evidence.
	CheckNotApplicable CheckOutcome = "not_applicable"
)

// Check is one named check and its outcome.
type Check struct {
	// ID is stable, for scripts and tests, for example "receipt.pod_hash".
	ID string `json:"id"`
	// Outcome is pass, fail, missing or not_applicable.
	Outcome CheckOutcome `json:"outcome"`
	// Reason says what was compared, or why the check did not run.
	Reason string `json:"reason"`
}

// ProofCheck is what a ProofVerifier learned about a proof bundle.
type ProofCheck struct {
	// Bundle is the decoded bundle, or nil when it did not decode.
	Bundle *BundleFacts
	// DecodeErr is set when the bytes are not a konareef-bundle/v2.
	DecodeErr error
	// OK is true only when every verifier check passed, the SNARK included.
	OK bool
	// VerifierMissing is true when the only failure is that no SNARK
	// verifier is configured: the proof may be genuine but was not checked.
	VerifierMissing bool
	// Divergences are the verifier's failure messages.
	Divergences []string
}

// BundleFacts are the fields of a decoded bundle that the replay compares.
type BundleFacts struct {
	// Disclosure is "C" or "D".
	Disclosure string
	// Manifest is the manifest bytes the bundle discloses.
	Manifest []byte
	// GenesisFieldsRoot is the carried z0[Z_FIELDS_ROOT] lane.
	GenesisFieldsRoot []byte
}

// ProofVerifier verifies a proof bundle. ProductionProofVerifier is the
// real one; tests inject others.
type ProofVerifier func(bundle []byte) ProofCheck

// Evidence is the input of Replay. A nil field is missing evidence, and
// its Problem string (optional) says why, for example a file read error.
type Evidence struct {
	// Commission is the buyer's commission, decoded but NOT yet verified.
	// Replay verifies it; a caller must not pre-filter it.
	Commission        *commission.Commission
	CommissionProblem string
	// Receipt is the raw JSON of the receipt, or of the 201/200 response
	// that carries it under "receipt".
	Receipt        []byte
	ReceiptProblem string
	// Manifest is the canonical manifest bytes (the h_manifest preimage).
	Manifest        []byte
	ManifestProblem string
	// Proof is the konareef-bundle/v2 CBOR bytes. It is optional: a closed
	// pod produces no proof.
	Proof        []byte
	ProofProblem string
	// VerifyProof verifies Proof; nil means ProductionProofVerifier.
	VerifyProof ProofVerifier
}

// derivation is the §9 envelope the replay derives from the manifest.
type derivation struct {
	models    []string
	tools     []string
	cMax      uint64
	authorFee uint64
	trailer   canon.CommitTrailer
	class     string
}

// replayer carries the state of one Replay call.
type replayer struct {
	ev     Evidence
	checks []Check

	commissionOK bool
	proposal     commission.Proposal
	hCommission  [32]byte
	pubKeyHex    string

	receipt *api.CommissionReceipt

	manifestOK bool
	derived    *derivation

	runStarted    bool
	proofVerified bool
}

// Replay checks the evidence and returns the report. It never panics on
// malformed evidence and never returns nil.
//
// Input: the evidence. Output: the report, with every check, every
// dimension and the verdict.
func Replay(ev Evidence) (report *Report) {
	r := &replayer{ev: ev}
	defer func() {
		// A decoder or library panic on hostile bytes must degrade the
		// verdict, not crash the command.
		if p := recover(); p != nil {
			r.add("replay.internal", CheckFail, "the replay stopped on malformed evidence: %v", p)
			report = r.report()
		}
	}()
	r.checkCommission()
	r.checkReceipt()
	r.checkManifest()
	r.checkDerivation()
	r.checkContainment()
	r.checkEffective()
	r.checkProof()
	return r.report()
}

// add records one check.
func (r *replayer) add(id string, outcome CheckOutcome, format string, args ...any) {
	r.checks = append(r.checks, Check{ID: id, Outcome: outcome, Reason: fmt.Sprintf(format, args...)})
}

// passFail records a pass when ok, else a fail with the given reason.
func (r *replayer) passFail(id string, ok bool, pass string, fail string, args ...any) bool {
	if ok {
		r.add(id, CheckPass, "%s", pass)
	} else {
		r.add(id, CheckFail, fail, args...)
	}
	return ok
}

// missing records each id as missing with the same reason.
func (r *replayer) missing(reason string, ids ...string) {
	for _, id := range ids {
		r.add(id, CheckMissing, "%s", reason)
	}
}

// problem returns the evidence problem text, or a default.
func problem(p, fallback string) string {
	if p != "" {
		return p
	}
	return fallback
}

// ── commission ──────────────────────────────────────────────────────

// checkCommission verifies the signature and the semantic validity of the
// buyer's commission (§14.4 items 1–2).
func (r *replayer) checkCommission() {
	if r.ev.Commission == nil {
		r.missing(problem(r.ev.CommissionProblem, "no commission artifact was supplied"),
			"commission.present", "commission.signature", "commission.valid")
		return
	}
	c := *r.ev.Commission
	r.add("commission.present", CheckPass, "the commission artifact decoded")
	if err := c.Verify(); err != nil {
		r.add("commission.signature", CheckFail, "the signature does not verify over the canonical bytes: %v", err)
		r.add("commission.valid", CheckMissing, "not checked: the signature did not verify")
		return
	}
	// Verify applies the strict DER gate only while
	// identity.StrictDerGateEnabled is set; the server applies it always
	// (Q4), so the replay does too, with the 33-byte compressed key rule.
	if pub, err := hex.DecodeString(c.PubKeyHex); err != nil || len(pub) != 33 || (pub[0] != 0x02 && pub[0] != 0x03) {
		r.add("commission.signature", CheckFail, "the public key is not a 33-byte compressed secp256k1 key, which the server refuses")
		r.add("commission.valid", CheckMissing, "not checked: the signature did not pass")
		return
	}
	if _, _, err := identity.ParseStrict(c.Sig); err != nil {
		r.add("commission.signature", CheckFail, "the signature is not strict low-S DER, which the server refuses: %v", err)
		r.add("commission.valid", CheckMissing, "not checked: the signature did not pass")
		return
	}
	r.add("commission.signature", CheckPass, "signer %s attested SHA-256 of the canonical bytes (strict low-S DER)", c.PubKeyHex)
	if err := commission.ValidateSignable(c.Proposal()); err != nil {
		r.add("commission.valid", CheckFail, "the signed artifact is not a commission the server admits: %v", err)
		return
	}
	h, err := c.Proposal().HCommission()
	if err != nil {
		r.add("commission.valid", CheckFail, "h_commission cannot be computed: %v", err)
		return
	}
	r.add("commission.valid", CheckPass, "every dimension is stated, the binding pins %s, and the artifact is within the admission limits", c.Proposal().Binding.PodRef)
	r.commissionOK = true
	r.proposal = c.Proposal()
	r.hCommission = h
	r.pubKeyHex = c.PubKeyHex
}

// ── receipt ─────────────────────────────────────────────────────────

// errReceiptAmbiguous means the receipt JSON can be read two ways.
var errReceiptAmbiguous = errors.New("the receipt JSON is ambiguous")

// errReceiptMalformed means the receipt names a commission or receipt id
// but its fields do not have the server's types.
var errReceiptMalformed = errors.New("the receipt is malformed")

// checkReceiptKeys walks the JSON and refuses a duplicate key in any
// object, and any key that is not lowercase ASCII. encoding/json matches
// keys case-insensitively (with Unicode folding) and keeps the last
// duplicate, so without this check `"run_state":"launch_failed",
// "RUN_STATE":"started"` would be read differently here and by another
// reader. reef-core writes only lowercase ASCII keys, once each.
//
// Input: the JSON text. Output: nil, or an error wrapping
// errReceiptAmbiguous.
func checkReceiptKeys(raw []byte) error {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	type frame struct {
		object bool
		keys   map[string]bool
		expect bool // the next token in this object is a key
	}
	var stack []*frame
	for {
		tok, err := dec.Token()
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return nil // syntax errors are reported by the typed decode
		}
		var top *frame
		if len(stack) > 0 {
			top = stack[len(stack)-1]
		}
		if key, isKey := tok.(string); isKey && top != nil && top.object && top.expect {
			if !receiptKey.MatchString(key) {
				return fmt.Errorf("%w: key %q is not lowercase ASCII", errReceiptAmbiguous, key)
			}
			if top.keys[key] {
				return fmt.Errorf("%w: key %q appears twice in one object", errReceiptAmbiguous, key)
			}
			top.keys[key] = true
			top.expect = false
			continue
		}
		switch tok {
		case json.Delim('{'):
			stack = append(stack, &frame{object: true, keys: map[string]bool{}, expect: true})
			continue
		case json.Delim('['):
			stack = append(stack, &frame{})
			continue
		case json.Delim('}'), json.Delim(']'):
			stack = stack[:len(stack)-1]
		}
		// A value ended: the enclosing object expects a key next.
		if len(stack) > 0 && stack[len(stack)-1].object {
			stack[len(stack)-1].expect = true
		}
	}
}

// decodeReceipt reads a bare receipt or a response that carries one
// under "receipt".
//
// Output: the receipt, or an error. An error wrapping errReceiptAmbiguous
// or errReceiptMalformed means the evidence is tampered or malformed (a
// failed check); any other error means there is no readable receipt.
func decodeReceipt(raw []byte) (*api.CommissionReceipt, error) {
	var probe map[string]json.RawMessage
	if err := json.Unmarshal(raw, &probe); err != nil {
		return nil, fmt.Errorf("not a JSON object: %w", err)
	}
	if err := checkReceiptKeys(raw); err != nil {
		return nil, err
	}
	if inner, ok := probe["receipt"]; ok {
		raw = inner
		probe = nil
		if err := json.Unmarshal(raw, &probe); err != nil {
			return nil, fmt.Errorf("the receipt is not a JSON object: %w", err)
		}
	}
	_, hasID := probe["receipt_id"]
	_, hasH := probe["h_commission"]
	var rec api.CommissionReceipt
	if err := json.Unmarshal(raw, &rec); err != nil {
		if hasID || hasH {
			return nil, fmt.Errorf("%w: %v", errReceiptMalformed, err)
		}
		return nil, fmt.Errorf("not a receipt: %w", err)
	}
	if rec.HCommission == "" && rec.ReceiptID == "" {
		return nil, errors.New("the object has neither receipt_id nor h_commission")
	}
	return &rec, nil
}

// hexEqual reports whether hex text s encodes exactly want. Case is
// ignored; anything that is not hex is unequal.
func hexEqual(s string, want []byte) bool {
	got, err := hex.DecodeString(s)
	return err == nil && bytes.Equal(got, want)
}

// checkReceipt compares the receipt with the commission and with the
// constants of the limited mode.
func (r *replayer) checkReceipt() {
	ids := []string{"receipt.present", "receipt.contract", "receipt.authenticity", "receipt.inputs",
		"receipt.run_state", "receipt.h_commission", "receipt.signer", "receipt.pod_ref", "receipt.pod_hash"}
	if r.ev.Receipt == nil {
		r.missing(problem(r.ev.ReceiptProblem, "no receipt was supplied"), ids...)
		return
	}
	rec, err := decodeReceipt(r.ev.Receipt)
	if errors.Is(err, errReceiptAmbiguous) || errors.Is(err, errReceiptMalformed) {
		r.add("receipt.present", CheckFail, "%v; reef-core never writes such a receipt", err)
		r.missing("not checked: the receipt is not usable", ids[1:]...)
		return
	}
	if err != nil {
		r.add("receipt.present", CheckMissing, "the receipt is unreadable: %v", err)
		r.missing("not checked: the receipt is unreadable", ids[1:]...)
		return
	}
	r.receipt = rec
	r.add("receipt.present", CheckPass, "receipt %q decoded", rec.ReceiptID)

	r.passFail("receipt.contract",
		rec.Contract == commission.AdmissionContractV1 && rec.AssuranceMode == commission.AssuranceModeLimitedV1,
		"contract "+commission.AdmissionContractV1+", mode "+commission.AssuranceModeLimitedV1,
		"the receipt names contract %q and mode %q; this verifier replays only %s under %s",
		rec.Contract, rec.AssuranceMode, commission.AdmissionContractV1, commission.AssuranceModeLimitedV1)

	// An authenticity mode this verifier cannot check is refused, never
	// read as stronger evidence than an API session.
	r.passFail("receipt.authenticity", rec.Authenticity == receiptAuthenticity,
		"the receipt says it is authenticated only by the API session that delivered it; it is not signed",
		"the receipt claims authenticity %q, which this verifier cannot check; only %q is defined",
		rec.Authenticity, receiptAuthenticity)

	r.passFail("receipt.inputs", rec.Inputs == receiptInputs,
		"the receipt says the run inputs are not buyer-signed",
		"the receipt says inputs are %q; the limited mode never signs inputs (%q)", rec.Inputs, receiptInputs)

	switch rec.RunState {
	case runStateStarted:
		r.runStarted = true
		r.add("receipt.run_state", CheckPass, "the receipt says the run started")
	case runStateLaunchFail:
		r.add("receipt.run_state", CheckPass, "the receipt says the commission was consumed and the run failed to launch")
	case "claimed", "released":
		// reef-core Claims.receipt/1 reports the claim state for a claim
		// that never started: in progress, or released after a failure
		// before launch. Such a receipt admits no run.
		r.add("receipt.run_state", CheckMissing, "run_state %q: the claim did not start a run, so there is no admitted run to replay", rec.RunState)
	default:
		r.add("receipt.run_state", CheckFail, "run_state %q is not a state of an admitted commission (started or launch_failed)", rec.RunState)
	}

	if !r.commissionOK {
		r.missing("not checked: the commission did not verify", ids[5:]...)
		return
	}
	r.passFail("receipt.h_commission", hexEqual(rec.HCommission, r.hCommission[:]),
		"the receipt names this commission ("+hex.EncodeToString(r.hCommission[:])+")",
		"the receipt names commission %q, but this artifact is %x: the receipt is for another commission",
		rec.HCommission, r.hCommission)
	wantKey, _ := hex.DecodeString(r.pubKeyHex)
	r.passFail("receipt.signer", len(wantKey) > 0 && hexEqual(rec.SignerPubkey, wantKey),
		"the receipt names the commission's signer",
		"the receipt names signer %q, but the commission is signed by %s", rec.SignerPubkey, r.pubKeyHex)
	r.passFail("receipt.pod_ref", rec.PodRef == r.proposal.Binding.PodRef,
		"the receipt names the signed pod_ref",
		"the receipt names pod %q, but the commission binds %q", rec.PodRef, r.proposal.Binding.PodRef)
	r.passFail("receipt.pod_hash", hexEqual(rec.PodHash, r.proposal.Binding.HManifest[:]),
		"the receipt's pod_hash equals the signed h_manifest",
		"the receipt names pod_hash %q, but the commission pins %x", rec.PodHash, r.proposal.Binding.HManifest)
}

// ── manifest ────────────────────────────────────────────────────────

// checkManifest binds the manifest bytes to the signed commission
// (§14.4 item 3).
func (r *replayer) checkManifest() {
	ids := []string{"manifest.present", "manifest.hash", "manifest.version", "manifest.commitment"}
	m := r.ev.Manifest
	if m == nil {
		r.missing(problem(r.ev.ManifestProblem, "no manifest was supplied"), ids...)
		return
	}
	r.add("manifest.present", CheckPass, "%d manifest bytes supplied", len(m))
	if !r.commissionOK {
		r.missing("not checked: the commission did not verify, so there is no trusted h_manifest", ids[1:]...)
		return
	}
	sum := sha256.Sum256(m)
	if !r.passFail("manifest.hash", sum == r.proposal.Binding.HManifest,
		"SHA-256(manifest) equals the signed h_manifest",
		"SHA-256(manifest) is %x, but the commission pins %x: this is not the pinned manifest",
		sum, r.proposal.Binding.HManifest) {
		r.missing("not checked: the manifest is not the pinned artifact", ids[2:]...)
		return
	}
	version, _ := canon.VersionIdentifier(m)
	if !r.passFail("manifest.version", canon.CheckMagicLine(m) == nil && bytes.HasPrefix(m, []byte("#!konareef-toml/v2\n")),
		"konareef-toml/v2, the only version the contract admits (D7)",
		"the manifest version is %q; admission accepts konareef-toml/v2 only (D7), so a receipt for it contradicts the contract", version) {
		r.missing("not checked: unsupported manifest version", "manifest.commitment")
		return
	}
	if err := r.proposal.Binding.ValidateAgainstManifest(m); err != nil {
		r.add("manifest.commitment", CheckFail, "the pinned fields_root and the manifest trailer do not bind: %v", err)
		return
	}
	r.add("manifest.commitment", CheckPass, "the pinned fields_root equals the trailer, and the manifest's declared fields reproduce it")
	r.manifestOK = true
}

// ── derivation ──────────────────────────────────────────────────────

// deriveEnvelope applies the §9 derivation to a v2 manifest the way
// reef-core ManifestDerivation.derive/1 does. Output: the derivation, or
// the reason the server's admission rules refuse the manifest.
func deriveEnvelope(manifest []byte) (*derivation, error) {
	if !bytes.HasPrefix(manifest, []byte("#!konareef-toml/v2\n")) || !canonicalTrailer.Match(manifest) {
		return nil, errors.New("commission_manifest_commitment_unreadable: the [_commit] trailer is not the exact canonical form (P1e)")
	}
	if bytes.IndexByte(manifest, '\r') >= 0 {
		return nil, errors.New("commission_manifest_invalid: the manifest contains a CR byte")
	}
	spec, meta, err := pod.ParseWithMeta(manifest)
	if err != nil {
		return nil, fmt.Errorf("commission_manifest_invalid: parse: %w", err)
	}
	// The sealed-grants marker is read before the schema, as the server
	// does: neither schema knows it yet.
	if pod.HasSealedGrantsMarker(*spec) {
		return nil, errors.New("commission_sealed_grants_unsupported: the manifest carries the sealed-grants marker (D16)")
	}
	head, err := authoredTree(manifest)
	if err != nil {
		return nil, fmt.Errorf("commission_manifest_invalid: %w", err)
	}
	if issues, err := pod.Validate(head); err != nil || len(issues) > 0 {
		return nil, fmt.Errorf("commission_manifest_invalid: the manifest fails the pod schema: %v%v", err, issues)
	}
	if spec.Context != nil && len(spec.Context.Memory) > 0 {
		return nil, errors.New("commission_memory_unsupported: the manifest declares [[context.memory]]")
	}
	if spec.Model == nil {
		return nil, errors.New("commission_model_undeclared: the manifest has no [model]")
	}
	modelID, err := canon.ModelID(spec.Model.Provider, spec.Model.Name)
	if err != nil {
		return nil, fmt.Errorf("commission_manifest_invalid: [model]: %w", err)
	}
	// reef-core ModelSelection.qualified_id/2 refuses a provider that
	// contains "/" (model_provider_ambiguous); canon.ModelID allows it.
	if strings.Contains(spec.Model.Provider, "/") {
		return nil, errors.New("commission_manifest_invalid: [model].provider contains \"/\"")
	}
	if !meta.IsDefined("budget", "max_sats") {
		return nil, errors.New("commission_budget_undeclared: the manifest has no [budget].max_sats")
	}
	if spec.Budget == nil || spec.Budget.MaxSats < 0 {
		return nil, errors.New("commission_manifest_invalid: [budget].max_sats is negative")
	}
	var s1 []string
	if spec.Context != nil {
		for _, t := range spec.Context.Tools {
			s1 = append(s1, t.Source)
		}
	}
	if err := toolPolicy(s1, spec, meta.IsDefined("directive", "tools_allowed")); err != nil {
		return nil, err
	}
	sorted := slices.Clone(s1)
	slices.Sort(sorted)
	if len(sorted) > maxCommittedTools || len(slices.Compact(slices.Clone(sorted))) != len(sorted) {
		return nil, fmt.Errorf("commission_manifest_invalid: %d declared tools, or a duplicate; the tools tree holds at most %d distinct names", len(s1), maxCommittedTools)
	}
	// FromManifest applies the shipped D3/D5 rules and the committed-tools
	// set, so the replay and `commission check` refuse the same manifests.
	declared, err := commission.FromManifest(manifest, *spec)
	if err != nil {
		return nil, fmt.Errorf("commission_tool_policy_invalid: %w", err)
	}
	trailer, err := canon.ParseCommitTrailer(manifest)
	if err != nil {
		return nil, fmt.Errorf("commission_manifest_invalid: [_commit]: %w", err)
	}
	d := &derivation{
		models:  []string{modelID},
		tools:   envelope.Normalise(declared.Tools),
		cMax:    uint64(spec.Budget.MaxSats),
		trailer: trailer,
	}
	if m := spec.Marketplace; m != nil && m.PriceModel == "per_run" && m.PriceSats > 0 {
		d.authorFee = uint64(m.PriceSats)
	}
	class, err := canon.ClassifyMemoryRoot(trailer, d.models, d.tools, d.cMax)
	if err != nil {
		return nil, fmt.Errorf("commission_manifest_invalid: recompute fields_root: %w", err)
	}
	switch class {
	case canon.MemoryFreeRInitV1:
		d.class = memoryClassRInitV1
	case canon.MemoryFreeLegacyZero:
		d.class = memoryClassLegacy
	default:
		return nil, fmt.Errorf("commission_fields_root_unrecognized: the trailer matches neither memory-free convention (%s)", class)
	}
	return d, nil
}

// authoredTree returns the whole decoded manifest without its synthesized
// tables ([_files] and [_commit]), re-encoded as TOML for pod.Validate. The
// server validates the decoded tree the same way
// (SchemaCheck.strip_synthesized/2), so a table placed anywhere, including
// after [_files], is validated. A text cut would miss such a table.
//
// Input: the manifest bytes. Output: TOML bytes, or a decode error.
func authoredTree(manifest []byte) ([]byte, error) {
	var tree map[string]any
	if _, err := toml.Decode(string(manifest), &tree); err != nil {
		return nil, fmt.Errorf("decode: %w", err)
	}
	delete(tree, "_files")
	delete(tree, "_commit")
	var out bytes.Buffer
	if err := toml.NewEncoder(&out).Encode(tree); err != nil {
		return nil, fmt.Errorf("re-encode for the schema: %w", err)
	}
	return out.Bytes(), nil
}

// toolPolicy applies the accepted TA-00 rules in reef-core's order
// (contract §9.3): non-empty NFC names, no wildcard characters in S3/S4,
// S3 inside S1 (D3), no present-and-empty tools_allowed beside a
// non-empty S1 (D4, D18 = a), and no name in both S3 and S4 (D5).
func toolPolicy(s1 []string, spec *pod.Spec, s3Present bool) error {
	var s3, s4 []string
	if spec.Directive != nil {
		s3, s4 = spec.Directive.ToolsAllowed, spec.Directive.ToolsDenied
	}
	for _, name := range slices.Concat(s1, s3, s4) {
		if name == "" || !norm.NFC.IsNormalString(name) {
			return fmt.Errorf("commission_tool_policy_invalid: %q is empty or not NFC (D5 covers S1, S3 and S4)", name)
		}
	}
	for _, name := range slices.Concat(s3, s4) {
		if strings.ContainsAny(name, toolWildcardChars) {
			return fmt.Errorf("commission_tool_policy_invalid: %q uses a wildcard character", name)
		}
	}
	for _, name := range s3 {
		if !slices.Contains(s1, name) {
			return fmt.Errorf("commission_tool_policy_invalid: tools_allowed names %q, which [[context.tools]] does not declare (D3)", name)
		}
	}
	if s3Present && len(s3) == 0 && len(s1) > 0 {
		return errors.New("commission_tool_policy_invalid: tools_allowed = [] beside declared tools (D4)")
	}
	for _, name := range s4 {
		if slices.Contains(s3, name) {
			return fmt.Errorf("commission_tool_policy_invalid: %q is both allowed and denied (D5)", name)
		}
	}
	return nil
}

// expectedDimensions is the dimensions map the limited mode writes for a
// memory class (reef-core Verifier admission/8).
func expectedDimensions(class string) map[string]string {
	memory := memoryClaimRInitV1
	if class == memoryClassLegacy {
		memory = memoryClaimLegacy
	}
	return map[string]string{
		"models": "admission_checked",
		"tools":  "admission_checked_declared_only",
		"spend":  "admission_checked",
		"labels": "not_evaluated",
		"memory": memory,
	}
}

// checkDerivation recomputes the §9 derivation and compares it with the
// receipt (§14.4 item 4).
func (r *replayer) checkDerivation() {
	ids := []string{"derivation.manifest", "derivation.receipt_derived", "derivation.fields_root",
		"derivation.memory_class", "derivation.fees", "receipt.dimensions"}
	if !r.manifestOK {
		r.missing("not checked: no verified manifest", ids...)
		return
	}
	d, err := deriveEnvelope(r.ev.Manifest)
	if err != nil {
		r.add("derivation.manifest", CheckFail, "the admission rules refuse this manifest, so no admission of it can be genuine: %v", err)
		r.missing("not checked: the manifest does not derive", ids[1:]...)
		return
	}
	r.derived = d
	r.add("derivation.manifest", CheckPass, "derived models=%q tools=%q c_max_sats=%d author_fee_sats=%d memory_class=%s",
		d.models, d.tools, d.cMax, d.authorFee, d.class)

	rec := r.receipt
	if rec == nil {
		r.missing("not checked: no readable receipt", ids[1:]...)
		return
	}
	r.passFail("derivation.receipt_derived",
		slices.Equal(rec.Derived.Models, d.models) && slices.Equal(rec.Derived.Tools, d.tools) && rec.Derived.CMaxSats == d.cMax,
		"the receipt's derived models, tools and c_max equal the offline derivation",
		"the receipt says derived models=%q tools=%q c_max_sats=%d, but the manifest derives models=%q tools=%q c_max_sats=%d",
		rec.Derived.Models, rec.Derived.Tools, rec.Derived.CMaxSats, d.models, d.tools, d.cMax)
	r.passFail("derivation.fields_root", hexEqual(rec.FieldsRoot, d.trailer.FieldsRoot[:]),
		"the receipt's fields_root equals the manifest trailer",
		"the receipt names fields_root %q, but the manifest trailer is %x", rec.FieldsRoot, d.trailer.FieldsRoot)
	r.passFail("derivation.memory_class", rec.MemoryClass == d.class,
		"memory_class "+d.class+" recomputed from the declared fields",
		"the receipt says memory_class %q, but the trailer recomputes as %q", rec.MemoryClass, d.class)
	r.passFail("derivation.fees", rec.Fees.BoundedByCommission && rec.Fees.AuthorFeeSats == d.authorFee,
		"the author fee equals the manifest's per-run price, and the fees are bounded by the commission (D17 = b)",
		"the receipt says author_fee_sats=%d bounded_by_commission=%t, but the manifest's per-run price is %d and the contract bounds fees (D17 = b)",
		rec.Fees.AuthorFeeSats, rec.Fees.BoundedByCommission, d.authorFee)

	// A receipt that claims more than the limited mode checks is an
	// overclaim, and an extra dimension is a claim this verifier cannot
	// read; both are failures.
	want := expectedDimensions(d.class)
	var diffs []string
	for _, k := range sortedKeys(want, rec.Dimensions) {
		if rec.Dimensions[k] != want[k] {
			diffs = append(diffs, fmt.Sprintf("%s=%q (want %q)", k, rec.Dimensions[k], want[k]))
		}
	}
	r.passFail("receipt.dimensions", len(diffs) == 0,
		"the receipt claims exactly the limited mode's statuses",
		"the receipt's dimension statuses differ from what the limited mode checks: %s", strings.Join(diffs, "; "))
}

// sortedKeys returns the union of the keys of the maps, sorted.
func sortedKeys(maps ...map[string]string) []string {
	var keys []string
	for _, m := range maps {
		for k := range m {
			if !slices.Contains(keys, k) {
				keys = append(keys, k)
			}
		}
	}
	slices.Sort(keys)
	return keys
}

// ── containment ─────────────────────────────────────────────────────

// checkContainment checks the derived envelope against the commission
// (§14.4 item 5), with spend_total under D17 = b.
func (r *replayer) checkContainment() {
	ids := []string{"containment.models", "containment.tools", "containment.spend", "containment.spend_total"}
	if !r.commissionOK || r.derived == nil {
		r.missing("not checked: needs a verified commission and a derived manifest envelope", ids...)
		return
	}
	d, p := r.derived, r.proposal
	models, tools := envelope.Normalise(p.Envelope.Models), envelope.Normalise(p.Envelope.Tools)
	r.passFail("containment.models", subset(d.models, models),
		"the declared model is inside the commission's models",
		"the manifest declares models %q, and the commission permits %q", d.models, models)
	r.passFail("containment.tools", subset(d.tools, tools),
		"the declared tools (S1) are inside the commission's tools",
		"the manifest declares tools %q, and the commission permits %q", d.tools, tools)
	if !r.passFail("containment.spend", d.cMax <= p.Envelope.CMax,
		"the manifest's compute cap is at most the commission's cap",
		"the manifest's compute cap %d is over the commission's cap %d", d.cMax, p.Envelope.CMax) {
		r.add("containment.spend_total", CheckMissing, "not checked: the compute cap is already over")
		return
	}
	if r.receipt == nil {
		r.add("containment.spend_total", CheckMissing, "not checked: the ZK fee is known only from the receipt")
		return
	}
	zk := r.receipt.Fees.ZKFeeSats
	total, overflow := addNoOverflow(d.cMax, d.authorFee, zk)
	r.passFail("containment.spend_total", !overflow && total <= p.Envelope.CMax,
		fmt.Sprintf("compute cap %d + author fee %d + ZK fee %d (server's value) is at most the commission's cap %d", d.cMax, d.authorFee, zk, p.Envelope.CMax),
		"compute cap %d + author fee %d + ZK fee %d is over the commission's cap %d (D17 = b)", d.cMax, d.authorFee, zk, p.Envelope.CMax)
}

// subset reports whether every element of a is in b.
func subset(a, b []string) bool {
	for _, x := range a {
		if !slices.Contains(b, x) {
			return false
		}
	}
	return true
}

// addNoOverflow adds unsigned values and reports whether the sum wrapped.
func addNoOverflow(values ...uint64) (uint64, bool) {
	var total uint64
	for _, v := range values {
		if total+v < total {
			return 0, true
		}
		total += v
	}
	return total, false
}

// ── effective values ────────────────────────────────────────────────

// checkEffective checks that the receipt's effective runtime values are the
// derived values and inside the commission (§14.4 item 6).
func (r *replayer) checkEffective() {
	ids := []string{"effective.model", "effective.budget"}
	switch {
	case r.receipt == nil:
		r.missing("not checked: no readable receipt", ids...)
		return
	case !r.runStarted:
		for _, id := range ids {
			r.add(id, CheckNotApplicable, "no run was launched")
		}
		return
	case !r.commissionOK || r.derived == nil:
		r.missing("not checked: needs a verified commission and a derived manifest envelope", ids...)
		return
	}
	eff := r.receipt.Effective
	permitted := envelope.Normalise(r.proposal.Envelope.Models)
	r.passFail("effective.model", eff.ModelID == r.derived.models[0] && slices.Contains(permitted, eff.ModelID),
		"the receipt's effective model is the declared model, inside the commission",
		"the receipt's effective model %q is not the declared model %q inside the commission's %q",
		eff.ModelID, r.derived.models[0], permitted)
	r.passFail("effective.budget", eff.BudgetSats == r.derived.cMax && eff.BudgetSats <= r.proposal.Envelope.CMax,
		"the receipt's effective budget is the declared compute cap, inside the commission",
		"the receipt's effective budget %d is not the declared cap %d, or is over the commission's cap %d",
		eff.BudgetSats, r.derived.cMax, r.proposal.Envelope.CMax)
}

// ── proof ───────────────────────────────────────────────────────────

// checkProof verifies an optional proof and binds it to these manifest
// bytes and this trailer (§14.4 item 7). A proof is never bound to the
// receipt's run: the bundle names neither the run nor h_commission.
func (r *replayer) checkProof() {
	ids := []string{"proof.snark", "proof.disclosure", "proof.manifest", "proof.fields_root", "proof.memory_eligible"}
	if r.ev.Proof == nil {
		reason := problem(r.ev.ProofProblem, "no proof bundle was supplied (a closed pod produces none)")
		if r.ev.ProofProblem != "" {
			r.add("proof.present", CheckMissing, "%s", reason)
		} else {
			r.add("proof.present", CheckNotApplicable, "%s", reason)
		}
		for _, id := range ids {
			r.add(id, CheckNotApplicable, "no proof")
		}
		return
	}
	r.add("proof.present", CheckPass, "%d proof bytes supplied", len(r.ev.Proof))
	if r.receipt != nil && !r.runStarted {
		for _, id := range ids {
			r.add(id, CheckNotApplicable, "the receipt says no run was launched, so no proof can be about this run")
		}
		return
	}
	verifyProof := r.ev.VerifyProof
	if verifyProof == nil {
		verifyProof = ProductionProofVerifier
	}
	pc := verifyProof(r.ev.Proof)
	if pc.DecodeErr != nil || pc.Bundle == nil {
		r.add("proof.snark", CheckFail, "the proof is not a konareef-bundle/v2: %v", pc.DecodeErr)
		r.missing("not checked: the proof did not decode", ids[1:]...)
		return
	}
	switch {
	case pc.OK:
		r.add("proof.snark", CheckPass, "every bundle check passed, including the SNARK")
	case pc.VerifierMissing:
		r.add("proof.snark", CheckMissing, "the verifier reported only that no SNARK verifier is configured ("+verify.VerifierNotConfiguredHint+"); the proof is not verified")
	default:
		r.add("proof.snark", CheckFail, "the proof does not verify: %s", strings.Join(pc.Divergences, "; "))
	}
	b := pc.Bundle
	if b.Disclosure == "C" {
		r.add("proof.disclosure", CheckPass, "Type-C: the verifier binds the proof's h_manifest input and genesis fields_root to the disclosed manifest")
	} else {
		r.add("proof.disclosure", CheckMissing, "disclosure %q: the verifier does not bind this bundle type's proof to the manifest's fields_root, so it supports no dimension here", b.Disclosure)
	}
	if !r.manifestOK || r.derived == nil {
		r.missing("not checked: no verified, derivable manifest to compare with", ids[2:]...)
		return
	}
	r.passFail("proof.manifest", bytes.Equal(b.Manifest, r.ev.Manifest),
		"the proof discloses exactly the pinned manifest bytes",
		"the proof discloses a different manifest (SHA-256 %x): it is not a proof of this pod", sha256.Sum256(b.Manifest))
	r.passFail("proof.fields_root", bytes.Equal(b.GenesisFieldsRoot, r.derived.trailer.FieldsRoot[:]),
		"the proof's genesis fields_root equals the manifest trailer",
		"the proof's genesis fields_root %x is not the manifest trailer %x", b.GenesisFieldsRoot, r.derived.trailer.FieldsRoot)
	if r.derived.class == memoryClassRInitV1 {
		r.add("proof.memory_eligible", CheckPass, "the trailer commits the empty memory root E20, which is proof-eligible")
	} else {
		r.add("proof.memory_eligible", CheckMissing, "the trailer commits the legacy zero memory root, which is not proof-eligible (MEM-00 R-M17); the proof supports no dimension")
	}
	r.proofVerified = r.outcome("proof.snark") == CheckPass && r.outcome("proof.disclosure") == CheckPass &&
		r.outcome("proof.manifest") == CheckPass && r.outcome("proof.fields_root") == CheckPass &&
		r.outcome("proof.memory_eligible") == CheckPass
}

// outcome returns the outcome of the check with this id, or "" if absent.
func (r *replayer) outcome(id string) CheckOutcome {
	for _, c := range r.checks {
		if c.ID == id {
			return c.Outcome
		}
	}
	return ""
}
