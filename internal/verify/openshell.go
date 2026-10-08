// Copyright 2026 Jerry David Chan, Konareef.ai
// SPDX-License-Identifier: Apache-2.0

// openshell.go — the containment grade of an OpenShell run (reef-core
// OpenShell adapter, phase 2, design section 8; story US-111).
//
// reef-core and its launcher record the evidence; konareef grades it.
// A run on the OpenShell backend has an `openshell_precommit` link in its
// chain and a block of OpenShell lines in its custody blob, in one of two
// forms (design section 6):
//
//   - the full form, 16 lines, when reef-core stored the run's
//     reef-ocsf/v1 records; the bundle then carries them under the
//     `openshell_evidence` key (design section 7);
//   - the unavailable form, 5 lines, ending in
//     `OPENSHELL_EVIDENCE: unavailable <reason>`.
//
// AssessContainment reads both and returns a ContainmentAssessment:
//
//   - hard failures (design 8.2) are returned as a *ContainmentError,
//     and the verify fails;
//   - the derived checks (design 8.3) recompute `gapless`,
//     `policy_changed`, the supervisor markers and the listener count
//     from the records;
//   - the grade (design 8.4) is not_claimed, claimed or
//     operator_attested. A bundle cannot reach gateway_attested.
//
// The grade is operator-attested evidence: the node operator's own
// software recorded it. It is not a proof against the operator.
//
// Choices the design text does not fix word for word (the reef-core
// module ReefCore.Proofs.OpenShellEvidence makes the same ones):
//
//   - "log push drop text": a SUPERVISOR:WARN or SUPERVISOR:ERROR msg that
//     holds both "log push" and "drop" (case-insensitive), or that holds
//     "Failed to flush".
//   - policy_changed rule 2 reads `policy_revision.end > 2`, and rule 8
//     reads a change of `provider_env_digest` as the provider revision
//     change.
//   - `listener_seen` counts `HTTP:* ... ALLOWED` records whose URL
//     authority is the one endpoint of the `reef_run_listener` network
//     policy in `policy_yaml`.
//   - A record that is not in the form of design 4.1 (class, key set,
//     value shapes) fails rule 9, as reef-core's `summarize/3` refuses it.
//   - The redaction metadata (`class`, `seq`) of a withheld leaf is
//     checked for consistency, and a problem is a grade reason. It is
//     never a reason to raise the grade: a withheld leaf caps the grade
//     at claimed whatever the metadata says.
//
// The cross-check of rules X1 to X4 (design section 9, story US-112)
// compares the tool log and the policy file with the records. It is in
// openshell_crosscheck.go.
package verify

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"regexp"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
)

// ContainmentGrade is the verifier's grade for an OpenShell run.
type ContainmentGrade string

// The grades of design section 8.4. gateway_attested is not defined in
// phase 2.
const (
	GradeNotClaimed       ContainmentGrade = "not_claimed"
	GradeClaimed          ContainmentGrade = "claimed"
	GradeOperatorAttested ContainmentGrade = "operator_attested"
)

// SupervisorMarker is one gateway "supervisor session: stream error" record.
// Seq is 0 for a marker record with no seq (it then counts as possible loss).
type SupervisorMarker struct {
	Seq   uint64 `json:"seq"`
	Class string `json:"class"` // "possible_loss" (seq <= drain_end_seq) or "informational"
}

// CrossCheck is the result of rules X1 to X4 (design section 9; see
// openshell_crosscheck.go). Rows has one entry per failed rule.
type CrossCheck struct {
	Outcome string   `json:"outcome"`          // consistent | inconsistent | not_checked
	Reason  string   `json:"reason,omitempty"` // redacted | no_tool_log | incomplete
	Rows    []string `json:"rows,omitempty"`   // one row per failed rule
}

// ContainmentAssessment is the verifier's result for the containment
// evidence (design section 8.1). It is printed in the report and written
// as the JSON field "containment".
type ContainmentAssessment struct {
	Grade             ContainmentGrade   `json:"grade"`
	Form              string             `json:"form"`           // "full", "unavailable", or "" for not_claimed
	Reasons           []string           `json:"reasons"`        // why the grade is below operator_attested; empty at the top
	Redacted          bool               `json:"redacted"`       // any withheld leaf
	Gapless           *bool              `json:"gapless"`        // nil when not computed (unavailable form, no key, redacted)
	PolicyChanged     *bool              `json:"policy_changed"` // nil when not computed
	DrainEndSeq       *uint64            `json:"drain_end_seq"`  // the header's drain_end_seq; nil when not read
	SupervisorMarkers []SupervisorMarker `json:"supervisor_markers"`
	ListenerServed    *uint64            `json:"listener_served"`  // OPENSHELL_LISTENER_REQUESTS; nil in the unavailable form
	ListenerSeen      *uint64            `json:"listener_seen"`    // nil when not computed
	PolicyV1Source    string             `json:"policy_v1_source"` // "end", "create" or ""
	CrossCheck        CrossCheck         `json:"cross_check"`
	Informational     []string           `json:"informational"` // informational markers, policy_v1_source create, and the like
}

// OpenShellEvidence is the `openshell_evidence` key of a
// konareef-bundle/v1 bundle (design section 7).
type OpenShellEvidence struct {
	Rule           string          `json:"rule"`
	RunID          string          `json:"run_id"`
	PolicyYAML     string          `json:"policy_yaml"`
	Gateway        json.RawMessage `json:"gateway"`
	ToolLogRecords string          `json:"tool_log_records"` // base64 of the 113-byte tool-log records
	Leaves         []OCSFLeaf      `json:"leaves"`
}

// OCSFLeaf is one leaf of the evidence: a real record (`record`, base64 of
// tag || JCS), or a withheld leaf (`withheld`, the hex leaf hash, with the
// redaction metadata `class` and `seq`, which no hash binds).
type OCSFLeaf struct {
	Record   *string         `json:"record,omitempty"`
	Withheld *string         `json:"withheld,omitempty"`
	Class    *string         `json:"class,omitempty"`
	Seq      json.RawMessage `json:"seq,omitempty"`
}

// ContainmentError is a hard failure of design section 8.2: the bundle
// contradicts itself, and the verify fails. Rule is the rule number of the
// design table (1 to 12). Checks that the table does not name are filed
// under the nearest rule: an unknown openshell_evidence.rule and a record
// not in the form of design 4.1 under rule 9; a gateway object that lacks
// a field, or whose values differ from the custody lines derived from it,
// under rule 10; a gateway run_id that differs from RUN_ID under rule 7;
// more than one precommit link under rule 3; a precommit link or a key
// without OpenShell lines under rule 1.
type ContainmentError struct {
	Rule int
	Msg  string
}

// Error returns the text of a hard failure.
func (e *ContainmentError) Error() string {
	return fmt.Sprintf("openshell containment (rule %d): %s", e.Rule, e.Msg)
}

// The report texts that design sections 8.2 to 8.4 quote.
const (
	reasonRedacted               = "evidence withheld in the public bundle; verify the verifiable bundle for operator_attested"
	reasonNoKey                  = "evidence not in the bundle"
	reasonDisplayBundle          = "display bundle, not verifiable"
	reasonPossibleLoss           = "supervisor stream error before the drain ended: lines may be lost"
	reasonBundleNotVerified      = "the bundle did not verify"
	reasonCrossCheckInconsistent = "cross-check inconsistent"
	infoMarkerAtStop             = "supervisor session ended at the stop (informational)"
	infoPolicyV1FromCreate       = "policy revision 1 hash from the create read (not in the end read)"
	infoPolicyFileToRevision1    = "policy file to revision 1: checked by the launcher at create"

	// OperatorAttestedNotice is the sentence the report prints with every
	// OpenShell grade (design section 8.4, "The words").
	OperatorAttestedNotice = "operator attested: the node operator's own software recorded this. It is not a proof against the operator."
)

// reef-ocsf/v1 constants (design section 4.1).
const (
	ocsfRule           = "reef-ocsf/v1"
	ocsfHeaderTag      = 0x4e
	ocsfEventTag       = 0x4f
	ocsfLengthTag      = 0x13
	ocsfCreating       = "Creating sandbox container"
	ocsfStopping       = "Stopping sandbox container"
	ocsfMarker         = "supervisor session: stream error"
	ocsfMaxSupervisor  = 512
	listenerPolicyName = "reef_run_listener"
)

// The unavailable reason codes of design section 6. storage_failed is
// valid for the verifier although reef-core never writes it.
var openShellReasonCodes = map[string]bool{
	"launcher_died":        true,
	"capture_error":        true,
	"records_missing":      true,
	"evidence_verb_failed": true,
	"storage_failed":       true,
}

// The line keys of the two forms, in their fixed order (design section 6).
var (
	openShellFullKeys = []string{
		"ISOLATION_ENGINE", "OPENSHELL_SANDBOX_ID", "OPENSHELL_PRECOMMIT",
		"OPENSHELL_POLICY_SUBMITTED_SHA256", "OPENSHELL_POLICY_V1_HASH",
		"OPENSHELL_POLICY_ENRICHED_HASH", "OPENSHELL_POLICY_REVISION",
		"OPENSHELL_POLICY_HISTORY_SHA256", "OPENSHELL_SETTINGS_DIGEST",
		"OPENSHELL_PROVIDER_ENV_DIGEST", "OCSF_LOG_ROOT", "OCSF_LOG_RECORDS",
		"OCSF_STREAM_GAPLESS", "OPENSHELL_LISTENER_REQUESTS", "POLICY_CHANGED",
		"POLICY_EVIDENCE",
	}
	openShellUnavailableKeys = []string{
		"ISOLATION_ENGINE", "OPENSHELL_SANDBOX_ID", "OPENSHELL_PRECOMMIT",
		"OPENSHELL_POLICY_SUBMITTED_SHA256", "OPENSHELL_EVIDENCE",
	}
	openShellAllKeys = func() map[string]bool {
		keys := map[string]bool{}
		for _, key := range append(append([]string{}, openShellFullKeys...), openShellUnavailableKeys...) {
			keys[key] = true
		}
		return keys
	}()
)

// The value form of each line (design section 6), as a regexp over the
// text after "KEY: ". The unavailable reason is checked by rule 2, so its
// form here takes any lower-case code.
var (
	formHex64    = `[0-9a-f]{64}`
	formSHA      = `sha256:` + formHex64
	formUUID     = `[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}`
	formRevision = `[1-9][0-9]*`

	openShellValueForms = map[string]*regexp.Regexp{
		"ISOLATION_ENGINE":                  regexp.MustCompile(`^openshell$`),
		"OPENSHELL_SANDBOX_ID":              regexp.MustCompile(`^` + formUUID + `$`),
		"OPENSHELL_PRECOMMIT":               regexp.MustCompile(`^` + formSHA + `$`),
		"OPENSHELL_POLICY_SUBMITTED_SHA256": regexp.MustCompile(`^` + formSHA + `$`),
		"OPENSHELL_POLICY_V1_HASH":          regexp.MustCompile(`^` + formHex64 + `$`),
		"OPENSHELL_POLICY_ENRICHED_HASH":    regexp.MustCompile(`^(` + formHex64 + `|none)$`),
		"OPENSHELL_POLICY_REVISION":         regexp.MustCompile(`^create=` + formRevision + ` end=` + formRevision + `$`),
		"OPENSHELL_POLICY_HISTORY_SHA256":   regexp.MustCompile(`^` + formSHA + `$`),
		"OPENSHELL_SETTINGS_DIGEST":         regexp.MustCompile(`^create=` + formSHA + ` end=` + formSHA + `$`),
		"OPENSHELL_PROVIDER_ENV_DIGEST":     regexp.MustCompile(`^create=` + formSHA + ` end=` + formSHA + `$`),
		"OCSF_LOG_ROOT":                     regexp.MustCompile(`^` + formSHA + `$`),
		"OCSF_LOG_RECORDS":                  regexp.MustCompile(`^[1-9][0-9]*$`),
		"OCSF_STREAM_GAPLESS":               regexp.MustCompile(`^(true|false)$`),
		"OPENSHELL_LISTENER_REQUESTS":       regexp.MustCompile(`^(0|[1-9][0-9]*)$`),
		"POLICY_CHANGED":                    regexp.MustCompile(`^(true|false)$`),
		"POLICY_EVIDENCE":                   regexp.MustCompile(`^operator_attested$`),
		"OPENSHELL_EVIDENCE":                regexp.MustCompile(`^unavailable \S+$`),
	}
	unavailableSandboxForm = regexp.MustCompile(`^(` + formUUID + `|unknown)$`)

	ocsfClassPattern     = regexp.MustCompile(`^(GATEWAY|STATUS|PLATFORM|DRAFT_POLICY_UPDATE|OCSF|UNKNOWN|STREAM:(WARNING|TRUNCATED|END)|SUPERVISOR:(WARN|ERROR)|LOG:[A-Za-z]{1,16}|(CONFIG|NET|HTTP):[A-Z0-9_]+(:[A-Z0-9_]+)*)$`)
	ocsfEpochPattern     = regexp.MustCompile(`^` + formUUID + `$`)
	ocsfHex64Pattern     = regexp.MustCompile(`^` + formHex64 + `$`)
	ocsfRunIDPattern     = regexp.MustCompile(`^[0-9a-f]{32}$`)
	ocsfLoadedHash       = regexp.MustCompile(`\[hash:([0-9a-f]{64})\]`)
	withheldClassPattern = regexp.MustCompile(`^HTTP:[A-Z0-9_]+$`)
)

// AssessContainment reads the custody blob and the bundle's
// openshell_evidence and returns the assessment (design section 8.1).
//
// Input: b, the bundle.
// Output: the assessment, and a *ContainmentError for a bundle that is
// internally inconsistent (a hard failure, design section 8.2). On a hard
// failure the assessment keeps its form, has grade not_claimed and names
// the failure in Reasons.
func AssessContainment(b *Bundle) (ContainmentAssessment, error) {
	a := newContainmentAssessment()
	err := assessContainment(b, &a)
	if err != nil {
		a.Grade = GradeNotClaimed
		a.Reasons = []string{"hard failure: " + err.Error()}
	}
	return a, err
}

// newContainmentAssessment returns the not_claimed assessment with empty
// lists (so the JSON form has [] rather than null).
func newContainmentAssessment() ContainmentAssessment {
	return ContainmentAssessment{
		Grade:             GradeNotClaimed,
		Reasons:           []string{},
		SupervisorMarkers: []SupervisorMarker{},
		CrossCheck:        CrossCheck{Outcome: "not_checked"},
		Informational:     []string{},
	}
}

// hardFailure builds a *ContainmentError.
func hardFailure(rule int, format string, args ...any) error {
	return &ContainmentError{Rule: rule, Msg: fmt.Sprintf(format, args...)}
}

// assessContainment fills a. It returns the first hard failure.
func assessContainment(b *Bundle, a *ContainmentAssessment) error {
	custodyIndex := -1
	var precommitIndexes []int
	for i, link := range b.Chain {
		switch link.ProofType {
		case "custody":
			custodyIndex = i
		case "openshell_precommit":
			precommitIndexes = append(precommitIndexes, i)
		}
	}
	if custodyIndex < 0 {
		// checkStructure already refuses a chain with no custody link.
		if len(precommitIndexes) > 0 || b.OpenShellEvidence != nil {
			return hardFailure(1, "the chain has OpenShell evidence but no custody link")
		}
		return nil
	}
	custody := b.Chain[custodyIndex]

	form, lines, err := parseOpenShellLines(custody.Data)
	if err != nil {
		return err
	}
	if form == "" {
		if len(precommitIndexes) > 0 {
			return hardFailure(1, "the chain has an openshell_precommit link, but the custody record has no OpenShell lines")
		}
		if b.OpenShellEvidence != nil {
			return hardFailure(1, "the bundle has an openshell_evidence key, but the custody record has no OpenShell lines")
		}
		return nil
	}
	a.Form = form

	// Rule 2 (unavailable form): the reason code.
	if form == "unavailable" {
		reason := strings.TrimPrefix(lines["OPENSHELL_EVIDENCE"], "unavailable ")
		if !openShellReasonCodes[reason] {
			return hardFailure(2, "unknown reason code %q in OPENSHELL_EVIDENCE", reason)
		}
	}

	// Rules 3 to 5: the precommit link.
	precommit, err := checkPrecommit(b, custodyIndex, precommitIndexes, lines)
	if err != nil {
		return err
	}

	notVerifiable := b.Verifiable != nil && !*b.Verifiable

	if form == "unavailable" {
		// Rule 6, then the unavailable path: no evidence checks.
		if b.OpenShellEvidence != nil {
			return hardFailure(6, "the custody record has the unavailable form, but the bundle has an openshell_evidence key")
		}
		a.Grade = GradeClaimed
		a.Reasons = append(a.Reasons, "evidence unavailable: "+strings.TrimPrefix(lines["OPENSHELL_EVIDENCE"], "unavailable "))
		if notVerifiable {
			a.Reasons = append(a.Reasons, reasonDisplayBundle)
		}
		return nil
	}

	served, _ := strconv.ParseUint(lines["OPENSHELL_LISTENER_REQUESTS"], 10, 64)
	a.ListenerServed = &served

	ev := b.OpenShellEvidence
	if ev == nil {
		a.Grade = GradeClaimed
		a.Reasons = append(a.Reasons, reasonNoKey)
		if notVerifiable {
			a.Reasons = append(a.Reasons, reasonDisplayBundle)
		}
		return nil
	}

	return assessFullEvidence(custody, lines, precommit, ev, notVerifiable, served, a)
}

// assessFullEvidence runs rules 7 to 12 and the derived checks for a
// full-form custody record with the openshell_evidence key, and sets the
// grade.
func assessFullEvidence(custody ChainLink, lines map[string]string, precommit precommitBlob,
	ev *OpenShellEvidence, notVerifiable bool, served uint64, a *ContainmentAssessment) error {
	if ev.Rule != ocsfRule {
		return hardFailure(9, "openshell_evidence.rule is %q, not %q", ev.Rule, ocsfRule)
	}
	// Rule 7 (key run_id).
	if ev.RunID != precommit.runID {
		return hardFailure(7, "openshell_evidence.run_id %q differs from the precommit RUN_ID %q", ev.RunID, precommit.runID)
	}

	// Rules 8 and 9: the leaves, the root and the records.
	leaves, err := readOCSFLeaves(ev.Leaves)
	if err != nil {
		return err
	}
	root := ocsfRootFromLeafHashes(leaves.hashes)
	if want := strings.TrimPrefix(lines["OCSF_LOG_ROOT"], "sha256:"); hex.EncodeToString(root[:]) != want {
		return hardFailure(8, "the root recomputed from the leaves %x differs from OCSF_LOG_ROOT %s", root, want)
	}
	if count := strconv.Itoa(len(ev.Leaves)); count != lines["OCSF_LOG_RECORDS"] {
		return hardFailure(8, "the bundle has %s leaves, OCSF_LOG_RECORDS is %s", count, lines["OCSF_LOG_RECORDS"])
	}
	header := leaves.header
	// Rule 7 (header run_id).
	if header.runID != precommit.runID {
		return hardFailure(7, "the header record's run_id %q differs from the precommit RUN_ID %q", header.runID, precommit.runID)
	}

	// Rule 11: the policy file.
	policyHash := sha256.Sum256([]byte(ev.PolicyYAML))
	if want := strings.TrimPrefix(lines["OPENSHELL_POLICY_SUBMITTED_SHA256"], "sha256:"); hex.EncodeToString(policyHash[:]) != want {
		return hardFailure(11, "SHA-256(policy_yaml) %x differs from OPENSHELL_POLICY_SUBMITTED_SHA256 %s", policyHash, want)
	}

	// Rule 12: the tool-log root. The cross-check reads the records only
	// after this check.
	toolLog, err := checkToolLogRecords(custody.Data, ev.ToolLogRecords)
	if err != nil {
		return err
	}

	// Rule 10 needs the gateway object.
	gateway, err := readOCSFGateway(ev.Gateway)
	if err != nil {
		return err
	}
	// Rule 10 (binding): the gateway object is under no hash, and the
	// policy_changed rule reads it. So every custody line that reef-core
	// derives from the object must equal the object's value, and its run_id
	// must be the precommit RUN_ID. Without this check a bundle could pair
	// a hash-bound line (for example OPENSHELL_POLICY_REVISION: create=1
	// end=4) with a gateway object that recomputes policy_changed false.
	for _, key := range openShellFullKeys {
		if want, derived := gateway.lines[key]; derived && lines[key] != want {
			return hardFailure(10, "custody line %s %q differs from the gateway object value %q", key, lines[key], want)
		}
	}
	if gateway.runID != precommit.runID {
		return hardFailure(7, "openshell_evidence.gateway.run_id %q differs from the precommit RUN_ID %q", gateway.runID, precommit.runID)
	}

	a.Redacted = leaves.withheld > 0
	drainEndSeq := header.drainEndSeq
	a.DrainEndSeq = &drainEndSeq
	a.PolicyV1Source = gateway.policyV1Source

	summary := summarizeOCSF(header, leaves.events, gateway, lines["OPENSHELL_SANDBOX_ID"], listenerEndpoint(ev.PolicyYAML), !a.Redacted)

	// Rule 10: the cached lines.
	policyChanged := len(summary.policyChangedReasons) > 0
	if strconv.FormatBool(policyChanged) != lines["POLICY_CHANGED"] {
		return hardFailure(10, "recomputed policy_changed %t differs from POLICY_CHANGED %s", policyChanged, lines["POLICY_CHANGED"])
	}
	a.PolicyChanged = &policyChanged
	if !a.Redacted {
		gapless := len(summary.gaplessReasons) == 0
		if strconv.FormatBool(gapless) != lines["OCSF_STREAM_GAPLESS"] {
			return hardFailure(10, "recomputed gapless %t differs from OCSF_STREAM_GAPLESS %s", gapless, lines["OCSF_STREAM_GAPLESS"])
		}
		a.Gapless = &gapless
	}

	a.SupervisorMarkers = summary.markers
	if summary.listenerSeen != nil {
		seen := *summary.listenerSeen
		a.ListenerSeen = &seen
	}

	gradeFullEvidence(a, summary, leaves, notVerifiable, served, crossCheckInput{
		policyYAML: ev.PolicyYAML,
		endpoint:   listenerEndpoint(ev.PolicyYAML),
		toolLog:    toolLog,
	})
	return nil
}

// gradeFullEvidence sets the grade, the reasons, the informational lines
// and the cross-check of a full-form bundle whose hard-failure rules all
// passed (design sections 8.3, 8.4 and 9).
//
// Inputs: a, the assessment to fill; summary, the derived checks; leaves,
// the decoded leaves; notVerifiable, the bundle's `verifiable: false`;
// served, OPENSHELL_LISTENER_REQUESTS; input, the cross-check inputs (the
// policy file, its listener endpoint and the tool-log records that rule
// 12 checked). Output: none (a is updated).
func gradeFullEvidence(a *ContainmentAssessment, summary ocsfSummary, leaves ocsfLeaves,
	notVerifiable bool, served uint64, input crossCheckInput) {
	if notVerifiable {
		a.Reasons = append(a.Reasons, reasonDisplayBundle)
	}
	if a.Redacted {
		a.Reasons = append(a.Reasons, reasonRedacted)
		a.Reasons = append(a.Reasons, leaves.metadataProblems...)
	}
	if a.Gapless != nil && !*a.Gapless {
		a.Reasons = append(a.Reasons, "OCSF stream not gapless: "+strings.Join(summary.gaplessReasons, ", "))
	}
	possibleLoss, atStop := false, false
	for _, marker := range summary.markers {
		if marker.Class == "possible_loss" {
			possibleLoss = true
		} else {
			atStop = true
		}
	}
	if possibleLoss {
		a.Reasons = append(a.Reasons, reasonPossibleLoss)
	}
	if atStop {
		a.Informational = append(a.Informational, infoMarkerAtStop)
	}

	switch {
	case a.Redacted:
		// The HTTP:* leaves are withheld: no listener count.
	case a.ListenerSeen == nil:
		a.Reasons = append(a.Reasons, "listener lines not checked: no "+listenerPolicyName+" endpoint in policy_yaml")
	case *a.ListenerSeen < served:
		a.Reasons = append(a.Reasons, fmt.Sprintf("listener lines missing: %d served, %d in OCSF", served, *a.ListenerSeen))
	}

	if a.PolicyChanged != nil && *a.PolicyChanged {
		a.Reasons = append(a.Reasons, "policy changed during the run: "+strings.Join(summary.policyChangedReasons, ", "))
	}
	if a.PolicyV1Source == "create" {
		a.Informational = append(a.Informational, infoPolicyV1FromCreate)
	}
	a.Informational = append(a.Informational, infoPolicyFileToRevision1)

	// Complete evidence (design 8.3), as rule X2 needs it.
	input.complete = a.Gapless != nil && *a.Gapless && !possibleLoss &&
		a.ListenerSeen != nil && *a.ListenerSeen == served
	input.redacted = a.Redacted
	input.served = served
	input.seen = a.ListenerSeen
	a.CrossCheck = crossCheck(leaves.events, input)
	if a.CrossCheck.Outcome == "inconsistent" {
		a.Reasons = append(a.Reasons, reasonCrossCheckInconsistent)
	}

	// operator_attested also needs the cross-check outcome of design 8.4
	// directly, so that a later change to the reasons cannot open the
	// grade.
	crossCheckAllows := a.CrossCheck.Outcome == "consistent" ||
		(a.CrossCheck.Outcome == "not_checked" && a.CrossCheck.Reason == "no_tool_log")
	if len(a.Reasons) == 0 && !crossCheckAllows {
		a.Reasons = append(a.Reasons, "cross-check "+a.CrossCheck.Outcome+" ("+a.CrossCheck.Reason+")")
	}
	if len(a.Reasons) == 0 && crossCheckAllows {
		a.Grade = GradeOperatorAttested
	} else {
		a.Grade = GradeClaimed
	}
}

// ── Custody lines (design section 6) ─────────────────────────────

// parseOpenShellLines finds and checks the OpenShell lines of a custody
// blob (rule 1).
//
// Input: the custody `data` blob.
// Output: the form ("" when the blob has none of the keys, "full" or
// "unavailable"), the line values by key, or a rule-1 failure: lines not
// in one block right after AGENT_KEY (only MCP_BROKER lines may follow),
// not exactly the keys of one form in its order, or a value not in its
// form.
func parseOpenShellLines(data string) (string, map[string]string, error) {
	lines := strings.Split(data, "\n")
	var keys []string
	start := -1
	for i, line := range lines {
		key := custodyLineKey(line)
		if !openShellAllKeys[key] {
			continue
		}
		if start < 0 {
			start = i
		}
		if i != start+len(keys) {
			return "", nil, hardFailure(1, "the OpenShell lines are not one block")
		}
		keys = append(keys, key)
	}
	if start < 0 {
		return "", nil, nil
	}
	if start == 0 || custodyLineKey(lines[start-1]) != "AGENT_KEY" {
		return "", nil, hardFailure(1, "the OpenShell lines do not follow the AGENT_KEY line")
	}
	for _, line := range lines[start+len(keys):] {
		if custodyLineKey(line) != "MCP_BROKER" {
			return "", nil, hardFailure(1, "a line other than MCP_BROKER follows the OpenShell lines")
		}
	}

	var form string
	switch {
	case equalStrings(keys, openShellFullKeys):
		form = "full"
	case equalStrings(keys, openShellUnavailableKeys):
		form = "unavailable"
	default:
		return "", nil, hardFailure(1, "the OpenShell lines are not the line set of either form, in order: %s", strings.Join(keys, ", "))
	}

	values := map[string]string{}
	for i, key := range keys {
		line := lines[start+i]
		value, ok := strings.CutPrefix(line, key+": ")
		valueForm := openShellValueForms[key]
		if form == "unavailable" && key == "OPENSHELL_SANDBOX_ID" {
			valueForm = unavailableSandboxForm
		}
		if !ok || !valueForm.MatchString(value) {
			return "", nil, hardFailure(1, "malformed line %s", key)
		}
		values[key] = value
	}
	return form, values, nil
}

// custodyLineKey returns the text before the first ':' of a custody line,
// or "" for a line with no ':'.
func custodyLineKey(line string) string {
	key, _, found := strings.Cut(line, ":")
	if !found {
		return ""
	}
	return key
}

// equalStrings reports whether two string lists are equal.
func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// ── Precommit link (design section 5; rules 3 to 5) ──────────────

// precommitBlob holds the fields of an openshell_precommit blob.
type precommitBlob struct {
	taskID, podID, runID, image, policySHA256 string
}

// precommitLinePattern is the exact blob of design section 5, in order.
var precommitLinePattern = regexp.MustCompile(
	`^OPENSHELL_PRECOMMIT: v1\nTASK_ID: ([^\n]+)\nPOD_ID: ([^\n]+)\nRUN_ID: ([0-9a-f]{32})\n` +
		`IMAGE: ([^\n]+)\nPOLICY_SHA256: sha256:([0-9a-f]{64})\nENGINE: openshell$`)

// checkPrecommit applies rules 3, 4 and 5.
//
// Inputs: the bundle, the index of the custody link, the indexes of the
// openshell_precommit links, and the custody record's OpenShell lines.
// Output: the parsed precommit blob, or the failure.
func checkPrecommit(b *Bundle, custodyIndex int, precommitIndexes []int, lines map[string]string) (precommitBlob, error) {
	named := strings.TrimPrefix(lines["OPENSHELL_PRECOMMIT"], "sha256:")
	if len(precommitIndexes) > 1 {
		return precommitBlob{}, hardFailure(3, "the chain has %d openshell_precommit links; one is allowed", len(precommitIndexes))
	}
	if len(precommitIndexes) == 0 || precommitIndexes[0] > custodyIndex || b.Chain[precommitIndexes[0]].Hash != named {
		return precommitBlob{}, hardFailure(3, "OPENSHELL_PRECOMMIT sha256:%s names no openshell_precommit link earlier in the chain", named)
	}
	link := b.Chain[precommitIndexes[0]]
	m := precommitLinePattern.FindStringSubmatch(link.Data)
	if m == nil {
		return precommitBlob{}, hardFailure(3, "the openshell_precommit link's data is not in the form of design section 5")
	}
	blob := precommitBlob{taskID: m[1], podID: m[2], runID: m[3], image: m[4], policySHA256: m[5]}

	if want := strings.TrimPrefix(lines["OPENSHELL_POLICY_SUBMITTED_SHA256"], "sha256:"); blob.policySHA256 != want {
		return precommitBlob{}, hardFailure(4, "the precommit POLICY_SHA256 %s differs from OPENSHELL_POLICY_SUBMITTED_SHA256 %s", blob.policySHA256, want)
	}

	custody := b.Chain[custodyIndex]
	if custody.TaskID == nil || *custody.TaskID != blob.taskID {
		got := "<null>"
		if custody.TaskID != nil {
			got = *custody.TaskID
		}
		return precommitBlob{}, hardFailure(5, "the precommit TASK_ID %q differs from the custody link's task_id %q", blob.taskID, got)
	}
	if b.Snapshot != nil && b.Snapshot.PodID != blob.podID {
		return precommitBlob{}, hardFailure(5, "the precommit POD_ID %q differs from snapshot.pod_id %q", blob.podID, b.Snapshot.PodID)
	}
	return blob, nil
}

// ── Leaves and records (design 4.1; rules 8 and 9) ───────────────

// ocsfHeader holds the header record fields that the checks read.
type ocsfHeader struct {
	runID, sandboxID, cursorEpoch string
	firstSeq, lastSeq             uint64
	drainEndSeq                   uint64
	fields                        map[string]any
}

// ocsfEvent is one decoded event record (a real leaf after the header).
type ocsfEvent struct {
	class  string
	seq    uint64 // 0 when the record has seq null
	hasSeq bool
	fields map[string]any
}

// ocsfLeaves is the decoded leaf list.
type ocsfLeaves struct {
	hashes           [][32]byte
	header           ocsfHeader
	events           []ocsfEvent // the real event records, in order
	withheld         int
	metadataProblems []string
}

// readOCSFLeaves decodes every leaf (rules 8 and 9).
//
// Input: the bundle's leaves. Output: the leaf hashes, the header, the
// real event records and the withheld-leaf count, or the failure: a leaf
// that is neither a record nor a withheld hash (rule 8), a withheld
// header (rule 9), or a record whose tag, JCS bytes or form is wrong
// (rule 9). The redaction metadata of withheld leaves is checked, and each
// problem is listed in metadataProblems (it never raises a grade).
func readOCSFLeaves(leaves []OCSFLeaf) (ocsfLeaves, error) {
	out := ocsfLeaves{}
	if len(leaves) == 0 {
		return out, hardFailure(9, "openshell_evidence has no leaves")
	}
	type withheldMeta struct {
		index int
		class string
		seq   json.RawMessage
	}
	var withheld []withheldMeta
	lastSeqOrder := []struct {
		index int
		seq   uint64
		real  bool
	}{}

	for i, leaf := range leaves {
		switch {
		case leaf.Record != nil && leaf.Withheld == nil:
			recordBytes, err := base64.StdEncoding.DecodeString(*leaf.Record)
			if err != nil {
				return out, hardFailure(9, "leaf %d: record is not base64", i)
			}
			out.hashes = append(out.hashes, ocsfLeafHash(recordBytes))
			if i == 0 {
				header, err := decodeOCSFHeader(recordBytes)
				if err != nil {
					return out, err
				}
				out.header = header
				continue
			}
			event, err := decodeOCSFEvent(recordBytes, i, i == len(leaves)-1)
			if err != nil {
				return out, err
			}
			out.events = append(out.events, event)
			if event.hasSeq {
				lastSeqOrder = append(lastSeqOrder, struct {
					index int
					seq   uint64
					real  bool
				}{i, event.seq, true})
			}
		case leaf.Withheld != nil && leaf.Record == nil:
			if i == 0 {
				return out, hardFailure(9, "leaf 0 (the header) is withheld")
			}
			hash, ok := decodeHash32(*leaf.Withheld)
			if !ok || !ocsfHex64Pattern.MatchString(*leaf.Withheld) {
				return out, hardFailure(8, "leaf %d: withheld is not a 64-hex leaf hash", i)
			}
			out.hashes = append(out.hashes, hash)
			out.withheld++
			class := ""
			if leaf.Class != nil {
				class = *leaf.Class
			}
			withheld = append(withheld, withheldMeta{i, class, leaf.Seq})
			if seq, ok := parseWithheldSeq(leaf.Seq); ok {
				lastSeqOrder = append(lastSeqOrder, struct {
					index int
					seq   uint64
					real  bool
				}{i, seq, false})
			}
		default:
			return out, hardFailure(8, "leaf %d is neither a record nor a withheld leaf hash", i)
		}
	}

	// Redaction metadata (US-110 README, coordinator carry-forward): the
	// class of a withheld leaf is HTTP:*, and its seq is an integer within
	// [first_seq, last_seq] above the seq of every earlier leaf with a seq.
	// A withheld seq outside the header range is reported once, below, and
	// does not count as an earlier seq (so one forged value does not flag
	// every later leaf).
	previous := map[int]uint64{} // leaf index -> highest seq of the leaves before it
	var highest uint64
	for _, entry := range lastSeqOrder {
		previous[entry.index] = highest
		outOfRange := entry.seq < out.header.firstSeq || entry.seq > out.header.lastSeq
		if !entry.real && outOfRange {
			continue
		}
		if entry.seq > highest {
			highest = entry.seq
		}
	}
	for _, meta := range withheld {
		if !withheldClassPattern.MatchString(meta.class) {
			out.metadataProblems = append(out.metadataProblems,
				fmt.Sprintf("redaction metadata of leaf %d: class %q is not HTTP:*", meta.index, meta.class))
		}
		seq, ok := parseWithheldSeq(meta.seq)
		switch {
		case !ok:
			out.metadataProblems = append(out.metadataProblems,
				fmt.Sprintf("redaction metadata of leaf %d: seq is not a positive integer", meta.index))
		case seq < out.header.firstSeq || seq > out.header.lastSeq:
			out.metadataProblems = append(out.metadataProblems,
				fmt.Sprintf("redaction metadata of leaf %d: seq %d is outside [%d, %d]", meta.index, seq, out.header.firstSeq, out.header.lastSeq))
		case seq <= previous[meta.index]:
			out.metadataProblems = append(out.metadataProblems,
				fmt.Sprintf("redaction metadata of leaf %d: seq %d is not above the seq of an earlier leaf", meta.index, seq))
		}
	}
	return out, nil
}

// parseWithheldSeq reads the seq of a withheld leaf: a positive integer.
func parseWithheldSeq(raw json.RawMessage) (uint64, bool) {
	text := strings.TrimSpace(string(raw))
	if text == "" || text == "null" {
		return 0, false
	}
	seq, err := strconv.ParseUint(text, 10, 64)
	if err != nil || seq == 0 {
		return 0, false
	}
	return seq, true
}

// ocsfLeafHash is SHA-256(0x00 || record) (design 4.1 item 2).
func ocsfLeafHash(record []byte) [32]byte {
	return sha256.Sum256(append([]byte{custodyLeafTag}, record...))
}

// ocsfRootFromLeafHashes is the reef-ocsf/v1 root over leaf hashes:
// SHA-256(0x13 || ULEB128(n) || top), on the padded tree of the custody
// tool log (design 4.1 item 2).
//
// Input: the leaf hashes in order. Output: the 32-byte root.
func ocsfRootFromLeafHashes(leafHashes [][32]byte) [32]byte {
	top := custodyTreeTop(leafHashes)
	pre := append([]byte{ocsfLengthTag}, custodyULEB128(uint64(len(leafHashes)))...)
	pre = append(pre, top[:]...)
	return sha256.Sum256(pre)
}

// OCSFRoot is the reef-ocsf/v1 root of a record list.
//
// Input: the records (tag || JCS), header first. Output: the root.
func OCSFRoot(records [][]byte) [32]byte {
	hashes := make([][32]byte, len(records))
	for i, record := range records {
		hashes[i] = ocsfLeafHash(record)
	}
	return ocsfRootFromLeafHashes(hashes)
}

// decodeOCSFRecord checks the tag and the JCS bytes of one record and
// decodes its object (rule 9).
func decodeOCSFRecord(record []byte, index int, tag byte) (map[string]any, error) {
	if len(record) == 0 || record[0] != tag {
		return nil, hardFailure(9, "record %d: tag is not 0x%02x", index, tag)
	}
	body := record[1:]
	canonical, err := jcsCanonicalize(body)
	if err != nil {
		return nil, hardFailure(9, "record %d: not JSON: %v", index, err)
	}
	if !bytes.Equal(canonical, body) {
		return nil, hardFailure(9, "record %d: not canonical JCS", index)
	}
	value, _ := jcsDecode(body)
	object, ok := value.(map[string]any)
	if !ok {
		return nil, hardFailure(9, "record %d: not a JSON object", index)
	}
	if object["v"] != ocsfRule {
		return nil, hardFailure(9, "record %d: v is not %q", index, ocsfRule)
	}
	return object, nil
}

// headerKeys are the keys of the header record (design 4.1 item 3).
var headerKeys = []string{"v", "run_id", "sandbox_id", "sandbox_name", "workspace_scope", "cursor_epoch",
	"first_seq", "last_seq", "gateway_version", "stream", "drain_ms", "drain_quiet", "drain_end_seq",
	"node_address_redacted", "node_placeholder"}

// decodeOCSFHeader decodes leaf 0 (rule 9).
func decodeOCSFHeader(record []byte) (ocsfHeader, error) {
	object, err := decodeOCSFRecord(record, 0, ocsfHeaderTag)
	if err != nil {
		return ocsfHeader{}, err
	}
	firstSeq, okFirst := jsonUint(object["first_seq"])
	lastSeq, okLast := jsonUint(object["last_seq"])
	drainEnd, okDrain := jsonUint(object["drain_end_seq"])
	_, okDrainMS := jsonUint(object["drain_ms"])
	runID, _ := object["run_id"].(string)
	valid := exactKeys(object, headerKeys) &&
		ocsfRunIDPattern.MatchString(runID) &&
		isString(object["sandbox_id"]) && isString(object["sandbox_name"]) &&
		object["workspace_scope"] == "default" && isString(object["cursor_epoch"]) &&
		okFirst && okLast && isString(object["gateway_version"]) &&
		object["stream"] == "WatchSandbox" && okDrainMS && isBool(object["drain_quiet"]) &&
		okDrain && object["node_address_redacted"] == true && object["node_placeholder"] == "<node>"
	if !valid {
		return ocsfHeader{}, hardFailure(9, "record 0: not a reef-ocsf/v1 header")
	}
	return ocsfHeader{
		runID:       runID,
		sandboxID:   object["sandbox_id"].(string),
		cursorEpoch: object["cursor_epoch"].(string),
		firstSeq:    firstSeq,
		lastSeq:     lastSeq,
		drainEndSeq: drainEnd,
		fields:      object,
	}, nil
}

// decodeOCSFEvent decodes one event record (rule 9): its class, the key
// set of its class, the value shapes, and STREAM:END only as the last leaf.
func decodeOCSFEvent(record []byte, index int, last bool) (ocsfEvent, error) {
	object, err := decodeOCSFRecord(record, index, ocsfEventTag)
	if err != nil {
		return ocsfEvent{}, err
	}
	class, _ := object["class"].(string)
	if !ocsfClassPattern.MatchString(class) {
		return ocsfEvent{}, hardFailure(9, "record %d: class %q is not a reef-ocsf/v1 class", index, class)
	}
	if !exactKeys(object, ocsfEventKeys(class)) || !ocsfEventShape(class, object) {
		return ocsfEvent{}, hardFailure(9, "record %d: not in the form of class %s", index, class)
	}
	if class == "STREAM:END" && !last {
		return ocsfEvent{}, hardFailure(9, "record %d: STREAM:END is not the last record", index)
	}
	event := ocsfEvent{class: class, fields: object}
	if seq, ok := jsonUint(object["seq"]); ok {
		event.seq, event.hasSeq = seq, true
	}
	return event, nil
}

// ocsfEventKeys is the key set of an event record class (design 4.1).
func ocsfEventKeys(class string) []string {
	switch {
	case class == "STATUS":
		return []string{"v", "seq", "src", "class", "phase", "stub"}
	case class == "STREAM:WARNING":
		return []string{"v", "seq", "class", "lagged"}
	case class == "STREAM:TRUNCATED":
		return []string{"v", "seq", "class", "records", "bytes"}
	case class == "STREAM:END":
		return []string{"v", "seq", "class", "reason", "code", "message"}
	case strings.HasPrefix(class, "SUPERVISOR:"):
		return []string{"v", "seq", "src", "trust", "class", "sev", "msg", "t_ms", "msg_truncated"}
	case ocsfFullClass(class):
		return []string{"v", "seq", "src", "trust", "class", "sev", "msg", "t_ms"}
	default:
		return []string{"v", "seq", "src", "class", "stub"}
	}
}

// ocsfFullClass reports whether a class is a full record class.
func ocsfFullClass(class string) bool {
	return class == "GATEWAY" || strings.HasPrefix(class, "CONFIG:") ||
		strings.HasPrefix(class, "NET:") || strings.HasPrefix(class, "HTTP:")
}

// ocsfEventShape checks the value shapes of an event record.
func ocsfEventShape(class string, e map[string]any) bool {
	switch {
	case class == "STREAM:END":
		reason, _ := e["reason"].(string)
		return e["seq"] == nil &&
			(reason == "closed_after_stop" || reason == "server_end" || reason == "server_end_before_stop") &&
			isString(e["code"]) && isString(e["message"])
	case class == "STREAM:TRUNCATED":
		_, okRecords := jsonUint(e["records"])
		_, okBytes := jsonUint(e["bytes"])
		return e["seq"] == nil && okRecords && okBytes
	case class == "STREAM:WARNING":
		_, okLagged := jsonUint(e["lagged"])
		return optionalSeq(e["seq"]) && okLagged
	case class == "STATUS":
		return optionalSeq(e["seq"]) && isString(e["src"]) && isString(e["phase"]) && isHex64(e["stub"])
	case strings.HasPrefix(class, "SUPERVISOR:"):
		msg, _ := e["msg"].(string)
		return ocsfFullShape(e) && e["src"] == "sandbox" && e["trust"] == "supervisor_report" &&
			e["sev"] == strings.TrimPrefix(class, "SUPERVISOR:") && isBool(e["msg_truncated"]) &&
			len(msg) <= ocsfMaxSupervisor
	case ocsfFullClass(class):
		return ocsfFullShape(e)
	default:
		return optionalSeq(e["seq"]) && isString(e["src"]) && isHex64(e["stub"])
	}
}

// ocsfFullShape checks the fields of a full record.
func ocsfFullShape(e map[string]any) bool {
	tms := e["t_ms"]
	_, tmsInt := jsonInt(tms)
	return optionalSeq(e["seq"]) && isString(e["src"]) && isString(e["trust"]) &&
		isString(e["sev"]) && isString(e["msg"]) && (tms == nil || tmsInt)
}

// optionalSeq: a seq is null or a positive integer.
func optionalSeq(value any) bool {
	if value == nil {
		return true
	}
	seq, ok := jsonUint(value)
	return ok && seq > 0
}

// jsonUint reads a non-negative JSON integer (json.Number with no
// fraction or exponent).
func jsonUint(value any) (uint64, bool) {
	number, ok := value.(json.Number)
	if !ok {
		return 0, false
	}
	n, err := strconv.ParseUint(string(number), 10, 64)
	return n, err == nil
}

// jsonInt reads a JSON integer.
func jsonInt(value any) (int64, bool) {
	number, ok := value.(json.Number)
	if !ok {
		return 0, false
	}
	n, err := strconv.ParseInt(string(number), 10, 64)
	return n, err == nil
}

// exactKeys reports whether object has exactly the given keys.
func exactKeys(object map[string]any, keys []string) bool {
	if len(object) != len(keys) {
		return false
	}
	for _, key := range keys {
		if _, ok := object[key]; !ok {
			return false
		}
	}
	return true
}

func isString(value any) bool { _, ok := value.(string); return ok }
func isBool(value any) bool   { _, ok := value.(bool); return ok }
func isHex64(value any) bool {
	text, ok := value.(string)
	return ok && ocsfHex64Pattern.MatchString(text)
}

// ── Gateway object (design 3.4) ──────────────────────────────────

// ocsfGateway holds the gateway values the policy_changed rule reads.
type ocsfGateway struct {
	lines                       map[string]string // the custody line values reef-core derives from the object
	runID                       string
	revisionCreate, revisionEnd uint64
	settingsCreate, settingsEnd string
	providerCreate, providerEnd string
	enrichedHash                string
	policyV1Source              string
}

// readOCSFGateway reads the gateway object of the key (rule 10 needs it).
//
// Input: the raw `gateway` JSON. Output: the values, or a rule-10 failure
// for an object that lacks a field the checks read or holds it in another
// shape.
func readOCSFGateway(raw json.RawMessage) (ocsfGateway, error) {
	value, err := jcsDecode(raw)
	object, ok := value.(map[string]any)
	if err != nil || !ok {
		return ocsfGateway{}, hardFailure(10, "openshell_evidence.gateway is not a JSON object")
	}
	pair := func(key string) (any, any, bool) {
		inner, ok := object[key].(map[string]any)
		if !ok || len(inner) != 2 {
			return nil, nil, false
		}
		create, okCreate := inner["create"]
		end, okEnd := inner["end"]
		return create, end, okCreate && okEnd
	}
	gw := ocsfGateway{}
	create, end, ok := pair("policy_revision")
	revisionCreate, okCreate := jsonUint(create)
	revisionEnd, okEnd := jsonUint(end)
	gw.revisionCreate, gw.revisionEnd = revisionCreate, revisionEnd
	if !ok || !okCreate || !okEnd || gw.revisionCreate == 0 || gw.revisionEnd == 0 {
		return ocsfGateway{}, hardFailure(10, "openshell_evidence.gateway.policy_revision is not a create/end pair of revisions")
	}
	for _, field := range []struct {
		key         string
		create, end *string
	}{{"settings_digest", &gw.settingsCreate, &gw.settingsEnd}, {"provider_env_digest", &gw.providerCreate, &gw.providerEnd}} {
		create, end, ok := pair(field.key)
		createText, okCreate := create.(string)
		endText, okEnd := end.(string)
		if !ok || !okCreate || !okEnd {
			return ocsfGateway{}, hardFailure(10, "openshell_evidence.gateway.%s is not a create/end pair of strings", field.key)
		}
		*field.create, *field.end = createText, endText
	}
	enriched, ok := object["policy_enriched_hash"].(string)
	if !ok {
		return ocsfGateway{}, hardFailure(10, "openshell_evidence.gateway.policy_enriched_hash is not a string")
	}
	gw.enrichedHash = enriched
	source, _ := object["policy_v1_source"].(string)
	if source != "end" && source != "create" {
		return ocsfGateway{}, hardFailure(10, "openshell_evidence.gateway.policy_v1_source is not \"end\" or \"create\"")
	}
	gw.policyV1Source = source
	gw.runID, _ = object["run_id"].(string)
	text := func(key string) string { value, _ := object[key].(string); return value }
	enrichedLine := enriched
	if enrichedLine == "" {
		enrichedLine = "none"
	}
	// The line values as reef-core OpenShellCustody.gateway_pairs/1 renders
	// them from the object.
	gw.lines = map[string]string{
		"OPENSHELL_SANDBOX_ID":              text("sandbox_id"),
		"OPENSHELL_POLICY_SUBMITTED_SHA256": "sha256:" + text("policy_submitted_sha256"),
		"OPENSHELL_POLICY_V1_HASH":          text("policy_v1_hash"),
		"OPENSHELL_POLICY_ENRICHED_HASH":    enrichedLine,
		"OPENSHELL_POLICY_REVISION":         fmt.Sprintf("create=%d end=%d", gw.revisionCreate, gw.revisionEnd),
		"OPENSHELL_POLICY_HISTORY_SHA256":   "sha256:" + text("policy_history_sha256"),
		"OPENSHELL_SETTINGS_DIGEST":         "create=sha256:" + gw.settingsCreate + " end=sha256:" + gw.settingsEnd,
		"OPENSHELL_PROVIDER_ENV_DIGEST":     "create=sha256:" + gw.providerCreate + " end=sha256:" + gw.providerEnd,
	}
	return gw, nil
}

// ── Derived checks (design 8.3, 4.2.1) ───────────────────────────

// ocsfSummary is the result of the derived checks.
type ocsfSummary struct {
	gaplessReasons       []string // nil when every gapless condition holds (or not computed)
	policyChangedReasons []string // the rules that fired: rule_1 .. rule_8
	markers              []SupervisorMarker
	listenerSeen         *uint64 // nil when not computed
}

// summarizeOCSF runs the derived checks on the decoded records.
//
// Inputs: the header; the real event records; the gateway object; the
// OPENSHELL_SANDBOX_ID line; the listener endpoint ("" when unknown); and
// whether every leaf is a real record (the gap check and the listener
// count run only then).
// Output: the summary.
func summarizeOCSF(header ocsfHeader, events []ocsfEvent, gw ocsfGateway, sandboxID, endpoint string, allReal bool) ocsfSummary {
	summary := ocsfSummary{
		policyChangedReasons: policyChangedReasons(gw, events),
		markers:              supervisorMarkers(events, header.drainEndSeq),
	}
	if allReal {
		summary.gaplessReasons = gaplessReasons(header, events, sandboxID)
		if endpoint != "" {
			seen := listenerSeen(events, endpoint)
			summary.listenerSeen = &seen
		}
	}
	return summary
}

// gaplessReasons returns one name per failed gapless condition (design
// 8.3, "Gapless"); none when the stream is gapless. Records with seq null
// do not take part in the seq checks.
func gaplessReasons(header ocsfHeader, events []ocsfEvent, sandboxID string) []string {
	var seqEvents []ocsfEvent
	for _, event := range events {
		if event.hasSeq {
			seqEvents = append(seqEvents, event)
		}
	}
	dense := true
	for i, event := range seqEvents {
		if event.seq != uint64(i+1) {
			dense = false
			break
		}
	}
	var firstSeq, lastSeq uint64
	if len(seqEvents) > 0 {
		firstSeq, lastSeq = seqEvents[0].seq, seqEvents[len(seqEvents)-1].seq
	}
	creatingFirst := len(seqEvents) > 0 && gatewayLine(seqEvents[0], ocsfCreating) && seqEvents[0].seq == 1
	var last *ocsfEvent
	if len(events) > 0 {
		last = &events[len(events)-1]
	}
	lastReason, lastCode := "", ""
	if last != nil && last.class == "STREAM:END" {
		lastReason, _ = last.fields["reason"].(string)
		lastCode, _ = last.fields["code"].(string)
	}

	anyClass := func(class string) bool {
		for _, event := range events {
			if event.class == class {
				return true
			}
		}
		return false
	}
	anyEvent := func(match func(ocsfEvent) bool) bool {
		for _, event := range events {
			if match(event) {
				return true
			}
		}
		return false
	}

	checks := []struct {
		name   string
		failed bool
	}{
		{"sandbox_id_mismatch", header.sandboxID != sandboxID},
		{"first_seq_not_creating", !creatingFirst},
		{"cursor_epoch", !ocsfEpochPattern.MatchString(header.cursorEpoch)},
		{"seq_not_dense", !dense},
		{"header_seq_mismatch", header.firstSeq != firstSeq || header.lastSeq != lastSeq},
		{"stream_warning", anyClass("STREAM:WARNING")},
		{"stream_truncated", anyClass("STREAM:TRUNCATED")},
		{"control_character", hasControlCharacter(header.fields) || anyEvent(func(e ocsfEvent) bool { return hasControlCharacter(e.fields) })},
		{"supervisor_drop", anyEvent(supervisorDrop)},
		{"stream_end_missing", last == nil || last.class != "STREAM:END"},
		{"server_end_before_stop", lastReason == "server_end_before_stop"},
		{"server_end_code", lastReason == "server_end" && lastCode != "OK" && lastCode != "CANCELLED"},
		{"stop_marker_missing", !anyEvent(func(e ocsfEvent) bool { return gatewayLine(e, ocsfStopping) })},
		{"drain_end_seq_above_last_seq", header.drainEndSeq > header.lastSeq},
	}
	var reasons []string
	for _, check := range checks {
		if check.failed {
			reasons = append(reasons, check.name)
		}
	}
	return reasons
}

// gatewayLine reports whether event is the GATEWAY record with msg.
func gatewayLine(event ocsfEvent, msg string) bool {
	return event.class == "GATEWAY" && event.fields["msg"] == msg
}

// hasControlCharacter reports whether any string value of a record holds
// a C0 control character (U+0000 to U+001F).
func hasControlCharacter(fields map[string]any) bool {
	for _, value := range fields {
		text, ok := value.(string)
		if !ok {
			continue
		}
		for _, r := range text {
			if r < 0x20 {
				return true
			}
		}
	}
	return false
}

// supervisorDrop is the supervisor drop rule: a SUPERVISOR:WARN or
// SUPERVISOR:ERROR msg that holds "Failed to flush", or both "log push"
// and "drop" (case-insensitive).
func supervisorDrop(event ocsfEvent) bool {
	if !strings.HasPrefix(event.class, "SUPERVISOR:") {
		return false
	}
	msg, _ := event.fields["msg"].(string)
	lower := strings.ToLower(msg)
	return strings.Contains(msg, "Failed to flush") ||
		(strings.Contains(lower, "log push") && strings.Contains(lower, "drop"))
}

// supervisorMarkers lists the GATEWAY "supervisor session: stream error"
// records: possible_loss when seq <= drain_end_seq (or no seq), else
// informational (design 4.1 item 6).
func supervisorMarkers(events []ocsfEvent, drainEndSeq uint64) []SupervisorMarker {
	markers := []SupervisorMarker{}
	for _, event := range events {
		if !gatewayLine(event, ocsfMarker) {
			continue
		}
		class := "possible_loss"
		if event.hasSeq && event.seq > drainEndSeq {
			class = "informational"
		}
		markers = append(markers, SupervisorMarker{Seq: event.seq, Class: class})
	}
	return markers
}

// listenerSeen counts the HTTP:* records with msg "ALLOWED <METHOD> <url>
// ..." whose URL authority is endpoint (design 8.3, "Listener complete").
func listenerSeen(events []ocsfEvent, endpoint string) uint64 {
	var seen uint64
	for _, event := range events {
		if !strings.HasPrefix(event.class, "HTTP:") {
			continue
		}
		msg, _ := event.fields["msg"].(string)
		rest, ok := strings.CutPrefix(msg, "ALLOWED ")
		if !ok {
			continue
		}
		parts := strings.SplitN(rest, " ", 3)
		if len(parts) >= 2 && urlAuthority(parts[1]) == endpoint {
			seen++
		}
	}
	return seen
}

// uriDefaultPorts is the default port table of Elixir URI.default_port/1,
// which reef-core's listener count uses.
var uriDefaultPorts = map[string]string{
	"ftp": "21", "sftp": "22", "tftp": "69", "http": "80", "https": "443", "ldap": "389", "ws": "80", "wss": "443",
}

// urlAuthority returns "<host>:<port>" of a URL (IPv6 in brackets), as
// reef-core derives it with URI.parse/1: the authority after "://" up to
// the first '/', '?' or '#', without user info, with the scheme's default
// port when the URL has none. It returns "" when the URL has no scheme,
// no host, or no numeric port. The rest of the URL is not parsed, so a
// path that is not valid does not change the result.
func urlAuthority(rawURL string) string {
	scheme, rest, found := strings.Cut(rawURL, "://")
	if !found || scheme == "" {
		return ""
	}
	if end := strings.IndexAny(rest, "/?#"); end >= 0 {
		rest = rest[:end]
	}
	if at := strings.LastIndex(rest, "@"); at >= 0 {
		rest = rest[at+1:]
	}
	var host, port string
	if strings.HasPrefix(rest, "[") {
		closing := strings.Index(rest, "]")
		if closing < 0 {
			return ""
		}
		host, port = rest[1:closing], strings.TrimPrefix(rest[closing+1:], ":")
	} else if colon := strings.LastIndex(rest, ":"); colon >= 0 {
		host, port = rest[:colon], rest[colon+1:]
	} else {
		host = rest
	}
	if port == "" {
		port = uriDefaultPorts[strings.ToLower(scheme)]
	}
	if host == "" || port == "" {
		return ""
	}
	if _, err := strconv.ParseUint(port, 10, 16); err != nil {
		return ""
	}
	return net.JoinHostPort(host, port)
}

// listenerEndpoint reads the reef_run_listener endpoint of the policy
// file: "<host>:<port>" of its one endpoint, or "" when the policy has no
// such network policy, more than one endpoint, or does not parse.
func listenerEndpoint(policyYAML string) string {
	var policy struct {
		NetworkPolicies map[string]struct {
			Endpoints []struct {
				Host string `yaml:"host"`
				Port int    `yaml:"port"`
			} `yaml:"endpoints"`
		} `yaml:"network_policies"`
	}
	if err := yaml.Unmarshal([]byte(policyYAML), &policy); err != nil {
		return ""
	}
	listener, ok := policy.NetworkPolicies[listenerPolicyName]
	if !ok || len(listener.Endpoints) != 1 {
		return ""
	}
	endpoint := listener.Endpoints[0]
	if endpoint.Host == "" || endpoint.Port <= 0 || endpoint.Port > 65535 {
		return ""
	}
	return net.JoinHostPort(endpoint.Host, strconv.Itoa(endpoint.Port))
}

// policyChangedReasons applies the policy_changed rule of design 4.2.1 to
// the gateway object and the CONFIG:* records. Output: the rules that
// fired ("rule_1" to "rule_8"); none when the policy did not change.
func policyChangedReasons(gw ocsfGateway, events []ocsfEvent) []string {
	var loadedHashes []string // "" for a CONFIG:LOADED record with no hash
	firstLoadedHasHash := false
	globalLoad, approved, providerDetected := false, false, false
	for _, event := range events {
		msg, _ := event.fields["msg"].(string)
		switch event.class {
		case "CONFIG:LOADED":
			hash := ""
			if m := ocsfLoadedHash.FindStringSubmatch(msg); m != nil {
				hash = m[1]
			}
			if len(loadedHashes) == 0 {
				firstLoadedHasHash = hash != ""
			}
			loadedHashes = append(loadedHashes, hash)
			if strings.Contains(msg, "(global)") {
				globalLoad = true
			}
		case "CONFIG:APPROVED", "CONFIG:MERGED", "CONFIG:UPDATED":
			approved = true
		case "CONFIG:DETECTED":
			if strings.Contains(msg, "provider_env_changed:true") {
				providerDetected = true
			}
		}
	}
	distinct := map[string]bool{}
	for _, hash := range loadedHashes {
		if hash != "" {
			distinct[hash] = true
		}
	}
	providerChanged := gw.providerCreate != gw.providerEnd

	rules := []struct {
		name  string
		fired bool
	}{
		{"rule_1", !(gw.revisionEnd == gw.revisionCreate || (gw.revisionCreate == 1 && gw.revisionEnd == 2))},
		{"rule_2", gw.revisionEnd > 2},
		// A first CONFIG:LOADED with no hash fires the rule, as in reef-core
		// ({:ok, nil} never equals {:ok, enriched}).
		{"rule_3", len(loadedHashes) > 0 && (!firstLoadedHasHash || loadedHashes[0] != gw.enrichedHash)},
		{"rule_4", len(distinct) > 1},
		{"rule_5", globalLoad},
		{"rule_6", gw.settingsCreate != gw.settingsEnd || providerChanged},
		{"rule_7", approved},
		{"rule_8", providerChanged && providerDetected},
	}
	var fired []string
	for _, rule := range rules {
		if rule.fired {
			fired = append(fired, rule.name)
		}
	}
	return fired
}

// ── Tool log (rule 12) ───────────────────────────────────────────

// checkToolLogRecords recomputes TOOL_LOG_ROOT from tool_log_records and
// compares it with the custody blob's line (rule 12).
//
// Inputs: the custody blob; the base64 tool-log records of the key.
// Output: the 113-byte records in order (none for an empty tool log), or
// the rule-12 failure.
func checkToolLogRecords(custodyData, recordsBase64 string) ([][]byte, error) {
	blob, err := base64.StdEncoding.DecodeString(recordsBase64)
	if err != nil {
		return nil, hardFailure(12, "tool_log_records is not base64")
	}
	records, err := SplitCustodyToolLogRecords(blob)
	if err != nil {
		return nil, hardFailure(12, "tool_log_records is not a whole number of 113-byte records")
	}
	want, present, err := blobToolLogRoot(strings.Split(custodyData, "\n"))
	if err != nil || !present {
		return nil, hardFailure(12, "the custody record has no single well-formed TOOL_LOG_ROOT line")
	}
	got := CustodyToolLogRoot(records)
	if !bytes.Equal(got[:], want) {
		return nil, hardFailure(12, "TOOL_LOG_ROOT recomputed from tool_log_records %x differs from the custody line %x", got, want)
	}
	return records, nil
}
