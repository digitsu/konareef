// Copyright 2026 Jerry David Chan, Konareef.ai
// SPDX-License-Identifier: Apache-2.0

// openshell_phase3_test.go — tests of the phase-3 verifier changes of the
// reef-core OpenShell adapter (story US-206; phase-3 design sections 5 and
// 6.6, and the folded konareef issues #44, #45 and #46):
//
//   - the grade ladder: the reserved gateway_attested grade, --strict and
//     the "bundle did not verify" cap by rank;
//   - X2t: the per-tool cross-check for a policy with the W20 mcp listener
//     endpoint, on the US-205 fixtures (testdata/reef_ocsf_v1/w20_*,
//     manifest.w20.json; testdata/openshell_custody/w20*);
//   - #44: a cut SUPERVISOR record is a grade reason only;
//   - #45: an OPENSHELL_LISTENER_REQUESTS overflow fails rule 1;
//   - #46: an explicit `verifiable: true`, and the precommit prev_hash
//     under rule 3.
package verify

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// w20MCPURL is the MCP URL of the W20 fixtures (the mcp endpoint on
// run_mcp_port 4102).
const w20MCPURL = "http://192.0.2.10:4102/mcp/open_brain"

// mcpRecord is an ALLOWED HTTP:POST record to the W20 MCP URL at seq, with
// the given "[msg:...]" tag content (the US-202 cut form).
func mcpRecord(t *testing.T, seq int, tag string) []byte {
	return httpRecord(t, seq, "POST", "ALLOWED POST "+w20MCPURL+" [policy:reef_run_listener engine:l7-mcp] [msg:"+tag+"]")
}

// mcpEvent decodes an mcpRecord into an event, for the cross-check
// functions that take events.
func mcpEvent(t *testing.T, seq int, tag string) ocsfEvent {
	t.Helper()
	fields := recordFields(t, mcpRecord(t, seq, tag))
	return ocsfEvent{class: "HTTP:POST", seq: uint64(seq), hasSeq: true, fields: fields}
}

// toolLogOf encodes one tool-log record per tool id.
func toolLogOf(toolIDs ...string) [][]byte {
	records := make([][]byte, len(toolIDs))
	for i, id := range toolIDs {
		records[i] = toolLogRecord(id, i)
	}
	return records
}

// repeatID returns n copies of id.
func repeatID(id string, n int) []string {
	ids := make([]string, n)
	for i := range ids {
		ids[i] = id
	}
	return ids
}

// cutSupervisorRecord is a SUPERVISOR:WARN record at seq whose msg the
// launcher cut (msg_truncated true).
func cutSupervisorRecord(t *testing.T, seq int, msg string) []byte {
	return makeRecord(t, ocsfEventTag, map[string]any{
		"v": ocsfRule, "seq": seq, "src": "sandbox", "trust": "supervisor_report",
		"class": "SUPERVISOR:WARN", "sev": "WARN", "msg": msg, "t_ms": 1791459259900, "msg_truncated": true,
	})
}

// setPolicyYAML replaces the evidence's policy_yaml and makes every value
// bound to its hash agree: the gateway policy_submitted_sha256, the
// precommit POLICY_SHA256 (and so the custody OPENSHELL_PRECOMMIT line),
// and the custody OPENSHELL_POLICY_SUBMITTED_SHA256 line.
func setPolicyYAML(t *testing.T, b *Bundle, policyYAML string) {
	t.Helper()
	b.OpenShellEvidence.PolicyYAML = policyYAML
	hash := sha256.Sum256([]byte(policyYAML))
	hexHash := hex.EncodeToString(hash[:])
	setGatewayField(t, b, "policy_submitted_sha256", hexHash)
	editPrecommit(t, b, "POLICY_SHA256", "sha256:"+hexHash)
	setCustodyLine(t, b, "OPENSHELL_POLICY_SUBMITTED_SHA256", "sha256:"+hexHash)
}

// editW20Policy loads w20.bundle.json and replaces old with new in its
// policy_yaml (exactly once).
func editW20Policy(t *testing.T, old, new string) *Bundle {
	t.Helper()
	b := loadOpenShellGolden(t, "w20.bundle.json")
	policy := b.OpenShellEvidence.PolicyYAML
	if strings.Count(policy, old) != 1 {
		t.Fatalf("policy_yaml holds %q %d times", old, strings.Count(policy, old))
	}
	setPolicyYAML(t, b, strings.Replace(policy, old, new, 1))
	return b
}

// ── Grade ladder (design 5.1, 5.2) ───────────────────────────────

// TestGradeLadder_Ranks: not_claimed < claimed < operator_attested <
// gateway_attested, and a grade that is not on the ladder ranks below all.
func TestGradeLadder_Ranks(t *testing.T) {
	ladder := []ContainmentGrade{GradeNotClaimed, GradeClaimed, GradeOperatorAttested, GradeGatewayAttested}
	for i := 1; i < len(ladder); i++ {
		if GradeRank(ladder[i-1]) >= GradeRank(ladder[i]) {
			t.Errorf("rank %s %d is not below rank %s %d", ladder[i-1], GradeRank(ladder[i-1]), ladder[i], GradeRank(ladder[i]))
		}
	}
	if GradeGatewayAttested != "gateway_attested" {
		t.Errorf("reserved grade %q", GradeGatewayAttested)
	}
	if got := GradeRank("no_such_grade"); got >= GradeRank(GradeNotClaimed) {
		t.Errorf("unknown grade rank %d", got)
	}
	for grade, want := range map[ContainmentGrade]bool{
		GradeNotClaimed: false, GradeClaimed: false, GradeOperatorAttested: true, GradeGatewayAttested: true, "no_such_grade": false,
	} {
		if AtLeastOperatorAttested(grade) != want {
			t.Errorf("AtLeastOperatorAttested(%s) = %t", grade, !want)
		}
	}
}

// TestGradeLadder_NoGoldenAboveOperatorAttested: no golden bundle grades
// above operator_attested. AssessContainment never returns the reserved
// gateway_attested (design 5.1).
func TestGradeLadder_NoGoldenAboveOperatorAttested(t *testing.T) {
	paths, err := filepath.Glob(filepath.Join(openShellCustodyDir, "*.bundle.json"))
	if err != nil || len(paths) < 7 {
		t.Fatalf("golden bundles %v (%v)", paths, err)
	}
	paths = append(paths, "testdata/parity-real-1.bundle.json")
	for _, path := range paths {
		b := loadBundleFile(t, path)
		a, _ := AssessContainment(b)
		r := Verify(b)
		for _, grade := range []ContainmentGrade{a.Grade, r.Containment.Grade} {
			if GradeRank(grade) > GradeRank(GradeOperatorAttested) || grade == GradeGatewayAttested || GradeRank(grade) < 0 {
				t.Errorf("%s: grade %q is above operator_attested or not on the ladder", path, grade)
			}
		}
	}
}

// TestGradeLadder_CapAndStrictByRank: the "bundle did not verify" cap and
// --strict compare by rank (design 5.2). A test-only grade above
// operator_attested is capped to claimed when the bundle did not verify,
// and passes --strict; an unknown grade fails --strict.
func TestGradeLadder_CapAndStrictByRank(t *testing.T) {
	const testOnlyAbove ContainmentGrade = "test_only_above_operator_attested"
	containmentGradeRanks[testOnlyAbove] = GradeRank(GradeGatewayAttested) + 1
	t.Cleanup(func() { delete(containmentGradeRanks, testOnlyAbove) })

	for _, grade := range []ContainmentGrade{testOnlyAbove, GradeGatewayAttested, GradeOperatorAttested} {
		capped := capContainmentGrade(ContainmentAssessment{Grade: grade, Form: "full", Reasons: []string{}}, false)
		if capped.Grade != GradeClaimed || !slices.Equal(capped.Reasons, []string{reasonBundleNotVerified}) {
			t.Errorf("%s, not verified: %s %v, want claimed with the not-verified reason", grade, capped.Grade, capped.Reasons)
		}
		kept := capContainmentGrade(ContainmentAssessment{Grade: grade, Form: "full", Reasons: []string{}}, true)
		if kept.Grade != grade || len(kept.Reasons) != 0 {
			t.Errorf("%s, verified: %s %v, want unchanged", grade, kept.Grade, kept.Reasons)
		}
		if strictContainmentFails(kept) {
			t.Errorf("%s fails --strict", grade)
		}
	}
	for _, grade := range []ContainmentGrade{GradeClaimed, GradeNotClaimed, "no_such_grade"} {
		a := capContainmentGrade(ContainmentAssessment{Grade: grade, Form: "full", Reasons: []string{}}, false)
		if a.Grade != grade || len(a.Reasons) != 0 {
			t.Errorf("%s, not verified: %s %v, want unchanged", grade, a.Grade, a.Reasons)
		}
		if !strictContainmentFails(a) {
			t.Errorf("%s passes --strict", grade)
		}
	}
	if strictContainmentFails(ContainmentAssessment{Grade: GradeNotClaimed}) {
		t.Error("--strict fails a bundle without isolation backend lines")
	}
}

// TestGradeLadder_StrictW20Goldens: --strict passes the verifiable W20
// bundle and fails the public and the cut W20 bundles, as for the phase-2
// goldens (TestContainment_Strict keeps those).
func TestGradeLadder_StrictW20Goldens(t *testing.T) {
	for name, pass := range map[string]bool{
		"w20.bundle.json":        true,
		"w20.public.bundle.json": false,
		"w20_cut.bundle.json":    false,
	} {
		t.Run(name, func(t *testing.T) {
			b := loadOpenShellGolden(t, name)
			signBundle(t, b)
			if r := Verify(b); !r.OK {
				t.Fatalf("default mode failed: %v", r.Divergences)
			}
			r := VerifyStrict(b)
			if r.OK != pass {
				t.Errorf("--strict ok %t, want %t: %v", r.OK, pass, r.Divergences)
			}
			if !pass && !containsAny(r.Divergences, "--strict requires containment grade operator_attested") {
				t.Errorf("--strict divergences lack the containment rule: %v", r.Divergences)
			}
		})
	}
}

// ── W20 fixtures (US-205) ────────────────────────────────────────

// TestOCSFVectors_W20Manifest: the W20 vectors of manifest.w20.json have
// the manifest roots and counts, are gapless with no policy change, and
// their listener lines over both endpoints equal the served count of the
// matching custody golden.
func TestOCSFVectors_W20Manifest(t *testing.T) {
	var manifest struct {
		Rule    string `json:"rule"`
		Vectors []struct {
			Name        string `json:"name"`
			File        string `json:"file"`
			RecordCount int    `json:"record_count"`
			Root        string `json:"root"`
		} `json:"vectors"`
	}
	raw, err := os.ReadFile(filepath.Join(ocsfVectorDir, "manifest.w20.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(raw, &manifest); err != nil {
		t.Fatal(err)
	}
	if manifest.Rule != ocsfRule || len(manifest.Vectors) != 2 {
		t.Fatalf("manifest.w20.json: rule %q, %d vectors", manifest.Rule, len(manifest.Vectors))
	}
	endpoints := []string{"192.0.2.10:4100", "192.0.2.10:4102"}
	wantSeen := map[string]uint64{"w20_run": 7, "w20_cut": 2}
	for _, vector := range manifest.Vectors {
		records := readRecordsFile(t, filepath.Join(ocsfVectorDir, vector.File))
		if len(records) != vector.RecordCount {
			t.Errorf("%s: %d records, manifest says %d", vector.Name, len(records), vector.RecordCount)
		}
		root := OCSFRoot(records)
		if hex.EncodeToString(root[:]) != vector.Root {
			t.Errorf("%s: root %x, manifest says %s", vector.Name, root, vector.Root)
		}
		gatewayRaw, err := os.ReadFile(filepath.Join(ocsfVectorDir, vector.Name+".gateway.json"))
		if err != nil {
			t.Fatal(err)
		}
		gateway, err := readOCSFGateway(gatewayRaw)
		if err != nil {
			t.Fatalf("%s.gateway.json: %v", vector.Name, err)
		}
		leaves, err := readOCSFLeaves(leavesOf(records))
		if err != nil {
			t.Fatalf("%s: %v", vector.Name, err)
		}
		summary := summarizeOCSF(leaves.header, leaves.events, gateway, leaves.header.sandboxID, endpoints, true)
		if len(summary.gaplessReasons) != 0 || len(summary.policyChangedReasons) != 0 || summary.supervisorCut {
			t.Errorf("%s: gapless %v, policy_changed %v, supervisor cut %t", vector.Name, summary.gaplessReasons, summary.policyChangedReasons, summary.supervisorCut)
		}
		if summary.listenerSeen == nil || *summary.listenerSeen != wantSeen[vector.Name] {
			t.Errorf("%s: listener_seen %v, want %d", vector.Name, summary.listenerSeen, wantSeen[vector.Name])
		}
		// One endpoint alone counts fewer lines: both endpoints are needed.
		if one := listenerSeen(leaves.events, endpoints[:1]); one >= wantSeen[vector.Name] {
			t.Errorf("%s: run_port alone gives %d listener lines", vector.Name, one)
		}
	}
}

// TestW20Goldens_Grades: the US-205 custody goldens verify, and rule 10
// passes with the provider attached (OPENSHELL_PROVIDER_ENV_DIGEST is not
// the phase-2 value). The verifiable bundle is operator_attested with X2t
// consistent; the cut bundle is claimed with X2t not_checked (incomplete);
// the public bundle is claimed and redacted.
func TestW20Goldens_Grades(t *testing.T) {
	full := loadOpenShellGolden(t, "full.bundle.json")
	w20 := loadOpenShellGolden(t, "w20.bundle.json")
	phase2Digest := custodyLines(t, full)["OPENSHELL_PROVIDER_ENV_DIGEST"]
	if w20Digest := custodyLines(t, w20)["OPENSHELL_PROVIDER_ENV_DIGEST"]; w20Digest == phase2Digest {
		t.Fatalf("the W20 provider digest is the phase-2 value %s", w20Digest)
	}

	cases := []struct {
		name     string
		grade    ContainmentGrade
		outcome  string
		reason   string
		redacted bool
		seen     uint64
	}{
		{"w20.bundle.json", GradeOperatorAttested, "consistent", "", false, 7},
		{"w20_cut.bundle.json", GradeClaimed, "not_checked", "incomplete", false, 2},
		{"w20.public.bundle.json", GradeClaimed, "not_checked", "redacted", true, 0},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := Verify(loadOpenShellGolden(t, c.name))
			if !r.OK {
				t.Fatalf("divergences %v", r.Divergences)
			}
			a := r.Containment
			if a.Grade != c.grade || a.CrossCheck.Outcome != c.outcome || a.CrossCheck.Reason != c.reason || a.Redacted != c.redacted {
				t.Errorf("grade %s cross_check %+v redacted %t, want %s %s (%s) %t", a.Grade, a.CrossCheck, a.Redacted, c.grade, c.outcome, c.reason, c.redacted)
			}
			if c.grade == GradeOperatorAttested && len(a.Reasons) != 0 {
				t.Errorf("operator_attested with reasons %v", a.Reasons)
			}
			if c.reason == "incomplete" && !slices.Contains(a.Reasons, "cross-check not_checked (incomplete)") {
				t.Errorf("reasons %v", a.Reasons)
			}
			if !c.redacted && (a.ListenerSeen == nil || *a.ListenerSeen != c.seen || *a.ListenerServed != c.seen) {
				t.Errorf("listener seen %v served %v, want %d", a.ListenerSeen, a.ListenerServed, c.seen)
			}
		})
	}
}

// custodyLines returns the "KEY: value" lines of the custody blob by key.
func custodyLines(t *testing.T, b *Bundle) map[string]string {
	t.Helper()
	lines := map[string]string{}
	for _, line := range strings.Split(custodyLink(t, b).Data, "\n") {
		if key, value, ok := strings.Cut(line, ": "); ok {
			lines[key] = value
		}
	}
	return lines
}

// ── X2t (design 6.6) ─────────────────────────────────────────────

// TestReadListenerPolicy_Shapes: the phase-2 one-endpoint listener keeps
// the old X2; the W20 two-endpoint listener gives the mcp endpoint and the
// brokered names; every other shape gives no endpoints (fail closed).
func TestReadListenerPolicy_Shapes(t *testing.T) {
	phase2 := readListenerPolicy(loadOpenShellGolden(t, "full.bundle.json").OpenShellEvidence.PolicyYAML)
	if !slices.Equal(phase2.endpoints, []string{"192.0.2.10:4100"}) || phase2.mcpEndpoint != "" || phase2.brokeredTools != nil {
		t.Errorf("phase-2 policy: %+v", phase2)
	}
	w20 := readListenerPolicy(loadOpenShellGolden(t, "w20.bundle.json").OpenShellEvidence.PolicyYAML)
	if !slices.Equal(w20.endpoints, []string{"192.0.2.10:4100", "192.0.2.10:4102"}) || w20.mcpEndpoint != "192.0.2.10:4102" ||
		!slices.Equal(w20.brokeredTools, []string{"jira.get_issue"}) {
		t.Errorf("W20 policy: %+v", w20)
	}

	listener := func(endpoints string) string {
		return "network_policies:\n  reef_run_listener:\n    endpoints:\n" + endpoints
	}
	rest := `      - {host: "192.0.2.10", port: 4100, protocol: rest}` + "\n"
	mcp := `      - {host: "192.0.2.10", port: 4102, protocol: mcp}` + "\n"
	refused := map[string]string{
		"two rest endpoints":   listener(rest + `      - {host: "192.0.2.10", port: 4102, protocol: rest}` + "\n"),
		"two mcp endpoints":    listener(mcp + `      - {host: "192.0.2.10", port: 4103, protocol: mcp}` + "\n"),
		"three endpoints":      listener(rest + mcp + `      - {host: "192.0.2.10", port: 4103}` + "\n"),
		"same authority twice": listener(rest + `      - {host: "192.0.2.10", port: 4100, protocol: mcp}` + "\n"),
		"no port":              listener(rest + `      - {host: "192.0.2.10", protocol: mcp}` + "\n"),
		"no endpoints":         listener(""),
	}
	for name, policy := range refused {
		if got := readListenerPolicy(policy); len(got.endpoints) != 0 || got.mcpEndpoint != "" {
			t.Errorf("%s: %+v, want no endpoints", name, got)
		}
	}
}

// TestBrokeredToolNames_AnyToolFallback: the "any tool" fallback (design
// 6.3) gives no brokered names, so X2t counts the static tools only. A
// static name in the allow list is never brokered.
func TestBrokeredToolNames_AnyToolFallback(t *testing.T) {
	policy := func(mcpBlock, rules string) string {
		return `network_policies:
  reef_run_listener:
    endpoints:
      - {host: "192.0.2.10", port: 4100, protocol: rest}
      - host: "192.0.2.10"
        port: 4102
        protocol: mcp
` + mcpBlock + `        rules:
` + rules
	}
	named := `          - allow: {method: tools/call, tool: {any: ["openbrain.recall", "jira.get_issue"]}}` + "\n"
	cases := map[string]struct {
		yaml string
		want []string
	}{
		"named list":           {policy("", named), []string{"jira.get_issue"}},
		"all known methods":    {policy("        mcp: {allow_all_known_mcp_methods: true}\n", named), nil},
		"tools/call, no tool":  {policy("", `          - allow: {method: tools/call}`+"\n"), nil},
		"empty any list":       {policy("", `          - allow: {method: tools/call, tool: {any: []}}`+"\n"), nil},
		"non-strict tool name": {policy("", `          - allow: {method: tools/call, tool: {any: ["*"]}}`+"\n"), nil},
	}
	for name, c := range cases {
		got := readListenerPolicy(c.yaml)
		if got.mcpEndpoint != "192.0.2.10:4102" || !slices.Equal(got.brokeredTools, c.want) || got.anyToolFallback != (c.want == nil) {
			t.Errorf("%s: %+v, want brokered %v", name, got, c.want)
		}
	}

	// Review F1: on a bundle, the fallback keeps the grade and adds an
	// informational line; the named-list W20 golden has no such line.
	if a := mustAssess(t, loadOpenShellGolden(t, "w20.bundle.json")); slices.Contains(a.Informational, infoX2tStaticOnly) {
		t.Errorf("named list: informational %v", a.Informational)
	}
	fallbackBundle := editW20Policy(t, "          strict_tool_names: true\n", "          strict_tool_names: true\n          allow_all_known_mcp_methods: true\n")
	setToolLog(t, fallbackBundle, repeatID("jira.get_issue", 5)...)
	if a := mustAssess(t, fallbackBundle); a.Grade != GradeOperatorAttested || a.CrossCheck.Outcome != "consistent" ||
		!slices.Contains(a.Informational, infoX2tStaticOnly) {
		t.Errorf("fallback bundle: grade %s cross_check %+v informational %v", a.Grade, a.CrossCheck, a.Informational)
	}

	// On the W20 run, a fallback policy does not count brokered calls: a
	// tool log with more jira.get_issue records than OCSF calls stays
	// consistent, while a static excess is still inconsistent.
	b := loadOpenShellGolden(t, "w20.bundle.json")
	leaves, err := readOCSFLeaves(b.OpenShellEvidence.Leaves)
	if err != nil {
		t.Fatal(err)
	}
	fallback := readListenerPolicy(cases["all known methods"].yaml)
	candidates := x2tCandidates(openBrainToolNames, fallback.brokeredTools)
	if row, incomplete := crossCheckX2t(leaves.events, toolLogOf(repeatID("jira.get_issue", 5)...), fallback.mcpEndpoint, candidates); row != "" || incomplete {
		t.Errorf("fallback, brokered excess: row %q incomplete %t, want consistent", row, incomplete)
	}
	if row, _ := crossCheckX2t(leaves.events, toolLogOf(OpenBrainToolLogID("proofs.list")), fallback.mcpEndpoint, candidates); row == "" {
		t.Error("fallback, static excess: consistent, want an X2 row")
	}
}

// TestX2t_W20Goldens: the X2t goldens of design 6.6 on the W20 bundle
// (OCSF: openbrain.recall twice, jira.get_issue twice, one denied
// jira.delete_issue), with the tool log changed per case.
func TestX2t_W20Goldens(t *testing.T) {
	cases := []struct {
		name    string
		toolLog []string
		outcome string
		row     string // a part of the X2 row, for inconsistent
	}{
		// A tool-log hash in C with no OCSF tool call is inconsistent.
		{"static tool-log call with no OCSF call", []string{OpenBrainToolLogID("proofs.list")}, "inconsistent", "proofs.list 1 in the tool log, 0 in OCSF"},
		// An OCSF call with no tool-log record is consistent.
		{"OCSF calls with no tool-log record", []string{"bash"}, "consistent", ""},
		// A brokered call's tool_id is its tools/call name, no prefix.
		{"brokered tool_id byte for byte", []string{"jira.get_issue", "jira.get_issue"}, "consistent", ""},
		{"brokered calls above OCSF", repeatID("jira.get_issue", 3), "inconsistent", "jira.get_issue 3 in the tool log, 2 in OCSF"},
		// A runtime record under a rendered name is not counted.
		{"brokered call under a rendered name", repeatID("open_brain_jira_get_issue", 5), "consistent", ""},
		// A static-tool record under an unexpected rendered name can only
		// be missed.
		{"static tool under an unexpected name", append(repeatID("openbrain.recall", 5), repeatID("open_brain.openbrain.recall", 5)...), "consistent", ""},
		{"static calls above OCSF", openBrainIDs(3), "inconsistent", "openbrain.recall 3 in the tool log, 2 in OCSF"},
		// The denied call is not an allowed tools/call.
		{"denied call is not counted", []string{"jira.delete_issue"}, "consistent", ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			b := loadOpenShellGolden(t, "w20.bundle.json")
			setToolLog(t, b, c.toolLog...)
			a := mustAssess(t, b)
			if a.CrossCheck.Outcome != c.outcome {
				t.Fatalf("cross_check %+v, want %s", a.CrossCheck, c.outcome)
			}
			if c.outcome == "inconsistent" {
				if len(a.CrossCheck.Rows) != 1 || !strings.HasPrefix(a.CrossCheck.Rows[0], "X2: ") || !strings.Contains(a.CrossCheck.Rows[0], c.row) ||
					!strings.Contains(a.CrossCheck.Rows[0], w20MCPURL) {
					t.Errorf("rows %v, want an X2 row with %q", a.CrossCheck.Rows, c.row)
				}
				if a.Grade != GradeClaimed {
					t.Errorf("grade %s", a.Grade)
				}
			} else if a.Grade != GradeOperatorAttested {
				t.Errorf("grade %s reasons %v", a.Grade, a.Reasons)
			}
		})
	}
}

// TestX2t_CutRecordIsNeverInconsistent: on the w20_cut bundle (a
// 100-character name cut after 56 characters) X2t is not_checked
// (incomplete), also with a tool log far above the OCSF calls.
func TestX2t_CutRecordIsNeverInconsistent(t *testing.T) {
	for name, toolLog := range map[string][]string{
		"fixture tool log": nil,
		"static excess":    openBrainIDs(9),
		"brokered excess":  repeatID("jira.get_issue", 9),
	} {
		t.Run(name, func(t *testing.T) {
			b := loadOpenShellGolden(t, "w20_cut.bundle.json")
			if toolLog != nil {
				setToolLog(t, b, toolLog...)
			}
			a := mustAssess(t, b)
			if a.CrossCheck.Outcome != "not_checked" || a.CrossCheck.Reason != "incomplete" || a.Grade != GradeClaimed {
				t.Errorf("cross_check %+v grade %s, want not_checked (incomplete), claimed", a.CrossCheck, a.Grade)
			}
		})
	}
}

// TestMCPToolNames_US202Captures: the completeness rule on the record text
// of the US-202 captures (ocsf-all-c.txt): a value is complete only when a
// space follows it inside the [msg:] tag.
func TestMCPToolNames_US202Captures(t *testing.T) {
	cases := []struct {
		name     string
		tag      string
		names    []string
		complete bool
	}{
		{"short name, cut endpoint", "JSONRPC_L7_REQUEST decision=allow rule_methods=tools/call tools=open_brain.search http_method=POST endpoint=192.0.2.10:4...",
			[]string{"open_brain.search"}, true},
		{"100-character name cut after 56", "JSONRPC_L7_REQUEST decision=allow rule_methods=tools/call tools=t" + strings.Repeat("x", 55) + "...",
			nil, false},
		{"batch of two", "JSONRPC_L7_REQUEST decision=allow rule_methods=tools/call,tools/call tools=open_brain.search,open_brain.capture http_met...",
			[]string{"open_brain.search", "open_brain.capture"}, true},
		{"no tool", "JSONRPC_L7_REQUEST decision=allow rule_methods=initialize tools=- http_method=POST endpoint=192.0.2.10:4203/mcp/open_bra...",
			nil, true},
		{"cut right after the value", "JSONRPC_L7_REQUEST decision=allow rule_methods=tools/call tools=openbrain.recall...", nil, false},
		{"space right before the cut", "JSONRPC_L7_REQUEST decision=allow rule_methods=tools/call tools=openbrain.recall ...", []string{"openbrain.recall"}, true},
		{"cut before tools=", "JSONRPC_L7_REQUEST decision=allow rule_methods=tools/call,tools/call,tools/call,tools/call,tool...", nil, false},
		{"two tools= fields", "JSONRPC_L7_REQUEST decision=allow rule_methods=tools/call tools=a.b tools=c.d http_method=POST ...", nil, false},
		{"empty name in a batch", "JSONRPC_L7_REQUEST decision=allow rule_methods=tools/call,tools/call,tools/call tools=a.b,,c.d http_method=POST ...", nil, false},
		// Review F2: the tools/call count of rule_methods must equal the
		// number of names (a deduplicated batch is incomplete).
		{"batch of two, one name", "JSONRPC_L7_REQUEST decision=allow rule_methods=tools/call,tools/call tools=openbrain.recall http_method=POST ...", nil, false},
		{"tools/call with no name", "JSONRPC_L7_REQUEST decision=allow rule_methods=tools/call tools=- http_method=POST ...", nil, false},
		{"no rule_methods", "JSONRPC_L7_REQUEST decision=allow tools=openbrain.recall http_method=POST ...", nil, false},
		// Hermes !183 note 9927: only a tools/call record gives names. A
		// non-call record with a strict tool name gives none.
		{"initialize with a tool name", "JSONRPC_L7_REQUEST decision=allow rule_methods=initialize tools=openbrain.search http_method=POST endpoint=192.0.2.10:4...", nil, true},
		{"tools/list with a tool name", "JSONRPC_L7_REQUEST decision=allow rule_methods=tools/list tools=openbrain.recall http_method=POST ...", nil, true},
		{"mixed batch", "JSONRPC_L7_REQUEST decision=allow rule_methods=tools/list,tools/call tools=openbrain.recall http_method=POST ...", nil, false},
		{"rule_methods cut", "JSONRPC_L7_REQUEST decision=allow rule_methods=tools/call,tools/ca...", nil, false},
		{"empty method entry", "JSONRPC_L7_REQUEST decision=allow rule_methods=tools/call, tools=a.b http_method=POST ...", nil, false},
		{"two rule_methods", "JSONRPC_L7_REQUEST rule_methods=initialize decision=allow rule_methods=tools/call tools=a.b http_method=POST ...", nil, false},
		{"tools= before rule_methods", "JSONRPC_L7_REQUEST decision=allow tools=a.b rule_methods=tools/call http_method=POST ...", nil, false},
	}
	for _, c := range cases {
		msg := "ALLOWED POST " + w20MCPURL + " [policy:reef_run_listener engine:l7-mcp] [msg:" + c.tag + "]"
		names, complete := mcpToolNames(msg)
		if complete != c.complete || !slices.Equal(names, c.names) {
			t.Errorf("%s: names %v complete %t, want %v %t", c.name, names, complete, c.names, c.complete)
		}
	}
	for name, msg := range map[string]string{
		"no tag":     "ALLOWED POST " + w20MCPURL + " [policy:reef_run_listener engine:l7-mcp]",
		"two tags":   "ALLOWED POST " + w20MCPURL + " [msg:x tools=a.b y] [msg:JSONRPC_L7_REQUEST tools=c.d http_method=POST ...]",
		"no closing": "ALLOWED POST " + w20MCPURL + " [policy:reef_run_listener engine:l7-mcp] [msg:JSONRPC_L7_REQUEST tools=a.b http_method=POST ...",
	} {
		if _, complete := mcpToolNames(msg); complete {
			t.Errorf("%s: complete", name)
		}
	}

	// In X2t, the complete short-name record counts, and the cut record
	// makes the check incomplete whatever the tool log holds.
	candidates := x2tCandidates(openBrainToolNames, []string{"open_brain.search"})
	complete := []ocsfEvent{mcpEvent(t, 1, cases[0].tag)}
	if row, incomplete := crossCheckX2t(complete, toolLogOf("open_brain.search"), "192.0.2.10:4102", candidates); row != "" || incomplete {
		t.Errorf("complete record: row %q incomplete %t", row, incomplete)
	}
	cut := append(complete, mcpEvent(t, 2, cases[1].tag))
	if row, incomplete := crossCheckX2t(cut, toolLogOf(repeatID("open_brain.search", 4)...), "192.0.2.10:4102", candidates); row != "" || !incomplete {
		t.Errorf("cut record: row %q incomplete %t, want incomplete", row, incomplete)
	}
}

// TestX2t_DotUnderscoreLimit: OpenBrainToolLogID maps the static names
// "a.b" and "a_b" to one id, so X2t compares it with the OCSF calls of
// both names and cannot tell them apart (design 6.6, "Limits"). Brokered
// ids have no such change: "a.b" and "a_b" stay two candidates.
func TestX2t_DotUnderscoreLimit(t *testing.T) {
	static := x2tCandidates([]string{"a.b", "a_b"}, nil)
	if len(static) != 1 || !slices.Equal(static[0].ocsfNames, []string{"a.b", "a_b"}) ||
		static[0].hash != sha256.Sum256([]byte("open_brain_a_b")) {
		t.Fatalf("static candidates %+v", static)
	}
	tag := func(name string) string {
		return "JSONRPC_L7_REQUEST decision=allow rule_methods=tools/call tools=" + name + " http_method=POST endpoint=192.0.2.10:41..."
	}
	twoDots := []ocsfEvent{mcpEvent(t, 1, tag("a.b")), mcpEvent(t, 2, tag("a.b"))}
	// Two a_b calls in the tool log, two a.b calls in OCSF: X2t misses it.
	if row, _ := crossCheckX2t(twoDots, toolLogOf(repeatID("open_brain_a_b", 2)...), "192.0.2.10:4102", static); row != "" {
		t.Errorf("static a.b/a_b: row %q, want the limit (no row)", row)
	}
	if row, _ := crossCheckX2t(twoDots, toolLogOf(repeatID("open_brain_a_b", 3)...), "192.0.2.10:4102", static); !strings.Contains(row, "a.b/a_b 3 in the tool log, 2 in OCSF") {
		t.Errorf("static a.b/a_b above both: row %q", row)
	}

	brokered := x2tCandidates(nil, []string{"a.b", "a_b"})
	if len(brokered) != 2 {
		t.Fatalf("brokered candidates %+v", brokered)
	}
	oneDot := []ocsfEvent{mcpEvent(t, 1, tag("a.b"))}
	if row, _ := crossCheckX2t(oneDot, toolLogOf("a_b"), "192.0.2.10:4102", brokered); !strings.Contains(row, "a_b 1 in the tool log, 0 in OCSF") {
		t.Errorf("brokered a_b with an a.b call: row %q, want inconsistent", row)
	}
}

// TestX2t_OldBundlesKeepX2: the phase-2 golden has no mcp endpoint, so the
// old X2 runs: a tool log above the POST count fails with the old row.
func TestX2t_OldBundlesKeepX2(t *testing.T) {
	b := loadOpenShellGolden(t, "full.bundle.json")
	if listener := readListenerPolicy(b.OpenShellEvidence.PolicyYAML); listener.mcpEndpoint != "" {
		t.Fatalf("phase-2 golden has an mcp endpoint: %+v", listener)
	}
	setToolLog(t, b, openBrainIDs(50)...)
	a := mustAssess(t, b)
	if a.CrossCheck.Outcome != "inconsistent" || len(a.CrossCheck.Rows) != 1 ||
		!strings.Contains(a.CrossCheck.Rows[0], "Open Brain tool calls in the tool log") {
		t.Errorf("cross_check %+v, want the old X2 row", a.CrossCheck)
	}
}

// ── konareef #44: a cut SUPERVISOR record ────────────────────────

// TestSupervisorCut_GradeReasonOnly: a SUPERVISOR record with
// msg_truncated true is a grade reason (grade claimed, X2 not run), and
// not a gapless reason. OCSF_STREAM_GAPLESS recomputes as today, so rule
// 10 gives the same result for an old (phase-2) and a new (W20) bundle:
// the line true passes, and a cut record that still shows drop text needs
// the line false, as before.
func TestSupervisorCut_GradeReasonOnly(t *testing.T) {
	bundles := map[string]struct {
		base string
		seq  int
	}{
		"old bundle": {"full.bundle.json", 61},
		"new bundle": {"w20.bundle.json", 12},
	}
	for name, base := range bundles {
		t.Run(name, func(t *testing.T) {
			add := func(t *testing.T, msg string) *Bundle {
				b := loadOpenShellGolden(t, base.base)
				setRecords(t, b, appendBeforeEnd(t, evidenceRecords(t, b), cutSupervisorRecord(t, base.seq, msg), base.seq))
				return b
			}
			b := add(t, "supervisor log text cut at 512 bytes")
			a := mustAssess(t, b)
			if a.Gapless == nil || !*a.Gapless {
				t.Errorf("gapless %v, want true", a.Gapless)
			}
			if a.Grade != GradeClaimed || !slices.Contains(a.Reasons, reasonSupervisorCut) {
				t.Errorf("grade %s reasons %v, want claimed with %q", a.Grade, a.Reasons, reasonSupervisorCut)
			}
			if a.CrossCheck.Outcome != "not_checked" || a.CrossCheck.Reason != "incomplete" {
				t.Errorf("cross_check %+v, want not_checked (incomplete)", a.CrossCheck)
			}
			if r := Verify(b); !r.OK {
				t.Errorf("Verify: %v", r.Divergences)
			}

			// The derivation of OCSF_STREAM_GAPLESS does not change: the
			// line false on the same records fails rule 10.
			setCustodyLine(t, b, "OCSF_STREAM_GAPLESS", "false")
			var ce *ContainmentError
			if _, err := AssessContainment(b); !errorAs(err, &ce) || ce.Rule != 10 {
				t.Errorf("line false: %v, want a rule-10 failure", err)
			}

			// A cut record that shows drop text is still a gapless reason,
			// as today: the line true fails rule 10.
			dropped := add(t, "log push channel full, dropping lines")
			if _, err := AssessContainment(dropped); !errorAs(err, &ce) || ce.Rule != 10 {
				t.Errorf("drop text with the line true: %v, want a rule-10 failure", err)
			}
			setCustodyLine(t, dropped, "OCSF_STREAM_GAPLESS", "false")
			a = mustAssess(t, dropped)
			if a.Gapless == nil || *a.Gapless || !slices.Contains(a.Reasons, reasonSupervisorCut) {
				t.Errorf("drop text: gapless %v reasons %v", a.Gapless, a.Reasons)
			}
		})
	}
}

// ── konareef #45: OPENSHELL_LISTENER_REQUESTS ────────────────────

// TestListenerRequests_MalformedFailsRule1: a count above 64 bits and a
// value that is not a number fail rule 1 as a malformed line.
func TestListenerRequests_MalformedFailsRule1(t *testing.T) {
	for _, value := range []string{"18446744073709551616", "99999999999999999999999", "seven", "-1", "07"} {
		b := loadOpenShellGolden(t, "full.bundle.json")
		setCustodyLine(t, b, "OPENSHELL_LISTENER_REQUESTS", value)
		var ce *ContainmentError
		_, err := AssessContainment(b)
		if !errorAs(err, &ce) || ce.Rule != 1 || !strings.Contains(ce.Msg, "malformed line OPENSHELL_LISTENER_REQUESTS") {
			t.Errorf("%q: %v, want a rule-1 malformed line", value, err)
		}
	}
	b := loadOpenShellGolden(t, "full.bundle.json")
	setCustodyLine(t, b, "OPENSHELL_LISTENER_REQUESTS", "18446744073709551615")
	if a, err := AssessContainment(b); err != nil || a.ListenerServed == nil || *a.ListenerServed != 18446744073709551615 {
		t.Errorf("the largest 64-bit count: %v %v", a.ListenerServed, err)
	}
}

// ── konareef #46: verifiable and the precommit prev_hash ─────────

// TestVerifiable_ExplicitTrueForTheFullGrade: a bundle without the
// `verifiable` field is not operator_attested.
func TestVerifiable_ExplicitTrueForTheFullGrade(t *testing.T) {
	for _, base := range []string{"full.bundle.json", "w20.bundle.json"} {
		b := loadOpenShellGolden(t, base)
		b.Verifiable = nil
		a := mustAssess(t, b)
		if a.Grade != GradeClaimed || !slices.Contains(a.Reasons, reasonVerifiableUnstated) {
			t.Errorf("%s: grade %s reasons %v, want claimed with %q", base, a.Grade, a.Reasons, reasonVerifiableUnstated)
		}
	}
}

// TestPrecommit_PrevHashUnderRule3: the precommit link must follow the
// openbrain_snapshot link and name it in prev_hash (rule 3).
func TestPrecommit_PrevHashUnderRule3(t *testing.T) {
	precommitIndex := func(b *Bundle) int {
		return slices.IndexFunc(b.Chain, func(l ChainLink) bool { return l.ProofType == "openshell_precommit" })
	}
	cases := map[string]func(t *testing.T, b *Bundle){
		"prev_hash names another link": func(t *testing.T, b *Bundle) {
			other := b.Chain[0].Hash
			b.Chain[precommitIndex(b)].PrevHash = &other
		},
		"prev_hash null": func(t *testing.T, b *Bundle) {
			b.Chain[precommitIndex(b)].PrevHash = nil
		},
		"precommit before the snapshot": func(t *testing.T, b *Bundle) {
			i := precommitIndex(b)
			b.Chain[i-1], b.Chain[i] = b.Chain[i], b.Chain[i-1]
			rechain(b)
			setCustodyLine(t, b, "OPENSHELL_PRECOMMIT", "sha256:"+b.Chain[i-1].Hash)
		},
	}
	for name, change := range cases {
		t.Run(name, func(t *testing.T) {
			b := goldenVariant{name: name, base: "full.bundle.json", change: change}.build(t)
			var ce *ContainmentError
			if _, err := AssessContainment(b); !errorAs(err, &ce) || ce.Rule != 3 {
				t.Errorf("%v, want a rule-3 failure", err)
			}
		})
	}
}

// TestX2t_BrokeredRenderingMergesWithStatic (review F3): a brokered name
// whose runtime rendering is a static tool's id (brokered plan_get.state,
// static plan.get_state: both open_brain_plan_get_state) is merged with the
// static candidate. A runtime record of the brokered call then counts
// against the OCSF calls of both names, so an honest run stays consistent.
func TestX2t_BrokeredRenderingMergesWithStatic(t *testing.T) {
	candidates := x2tCandidates(openBrainToolNames, []string{"plan_get.state"})
	staticIndex := slices.IndexFunc(candidates, func(c x2tCandidate) bool { return c.ocsfNames[0] == "plan.get_state" })
	if staticIndex < 0 || !slices.Equal(candidates[staticIndex].ocsfNames, []string{"plan.get_state", "plan_get.state"}) {
		t.Fatalf("static candidate %+v", candidates)
	}
	if len(candidates) != len(openBrainToolNames)+1 {
		t.Errorf("%d candidates, want the static ones and one brokered", len(candidates))
	}

	// Golden: the W20 bundle with plan_get.state in the allow list and two
	// allowed plan_get.state calls; the tool log has the runtime rendering
	// of both calls.
	b := editW20Policy(t, `                  - "jira.get_issue"`, `                  - "jira.get_issue"
                  - "plan_get.state"`)
	tag := "JSONRPC_L7_REQUEST decision=allow rule_methods=tools/call tools=plan_get.state http_method=POST endpoint=192.0.2.10:41..."
	records := appendBeforeEnd(t, evidenceRecords(t, b), mcpRecord(t, 12, tag), 12)
	records = appendBeforeEnd(t, records, mcpRecord(t, 13, tag), 13)
	setRecords(t, b, records)
	setCustodyLine(t, b, "OPENSHELL_LISTENER_REQUESTS", "9")
	setToolLog(t, b, "bash", "open_brain_plan_get_state", "open_brain_plan_get_state")
	a := mustAssess(t, b)
	if a.Grade != GradeOperatorAttested || a.CrossCheck.Outcome != "consistent" {
		t.Errorf("grade %s cross_check %+v reasons %v, want operator_attested, consistent", a.Grade, a.CrossCheck, a.Reasons)
	}
	// A third rendered record has no call behind it: inconsistent.
	setToolLog(t, b, repeatID("open_brain_plan_get_state", 3)...)
	if a := mustAssess(t, b); a.CrossCheck.Outcome != "inconsistent" ||
		!strings.Contains(strings.Join(a.CrossCheck.Rows, ""), "plan.get_state/plan_get.state 3 in the tool log, 2 in OCSF") {
		t.Errorf("cross_check %+v, want inconsistent", a.CrossCheck)
	}
}

// TestX2t_NonCallRecordCannotStandInForACall (Hermes !183 note 9927): on
// the W20 run, an allowed MCP record whose rule_methods is not tools/call
// (here initialize) but whose tools= field names a static tool does not
// count as a call: a tool-log record of that tool with no tools/call
// record stays inconsistent. A batch with a mismatched count is incomplete.
func TestX2t_NonCallRecordCannotStandInForACall(t *testing.T) {
	add := func(t *testing.T, tag string) *Bundle {
		b := loadOpenShellGolden(t, "w20.bundle.json")
		setRecords(t, b, appendBeforeEnd(t, evidenceRecords(t, b), mcpRecord(t, 12, tag), 12))
		setCustodyLine(t, b, "OPENSHELL_LISTENER_REQUESTS", "8")
		setToolLog(t, b, OpenBrainToolLogID("proofs.list"))
		return b
	}
	nonCall := add(t, "JSONRPC_L7_REQUEST decision=allow rule_methods=initialize tools=proofs.list http_method=POST endpoint=192.0.2.10:4102/mcp/open_bra...")
	if a := mustAssess(t, nonCall); a.CrossCheck.Outcome != "inconsistent" ||
		!strings.Contains(strings.Join(a.CrossCheck.Rows, ""), "proofs.list 1 in the tool log, 0 in OCSF") {
		t.Errorf("non-call record: cross_check %+v, want inconsistent", a.CrossCheck)
	}
	// Control: the same name in a real tools/call record satisfies it.
	call := add(t, "JSONRPC_L7_REQUEST decision=allow rule_methods=tools/call tools=proofs.list http_method=POST endpoint=192.0.2.10:41...")
	if a := mustAssess(t, call); a.CrossCheck.Outcome != "consistent" || a.Grade != GradeOperatorAttested {
		t.Errorf("tools/call record: cross_check %+v grade %s, want consistent", a.CrossCheck, a.Grade)
	}
	mismatch := add(t, "JSONRPC_L7_REQUEST decision=allow rule_methods=tools/call,tools/call tools=proofs.list http_method=POST ...")
	if a := mustAssess(t, mismatch); a.CrossCheck.Outcome != "not_checked" || a.CrossCheck.Reason != "incomplete" {
		t.Errorf("mismatched batch: cross_check %+v, want not_checked (incomplete)", a.CrossCheck)
	}
	// The real US-205 fixture still grades operator_attested.
	if a := mustAssess(t, loadOpenShellGolden(t, "w20.bundle.json")); a.Grade != GradeOperatorAttested || a.CrossCheck.Outcome != "consistent" {
		t.Errorf("w20 golden: grade %s cross_check %+v", a.Grade, a.CrossCheck)
	}
}
