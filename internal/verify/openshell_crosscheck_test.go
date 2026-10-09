// Copyright 2026 Jerry David Chan, Konareef.ai
// SPDX-License-Identifier: Apache-2.0

// openshell_crosscheck_test.go — tests of the cross-check of the tool log
// against the reef-ocsf/v1 records (US-112; reef-core OpenShell adapter,
// phase 2, design section 9).
//
// Each golden bundle is a testdata/openshell_custody bundle with one named
// change (goldenVariant, openshell_test.go). The verifiable bundle has 4
// HTTP:POST ALLOWED records to the listener 192.0.2.10:4100, 3 of them to
// /mcp/open_brain, 2 ALLOWED NET:OPEN records by the OpenCode binary, and
// OPENSHELL_LISTENER_REQUESTS 4 (seen == served).
package verify

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// opencodeBinary is the reef_run_listener binary of the golden policy.
const opencodeBinary = "/usr/local/lib/node_modules/opencode-ai/bin/opencode.exe"

// toolLogRecord encodes one 113-byte tool-log record for toolID:
// 0x20 || SHA-256(tool_id) || args_hash || result_hash || ts_us || sats.
func toolLogRecord(toolID string, index int) []byte {
	record := make([]byte, 0, custodyRecordSize)
	record = append(record, 0x20)
	digest := sha256.Sum256([]byte(toolID))
	record = append(record, digest[:]...)
	args := sha256.Sum256([]byte("args"))
	result := sha256.Sum256([]byte("result"))
	record = append(record, args[:]...)
	record = append(record, result[:]...)
	record = binary.BigEndian.AppendUint64(record, uint64(1791459258000000+index))
	record = binary.BigEndian.AppendUint64(record, 0)
	return record
}

// setToolLog replaces the evidence's tool_log_records with one record per
// tool id and sets the custody TOOL_LOG_ROOT line to their root, so that
// rule 12 holds.
func setToolLog(t *testing.T, b *Bundle, toolIDs ...string) {
	t.Helper()
	var blob []byte
	var records [][]byte
	for i, id := range toolIDs {
		record := toolLogRecord(id, i)
		records = append(records, record)
		blob = append(blob, record...)
	}
	b.OpenShellEvidence.ToolLogRecords = base64.StdEncoding.EncodeToString(blob)
	root := CustodyToolLogRoot(records)
	setCustodyLine(t, b, "TOOL_LOG_ROOT", "sha256:"+hex.EncodeToString(root[:]))
}

// netOpenRecord is a NET:OPEN record with msg at seq.
func netOpenRecord(t *testing.T, seq int, msg string) []byte {
	return makeRecord(t, ocsfEventTag, map[string]any{
		"v": ocsfRule, "seq": seq, "src": "sandbox", "trust": "supervisor_report",
		"class": "NET:OPEN", "sev": "INFO", "msg": msg, "t_ms": 1791459259900,
	})
}

// httpRecord is an HTTP:<method> record with msg at seq.
func httpRecord(t *testing.T, seq int, method, msg string) []byte {
	return makeRecord(t, ocsfEventTag, map[string]any{
		"v": ocsfRule, "seq": seq, "src": "sandbox", "trust": "supervisor_report",
		"class": "HTTP:" + method, "sev": "INFO", "msg": msg, "t_ms": 1791459259900,
	})
}

// addRecord inserts record (seq 61) before STREAM:END and sets the root
// and count lines. The stream stays gapless.
func addRecord(t *testing.T, b *Bundle, record []byte) {
	t.Helper()
	setRecords(t, b, appendBeforeEnd(t, evidenceRecords(t, b), record, 61))
}

// withholdHTTP replaces every HTTP:* leaf with its leaf hash and true
// redaction metadata, as a public bundle has it. The root does not change.
func withholdHTTP(t *testing.T, b *Bundle) {
	t.Helper()
	for i, leaf := range b.OpenShellEvidence.Leaves {
		record, err := base64.StdEncoding.DecodeString(*leaf.Record)
		if err != nil {
			t.Fatal(err)
		}
		if i == 0 {
			continue
		}
		fields := recordFields(t, record)
		class, _ := fields["class"].(string)
		if !strings.HasPrefix(class, "HTTP:") {
			continue
		}
		hash := ocsfLeafHash(record)
		withheld := hex.EncodeToString(hash[:])
		seq := json.RawMessage(fields["seq"].(json.Number).String())
		b.OpenShellEvidence.Leaves[i] = OCSFLeaf{Withheld: &withheld, Class: &class, Seq: seq}
	}
}

// openBrainIDs returns n copies of the tool-log id of openbrain.recall.
func openBrainIDs(n int) []string {
	ids := make([]string, n)
	for i := range ids {
		ids[i] = OpenBrainToolLogID("openbrain.recall")
	}
	return ids
}

// TestOpenBrainToolIDs_MatchThePinnedFile: the Open Brain tool-log ids of
// the verifier are the ids that testdata/open_brain_tools.json pins, in
// the form <MCP server key>_<tool name with . replaced by _> (US-102 D11).
func TestOpenBrainToolIDs_MatchThePinnedFile(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("testdata", "open_brain_tools.json"))
	if err != nil {
		t.Fatal(err)
	}
	var pinned struct {
		IDForm string `json:"id_form"`
		Source struct {
			Repository string `json:"repository"`
			Commit     string `json:"commit"`
			ServerKey  struct {
				Value string `json:"value"`
			} `json:"server_key"`
		} `json:"source"`
		Tools []struct {
			Name string `json:"name"`
			ID   string `json:"id"`
		} `json:"tools"`
	}
	if err := json.Unmarshal(raw, &pinned); err != nil {
		t.Fatal(err)
	}
	if pinned.Source.Repository != "reef-core" || len(pinned.Source.Commit) != 40 {
		t.Errorf("source %+v: want the reef-core commit", pinned.Source)
	}
	if pinned.Source.ServerKey.Value != openBrainMCPServerKey {
		t.Errorf("server key %q, want %q", pinned.Source.ServerKey.Value, openBrainMCPServerKey)
	}
	var names []string
	for _, tool := range pinned.Tools {
		names = append(names, tool.Name)
		if got := OpenBrainToolLogID(tool.Name); got != tool.ID {
			t.Errorf("tool %s: id %q, pinned %q", tool.Name, got, tool.ID)
		}
		if !openBrainToolHashes[sha256.Sum256([]byte(tool.ID))] {
			t.Errorf("tool %s: the hash of %q is not in the verifier's set", tool.Name, tool.ID)
		}
	}
	if !slices.Equal(names, openBrainToolNames) {
		t.Errorf("pinned names %v, verifier names %v", names, openBrainToolNames)
	}
	if len(openBrainToolHashes) != len(pinned.Tools) {
		t.Errorf("verifier has %d hashes, the file pins %d tools", len(openBrainToolHashes), len(pinned.Tools))
	}
	if got := OpenBrainToolLogID("openbrain.recall"); got != "open_brain_openbrain_recall" {
		t.Errorf("OpenBrainToolLogID(openbrain.recall) = %q", got)
	}
}

// TestCrossCheck_GoldenOutcomes: a golden bundle for each outcome of
// design section 9, for each rule, and for seen < served, seen > served
// and seen == served. No outcome fails the verify.
func TestCrossCheck_GoldenOutcomes(t *testing.T) {
	allowedNetOpen := func(binary, destination string) string {
		return "ALLOWED " + binary + "(0) -> " + destination + " [policy:reef_run_listener engine:opa]"
	}
	cases := []struct {
		variant  goldenVariant
		want     CrossCheck
		grade    ContainmentGrade
		redacted bool
	}{
		{
			variant: goldenVariant{name: "consistent: seen == served, tool calls within the MCP POSTs", base: "full.bundle.json", change: func(t *testing.T, b *Bundle) {
				// 3 Open Brain calls, 3 POSTs to /mcp/open_brain; the bash call
				// is not an Open Brain id.
				setToolLog(t, b, append(openBrainIDs(2), "bash", OpenBrainToolLogID("plan.get_state"))...)
			}},
			want:  CrossCheck{Outcome: "consistent"},
			grade: GradeOperatorAttested,
		},
		{
			variant: goldenVariant{name: "not_checked (no_tool_log): seen == served, empty tool log", base: "full.bundle.json"},
			want:    CrossCheck{Outcome: "not_checked", Reason: "no_tool_log"},
			grade:   GradeOperatorAttested,
		},
		{
			variant:  goldenVariant{name: "not_checked (redacted): public bundle", base: "full.public.bundle.json"},
			want:     CrossCheck{Outcome: "not_checked", Reason: "redacted"},
			grade:    GradeClaimed,
			redacted: true,
		},
		{
			variant: goldenVariant{name: "not_checked (incomplete): seen < served, X2 not run", base: "full.bundle.json", change: func(t *testing.T, b *Bundle) {
				// 4 Open Brain calls against 3 POSTs would fail X2 if it ran.
				setToolLog(t, b, openBrainIDs(4)...)
				setCustodyLine(t, b, "OPENSHELL_LISTENER_REQUESTS", "5")
			}},
			want:  CrossCheck{Outcome: "not_checked", Reason: "incomplete"},
			grade: GradeClaimed,
		},
		{
			variant: goldenVariant{name: "not_checked (incomplete): seen < served, empty tool log", base: "full.bundle.json", change: func(t *testing.T, b *Bundle) {
				setCustodyLine(t, b, "OPENSHELL_LISTENER_REQUESTS", "5")
			}},
			want:  CrossCheck{Outcome: "not_checked", Reason: "incomplete"},
			grade: GradeClaimed,
		},
		{
			variant: goldenVariant{name: "not_checked (incomplete): marker before the drain end, X2 not run", base: "full.bundle.json", change: func(t *testing.T, b *Bundle) {
				setRecords(t, b, readRecordsFile(t, filepath.Join(ocsfVectorDir, "real_run_marker_before_drain.records")))
				setToolLog(t, b, openBrainIDs(4)...)
			}},
			want:  CrossCheck{Outcome: "not_checked", Reason: "incomplete"},
			grade: GradeClaimed,
		},
		{
			variant: goldenVariant{name: "not_checked (incomplete): not gapless, X2 not run", base: "full.bundle.json", change: func(t *testing.T, b *Bundle) {
				records := evidenceRecords(t, b)
				setStreamEnd(t, records, "server_end", "UNAVAILABLE")
				setRecords(t, b, records)
				setCustodyLine(t, b, "OCSF_STREAM_GAPLESS", "false")
				setToolLog(t, b, openBrainIDs(4)...)
			}},
			want:  CrossCheck{Outcome: "not_checked", Reason: "incomplete"},
			grade: GradeClaimed,
		},
		{
			variant: goldenVariant{name: "inconsistent X1: NET:OPEN to a destination outside the policy", base: "full.bundle.json", change: func(t *testing.T, b *Bundle) {
				addRecord(t, b, netOpenRecord(t, 61, allowedNetOpen(opencodeBinary, "203.0.113.7:443")))
			}},
			want:  CrossCheck{Outcome: "inconsistent", Rows: []string{"X1: destination not an endpoint of policy_yaml: 203.0.113.7:443"}},
			grade: GradeClaimed,
		},
		{
			variant: goldenVariant{name: "inconsistent X1: HTTP:GET to a destination outside the policy", base: "full.bundle.json", change: func(t *testing.T, b *Bundle) {
				addRecord(t, b, httpRecord(t, 61, "GET", "ALLOWED GET http://198.51.100.9/index.html [policy:other engine:l7]"))
			}},
			want:  CrossCheck{Outcome: "inconsistent", Rows: []string{"X1: destination not an endpoint of policy_yaml: 198.51.100.9:80"}},
			grade: GradeClaimed,
		},
		{
			variant: goldenVariant{name: "inconsistent X2: more Open Brain tool calls than MCP POSTs", base: "full.bundle.json", change: func(t *testing.T, b *Bundle) {
				setToolLog(t, b, openBrainIDs(4)...)
			}},
			want: CrossCheck{Outcome: "inconsistent", Rows: []string{
				"X2: 4 Open Brain tool calls in the tool log, 3 HTTP:POST ALLOWED records to http://192.0.2.10:4100/mcp/open_brain"}},
			grade: GradeClaimed,
		},
		{
			variant: goldenVariant{name: "inconsistent X3: NET:OPEN by another binary", base: "full.bundle.json", change: func(t *testing.T, b *Bundle) {
				addRecord(t, b, netOpenRecord(t, 61, allowedNetOpen("/usr/bin/curl", "192.0.2.10:4100")))
			}},
			want:  CrossCheck{Outcome: "inconsistent", Rows: []string{"X3: NET:OPEN by a binary other than the reef_run_listener binary: /usr/bin/curl"}},
			grade: GradeClaimed,
		},
		{
			variant: goldenVariant{name: "inconsistent X4: seen > served, X2 not run", base: "full.bundle.json", change: func(t *testing.T, b *Bundle) {
				setToolLog(t, b, openBrainIDs(4)...)
				setCustodyLine(t, b, "OPENSHELL_LISTENER_REQUESTS", "3")
			}},
			want:  CrossCheck{Outcome: "inconsistent", Rows: []string{"X4: listener lines without a served request: 4 in OCSF, 3 served"}},
			grade: GradeClaimed,
		},
		{
			variant: goldenVariant{name: "inconsistent X1 and X3: an ALLOWED NET:OPEN that cannot be read", base: "full.bundle.json", change: func(t *testing.T, b *Bundle) {
				addRecord(t, b, netOpenRecord(t, 61, "ALLOWED something"))
			}},
			want: CrossCheck{Outcome: "inconsistent", Rows: []string{
				"X1: destination not an endpoint of policy_yaml: seq 61: no destination",
				"X3: NET:OPEN by a binary other than the reef_run_listener binary: seq 61: no binary"}},
			grade: GradeClaimed,
		},
		{
			variant: goldenVariant{name: "inconsistent X1, X2, X3 and X4 in rule order", base: "full.bundle.json", change: func(t *testing.T, b *Bundle) {
				addRecord(t, b, netOpenRecord(t, 61, allowedNetOpen("/usr/bin/curl", "203.0.113.7:443")))
				setToolLog(t, b, openBrainIDs(4)...)
				setCustodyLine(t, b, "OPENSHELL_LISTENER_REQUESTS", "3")
			}},
			// seen > served makes the evidence incomplete, so X2 does not run.
			want: CrossCheck{Outcome: "inconsistent", Rows: []string{
				"X1: destination not an endpoint of policy_yaml: 203.0.113.7:443",
				"X3: NET:OPEN by a binary other than the reef_run_listener binary: /usr/bin/curl",
				"X4: listener lines without a served request: 4 in OCSF, 3 served"}},
			grade: GradeClaimed,
		},
		{
			variant: goldenVariant{name: "inconsistent X3 in a redacted bundle: X1 and X3 still run", base: "full.bundle.json", change: func(t *testing.T, b *Bundle) {
				addRecord(t, b, netOpenRecord(t, 61, allowedNetOpen("/usr/bin/curl", "192.0.2.10:4100")))
				withholdHTTP(t, b)
			}},
			want:     CrossCheck{Outcome: "inconsistent", Rows: []string{"X3: NET:OPEN by a binary other than the reef_run_listener binary: /usr/bin/curl"}},
			grade:    GradeClaimed,
			redacted: true,
		},
		{
			variant: goldenVariant{name: "consistent: a DENIED NET:OPEN record and a tool call that is not Open Brain", base: "full.bundle.json", change: func(t *testing.T, b *Bundle) {
				// The golden run already has DENIED NET:OPEN records; X1 and X3
				// read ALLOWED records only.
				addRecord(t, b, netOpenRecord(t, 61, "DENIED /usr/bin/curl(0) -> 203.0.113.7:443 [reason:policy]"))
				setToolLog(t, b, "bash")
			}},
			want:  CrossCheck{Outcome: "consistent"},
			grade: GradeOperatorAttested,
		},
	}

	for _, c := range cases {
		t.Run(c.variant.name, func(t *testing.T) {
			b := c.variant.build(t)
			a := mustAssess(t, b)
			if a.CrossCheck.Outcome != c.want.Outcome || a.CrossCheck.Reason != c.want.Reason || !slices.Equal(a.CrossCheck.Rows, c.want.Rows) {
				t.Errorf("cross_check %+v, want %+v", a.CrossCheck, c.want)
			}
			if a.Grade != c.grade || a.Redacted != c.redacted {
				t.Errorf("grade %s redacted %t, want %s %t (reasons %v)", a.Grade, a.Redacted, c.grade, c.redacted, a.Reasons)
			}
			if inconsistent := slices.Contains(a.Reasons, reasonCrossCheckInconsistent); inconsistent != (c.want.Outcome == "inconsistent") {
				t.Errorf("reasons %v: the inconsistent reason is present %t, want %t", a.Reasons, inconsistent, !inconsistent)
			}
			// No outcome fails the verify.
			if r := Verify(b); !r.OK {
				t.Errorf("Verify failed: %v", r.Divergences)
			} else if r.Containment.CrossCheck.Outcome != c.want.Outcome {
				t.Errorf("Verify cross_check %+v", r.Containment.CrossCheck)
			}
		})
	}
}

// TestCrossCheck_OtherFormsNotChecked: the cross-check runs only for the
// full form with the key; the unavailable form and the full form without
// the key report not_checked with no reason and no rows.
func TestCrossCheck_OtherFormsNotChecked(t *testing.T) {
	for _, variant := range []goldenVariant{
		{name: "unavailable", base: "unavailable.bundle.json"},
		{name: "full without the key", base: "full.bundle.json", change: func(t *testing.T, b *Bundle) { b.OpenShellEvidence = nil }},
	} {
		t.Run(variant.name, func(t *testing.T) {
			a := mustAssess(t, variant.build(t))
			if a.CrossCheck.Outcome != "not_checked" || a.CrossCheck.Reason != "" || len(a.CrossCheck.Rows) != 0 {
				t.Errorf("cross_check %+v, want not_checked with no reason", a.CrossCheck)
			}
		})
	}
}

// TestCrossCheck_ToolLogReadAfterRule12: a tool log that does not match
// TOOL_LOG_ROOT is a rule-12 hard failure; the cross-check never reads it.
func TestCrossCheck_ToolLogReadAfterRule12(t *testing.T) {
	b := loadOpenShellGolden(t, "full.bundle.json")
	setToolLog(t, b, openBrainIDs(4)...)
	b.OpenShellEvidence.ToolLogRecords = base64.StdEncoding.EncodeToString(toolLogRecord("bash", 0))
	_, err := AssessContainment(b)
	var failure *ContainmentError
	if !errorAs(err, &failure) || failure.Rule != 12 {
		t.Fatalf("err %v, want a rule-12 hard failure", err)
	}
}

// TestNetOpenAllowed: the parts of NET:OPEN msgs.
func TestNetOpenAllowed(t *testing.T) {
	cases := []struct {
		msg     string
		allowed bool
		want    netOpenFields
	}{
		{allowedNetOpenMsg, true, netOpenFields{opencodeBinary, "192.0.2.10:4100"}},
		{"ALLOWED /bin/a (b)(12) -> [2001:db8::1]:443 [policy:x]", true, netOpenFields{"/bin/a (b)", "[2001:db8::1]:443"}},
		{"ALLOWED /bin/a(x) -> example.org:443", true, netOpenFields{"", "example.org:443"}},
		{"ALLOWED /bin/a(1) -> example.org", true, netOpenFields{"/bin/a", ""}},
		{"ALLOWED /bin/a(1) -> example.org:99999", true, netOpenFields{"/bin/a", ""}},
		{"ALLOWED something", true, netOpenFields{}},
		{"DENIED /bin/a(1) -> 203.0.113.7:443", false, netOpenFields{}},
		{"127.0.0.1:17670", false, netOpenFields{}},
	}
	for _, c := range cases {
		allowed, got := netOpenAllowed(ocsfEvent{class: "NET:OPEN", fields: map[string]any{"msg": c.msg}})
		if allowed != c.allowed || got != c.want {
			t.Errorf("netOpenAllowed(%q) = %t %+v, want %t %+v", c.msg, allowed, got, c.allowed, c.want)
		}
	}
}

// allowedNetOpenMsg is the measured ALLOWED NET:OPEN msg (US-102 P5).
const allowedNetOpenMsg = "ALLOWED /usr/local/lib/node_modules/opencode-ai/bin/opencode.exe(0) -> 192.0.2.10:4100 [policy:reef_run_listener engine:opa]"

// TestReadPolicyNetwork: the endpoints of every network policy and the
// listener binaries; a file that does not parse gives empty sets.
func TestReadPolicyNetwork(t *testing.T) {
	policy := readPolicyNetwork(loadOpenShellGolden(t, "full.bundle.json").OpenShellEvidence.PolicyYAML)
	if !policy.endpoints["192.0.2.10:4100"] || len(policy.endpoints) != 1 {
		t.Errorf("endpoints %v", policy.endpoints)
	}
	if !policy.listenerBinaries[opencodeBinary] || len(policy.listenerBinaries) != 1 {
		t.Errorf("listener binaries %v", policy.listenerBinaries)
	}
	multi := readPolicyNetwork(`network_policies:
  reef_run_listener:
    endpoints: [{host: "192.0.2.10", port: 4100}]
    binaries: [{path: "/bin/a"}]
  reef_egress:
    endpoints: [{host: "Example.ORG", port: 443}, {host: "", port: 80}, {host: "203.0.113.7"}]
    binaries: [{path: "/bin/b"}]
`)
	if !multi.endpoints["Example.ORG:443"] || multi.endpoints["example.org:443"] || len(multi.endpoints) != 2 {
		t.Errorf("endpoints %v", multi.endpoints)
	}
	if !multi.listenerBinaries["/bin/a"] || multi.listenerBinaries["/bin/b"] {
		t.Errorf("listener binaries %v", multi.listenerBinaries)
	}
	if empty := readPolicyNetwork("network_policies: [\n"); len(empty.endpoints) != 0 || len(empty.listenerBinaries) != 0 {
		t.Errorf("a file that does not parse gave %+v", empty)
	}
}

// TestCrossCheck_RefusesAmbiguousForms: golden bundles whose one added
// record could be read in two ways. Each fails X1 or X3 (fail closed),
// and none fails the verify.
func TestCrossCheck_RefusesAmbiguousForms(t *testing.T) {
	const listenerMCP = "http://192.0.2.10:4100/mcp/open_brain"
	cases := []struct {
		name   string
		record func(t *testing.T) []byte
		served string // OPENSHELL_LISTENER_REQUESTS after the change; "" keeps 4
		rows   []string
	}{
		{
			name: "NET:OPEN msg with a prefix before ALLOWED",
			record: func(t *testing.T) []byte {
				return netOpenRecord(t, 61, "[INFO] "+allowedNetOpenMsg)
			},
			rows: []string{"X1: destination not an endpoint of policy_yaml: seq 61: unknown NET:OPEN msg form"},
		},
		{
			name: "NET:OPEN msg with allowed in lower case",
			record: func(t *testing.T) []byte {
				return netOpenRecord(t, 61, "allowed"+strings.TrimPrefix(allowedNetOpenMsg, "ALLOWED"))
			},
			rows: []string{"X1: destination not an endpoint of policy_yaml: seq 61: unknown NET:OPEN msg form"},
		},
		{
			name: "HTTP:POST msg that is neither ALLOWED nor DENIED",
			record: func(t *testing.T) []byte {
				return httpRecord(t, 61, "POST", "POST "+listenerMCP)
			},
			rows: []string{"X1: destination not an endpoint of policy_yaml: seq 61: unknown HTTP:POST msg form"},
		},
		{
			name: "NET:OPEN msg with two arrows",
			record: func(t *testing.T) []byte {
				return netOpenRecord(t, 61, "ALLOWED /tmp/x(0) -> 203.0.113.7:443(0) -> 192.0.2.10:4100 [policy:reef_run_listener engine:opa]")
			},
			rows: []string{
				"X1: destination not an endpoint of policy_yaml: seq 61: no destination",
				"X3: NET:OPEN by a binary other than the reef_run_listener binary: seq 61: no binary"},
		},
		{
			name: "HTTP:POST class with a GET method in msg",
			record: func(t *testing.T) []byte {
				return httpRecord(t, 61, "POST", "ALLOWED GET "+listenerMCP+" [policy:reef_run_listener engine:l7]")
			},
			served: "5", // the record is a listener line, so seen is 5
			rows:   []string{`X1: destination not an endpoint of policy_yaml: seq 61: method "GET" differs from class HTTP:POST`},
		},
		{
			name: "HTTP:POST class with the method in lower case",
			record: func(t *testing.T) []byte {
				return httpRecord(t, 61, "POST", "ALLOWED post "+listenerMCP+" [policy:reef_run_listener engine:l7]")
			},
			served: "5",
			rows:   []string{`X1: destination not an endpoint of policy_yaml: seq 61: method "post" differs from class HTTP:POST`},
		},
		{
			name: "ALLOWED HTTP:GET with no URL",
			record: func(t *testing.T) []byte {
				return httpRecord(t, 61, "GET", "ALLOWED GET")
			},
			rows: []string{"X1: destination not an endpoint of policy_yaml: seq 61: no destination"},
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			b := goldenVariant{base: "full.bundle.json", change: func(t *testing.T, b *Bundle) {
				addRecord(t, b, c.record(t))
				if c.served != "" {
					setCustodyLine(t, b, "OPENSHELL_LISTENER_REQUESTS", c.served)
				}
			}}.build(t)
			a := mustAssess(t, b)
			if a.CrossCheck.Outcome != "inconsistent" || !slices.Equal(a.CrossCheck.Rows, c.rows) {
				t.Errorf("cross_check %+v, want inconsistent %q", a.CrossCheck, c.rows)
			}
			if a.Grade != GradeClaimed {
				t.Errorf("grade %s, want claimed", a.Grade)
			}
			if r := Verify(b); !r.OK {
				t.Errorf("Verify failed: %v", r.Divergences)
			}
		})
	}

	t.Run("NET:OPEN to a destination outside the policy in a redacted bundle", func(t *testing.T) {
		b := goldenVariant{base: "full.bundle.json", change: func(t *testing.T, b *Bundle) {
			addRecord(t, b, netOpenRecord(t, 61, "ALLOWED "+opencodeBinary+"(0) -> 203.0.113.7:443 [policy:x engine:opa]"))
			withholdHTTP(t, b)
		}}.build(t)
		a := mustAssess(t, b)
		want := []string{"X1: destination not an endpoint of policy_yaml: 203.0.113.7:443"}
		if a.CrossCheck.Outcome != "inconsistent" || !slices.Equal(a.CrossCheck.Rows, want) || !a.Redacted {
			t.Errorf("cross_check %+v redacted %t, want inconsistent %q", a.CrossCheck, a.Redacted, want)
		}
	})
}

// TestCrossCheck_ExactComparison: X1 and X3 compare byte for byte, as
// reef-core compares the listener authority: no case folding, no Unicode
// normalization, no IPv6 rewriting.
func TestCrossCheck_ExactComparison(t *testing.T) {
	policy := policyNetwork{
		endpoints:        map[string]bool{"example.org:443": true, "[2001:db8::1]:443": true},
		listenerBinaries: map[string]bool{"/opt/caf\u00e9/bin": true}, // NFC é
	}
	open := func(binary, destination string) ocsfEvent {
		return ocsfEvent{class: "NET:OPEN", seq: 61, hasSeq: true,
			fields: map[string]any{"msg": "ALLOWED " + binary + "(0) -> " + destination + " [policy:x engine:opa]"}}
	}
	for destination, wantRow := range map[string]bool{
		"example.org:443":     false,
		"EXAMPLE.org:443":     true,
		"[2001:db8::1]:443":   false,
		"[2001:0db8::1]:443":  true,
		"example.org:0443":    true,
		"example.org.:443":    true,
		"203.0.113.7:443":     true,
		"[2001:db8::1]:00443": true,
	} {
		row := crossCheckX1([]ocsfEvent{open("/opt/caf\u00e9/bin", destination)}, policy)
		if (row != "") != wantRow {
			t.Errorf("destination %q: row %q, want a row %t", destination, row, wantRow)
		}
	}
	if row := crossCheckX3([]ocsfEvent{open("/opt/caf\u00e9/bin", "example.org:443")}, policy); row != "" {
		t.Errorf("NFC binary: row %q", row)
	}
	if row := crossCheckX3([]ocsfEvent{open("/opt/cafe\u0301/bin", "example.org:443")}, policy); row == "" {
		t.Error("an NFD spelling of the listener binary passed X3")
	}
}

// TestCrossCheck_X2CountsOnlyTheExactURL: X2 counts a POST only for the
// exact listener MCP URL. Every other spelling is not counted, and every
// counted POST is also a listener line (listenerSeen), so X2 never reads a
// record differently from X4 and reef-core in the lenient direction.
func TestCrossCheck_X2CountsOnlyTheExactURL(t *testing.T) {
	const endpoint = "192.0.2.10:4100"
	post := func(url string) ocsfEvent {
		return ocsfEvent{class: "HTTP:POST", seq: 61, hasSeq: true,
			fields: map[string]any{"msg": "ALLOWED POST " + url + " [policy:reef_run_listener engine:l7]"}}
	}
	toolLog := [][]byte{toolLogRecord(OpenBrainToolLogID("openbrain.recall"), 0)}
	urls := map[string]bool{ // URL -> counted by X2
		"http://192.0.2.10:4100/mcp/open_brain":        true,
		"http://192.0.2.10:4100/mcp/open_brain?x=1":    false,
		"http://192.0.2.10:4100/mcp/open_brain/":       false,
		"http://192.0.2.10:4100/mcp/open_brain#f":      false,
		"http://192.0.2.10:4100/mcp/open%5Fbrain":      false,
		"http://192.0.2.10:4100/MCP/open_brain":        false,
		"HTTP://192.0.2.10:4100/mcp/open_brain":        false,
		"http://user@192.0.2.10:4100/mcp/open_brain":   false,
		"https://192.0.2.10:4100/mcp/open_brain":       false,
		"http://192.0.2.10:04100/mcp/open_brain":       false,
		"http://192.0.2.10:4100//mcp/open_brain":       false,
		"http://192.0.2.10:4100/mcp/./open_brain":      false,
		"http://192.0.2.10:4100/mcp/open_brain\u200b":  false,
		"http://192.0.2.10:4100/mcp/open_brain%20":     false,
		"http://198.51.100.9:4100/mcp/open_brain":      false,
		"http://192.0.2.10:4100/mcp/open_brain/../x":   false,
		"http://192.0.2.10:4100/mcp/open_brain;a=b":    false,
		"http://192.0.2.10:4100/mcp/open_brain?":       false,
		"http://192.0.2.10:4100/mcp/open_brain\\":      false,
		"http://[192.0.2.10]:4100/mcp/open_brain":      false,
		"http://192.0.2.10:4100/mcp/open_brain.":       false,
		"http://192.0.2.10:4100/mcp/open_brain%2F":     false,
		"http://192.0.2.10:4100/mcp/OPEN_BRAIN":        false,
		"http://192.0.2.10:4100/mcp/open_brain?a#b":    false,
		"http://192.0.2.10.:4100/mcp/open_brain":       false,
		"http://0xc0.0.2.10:4100/mcp/open_brain":       false,
		"http://192.0.2.10:4100/mcp%2Fopen_brain":      false,
		"http://192.0.2.10:4100/mcp/open_brain/mcp":    false,
		"http://192.0.2.10:4100/mcp/open_brain?a=/mcp": false,
	}
	for url, counted := range urls {
		events := []ocsfEvent{post(url)}
		row := crossCheckX2(events, toolLog, endpoint)
		if (row == "") != counted {
			t.Errorf("%q: X2 row %q, want counted %t", url, row, counted)
		}
		if counted && listenerSeen(events, endpoint) != 1 {
			t.Errorf("%q: counted by X2 but not a listener line", url)
		}
	}
	// A record whose class is not HTTP:POST is never counted.
	get := ocsfEvent{class: "HTTP:GET", fields: map[string]any{"msg": "ALLOWED POST http://192.0.2.10:4100/mcp/open_brain"}}
	if row := crossCheckX2([]ocsfEvent{get}, toolLog, endpoint); row == "" {
		t.Error("an HTTP:GET record was counted as an MCP POST")
	}
	// A record that is not 113 bytes is skipped, not read out of range.
	if row := crossCheckX2(nil, [][]byte{{0x20, 0x01}}, endpoint); row != "" {
		t.Errorf("short record: row %q", row)
	}
}

// TestCrossCheck_JSONFormsWithTwoReadingsFailRule9: record bytes that a
// JSON reader could read in two ways (duplicate keys, data after the
// value, a non-integer seq spelling, invalid UTF-8, an integer above
// 2^53) are not canonical JCS, so rule 9 refuses them before the
// cross-check reads them.
func TestCrossCheck_JSONFormsWithTwoReadingsFailRule9(t *testing.T) {
	canonical := string(netOpenRecord(t, 61, allowedNetOpenMsg)[1:])
	forms := map[string]string{
		"duplicate class key":  strings.Replace(canonical, `"class":"NET:OPEN"`, `"class":"HTTP:POST","class":"NET:OPEN"`, 1),
		"data after the value": canonical + `{}`,
		"seq 61.0":             strings.Replace(canonical, `"seq":61`, `"seq":61.0`, 1),
		"seq 6.1e1":            strings.Replace(canonical, `"seq":61`, `"seq":6.1e1`, 1),
		"seq above 2^53":       strings.Replace(canonical, `"seq":61`, `"seq":9007199254740993`, 1),
		"invalid UTF-8 in msg": strings.Replace(canonical, "ALLOWED", "ALLOWED\xff", 1),
		"escaped A in msg":     strings.Replace(canonical, "ALLOWED", "\\u0041LLOWED", 1),
	}
	for name, body := range forms {
		t.Run(name, func(t *testing.T) {
			if body == canonical {
				t.Fatal("the form did not change the record")
			}
			b := loadOpenShellGolden(t, "full.bundle.json")
			addRecord(t, b, append([]byte{ocsfEventTag}, body...))
			_, err := AssessContainment(b)
			var failure *ContainmentError
			if !errorAs(err, &failure) || failure.Rule != 9 {
				t.Errorf("err %v, want a rule-9 hard failure", err)
			}
		})
	}
}

// TestOpenBrainToolIDs_OneReading: each pinned tool name has only the
// characters [a-z_.], so the id form replaces nothing else, and the ids
// are distinct. The OpenCode configuration has one MCP server key,
// open_brain (reef-core config_materializer.ex:151-152), so no other key
// can make an id that starts with "open_brain_".
func TestOpenBrainToolIDs_OneReading(t *testing.T) {
	ids := map[string]string{}
	for _, name := range openBrainToolNames {
		for _, r := range name {
			if !(r >= 'a' && r <= 'z') && r != '_' && r != '.' {
				t.Errorf("tool name %q has the character %q", name, r)
			}
		}
		id := OpenBrainToolLogID(name)
		if other, dup := ids[id]; dup {
			t.Errorf("tools %q and %q have the same id %q", other, name, id)
		}
		ids[id] = name
	}
}

// TestPolicyYAMLWithTwoReadings: a policy file with a duplicate key could
// be read in two ways; yaml.v3 refuses it, so the listener endpoint is
// unknown and every ALLOWED destination and binary fails X1 and X3.
func TestPolicyYAMLWithTwoReadings(t *testing.T) {
	duplicate := `network_policies:
  reef_run_listener:
    endpoints: [{host: "192.0.2.10", port: 4100}]
    binaries: [{path: "/bin/a"}]
  reef_run_listener:
    endpoints: [{host: "203.0.113.7", port: 443}]
    binaries: [{path: "/bin/b"}]
`
	policy := readPolicyNetwork(duplicate)
	if len(policy.endpoints) != 0 || len(policy.listenerBinaries) != 0 {
		t.Errorf("duplicate keys gave %+v", policy)
	}
	if endpoint := listenerEndpoint(duplicate); endpoint != "" {
		t.Errorf("duplicate keys gave the listener endpoint %q", endpoint)
	}
	quotedPort := `network_policies:
  reef_run_listener:
    endpoints: [{host: "192.0.2.10", port: "4100"}]
`
	if policy := readPolicyNetwork(quotedPort); len(policy.endpoints) != 0 || listenerEndpoint(quotedPort) != "" {
		t.Errorf("a quoted port gave %+v", policy)
	}
}

// TestCrossCheck_BareNetOpen: a bare NET:OPEN "<host>:<port>" (no
// ALLOWED or DENIED verdict) to a loopback address is accepted; to any
// other address it must be a policy endpoint, else X1 fails (coordinator
// decision 2026-10-09). The US-108 real run, which has the bare form
// 127.0.0.1:17670, keeps its outcome.
func TestCrossCheck_BareNetOpen(t *testing.T) {
	const x1 = "X1: destination not an endpoint of policy_yaml: "
	cases := []struct {
		msg  string
		want CrossCheck
	}{
		{"127.0.0.1:9999", CrossCheck{Outcome: "not_checked", Reason: "no_tool_log"}},
		{"127.5.6.7:1", CrossCheck{Outcome: "not_checked", Reason: "no_tool_log"}},
		{"[::1]:8080", CrossCheck{Outcome: "not_checked", Reason: "no_tool_log"}},
		{"192.0.2.10:4100", CrossCheck{Outcome: "not_checked", Reason: "no_tool_log"}},
		{"203.0.113.7:443", CrossCheck{Outcome: "inconsistent", Rows: []string{x1 + "203.0.113.7:443"}}},
		{"[2001:db8::1]:443", CrossCheck{Outcome: "inconsistent", Rows: []string{x1 + "[2001:db8::1]:443"}}},
		{"localhost:80", CrossCheck{Outcome: "inconsistent", Rows: []string{x1 + "localhost:80"}}},
		{"192.0.2.10:4101", CrossCheck{Outcome: "inconsistent", Rows: []string{x1 + "192.0.2.10:4101"}}},
		{"127.000.0.1:80", CrossCheck{Outcome: "inconsistent", Rows: []string{x1 + "127.000.0.1:80"}}},
	}
	for _, c := range cases {
		t.Run(c.msg, func(t *testing.T) {
			b := goldenVariant{base: "full.bundle.json", change: func(t *testing.T, b *Bundle) {
				addRecord(t, b, netOpenRecord(t, 61, c.msg))
			}}.build(t)
			a := mustAssess(t, b)
			if a.CrossCheck.Outcome != c.want.Outcome || a.CrossCheck.Reason != c.want.Reason || !slices.Equal(a.CrossCheck.Rows, c.want.Rows) {
				t.Errorf("cross_check %+v, want %+v", a.CrossCheck, c.want)
			}
			wantGrade := GradeOperatorAttested
			if c.want.Outcome == "inconsistent" {
				wantGrade = GradeClaimed
			}
			if a.Grade != wantGrade {
				t.Errorf("grade %s, want %s (reasons %v)", a.Grade, wantGrade, a.Reasons)
			}
			if r := Verify(b); !r.OK {
				t.Errorf("Verify failed: %v", r.Divergences)
			}
		})
	}

	t.Run("US-108 real run keeps its outcome", func(t *testing.T) {
		b := loadOpenShellGolden(t, "full.bundle.json")
		setRecords(t, b, readRecordsFile(t, filepath.Join(ocsfVectorDir, "real_run.records")))
		hasBare := false
		for _, record := range evidenceRecords(t, b) {
			if fields := recordFields(t, record); fields["class"] == "NET:OPEN" && fields["msg"] == "127.0.0.1:17670" {
				hasBare = true
			}
		}
		if !hasBare {
			t.Fatal("the real run has no bare NET:OPEN 127.0.0.1:17670 record")
		}
		a := mustAssess(t, b)
		if a.CrossCheck.Outcome != "not_checked" || a.CrossCheck.Reason != "no_tool_log" || a.Grade != GradeOperatorAttested {
			t.Errorf("cross_check %+v grade %s, want not_checked (no_tool_log), operator_attested", a.CrossCheck, a.Grade)
		}
	})
}
